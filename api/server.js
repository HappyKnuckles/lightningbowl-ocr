const { BlobServiceClient } = require('@azure/storage-blob');
const {
  ComputerVisionClient,
} = require('@azure/cognitiveservices-computervision');
const { ApiKeyCredentials } = require('@azure/ms-rest-js');
const crypto = require('crypto');

// --- Configuration with validation ---
const subKey = process.env.AZURE_COMPUTER_VISION_KEY;
const endPointUrl = process.env.AZURE_COMPUTER_VISION_ENDPOINT;
const sasUrl = process.env.AZURE_BLOB_SAS_URL;

// Validate required environment variables
if (!subKey || !endPointUrl || !sasUrl) {
  throw new Error('Missing required environment variables');
}

const computerVisionClient = new ComputerVisionClient(
  new ApiKeyCredentials({ inHeader: { 'Ocp-Apim-Subscription-Key': subKey } }),
  endPointUrl
);

const blobServiceClient = new BlobServiceClient(sasUrl);
const containerClient = blobServiceClient.getContainerClient('images');

const ALLOWED_ORIGIN_ENTRIES = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean);

const ALLOWED_ORIGINS = [];
const ALLOWED_ORIGIN_PATTERNS = [];

for (const entry of ALLOWED_ORIGIN_ENTRIES) {
  try {
    new URL(entry);
    ALLOWED_ORIGINS.push(entry);
  } catch {
    try {
      // Treat non-URL entries as regex patterns and anchor to avoid partial matches.
      ALLOWED_ORIGIN_PATTERNS.push(new RegExp(`^${entry}$`));
    } catch {
      console.warn(`Invalid ALLOWED_ORIGINS entry (skipped): ${entry}`);
    }
  }
}

if (ALLOWED_ORIGINS.length === 0 && ALLOWED_ORIGIN_PATTERNS.length === 0) {
  console.warn('No valid ALLOWED_ORIGINS configured; CORS requests with Origin header will be rejected.');
}

function isOriginAllowed(origin) {
  if (!origin) return false;
  return ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGIN_PATTERNS.some((pattern) => pattern.test(origin));
}

// --- Rate Limiting Setup ---
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 10;
const MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB
const MAX_BASE64_INPUT_SIZE = Math.ceil((MAX_IMAGE_SIZE_BYTES * 4) / 3) + 1000;
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/bmp'];
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const userRequests = rateLimitMap.get(ip) || [];

  // Filter out requests older than the window
  const recentRequests = userRequests.filter(
    (timestamp) => now - timestamp < RATE_LIMIT_WINDOW
  );

  if (recentRequests.length >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }

  recentRequests.push(now);
  rateLimitMap.set(ip, recentRequests);

  // If the map gets too big, remove IPs that haven't been active recently
  if (rateLimitMap.size > 1000) {
    for (const [key, timestamps] of rateLimitMap.entries()) {
      const isActive = timestamps.some((t) => now - t < RATE_LIMIT_WINDOW);
      if (!isActive) {
        rateLimitMap.delete(key);
      }
    }
  }
  return true;
}

function validateBase64Image(base64String) {
  // Check if it's a valid base64 string
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  
  // Remove data URL prefix if present
  let cleanBase64 = base64String;
  if (base64String.includes(',')) {
    cleanBase64 = base64String.split(',')[1];
  }
  
  if (!base64Regex.test(cleanBase64)) {
    return { valid: false, error: 'Invalid base64 format' };
  }
  
  return { valid: true, data: cleanBase64 };
}

function detectImageMimeType(buffer) {
  // Check magic numbers to detect real file type
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'image/jpeg';
  }
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return 'image/png';
  }
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46) {
    return 'image/gif';
  }
  if (buffer[0] === 0x42 && buffer[1] === 0x4D) {
    return 'image/bmp';
  }
  return null;
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
}

module.exports = async function (req, res) {
  // Set security headers for all responses
  setSecurityHeaders(res);
  
  const origin = req.headers.origin;
  if (isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (origin && !isOriginAllowed(origin)) {
    res.status(403).send('Origin not allowed');
    return;
  }

  const ip =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.connection?.remoteAddress ||
    'unknown';

  if (!checkRateLimit(ip)) {
    res.status(429).send('Too many requests.');
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed.');
    return;
  }

  if (!req.body || !req.body.image) {
    res.status(400).send('No image found.');
    return;
  }

  // Validate input size before processing
  if (req.body.image.length > MAX_BASE64_INPUT_SIZE) {
    res.status(413).send('Image too large.');
    return;
  }

  // Validate base64 format
  const validation = validateBase64Image(req.body.image);
  if (!validation.valid) {
    res.status(400).send('Invalid image format.');
    return;
  }

  let imageBuffer;
  try {
    imageBuffer = Buffer.from(validation.data, 'base64');
  } catch (error) {
    res.status(400).send('Invalid base64 encoding.');
    return;
  }

  // Check actual decoded size
  if (imageBuffer.length > MAX_IMAGE_SIZE_BYTES) {
    res.status(413).send('Image too large.');
    return;
  }

  // Validate it's actually an image by checking magic numbers
  const mimeType = detectImageMimeType(imageBuffer);
  if (!mimeType || !ALLOWED_IMAGE_TYPES.includes(mimeType)) {
    res.status(400).send('Unsupported image type. Please upload JPEG, PNG, GIF, or BMP.');
    return;
  }

  let blobNameForDeletion = null;

  try {
    const { urlWithSas, blobName } = await uploadImageToStorage(imageBuffer, mimeType);
    blobNameForDeletion = blobName;

    const printedResult = await readTextFromURL(urlWithSas);

    const extractedText = printRecognizedText(printedResult);

    if (blobNameForDeletion) {
      await deleteImageFromStorage(blobNameForDeletion);
      blobNameForDeletion = null;
    }

    res.status(200).send(extractedText);
  } catch (error) {
    console.error('Pipeline Error:', error);
    // Don't leak internal error details to client
    res.status(500).send('Error processing image. Please try again.');
  } finally {
    if (blobNameForDeletion) {
      try {
        await deleteImageFromStorage(blobNameForDeletion);
      } catch (e) {
        console.error('Cleanup error:', e);
      }
    }
  }
};


async function uploadImageToStorage(image, mimeType) {
  // Use crypto for better uniqueness to prevent collisions
  const randomId = crypto.randomBytes(16).toString('hex');
  const timestamp = Date.now();
  const extension = mimeType.split('/')[1] || 'jpg';
  const blobName = `image-${timestamp}-${randomId}.${extension}`;
  
  const blockBlobClient = containerClient.getBlockBlobClient(blobName);

  await blockBlobClient.uploadData(image, {
    blobHTTPHeaders: {
      blobContentType: mimeType
    }
  });

  return {
    urlWithSas: blockBlobClient.url,
    blobName: blobName,
  };
}

async function readTextFromURL(imageUrl) {
  let result = await computerVisionClient.read(imageUrl);
  let operation = result.operationLocation.split('/').slice(-1)[0];

  let readOperationResult;
  let attempts = 0;
  const MAX_ATTEMPTS = 30; // 30 seconds timeout

  do {
    attempts++;
    if (attempts > MAX_ATTEMPTS) {
      throw new Error('OCR processing timeout');
    }

    await sleep(1000);
    readOperationResult = await computerVisionClient.getReadResult(operation);
  } while (
    readOperationResult.status !== 'succeeded' &&
    readOperationResult.status !== 'failed'
  );

  if (readOperationResult.status === 'failed') {
    throw new Error('OCR processing failed');
  }

  return readOperationResult.analyzeResult.readResults;
}

function printRecognizedText(readResults) {
  if (!readResults || !Array.isArray(readResults)) {
    return '';
  }
  
  let recognizedText = '';
  for (const result of readResults) {
    if (result.lines && Array.isArray(result.lines)) {
      for (const line of result.lines) {
        if (line.text) {
          // Sanitize output to prevent any potential injection
          recognizedText += line.text.replace(/[<>]/g, '') + '\n';
        }
      }
    }
  }
  return recognizedText.trim();
}

async function deleteImageFromStorage(blobName) {
  // Sanitize blob name to prevent path traversal
  const safeBlobName = blobName.replace(/[^a-zA-Z0-9._-]/g, '');
  if (safeBlobName !== blobName) {
    throw new Error('Invalid blob name');
  }
  
  const blockBlobClient = containerClient.getBlockBlobClient(safeBlobName);
  await blockBlobClient.delete();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
