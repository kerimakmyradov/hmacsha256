const crypto = require('crypto');

// Function to generate HMAC SHA-256 signature with Base64 output
function generateHmacSignature(login, password, unixTime, secretKey) {
    // Create message in format: {unixTime}{login}{password}
    const message = `${unixTime}${login}${password}`;
    
    // Decode Base64 secret key
    const decodedKey = Buffer.from(secretKey, 'base64');
    
    const hmac = crypto.createHmac('sha256', decodedKey);
    hmac.update(message);
    // Return Base64 encoded signature
    return hmac.digest('base64');
}

// Function to validate HMAC signature
function validateHmacSignature(login, password, unixTime, signature, secretKey) {
    const expectedSignature = generateHmacSignature(login, password, unixTime, secretKey);
    return crypto.timingSafeEqual(
        Buffer.from(signature, 'base64'),
        Buffer.from(expectedSignature, 'base64')
    );
}

// Example usage matching the documentation
const login = 'login';
const password = 'password';
const unixTime = '1654507324';
const secretKey = 'j3Aa/l4DMy9xcQhS4Evw/5AlzK1aBkdvYmoAESp90RU='; // Base64 encoded key

try {
    // Generate signature
    const signature = generateHmacSignature(login, password, unixTime, secretKey);
    console.log('HMAC SHA-256 Signature (Base64):', signature);
    
    // Validate signature
    const isValid = validateHmacSignature(login, password, unixTime, signature, secretKey);
    console.log('Signature is valid:', isValid);
    
    // Validate against the example signature from docs
    const docSignature = 'NpCesaIBpU7Requ+D0ilg5JI7v/laC6IRXpT5e8n12I=';
    const isDocValid = validateHmacSignature(login, password, unixTime, docSignature, secretKey);
    console.log('Documentation signature is valid:', isDocValid);
} catch (error) {
    console.error('Error:', error.message);
}
