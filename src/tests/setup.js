// Test setup file
const { TextEncoder, TextDecoder } = require('util');

// Polyfill for Node.js environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.SERVICE_SECRET = 'test-service-secret';
process.env.AUTH0_DOMAIN = 'test.auth0.com';
process.env.AUTH0_CLIENT_ID = 'test-client-id';
process.env.AUTH0_CLIENT_SECRET = 'test-client-secret';
process.env.AUTH0_CALLBACK_URL = 'http://localhost:3000/callback';

// Increase timeout for integration tests
jest.setTimeout(10000);
