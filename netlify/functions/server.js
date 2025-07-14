// netlify/functions/server.js
const serverless = require('serverless-http');
const expressApp = require('../../src/server.js'); // Adjust path based on your project structure

// This is the Netlify Function handler.
// It wraps your Express app using serverless-http.
exports.handler = serverless(expressApp);
