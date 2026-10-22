const http = require('http');

console.log('Running TrustVault Authorization Security Tests...');

// Test: Unauthenticated user trying to access a confidential document ID without token
http.get('http://localhost:3000/api/documents/999', (res) => {
  console.log(`Response Status Code: ${res.statusCode}`);
  
  // Unauthorized or Forbidden status expected (401 or 403 or 404)
  if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 404) {
    console.log('✅ TEST PASSED: Server successfully blocked unauthorized access!');
  } else {
    console.log('❌ TEST FAILED: Unauthorized access was not blocked by the server.');
  }
}).on('error', (err) => {
  console.error('❌ Error: Server is not running. Start the server using "npx nodemon server.js" first.');
});