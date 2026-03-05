// Test environment setup
// Set required environment variables before any tests run
process.env.JWT_KEY = 'test-jwt-secret-key-for-testing-only-32chars!';
process.env.MONGODB_CONNECT = 'mongodb://localhost:27017/hackerchat-test';
process.env.NEXT_PUBLIC_AUTH_CONNECT = 'http://localhost:3000';
process.env.NEXT_PUBLIC_WEBSOCKET_CONNECT = 'ws://localhost:3000';
