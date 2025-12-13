// Simple test script to reproduce the 41 logs issue
const { request } = require('./UI_3.0/ruoyi-element-ai/src/utils/request.ts');

async function testWafScan() {
  console.log('Testing WAF scan API...');
  try {
    const response = await request.post('/api/waf/scan', { url: 'https://example.com' });
    console.log('Response:', response);
  } catch (error) {
    console.error('Error:', error);
  }
}

testWafScan();