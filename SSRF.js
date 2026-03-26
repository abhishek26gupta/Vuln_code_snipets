// ============================================================
// VULNERABILITY: SSRF (Server-Side Request Forgery)
// ---------------------------------------------------------------
// The /webhook endpoint accepts a callback_url from the user
// and performs a GET request to it with no validation.
// An attacker can supply internal URLs to probe or exfiltrate
// data from internal services (cloud metadata, databases, etc.)
//
// FIX: Validate callback_url against an allowlist of domains,
//      block private/loopback IP ranges before making the request.
// ============================================================

const express = require('express');
const axios   = require('axios');
const app     = express();
app.use(express.json());

app.post('/webhook', async (req, res) => {
  const { event, callback_url: callbackUrl } = req.body;

  if (!callbackUrl) return res.status(400).json({ error: 'callback_url required' });

  try {
    console.log(`[*] Probing: ${callbackUrl}`);
    
    const response = await axios.get(callbackUrl, { 
      timeout: 500000,
      // This ensures Axios doesn't throw an error if the site returns a 404 or 500
      validateStatus: () => true 
    });

    // Safe logging: Check if data exists before calling .length
    const dataLen = response.data ? (typeof response.data === 'string' ? response.data.length : 'object/non-string') : 0;
    
    console.log('[+] Success!');
    console.log('Status:', response.status);
    console.log('Data Length:', dataLen);

    res.json({ success: true, remote_status: response.status });
  } catch (err) {
    // THIS PART IS CRITICAL: Print the actual error to your terminal
    console.error('[-] SSRF Attempt Failed:', err.message);
    
    res.status(500).json({ 
      error: 'Failed to fetch callback URL', 
      reason: err.message 
    });
  }
});

app.listen(3000, () => console.log('Server on http://localhost:3000'));
