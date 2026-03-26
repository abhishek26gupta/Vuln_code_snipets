// ============================================================
// VULNERABILITY: XXE (XML External Entity) Injection
// ---------------------------------------------------------------
// libxml.parseXml(req.body, { noent: true }) enables external
// entity resolution. An attacker can read local files like
// /etc/passwd by embedding an XXE payload in the request body.
//
// FIX: Use { noent: false } or strip/validate XML before parsing.
// ============================================================

// ============================================================
// HOW TO EXPLOIT:
//curl -X POST http://localhost:3002/profile/favorites \
//  -H "Content-Type: text/xml" \
//  -d '<?xml version="1.0"?>
//        <!DOCTYPE foo [
//          <!ENTITY xxe SYSTEM "file:///etc/passwd">
//        ]>
//        <favorites>
//          <title>&xxe;</title>
//        </favorites>'
// ============================================================

const express = require('express');
const libxml  = require('libxmljs2');   // libxmljs2 is the maintained fork
const app     = express();

// Accept raw XML body
app.use(express.text({ type: '*/xml' }));
app.use(express.text({ type: 'text/plain' }));

// Stub — in real app this would persist to DB
function addToFavorites(doc) {
  const title = doc.get('//title');
  return title ? title.text() : '(no title)';
}

app.post('/profile/favorites', (req, res) => {
  try {
    const favorite = libxml.parseXml(req.body, { noent: true }); // ← VULNERABLE change to false to secure it
    const result   = addToFavorites(favorite);
    res.send(`Added to favorites: ${result}`);
  } catch (e) {
    res.status(400).send('Invalid XML: ' + e.message);
  }
});

app.listen(3002, () => console.log('Server on http://localhost:3002'));
