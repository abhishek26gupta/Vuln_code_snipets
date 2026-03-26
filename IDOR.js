// ============================================================
// VULNERABILITY: IDOR (Insecure Direct Object Reference)
// ---------------------------------------------------------------
// When creating a share link, the code queries the file by
// fileId but NEVER checks that req.session.userId owns that
// file. Any authenticated user can create a share link for
// ANY file belonging to ANY other user.


// POST another user's fileId to get his access token and then access his file

//
// FIX: Add WHERE owner_id = ? to the SELECT query when
//      fetching the file before creating the share link.
// ============================================================

const express  = require('express');
const { v1: uuid } = require('uuid');
const app      = express();
app.use(express.json());

// ── Minimal in-memory DB ─────────────────────────────────────
const filesDB = [
  { id: 1, owner_id: 'user-AAA', path: 'uploads/report.pdf',  original_name: 'report.pdf'  },
  { id: 2, owner_id: 'user-BBB', path: 'uploads/secret.docx', original_name: 'secret.docx' },
];
const fileSharesDB = [];

const db = {
  query: async (sql, params) => {
    sql = sql.replace(/\s+/g, ' ').trim();
    if (sql.startsWith('SELECT * FROM files WHERE id = ?')) {
      return filesDB.filter(f => f.id === params[0]);
    }
    if (sql.startsWith('INSERT INTO file_shares')) {
      const row = { token: params[0], file_id: params[1], owner_id: params[2], created_at: new Date() };
      fileSharesDB.push(row);
      return row;
    }
    if (sql.startsWith('SELECT * FROM file_shares WHERE token = ?')) {
      return fileSharesDB.filter(s => s.token === params[0]);
    }
    return [];
  }
};

// Fake session middleware – sets userId from a header for demo
app.use((req, _res, next) => {
  req.session = { userId: req.headers['x-user-id'] || 'user-AAA' };
  next();
});

// ── Create share link ─────────────────────────────────────────
app.post('/api/files/create-share-link', async (req, res) => {
  const { fileId } = req.body;
  const userId     = req.session.userId;

  // VULNERABLE: no WHERE owner_id = userId  ← IDOR here
  const file = await db.query('SELECT * FROM files WHERE id = ?', [fileId]);

  if (!file) return res.status(403).json({ error: 'File not found' });

  const accessToken = uuid();

  await db.query(
    `INSERT INTO file_shares (token, file_id, owner_id, created_at) VALUES (?, ?, ?, NOW())`,
    [accessToken, fileId, userId]
  );

  res.json({
    success: true,
    docUrl:  `https://storage.example.com/d/${accessToken}`,
    token:   accessToken,
  });
});

// ── Download via share token ──────────────────────────────────
app.get('/d/:accessToken', async (req, res) => {
  const { accessToken } = req.params;

  const share = await db.query('SELECT * FROM file_shares WHERE token = ?', [accessToken]);
  if (!share || share.length === 0) return res.status(404).json({ error: 'File not found' });

  const file = await db.query('SELECT * FROM files WHERE id = ?', [share[0].file_id]);
  if (!file || file.length === 0) return res.status(404).json({ error: 'File not found' });

  // In real app: res.download(path.join('/storage', file[0].path), file[0].original_name);
  res.json({ message: `Serving file: ${file[0].original_name}`, ownedBy: file[0].owner_id });
});

// ── List all shares (debug endpoint) ─────────────────────────
app.get('/debug/shares', (_req, res) => res.json(fileSharesDB));

app.listen(3003, () => console.log('Server on http://localhost:3003'));
