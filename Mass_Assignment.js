// ============================================================
// VULNERABILITY: Mass Assignment – Privilege Escalation
// ---------------------------------------------------------------
// The registration endpoint blindly trusts req.body.isAdmin.
// Any user can register themselves as an admin by sending:
//   { "name":"hacker", "email":"h@h.com", "password":"x", "isAdmin": true }
//
// FIX: Never accept role/privilege fields from user input.
//      Hardcode isAdmin: false on registration.
// ============================================================

const express = require('express');
const bcrypt  = require('bcryptjs');
const app     = express();
app.use(express.json());

// In-memory "database"
const users = [];

app.post('/register', async (req, res) => {
  const user = {
    name:         req.body.name,
    email:        req.body.email,
    passwordHash: bcrypt.hashSync(req.body.password, 10),
    phone:        req.body.phone,
    isAdmin:      req.body.isAdmin,   // ← VULNERABLE: attacker-controlled
    address:      req.body.address,
  };

  users.push(user);

  if (!user) return res.status(404).send('User cannot be created');
  res.send(user);
});

app.get('/users', (req, res) => res.json(users));

app.listen(3000, () => console.log('Server on http://localhost:3000'));
