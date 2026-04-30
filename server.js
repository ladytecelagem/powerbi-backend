const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const CONFIG = {
  tenantId: process.env.TENANT_ID || '',
  clientId: process.env.CLIENT_ID || '',
  clientSecret: process.env.CLIENT_SECRET || '',
  groupId: process.env.GROUP_ID || 'a44afaa1-3b9e-4ea3-a33f-2ef1777ea80c',
  reportId: process.env.REPORT_ID || 'bad25a70-e239-4b00-8933-b1fa530185b4',
  adminPassword: process.env.ADMIN_PASSWORD || 'admin123',
  adminEmail: process.env.ADMIN_EMAIL || '',
};

// Banco em memoria (persiste enquanto o container rodar)
// Para producao real, usar um banco externo (ex: Railway PostgreSQL)
const users = {}; // email -> { name, email, company, status: 'pending'|'approved'|'rejected', token, createdAt }
const sessions = {}; // token -> email

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function getPbiToken() {
  const r = await fetch('https://login.microsoftonline.com/' + CONFIG.tenantId + '/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: CONFIG.clientId, client_secret: CONFIG.clientSecret, scope: 'https://analysis.windows.net/powerbi/api/.default' }).toString()
  });
  const d = await r.json();
  if (!r.ok) throw new Error('Azure AD ' + r.status + ': ' + JSON.stringify(d));
  return d.access_token;
}

// ——— AUTENTICACAO ———————————————————————

// Cadastro de novo usuario
app.post('/auth/register', (req, res) => {
  const { name, email, company } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Nome e email obrigatorios' });
  const key = email.toLowerCase();
  if (users[key]) return res.status(409).json({ error: 'Email ja cadastrado' });
  users[key] = { name, email: key, company: company || '', status: 'pending', createdAt: new Date().toISOString() };
  console.log('[AUTH] Novo cadastro:', key);
  res.json({ ok: true, message: 'Cadastro enviado! Aguarde aprovacao do administrador.' });
});

// Login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatorios' });
  const key = email.toLowerCase();
  const user = users[key];
  if (!user) return res.status(401).json({ error: 'Email nao encontrado' });
  if (user.password !== password) return res.status(401).json({ error: 'Senha incorreta' });
  if (user.status === 'pending') return res.status(403).json({ error: 'Cadastro aguardando aprovacao' });
  if (user.status === 'rejected') return res.status(403).json({ error: 'Acesso negado' });
  const token = generateToken();
  sessions[token] = key;
  res.json({ ok: true, token, name: user.name });
});

// Logout
app.post('/auth/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) delete sessions[token];
  res.json({ ok: true });
});

// ——— ADMIN ———————————————————————————

function adminAuth(req, res, next) {
  const pwd = req.headers['x-admin-password'];
  if (pwd !== CONFIG.adminPassword) return res.status(401).json({ error: 'Senha admin incorreta' });
  next();
}

// Lista todos os usuarios
app.get('/admin/users', adminAuth, (req, res) => {
  res.json(Object.values(users).map(u => ({ name: u.name, email: u.email, company: u.company, status: u.status, createdAt: u.createdAt })));
});

// Aprova usuario e define senha
app.post('/admin/approve', adminAuth, (req, res) => {
  const { email, password } = req.body;
  const key = email.toLowerCase();
  if (!users[key]) return res.status(404).json({ error: 'Usuario nao encontrado' });
  users[key].status = 'approved';
  users[key].password = password || generateToken().substring(0, 8);
  console.log('[ADMIN] Aprovado:', key, '| Senha:', users[key].password);
  res.json({ ok: true, password: users[key].password, message: 'Usuario aprovado. Envie a senha para o usuario.' });
});

// Rejeita usuario
app.post('/admin/reject', adminAuth, (req, res) => {
  const { email } = req.body;
  const key = email.toLowerCase();
  if (!users[key]) return res.status(404).json({ error: 'Usuario nao encontrado' });
  users[key].status = 'rejected';
  res.json({ ok: true });
});

// Remove usuario
app.delete('/admin/user', adminAuth, (req, res) => {
  const { email } = req.body;
  const key = email.toLowerCase();
  delete users[key];
  res.json({ ok: true });
// ——— POWER BI (protegido por sessao) ———————

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions[token]) return res.status(401).json({ error: 'Nao autenticado' });
  req.userEmail = sessions[token];
  next();
}

app.get('/getEmbedToken', requireAuth, async (req, res) => {
  try {
    const t = await getPbiToken();
    const rMeta = await fetch('https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId, { headers: { Authorization: 'Bearer ' + t } });
    const meta = await rMeta.json();
    if (!rMeta.ok) throw new Error('Report ' + rMeta.status + ': ' + JSON.stringify(meta));
    const rEmbed = await fetch('https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId + '/GenerateToken', {
      method: 'POST', headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' }, body: JSON.stringify({ accessLevel: 'View' })
    });
    const embed = await rEmbed.json();
    if (!rEmbed.ok) throw new Error('GenerateToken ' + rEmbed.status + ': ' + JSON.stringify(embed));
    res.json({ accessToken: embed.token, embedUrl: meta.embedUrl, reportId: CONFIG.reportId, expiration: embed.expiration });
  } catch (err) { console.error('[PBI]', err.message); res.status(500).json({ error: err.message }); }
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', function() { console.log('OK porta ' + PORT); });
