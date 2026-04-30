const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const CONFIG = {
  tenantId:      process.env.TENANT_ID      || '',
  clientId:      process.env.CLIENT_ID      || '',
  clientSecret:  process.env.CLIENT_SECRET  || '',
  groupId:       process.env.GROUP_ID       || 'a44afaa1-3b9e-4ea3-a33f-2ef1777ea80c',
  reportId:      process.env.REPORT_ID      || 'bad25a70-e239-4b00-8933-b1fa530185b4',
  adminPassword: process.env.ADMIN_PASSWORD || 'admin123',
};

const users = {};
const sessions = {};

async function getPbiToken() {
  const r = await fetch('https://login.microsoftonline.com/' + CONFIG.tenantId + '/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: CONFIG.clientId, client_secret: CONFIG.clientSecret, scope: 'https://analysis.windows.net/powerbi/api/.default' }).toString()
  });
  const d = await r.json();
  if (!r.ok) throw new Error('PBI token: ' + JSON.stringify(d));
  return d.access_token;
}

function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = email;
  return token;
}

function getSessionUser(token) {
  const email = sessions[token];
  return email ? users[email] : null;
}

function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  const user = getSessionUser(token);
  if (!user) return res.status(401).json({ error: 'Nao autenticado' });
  if (user.status !== 'approved') return res.status(403).json({ error: 'Acesso pendente de aprovacao' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-session-token'];
  const email = sessions[token];
  if (email !== '__admin__') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

app.post('/auth/register', async (req, res) => {
  const { name, email, company, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Nome, email e senha sao obrigatorios' });
  if (users[email]) return res.status(409).json({ error: 'Email ja cadastrado' });
  const passwordHash = await bcrypt.hash(password, 10);
  users[email] = { name, email, company: company || '', passwordHash, status: 'pending', createdAt: new Date().toISOString() };
  console.log('[AUTH] Novo cadastro:', email);
  res.json({ ok: true, message: 'Cadastro realizado! Aguarde aprovacao do administrador.' });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = users[email];
  if (!user) return res.status(401).json({ error: 'Email ou senha incorretos' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Email ou senha incorretos' });
  if (user.status === 'pending') return res.status(403).json({ error: 'pending', message: 'Seu acesso ainda nao foi aprovado.' });
  if (user.status === 'rejected') return res.status(403).json({ error: 'rejected', message: 'Seu acesso foi negado pelo administrador.' });
  const token = createSession(email);
  res.json({ ok: true, token, name: user.name });
});

app.post('/auth/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) delete sessions[token];
  res.json({ ok: true });
});

app.get('/auth/me', (req, res) => {
  const token = req.headers['x-session-token'];
  const user = getSessionUser(token);
  if (!user) return res.status(401).json({ error: 'Nao autenticado' });
  res.json({ name: user.name, email: user.email, status: user.status });
});

app.post('/admin/login', async (req, res) => {
  const { password } = req.body || {};
  if (password !== CONFIG.adminPassword) return res.status(401).json({ error: 'Senha incorreta' });
  const token = createSession('__admin__');
  res.json({ ok: true, token });
});

app.get('/admin/users', requireAdmin, (req, res) => {
  const list = Object.values(users).map(u => ({
    name: u.name, email: u.email, company: u.company, status: u.status, createdAt: u.createdAt
  }));
  res.json(list);
});

app.post('/admin/approve/:email', requireAdmin, (req, res) => {
  const user = users[req.params.email];
  if (!user) return res.status(404).json({ error: 'Usuario nao encontrado' });
  user.status = 'approved';
  console.log('[ADMIN] Aprovado:', req.params.email);
  res.json({ ok: true });
});

app.post('/admin/reject/:email', requireAdmin, (req, res) => {
  const user = users[req.params.email];
  if (!user) return res.status(404).json({ error: 'Usuario nao encontrado' });
  user.status = 'rejected';
  console.log('[ADMIN] Rejeitado:', req.params.email);
  res.json({ ok: true });
});

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
  } catch (err) {
    console.error('[PBI]', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('OK porta ' + PORT));
