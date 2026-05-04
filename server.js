const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const CONFIG = {
  tenantId:      process.env.TENANT_ID       || '',
  clientId:      process.env.CLIENT_ID       || '',
  clientSecret:  process.env.CLIENT_SECRET   || '',
  groupId:       process.env.GROUP_ID        || '',
  reportId:      process.env.REPORT_ID       || '',
  adminPassword: process.env.ADMIN_PASSWORD  || 'admin123',
  resendApiKey:  process.env.RESEND_API_KEY  || '',
  emailTo:       process.env.EMAIL_TO        || 'tecidos@ladytex.com.br',
  emailFrom:     process.env.EMAIL_FROM      || 'onboarding@resend.dev',
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Sessoes e tokens de reset ficam em memoria (expiravel, nao precisa persistir)
const sessions = {};
const resetTokens = {};

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email        VARCHAR(255) PRIMARY KEY,
      name         VARCHAR(255) NOT NULL,
      company      VARCHAR(255) DEFAULT '',
      password_hash VARCHAR(255) NOT NULL,
      status       VARCHAR(50)  DEFAULT 'pending',
      focco_rep_code VARCHAR(100),
      created_at   TIMESTAMP    DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id         SERIAL PRIMARY KEY,
      data_hora  VARCHAR(255),
      solicitante VARCHAR(255),
      company    VARCHAR(255),
      cliente    VARCHAR(255),
      previsao   VARCHAR(255),
      pecas      JSONB,
      obs        TEXT,
      status     VARCHAR(50) DEFAULT 'pendente',
      created_at TIMESTAMP   DEFAULT NOW()
    )
  `);
  console.log('[DB] Tabelas inicializadas.');
}

async function getPbiToken() {
  const r = await fetch('https://login.microsoftonline.com/' + CONFIG.tenantId + '/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: CONFIG.clientId,
      client_secret: CONFIG.clientSecret,
      scope: 'https://analysis.windows.net/powerbi/api/.default',
    }),
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

async function getSessionUser(token) {
  const email = sessions[token];
  if (!email) return null;
  if (email === '__admin__') return { email: '__admin__', name: 'Admin', status: 'approved' };
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return rows[0] || null;
}

async function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  const user = await getSessionUser(token);
  if (!user) return res.status(401).json({ error: 'Nao autenticado' });
  if (user.status !== 'approved') return res.status(403).json({ error: 'Acesso nao aprovado' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-session-token'];
  if (sessions[token] !== '__admin__') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

// AUTH

app.post('/auth/register', async (req, res) => {
  const { name, email, company, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Dados incompletos' });
  const { rows } = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
  if (rows.length) return res.status(400).json({ error: 'Email ja cadastrado' });
  const passwordHash = await bcrypt.hash(password, 10);
  await pool.query(
    'INSERT INTO users (email, name, company, password_hash, status) VALUES ($1, $2, $3, $4, $5)',
    [email, name, company || '', passwordHash, 'pending']
  );
  res.json({ ok: true });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Dados incompletos' });
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Email ou senha incorretos' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email ou senha incorretos' });
  if (user.status === 'pending') return res.status(403).json({ error: 'pendente' });
  if (user.status === 'rejected') return res.status(403).json({ error: 'rejeitado' });
  const token = createSession(email);
  res.json({ ok: true, token, name: user.name });
});

app.post('/auth/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) delete sessions[token];
  res.json({ ok: true });
});

app.get('/auth/me', async (req, res) => {
  const token = req.headers['x-session-token'];
  const user = await getSessionUser(token);
  if (!user) return res.status(401).json({ error: 'Nao autenticado' });
  res.json({ name: user.name, email: user.email, status: user.status });
});

// ESQUECI A SENHA
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email obrigatorio' });
  const { rows } = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
  if (rows.length) {
    const token = crypto.randomBytes(32).toString('hex');
    resetTokens[token] = { email, expires: Date.now() + 3600000 };
    Object.keys(resetTokens).forEach(t => {
      if (resetTokens[t].email === email && t !== token) delete resetTokens[t];
    });
    const baseUrl = 'https://powerbi-backend-production.up.railway.app';
    const resetUrl = baseUrl + '/reset-password.html?token=' + token;
    console.log('[RESET] Token para:', email, '| URL:', resetUrl);
    if (CONFIG.resendApiKey) {
      try {
        const resend = new Resend(CONFIG.resendApiKey);
        await resend.emails.send({
          from: 'LADY BI Dashboard <' + CONFIG.emailFrom + '>',
          to: [email],
          subject: 'Redefinicao de senha - LADY BI',
          html: '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">'
            + '<div style="background:#1d1d1f;padding:24px;border-radius:12px 12px 0 0;text-align:center">'
            + '<h1 style="color:white;margin:0;font-size:20px">LADY BI</h1></div>'
            + '<div style="background:#f8f8f8;padding:24px"><h2 style="font-size:16px;color:#1d1d1f;margin-bottom:12px">Redefinicao de senha</h2>'
            + '<p style="font-size:14px;color:#444;margin:12px 0">Clique no botao abaixo para redefinir sua senha:</p>'
            + '<div style="text-align:center;margin:24px 0"><a href="' + resetUrl + '" style="background:#1d1d1f;color:white;padding:12px 24px;text-decoration:none;border-radius:8px;font-size:14px">Redefinir Senha</a></div>'
            + '<p style="font-size:12px;color:#999">Este link expira em 1 hora.</p></div></div>',
        });
      } catch(e) { console.error('[RESET] Erro email:', e.message); }
    }
  }
  res.json({ ok: true, message: 'Se o email estiver cadastrado, voce recebera as instrucoes.' });
});

app.post('/auth/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Dados incompletos' });
  const entry = resetTokens[token];
  if (!entry || entry.expires < Date.now()) return res.status(400).json({ error: 'Token invalido ou expirado' });
  const { rows } = await pool.query('SELECT email FROM users WHERE email = $1', [entry.email]);
  if (!rows.length) return res.status(400).json({ error: 'Usuario nao encontrado' });
  const passwordHash = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [passwordHash, entry.email]);
  delete resetTokens[token];
  console.log('[RESET] Senha redefinida:', entry.email);
  res.json({ ok: true, message: 'Senha redefinida! Faca login com a nova senha.' });
});

// ADMIN

app.post('/admin/login', async (req, res) => {
  const { password } = req.body || {};
  if (password !== CONFIG.adminPassword) return res.status(401).json({ error: 'Senha incorreta' });
  const token = createSession('__admin__');
  res.json({ ok: true, token });
});

app.get('/admin/users', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT email, name, company, status, focco_rep_code, created_at FROM users ORDER BY created_at DESC'
  );
  res.json(rows.map(u => ({
    name: u.name,
    email: u.email,
    company: u.company,
    status: u.status,
    foccoRepCode: u.focco_rep_code || '',
    createdAt: u.created_at,
  })));
});

app.post('/admin/approve/:email', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'UPDATE users SET status = $1 WHERE email = $2 RETURNING email',
    ['approved', req.params.email]
  );
  if (!rows.length) return res.status(404).json({ error: 'Usuario nao encontrado' });
  res.json({ ok: true });
});

app.post('/admin/reject/:email', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'UPDATE users SET status = $1 WHERE email = $2 RETURNING email',
    ['rejected', req.params.email]
  );
  if (!rows.length) return res.status(404).json({ error: 'Usuario nao encontrado' });
  res.json({ ok: true });
});

app.delete('/admin/users/:email', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM users WHERE email = $1', [req.params.email]);
  Object.keys(sessions).forEach(t => { if (sessions[t] === req.params.email) delete sessions[t]; });
  console.log('[ADMIN] Usuario deletado:', req.params.email);
  res.json({ ok: true });
});

app.put('/admin/users/:email/focco', requireAdmin, async (req, res) => {
  const { foccoRepCode } = req.body || {};
  const { rows } = await pool.query(
    'UPDATE users SET focco_rep_code = $1 WHERE email = $2 RETURNING email',
    [foccoRepCode || null, req.params.email]
  );
  if (!rows.length) return res.status(404).json({ error: 'Usuario nao encontrado' });
  res.json({ ok: true });
});

app.get('/admin/email-history', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM submissions ORDER BY created_at DESC');
  res.json(rows.map(r => ({
    id: r.id,
    dataHora: r.data_hora,
    solicitante: r.solicitante,
    email: r.email,
    company: r.company,
    cliente: r.cliente,
    previsao: r.previsao,
    pecas: r.pecas,
    obs: r.obs,
    status: r.status,
  })));
});

// EMBED TOKEN
app.get('/getEmbedToken', requireAuth, async (req, res) => {
  try {
    const t = await getPbiToken();
    const rMeta = await fetch(
      'https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId,
      { headers: { Authorization: 'Bearer ' + t } }
    );
    const meta = await rMeta.json();
    if (!rMeta.ok) throw new Error('Report ' + rMeta.status + ': ' + JSON.stringify(meta));
    const rEmbed = await fetch(
      'https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId + '/GenerateToken',
      {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' },
        body: JSON.stringify({ accessLevel: 'View' }),
      }
    );
    const embed = await rEmbed.json();
    if (!rEmbed.ok) throw new Error('GenerateToken ' + rEmbed.status + ': ' + JSON.stringify(embed));
    res.json({ accessToken: embed.token, embedUrl: meta.embedUrl, reportId: CONFIG.reportId });
  } catch (err) {
    console.error('[PBI]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ENVIO DE LISTA
app.post('/send-list', requireAuth, async (req, res) => {
  const { pecas, obs, cliente, previsao } = req.body || {};
  const user = req.user;
  if (!pecas || !pecas.length) return res.status(400).json({ error: 'Nenhuma peca selecionada' });

  const dataHora = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

  const htmlEmail = '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f0f0f0;padding:20px">'
    + '<div style="background:#1d1d1f;padding:20px 24px;border-radius:10px 10px 0 0"><h2 style="color:white;margin:0;font-size:16px">LADY BI — Consulta de Peças</h2></div>'
    + '<div style="background:#f8f8f8;padding:20px 24px;border:1px solid #e5e5e5"><table style="width:100%;border-collapse:collapse;font-size:13px">'
    + '<tr><td style="padding:4px 0;color:#666;width:110px">Data/Hora:</td><td style="padding:4px 0;color:#1d1d1f">' + dataHora + '</td></tr>'
    + '<tr><td style="padding:4px 0;color:#666">Solicitante:</td><td style="padding:4px 0;color:#1d1d1f">' + user.name + '</td></tr>'
    + (user.company ? '<tr><td style="padding:4px 0;color:#666">Empresa:</td><td style="padding:4px 0;color:#1d1d1f">' + user.company + '</td></tr>' : '')
    + (cliente ? '<tr><td style="padding:4px 0;color:#666">Cliente:</td><td style="padding:4px 0;color:#1d1d1f">' + cliente + '</td></tr>' : '')
    + (previsao ? '<tr><td style="padding:4px 0;color:#666">Previsão:</td><td style="padding:4px 0;color:#1d1d1f">' + previsao + '</td></tr>' : '')
    + '</table></div>'
    + '<div style="background:white;padding:20px 24px;border:1px solid #e5e5e5"><table style="width:100%;border-collapse:collapse">'
    + pecas.map(function(p, i) {
        var bg = i % 2 === 0 ? '#f5f5f7' : 'white';
        return '<tr style="background:' + bg + '"><td style="padding:8px 12px;font-size:13px;font-weight:500;color:#1d1d1f">' + p.codigo + '</td><td style="padding:8px 12px;font-size:13px;color:#444">' + p.descricao + '</td></tr>';
      }).join('')
    + '</table>'
    + (obs ? '<div style="margin-top:14px;padding:12px;background:#fff8e6;border-radius:6px;font-size:13px;color:#666">' + obs + '</div>' : '')
    + '</div><div style="padding:12px 24px;background:#f0f0f0;border-radius:0 0 10px 10px;font-size:11px;color:#999;text-align:center">LADY BI Dashboard</div></div>';

  // Salvar no banco primeiro
  let submissionId;
  try {
    const { rows } = await pool.query(
      'INSERT INTO submissions (data_hora, solicitante, company, cliente, previsao, pecas, obs, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
      [dataHora, user.name, user.company || '', cliente || '', previsao || '', JSON.stringify(pecas), obs || '', 'pendente']
    );
    submissionId = rows[0].id;
  } catch (dbErr) {
    console.error('[DB] Erro ao salvar submission:', dbErr.message);
  }

  if (!CONFIG.resendApiKey) {
    if (submissionId) await pool.query('UPDATE submissions SET status=$1 WHERE id=$2', ['simulado', submissionId]).catch(() => {});
    return res.json({ ok: true, message: 'Lista registrada!' });
  }

  try {
    const resend = new Resend(CONFIG.resendApiKey);
    const { error } = await resend.emails.send({
      from: 'LADY BI Dashboard <' + CONFIG.emailFrom + '>',
      to: [CONFIG.emailTo],
      reply_to: user.email,
      subject: '[LADY BI] Consulta de Pecas - ' + (cliente || user.name) + ' (' + dataHora + ')',
      html: htmlEmail,
    });
    if (error) {
      if (submissionId) await pool.query('UPDATE submissions SET status=$1 WHERE id=$2', ['erro: ' + JSON.stringify(error), submissionId]).catch(() => {});
      throw new Error(JSON.stringify(error));
    }
    if (submissionId) await pool.query('UPDATE submissions SET status=$1 WHERE id=$2', ['enviado', submissionId]).catch(() => {});
    res.json({ ok: true, message: 'Lista enviada com sucesso para a expedicao!' });
  } catch (err) {
    if (submissionId) await pool.query('UPDATE submissions SET status=$1 WHERE id=$2', ['erro: ' + err.message, submissionId]).catch(() => {});
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log('OK porta ' + PORT));
}).catch(err => {
  console.error('[DB] Falha ao inicializar banco:', err.message);
  process.exit(1);
});
