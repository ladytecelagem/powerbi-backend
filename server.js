const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');

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
  resendApiKey:  process.env.RESEND_API_KEY || '',
  emailTo:       process.env.EMAIL_TO       || 'tecidos@ladytex.com.br',
  emailFrom:     process.env.EMAIL_FROM     || 'noreply@ladybi.com.br',
};

const users = {};
const sessions = {};
const emailHistory = [];

// --- POWER BI ---
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

// --- SESSAO ---
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
  if (user.status !== 'approved') return res.status(403).json({ error: 'Acesso pendente' });
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  const token = req.headers['x-session-token'];
  if (sessions[token] !== '__admin__') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

// --- AUTH ---
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

// --- ADMIN ---
app.post('/admin/login', async (req, res) => {
  const { password } = req.body || {};
  if (password !== CONFIG.adminPassword) return res.status(401).json({ error: 'Senha incorreta' });
  const token = createSession('__admin__');
  res.json({ ok: true, token });
});
app.get('/admin/users', requireAdmin, (req, res) => {
  res.json(Object.values(users).map(u => ({ name: u.name, email: u.email, company: u.company, status: u.status, createdAt: u.createdAt })));
});
app.post('/admin/approve/:email', requireAdmin, (req, res) => {
  const user = users[req.params.email];
  if (!user) return res.status(404).json({ error: 'Usuario nao encontrado' });
  user.status = 'approved';
  res.json({ ok: true });
});
app.post('/admin/reject/:email', requireAdmin, (req, res) => {
  const user = users[req.params.email];
  if (!user) return res.status(404).json({ error: 'Usuario nao encontrado' });
  user.status = 'rejected';
  res.json({ ok: true });
});
app.get('/admin/email-history', requireAdmin, (req, res) => {
  res.json(emailHistory.slice().reverse());
});

// --- EMBED TOKEN ---
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

// --- ENVIO DE LISTA (via Resend) ---
app.post('/send-list', requireAuth, async (req, res) => {
  const { pecas, obs, cliente, previsao } = req.body || {};
  const user = req.user;
  if (!pecas || !pecas.length) return res.status(400).json({ error: 'Nenhuma peca informada' });

  const dataHora = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

  const htmlEmail = '<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">'
    + '<div style="background:#1d1d1f;padding:20px 24px;border-radius:10px 10px 0 0">'
    + '<h2 style="color:white;margin:0;font-size:18px">Consulta de Disponibilidade de Pecas</h2>'
    + '<p style="color:#aaa;margin:6px 0 0;font-size:13px">Dashboard Comercial - LADY BI</p></div>'
    + '<div style="background:#f8f8f8;padding:20px 24px;border:1px solid #eee;border-top:none">'
    + '<table style="width:100%;border-collapse:collapse">'
    + '<tr><td style="padding:4px 0;color:#666;font-size:13px;width:110px">Data/Hora</td><td style="padding:4px 0;font-size:13px"><b>' + dataHora + '</b></td></tr>'
    + '<tr><td style="padding:4px 0;color:#666;font-size:13px">Solicitante</td><td style="padding:4px 0;font-size:13px">' + user.name + ' &lt;' + user.email + '&gt;</td></tr>'
    + (user.company ? '<tr><td style="padding:4px 0;color:#666;font-size:13px">Empresa</td><td style="padding:4px 0;font-size:13px">' + user.company + '</td></tr>' : '')
    + (cliente ? '<tr><td style="padding:4px 0;color:#666;font-size:13px">Cliente</td><td style="padding:4px 0;font-size:14px;font-weight:700;color:#1d1d1f">' + cliente + '</td></tr>' : '')
    + (previsao ? '<tr><td style="padding:4px 0;color:#666;font-size:13px">Previsao</td><td style="padding:4px 0;font-size:13px">' + previsao + '</td></tr>' : '')
    + '</table></div>'
    + '<div style="background:white;padding:20px 24px;border:1px solid #eee;border-top:none">'
    + '<h3 style="margin:0 0 14px;font-size:15px;color:#1d1d1f">Pecas Solicitadas (' + pecas.length + ')</h3>'
    + '<table style="width:100%;border-collapse:collapse">'
    + pecas.map(function(p, i) {
        var bg = i % 2 === 0 ? '#f5f5f7' : 'white';
        var code = p.code || p;
        var nome = p.nome || '';
        return '<tr style="background:' + bg + '">'
          + '<td style="padding:8px 12px;color:#888;font-size:12px;width:28px">' + (i+1) + '</td>'
          + '<td style="padding:8px 12px;font-family:monospace;font-size:14px;font-weight:700">' + code + '</td>'
          + '<td style="padding:8px 12px;font-size:13px;color:#444">' + nome + '</td>'
          + '</tr>';
      }).join('')
    + '</table>'
    + (obs ? '<div style="margin-top:14px;padding:12px;background:#fff8e6;border-radius:8px;border-left:4px solid #f0a500"><b style="font-size:13px">Observacoes:</b><p style="margin:4px 0 0;font-size:13px">' + obs + '</p></div>' : '')
    + '</div>'
    + '<div style="padding:12px 24px;background:#f0f0f0;border-radius:0 0 10px 10px;font-size:11px;color:#888;text-align:center">Enviado automaticamente pelo Dashboard Comercial LADY BI</div>'
    + '</div>';

  const registro = {
    id: Date.now(),
    dataHora, solicitante: user.name, email: user.email,
    empresa: user.company || '', cliente: cliente || '',
    previsao: previsao || '', pecas: pecas.map(function(p){ return p.code || p; }),
    obs: obs || '', status: 'pendente'
  };

  try {
    if (!CONFIG.resendApiKey) {
      registro.status = 'simulado';
      emailHistory.push(registro);
      console.log('[MAIL] RESEND_API_KEY nao configurada. Simulando envio.');
      return res.json({ ok: true, message: 'Lista registrada! (configure RESEND_API_KEY para envio real)' });
    }

    const resend = new Resend(CONFIG.resendApiKey);
    const assunto = '[LADY BI] Consulta de Pecas - ' + (cliente || user.name) + ' (' + pecas.length + ' itens)';

    const { error } = await resend.emails.send({
      from: 'LADY BI Dashboard <' + CONFIG.emailFrom + '>',
      to: [CONFIG.emailTo],
      reply_to: user.email,
      subject: assunto,
      html: htmlEmail,
    });

    if (error) {
      registro.status = 'erro: ' + JSON.stringify(error);
      emailHistory.push(registro);
      console.error('[MAIL] Resend erro:', error);
      return res.status(500).json({ error: 'Erro ao enviar: ' + JSON.stringify(error) });
    }

    registro.status = 'enviado';
    emailHistory.push(registro);
    console.log('[MAIL] Enviado via Resend para', CONFIG.emailTo, '- pecas:', pecas.length);
    res.json({ ok: true, message: 'Lista enviada com sucesso para a expedicao!' });
  } catch (err) {
    registro.status = 'erro: ' + err.message;
    emailHistory.push(registro);
    console.error('[MAIL] Erro:', err.message);
    res.status(500).json({ error: 'Erro: ' + err.message });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('OK porta ' + PORT));
