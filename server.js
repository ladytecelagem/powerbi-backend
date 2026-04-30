const express = require('express');
const cors    = require('cors');
const path    = require('path');
const app = express();
app.use(cors());
app.use(express.json());
const CONFIG = {
  tenantId:     process.env.TENANT_ID     || '',
  clientId:     process.env.CLIENT_ID     || '',
  clientSecret: process.env.CLIENT_SECRET || '',
  groupId:      process.env.GROUP_ID      || 'a44afaa1-3b9e-4ea3-a33f-2ef1777ea80c',
  reportId:     process.env.REPORT_ID     || 'bad25a70-e239-4b00-8933-b1fa530185b4',
};
async function getAzureADToken() {
  const url = 'https://login.microsoftonline.com/' + CONFIG.tenantId + '/oauth2/v2.0/token';
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: CONFIG.clientId, client_secret: CONFIG.clientSecret, scope: 'https://analysis.windows.net/powerbi/api/.default' });
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
  const d = await r.json();
  if (!r.ok) throw new Error('Azure AD: ' + r.status + ' ' + JSON.stringify(d));
  return d.access_token;
}
async function getReportMetadata(token) {
  const url = 'https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId;
  const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const d = await r.json();
  if (!r.ok) throw new Error('Report: ' + r.status + ' ' + JSON.stringify(d));
  return d;
}
async function generateEmbedToken(token) {
  const url = 'https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId + '/GenerateToken';
  const r = await fetch(url, { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ accessLevel: 'View' }) });
  const d = await r.json();
  if (!r.ok) throw new Error('GenerateToken: ' + r.status + ' ' + JSON.stringify(d));
  return d;
}
app.get('/getEmbedToken', async (req, res) => {
  try {
    const t = await getAzureADToken();
    const meta = await getReportMetadata(t);
    const embed = await generateEmbedToken(t);
    res.json({ accessToken: embed.token, embedUrl: meta.embedUrl, reportId: CONFIG.reportId, expiration: embed.expiration });
  } catch (err) { console.error('[PBI] ERRO:', err.message); res.status(500).json({ error: err.message }); }
});
app.get('/debug', async (req, res) => {
  try {
    const token = await getAzureADToken();
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
    // Lista workspaces via API normal
    const ws = await fetch('https://api.powerbi.com/v1.0/myorg/groups', { headers: { Authorization: 'Bearer ' + token } });
    const wsData = await ws.json();
    // Lista usuarios do workspace via Admin API (requer Tenant.Read.All)
    const users = await fetch('https://api.powerbi.com/v1.0/myorg/admin/groups/' + CONFIG.groupId + '/users', { headers: { Authorization: 'Bearer ' + token } });
    const usersData = await users.json();
    // Tenta acessar o workspace diretamente via Admin
    const wsAdmin = await fetch('https://api.powerbi.com/v1.0/myorg/admin/groups?$filter=id eq \'' + CONFIG.groupId + '\'', { headers: { Authorization: 'Bearer ' + token } });
    const wsAdminData = await wsAdmin.json();
    res.json({
      sp_appid: payload.appid,
      sp_oid: payload.oid,
      token_roles: payload.roles || [],
      workspaces_count: wsData['@odata.count'] || 0,
      workspace_users_status: users.status,
      workspace_users: usersData,
      workspace_admin_status: wsAdmin.status,
      workspace_admin: wsAdminData
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/health', (req, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname)));
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', function() { console.log('OK porta ' + PORT); });
