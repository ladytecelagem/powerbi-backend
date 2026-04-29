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
      const body = new URLSearchParams({
              grant_type:    'client_credentials',
              client_id:     CONFIG.clientId,
              client_secret: CONFIG.clientSecret,
              scope:         'https://analysis.windows.net/powerbi/api/.default',
      });
      const response = await fetch(url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: body.toString(),
      });
      const data = await response.json();
      if (!response.ok) throw new Error('Azure AD: ' + response.status + ' ' + JSON.stringify(data));
      return data.access_token;
}

async function getReportMetadata(token) {
      const url = 'https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId;
      const response = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
      const data = await response.json();
      if (!response.ok) throw new Error('Report: ' + response.status + ' ' + JSON.stringify(data));
      return data;
}

async function generateEmbedToken(token) {
      const url = 'https://api.powerbi.com/v1.0/myorg/groups/' + CONFIG.groupId + '/reports/' + CONFIG.reportId + '/GenerateToken';
      const response = await fetch(url, {
              method: 'POST',
              headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
              body: JSON.stringify({ accessLevel: 'View' }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error('GenerateToken: ' + response.status + ' ' + JSON.stringify(data));
      return data;
}

app.get('/getEmbedToken', async (req, res) => {
      try {
              console.log('[PBI] Autenticando...');
              const azureToken = await getAzureADToken();
              console.log('[PBI] OK. Buscando relatorio...');
              const meta = await getReportMetadata(azureToken);
              console.log('[PBI] OK. Gerando token...');
              const embed = await generateEmbedToken(azureToken);
              console.log('[PBI] Sucesso:', embed.expiration);
              res.json({ accessToken: embed.token, embedUrl: meta.embedUrl, reportId: CONFIG.reportId, expiration: embed.expiration });
      } catch (err) {
              console.error('[PBI] ERRO:', err.message);
              res.status(500).json({ error: err.message });
      }
});

app.get('/health', (req, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
      console.log('Servidor na porta ' + PORT);
});
