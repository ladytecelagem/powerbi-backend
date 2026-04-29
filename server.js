/**
 * server.js — Backend para geração de Embed Token do Power BI
 * Autenticação via Azure AD (Client Credentials Flow)
 * NÃO expõe segredos no frontend.
 */

const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// ─── CONFIGURAÇÃO ────────────────────────────────────────────────────────────
// Em produção, use variáveis de ambiente (.env) — nunca hardcode segredos.
const CONFIG = {
  tenantId:     process.env.TENANT_ID     || 'SEU_TENANT_ID',
  clientId:     process.env.CLIENT_ID     || 'SEU_CLIENT_ID',
  clientSecret: process.env.CLIENT_SECRET || 'SEU_CLIENT_SECRET',
  groupId:      process.env.GROUP_ID      || 'a44afaa1-3b9e-4ea3-a33f-2ef1777ea80c',
  reportId:     process.env.REPORT_ID     || 'bad25a70-e239-4b00-8933-b1fa530185b4',
};

// ─── HELPERS ─────────────────────────────────────────────────────────────────

/**
 * Obtém o Access Token do Azure AD via Client Credentials.
 * Escopo: Power BI API
 */
async function getAzureADToken() {
  const url = `https://login.microsoftonline.com/${CONFIG.tenantId}/oauth2/v2.0/token`;

  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     CONFIG.clientId,
    client_secret: CONFIG.clientSecret,
    scope:         'https://analysis.windows.net/powerbi/api/.default',
  });

  const response = await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    body.toString(),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Azure AD auth failed: ${response.status} — ${err}`);
  }

  const data = await response.json();
  return data.access_token;
}

/**
 * Obtém os metadados do relatório (embedUrl) via Power BI REST API.
 */
async function getReportMetadata(azureToken) {
  const url = `https://api.powerbi.com/v1.0/myorg/groups/${CONFIG.groupId}/reports/${CONFIG.reportId}`;

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${azureToken}` },
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Falha ao buscar metadados do relatório: ${response.status} — ${err}`);
  }

  return response.json(); // { id, embedUrl, ... }
}

/**
 * Gera o Embed Token para o relatório (acesso sem login do usuário final).
 */
async function generateEmbedToken(azureToken) {
  const url = `https://api.powerbi.com/v1.0/myorg/groups/${CONFIG.groupId}/reports/${CONFIG.reportId}/GenerateToken`;

  const response = await fetch(url, {
    method:  'POST',
    headers: {
      Authorization:  `Bearer ${azureToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ accessLevel: 'View' }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Falha ao gerar Embed Token: ${response.status} — ${err}`);
  }

  return response.json(); // { token, tokenId, expiration }
}

// ─── ENDPOINT PRINCIPAL ───────────────────────────────────────────────────────

/**
 * GET /getEmbedToken
 * Retorna: { accessToken, embedUrl, reportId }
 */
app.get('/getEmbedToken', async (req, res) => {
  try {
    console.log('[PowerBI] Iniciando autenticação Azure AD...');
    const azureToken = await getAzureADToken();

    console.log('[PowerBI] Buscando metadados do relatório...');
    const reportMeta = await getReportMetadata(azureToken);

    console.log('[PowerBI] Gerando Embed Token...');
    const embedTokenData = await generateEmbedToken(azureToken);

    res.json({
      accessToken: embedTokenData.token,
      embedUrl:    reportMeta.embedUrl,
      reportId:    CONFIG.reportId,
      expiration:  embedTokenData.expiration,
    });

    console.log('[PowerBI] ✅ Token gerado com sucesso. Expira em:', embedTokenData.expiration);
  } catch (error) {
    console.error('[PowerBI] ❌ Erro:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ─── SERVIR O FRONTEND ────────────────────────────────────────────────────────
// Serve o index.html diretamente quando ambos estão na mesma pasta.
app.use(express.static(path.join(__dirname)));

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Servidor rodando em http://localhost:${PORT}`);
  console.log(`   Endpoint: http://localhost:${PORT}/getEmbedToken\n`);
});
