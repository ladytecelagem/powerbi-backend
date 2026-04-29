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
    const url = `https://login.microsoftonline.com/${CONFIG.tenantId}/oauth2/v2.0/token`;
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
    if (!response.ok) {
          throw new Error(`Azure AD auth failed: ${response.status} - ${JSON.stringify(data)}`);
    }
    return data.access_token;
}

async function getReportMetadata(azureToken) {
    const url = `https://api.powerbi.com/v1.0/myorg/groups/${CONFIG.groupId}/reports/${CONFIG.reportId}`;
    const response = await fetch(url, {
          headers: { Authorization: `Bearer ${azureToken}` },
    });
    const data = await response.json();
    if (!response.ok) {
          throw new Error(`Report metadata failed: ${response.status} - ${JSON.stringify(data)}`);
    }
    return data;
}

async function generateEmbedToken(azureToken) {
    const url = `https://api.powerbi.com/v1.0/myorg/groups/${CONFIG.groupId}/reports/${CONFIG.reportId}/GenerateToken`;
    const response = await fetch(url, {
          method: 'POST',
          headers: {
                  Authorization:  `Bearer ${azureToken}`,
                  'Content-Type': 'application/json',
          },
          body: JSON.stringify({ accessLevel: 'View' }),
    });
    const data = await response.json();
    if (!response.ok) {
          throw new Error(`GenerateToken failed: ${response.status} - ${JSON.stringify(data)}`);
    }
    return data;
}

app.get('/getEmbedToken', async (req, res) => {
    try {
          console.log('[PowerBI] Autenticando no Azure AD...');
          const azureToken = await getAzureADToken();
          console.log('[PowerBI] Token Azure OK. Buscando metadados...');
          const reportMeta = await getReportMetadata(azureToken);
          console.log('[PowerBI] Metadados OK. Gerando Embed Token...');
          const embedTokenData = await generateEmbedToken(azureToken);
          console.log('[PowerBI] Sucesso! Expira:', embedTokenData.expiration);
          res.json({
                  accessToken: embedTokenData.token,
                  embedUrl:    reportMeta.embedUrl,
                  reportId:    CONFIG.repor
