# Dashboard Comercial — Power BI Embedded

Solução completa para exibir relatórios do Power BI sem exigir login do usuário final.

---

## Arquitetura

```
├── server.js     ← Backend Node.js (gera o Embed Token com segurança)
├── index.html    ← Frontend (exibe o relatório via powerbi-client)
└── README.md
```

---

## Pré-requisitos

- **Node.js** v18+ instalado
- **Service Principal** no Azure AD com acesso ao workspace do Power BI
- O workspace do Power BI deve ter o Service Principal como **Membro** ou **Admin**

---

## 1. Configurar o Service Principal no Azure AD

1. Acesse o [portal Azure](https://portal.azure.com) → **Azure Active Directory → Registros de Aplicativo → Novo registro**
2. Anote:
   - `CLIENT_ID` (ID do Aplicativo)
   - `TENANT_ID` (ID do Diretório)
3. Crie um **segredo de cliente** → anote o `CLIENT_SECRET`
4. Em **Permissões de API → Power BI Service**, adicione:
   - `Report.ReadAll` *(tipo: Application)*
   - `Dataset.ReadAll` *(tipo: Application)*
   - Clique em **Conceder consentimento de administrador**

---

## 2. Adicionar o Service Principal ao Workspace do Power BI

1. Acesse o [Power BI Service](https://app.powerbi.com)
2. Vá ao workspace `a44afaa1-3b9e-4ea3-a33f-2ef1777ea80c`
3. Configurações → Acesso → Adicione o Service Principal como **Membro** ou **Admin**

---

## 3. Instalar dependências

```bash
npm init -y
npm install express cors
```

> O backend usa `fetch` nativo (Node 18+). Não é necessário instalar `node-fetch`.

---

## 4. Configurar credenciais

### Opção A — Variáveis de Ambiente (recomendado para produção)

```bash
export TENANT_ID="seu-tenant-id"
export CLIENT_ID="seu-client-id"
export CLIENT_SECRET="seu-client-secret"
```

### Opção B — Arquivo `.env` com dotenv

```bash
npm install dotenv
```

Crie um arquivo `.env` na raiz:

```env
TENANT_ID=seu-tenant-id
CLIENT_ID=seu-client-id
CLIENT_SECRET=seu-client-secret
GROUP_ID=a44afaa1-3b9e-4ea3-a33f-2ef1777ea80c
REPORT_ID=bad25a70-e239-4b00-8933-b1fa530185b4
```

Adicione no topo do `server.js`:
```js
require('dotenv').config();
```

---

## 5. Rodar localmente

```bash
node server.js
```

Acesse: **http://localhost:3000**

---

## 6. Testar o endpoint diretamente

```bash
curl http://localhost:3000/getEmbedToken
```

Resposta esperada:

```json
{
  "accessToken": "H4sIAAAAAAAEA...",
  "embedUrl": "https://app.powerbi.com/reportEmbed?reportId=...",
  "reportId": "bad25a70-e239-4b00-8933-b1fa530185b4",
  "expiration": "2024-12-01T14:30:00Z"
}
```

---

## Segurança

| Prática | Status |
|---|---|
| `CLIENT_SECRET` nunca exposto no frontend | ✅ |
| Token gerado apenas no backend | ✅ |
| Embed Token com escopo `View` apenas | ✅ |
| Usuário final não precisa de conta Power BI | ✅ |
| Suporte a variáveis de ambiente | ✅ |

---

## Deploy em Produção

Para deploy no Railway, Render, Heroku ou Azure App Service:

1. Configure as variáveis de ambiente no painel do provedor
2. O `index.html` é servido estaticamente pelo Express
3. Ajuste `BACKEND_URL` no `index.html` para a URL do seu servidor:

```js
const BACKEND_URL = 'https://seu-servidor.com/getEmbedToken';
```

---

## Solução de Problemas

| Erro | Causa | Solução |
|---|---|---|
| `Azure AD auth failed: 401` | Credenciais incorretas | Verifique CLIENT_ID, CLIENT_SECRET, TENANT_ID |
| `Falha ao gerar Embed Token: 403` | Service Principal sem acesso ao workspace | Adicione o SP como membro do workspace |
| Tela em branco no relatório | embedUrl ou reportId incorretos | Verifique GROUP_ID e REPORT_ID |
| `CORS error` no frontend | Backend não está rodando | Certifique-se que `node server.js` está ativo |
