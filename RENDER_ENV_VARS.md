# Render Environment Variables

Set these in your Render backend service → Environment tab:

| Key | Value |
|-----|-------|
| DB_HOST | tramway.proxy.rlwy.net |
| DB_PORT | 53767 |
| DB_USER | root |
| DB_PASSWORD | OIYzyyIBmGfNaQvwujrqcErsPKGmBpKG |
| DB_NAME | dailybills |
| JWT_SECRET | dailybills-secret-key-2025 |
| ALLOWED_ORIGINS | https://daily-bills-frontend.onrender.com,http://localhost:3000 |
| NODE_ENV | production |

These MUST be set in Render dashboard — .env files are for local dev only on Render.
