[![ru](https://img.shields.io/badge/lang-ru-green.svg)](README.ru-RU.md)

Auth Server Frontend
-

OAuth2 authentication frontend for [AuthServer](../README.md) — a reusable Vue 3 + Vite SPA that ships with the module.

Overview
-

This application provides the user-facing authentication UI for any project built on **Apostol CRM**[^crm]. It handles login, registration, password recovery, and OAuth2 authorization consent — all through `HttpOnly` cookies with zero token management in JavaScript.

### Pages

| Route | Page | Purpose |
|-------|------|---------|
| `/login` | LoginPage | Username/password sign-in, Google sign-in |
| `/register` | RegisterPage | Email verification with 6-digit code |
| `/recover` | RecoverPage | Password reset via email |
| `/authorize` | AuthorizePage | OAuth2 consent screen (authorization code flow) |
| `/error` | ErrorPage | User-friendly error display |

### Technology stack

| Library | Version |
|---------|---------|
| Vue | 3.5+ |
| Vite | 8+ |
| Vue Router | 5 |
| vue-i18n | 11 |
| TypeScript | 5.9+ |
| SCSS | (sass 1.98+) |

Integration into another project
-

The frontend is a **shared component** of the AuthServer module. When `./configure` clones `module-AuthServer` into your project, the `frontend/` directory comes with it. Each project builds its own instance with project-specific configuration.

### Step 1. Install dependencies and build

```bash
cd backend/src/modules/Workers/AuthServer/frontend
npm install
```

Create a `.env` file with your project settings:

```env
# API host — leave empty for same-origin (recommended)
VITE_API_HOST=

# OAuth2 client ID (from conf/oauth2/*.json, "web" application)
VITE_CLIENT_ID=your-web-client-id

# OAuth2 scope
VITE_SCOPE=api

# Branding
VITE_APP_TITLE=Your App Name
VITE_APP_LOGO=/assets/logo.svg

# Google sign-in (optional — leave empty to hide the button)
VITE_GOOGLE_CLIENT_ID=

# Default locale (en or ru)
VITE_DEFAULT_LOCALE=en
```

Build:

```bash
npm run build    # output → dist/
```

### Step 2. Configure nginx

The frontend must be served as a same-origin proxy — nginx serves the static SPA and proxies API requests to the Apostol backend. This avoids CORS issues entirely.

Example nginx server block:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    root /var/www/auth;
    index index.html;

    # SPA: all routes → index.html
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy OAuth2 and API to backend
    location /oauth2/ {
        proxy_pass http://backend:4977;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Origin "https://$host";
    }

    location /api/ {
        proxy_pass http://backend:4977;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Origin "https://$host";
    }

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" always;
}
```

> **Important:** `proxy_set_header Origin "https://$host"` is required — the backend validates `Origin` against `javascript_origins` in the OAuth2 provider config.

### Step 3. Configure the backend

Add `auth.example.com` to `javascript_origins` in your OAuth2 provider config (`conf/oauth2/*.json`):

```json
{
  "web": {
    "javascript_origins": [
      "https://example.com",
      "https://auth.example.com"
    ]
  },
  "service": {
    "javascript_origins": [
      "https://example.com",
      "https://auth.example.com"
    ]
  }
}
```

Add a site config for the auth subdomain (`conf/sites/auth.json`):

```json
{
  "hosts": ["auth.example.com"],
  "roots": {
    "oauth2.identifier": "/login",
    "oauth2.secret": "/login",
    "oauth2.callback": "/authorize",
    "oauth2.error": "/error"
  }
}
```

These routes tell AuthServer where to redirect the browser during OAuth2 flows (e.g., `GET /oauth2/authorize` redirects to `/login`).

### Step 4. Deploy

Copy `dist/` contents to the nginx document root:

```bash
cp -r dist/* /var/www/auth/
```

Or in Docker, add a build stage to your Dockerfile:

```dockerfile
FROM node:22-alpine AS auth-builder
WORKDIR /app
COPY backend/src/modules/Workers/AuthServer/frontend/ .
COPY .env.auth .env
RUN npm ci && npm run build

FROM nginx:stable-bookworm
COPY --from=auth-builder /app/dist /var/www/auth
```

Development
-

```bash
npm run dev      # dev server on localhost:3100
                 # proxies /oauth2/ and /api/ to localhost:8080
```

Adding a locale
-

1. Copy `src/i18n/en.json` to `src/i18n/<locale>.json`
2. Translate all strings
3. Register the locale in `src/i18n/index.ts`

Project structure
-

```
frontend/
├── public/             # Static assets (logo, favicon)
├── src/
│   ├── assets/styles/  # SCSS (variables, base, auth)
│   ├── components/     # LoginForm, RegisterForm, RecoverForm, ConsentScreen, GoogleButton, AppBranding
│   ├── composables/    # useAuth (login/register/recover), useOAuth (consent flow)
│   ├── i18n/           # Locale JSON files + setup
│   ├── pages/          # Route pages (LoginPage, RegisterPage, RecoverPage, AuthorizePage, ErrorPage)
│   ├── config.ts       # VITE_* env reading
│   ├── router.ts       # Vue Router config
│   ├── types.ts        # TypeScript interfaces
│   ├── main.ts         # App entry point
│   └── App.vue         # Root component
├── index.html
├── vite.config.ts
├── tsconfig.json
└── package.json
```

[^crm]: **Apostol CRM** — a template project built on the [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) and [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform) frameworks.
