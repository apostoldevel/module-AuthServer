[![en](https://img.shields.io/badge/lang-en-green.svg)](README.md)

Фронтенд сервера авторизации
-

OAuth2-фронтенд для [AuthServer](../README.ru-RU.md) — переиспользуемое Vue 3 + Vite SPA, поставляемое вместе с модулем.

Обзор
-

Это приложение предоставляет пользовательский интерфейс аутентификации для любого проекта, построенного на **Apostol CRM**[^crm]. Оно обеспечивает вход, регистрацию, восстановление пароля и экран согласия OAuth2 — всё через `HttpOnly`-cookies без какого-либо управления токенами в JavaScript.

### Страницы

| Маршрут | Страница | Назначение |
|---------|----------|-----------|
| `/login` | LoginPage | Вход по логину/паролю, вход через Google |
| `/register` | RegisterPage | Подтверждение email 6-значным кодом |
| `/recover` | RecoverPage | Сброс пароля через email |
| `/authorize` | AuthorizePage | Экран согласия OAuth2 (поток authorization code) |
| `/error` | ErrorPage | Понятное отображение ошибок |

### Стек технологий

| Библиотека | Версия |
|------------|--------|
| Vue | 3.5+ |
| Vite | 8+ |
| Vue Router | 5 |
| vue-i18n | 11 |
| TypeScript | 5.9+ |
| SCSS | (sass 1.98+) |

Интеграция в другой проект
-

Фронтенд — это **общий компонент** модуля AuthServer. Когда `./configure` клонирует `module-AuthServer` в ваш проект, директория `frontend/` идёт вместе с ним. Каждый проект собирает свой экземпляр с проектно-специфичной конфигурацией.

### Шаг 1. Установка зависимостей и сборка

```bash
cd backend/src/modules/Workers/AuthServer/frontend
npm install
```

Создайте файл `.env` с настройками вашего проекта:

```env
# Хост API — оставьте пустым для same-origin (рекомендуется)
VITE_API_HOST=

# OAuth2 client ID (из conf/oauth2/*.json, приложение "web")
VITE_CLIENT_ID=your-web-client-id

# OAuth2 scope
VITE_SCOPE=api

# Брендинг
VITE_APP_TITLE=Название вашего приложения
VITE_APP_LOGO=/assets/logo.svg

# Вход через Google (необязательно — оставьте пустым, чтобы скрыть кнопку)
VITE_GOOGLE_CLIENT_ID=

# Локаль по умолчанию (en или ru)
VITE_DEFAULT_LOCALE=ru
```

Сборка:

```bash
npm run build    # результат → dist/
```

### Шаг 2. Настройка nginx

Фронтенд должен обслуживаться как same-origin прокси — nginx отдаёт статическое SPA и проксирует API-запросы на бэкенд Апостол. Это полностью устраняет проблемы с CORS.

Пример серверного блока nginx:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    root /var/www/auth;
    index index.html;

    # SPA: все маршруты → index.html
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Проксирование OAuth2 и API на бэкенд
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

    # Заголовки безопасности
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" always;
}
```

> **Важно:** `proxy_set_header Origin "https://$host"` обязателен — бэкенд проверяет `Origin` по `javascript_origins` в конфиге OAuth2-провайдера.

### Шаг 3. Настройка бэкенда

Добавьте `auth.example.com` в `javascript_origins` в конфиге OAuth2-провайдера (`conf/oauth2/*.json`):

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

Добавьте конфиг сайта для поддомена авторизации (`conf/sites/auth.json`):

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

Эти маршруты указывают AuthServer, куда перенаправлять браузер при потоках OAuth2 (например, `GET /oauth2/authorize` перенаправляет на `/login`).

### Шаг 4. Деплой

Скопируйте содержимое `dist/` в document root nginx:

```bash
cp -r dist/* /var/www/auth/
```

Или в Docker добавьте стадию сборки в Dockerfile:

```dockerfile
FROM node:22-alpine AS auth-builder
WORKDIR /app
COPY backend/src/modules/Workers/AuthServer/frontend/ .
COPY .env.auth .env
RUN npm ci && npm run build

FROM nginx:stable-bookworm
COPY --from=auth-builder /app/dist /var/www/auth
```

Разработка
-

```bash
npm run dev      # dev-сервер на localhost:3100
                 # проксирует /oauth2/ и /api/ на localhost:8080
```

Добавление локали
-

1. Скопируйте `src/i18n/en.json` в `src/i18n/<локаль>.json`
2. Переведите все строки
3. Зарегистрируйте локаль в `src/i18n/index.ts`

Структура проекта
-

```
frontend/
├── public/             # Статические ресурсы (логотип, favicon)
├── src/
│   ├── assets/styles/  # SCSS (переменные, базовые стили, auth)
│   ├── components/     # LoginForm, RegisterForm, RecoverForm, ConsentScreen, GoogleButton, AppBranding
│   ├── composables/    # useAuth (вход/регистрация/восстановление), useOAuth (поток согласия)
│   ├── i18n/           # JSON-файлы локалей + настройка
│   ├── pages/          # Страницы маршрутов (LoginPage, RegisterPage, RecoverPage, AuthorizePage, ErrorPage)
│   ├── config.ts       # Чтение переменных VITE_*
│   ├── router.ts       # Конфигурация Vue Router
│   ├── types.ts        # TypeScript-интерфейсы
│   ├── main.ts         # Точка входа приложения
│   └── App.vue         # Корневой компонент
├── index.html
├── vite.config.ts
├── tsconfig.json
└── package.json
```

[^crm]: **Apostol CRM** — шаблон-проект построенный на фреймворках [A-POST-OL](https://github.com/apostoldevel/libapostol) (C++20) и [PostgreSQL Framework for Backend Development](https://github.com/apostoldevel/db-platform).
