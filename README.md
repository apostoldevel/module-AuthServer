Auth Server
-

[![ru](https://img.shields.io/badge/lang-ru-green.svg)](https://github.com/apostoldevel/module-AuthServer/blob/master/README.ru-RU.md)

**Module** for [Apostol](https://github.com/apostoldevel/apostol) + [db-platform](https://github.com/apostoldevel/db-platform) — **Apostol CRM**[^crm].

Description
-

**Auth Server** is a C++ OAuth 2.0 Authorization Server module for the [Apostol](https://github.com/apostoldevel/apostol) framework. It runs inside Apostol worker processes and handles all requests under the `/oauth2/` path prefix.

Key characteristics:

* Written in C++14 using an asynchronous, non-blocking I/O model based on the **epoll** API.
* Implements [RFC 6749](https://tools.ietf.org/html/rfc6749) (OAuth 2.0), OpenID Connect, and [RFC 7519](https://tools.ietf.org/html/rfc7519) (JWT). Supported grant types: Authorization Code, Implicit, Resource Owner Password Credentials, Client Credentials, Token Exchange ([RFC 8693](https://tools.ietf.org/html/rfc8693)), and JWT Bearer.
* All token issuance and session management logic runs in the database (`daemon.token`, `daemon.login`). The C++ layer handles only HTTP transport, parameter validation, JWT signature operations, and cookie management.
* JWT verification is done locally using the `jwt-cpp` library — all 12 algorithms (HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512) are supported without a database round-trip.
* Supports external identity providers (Google, ESIA) via standard JWKS certificate endpoints, with public keys fetched and cached in memory.
* Simplifies user access by allowing sign-in through existing accounts (e.g. Google) without requiring a separate registration step.

### How it fits into Apostol

`CAuthServer` registers itself as the handler for any request whose path starts with `/oauth2/` (see `CheckLocation`). It accepts `GET`, `POST`, and `OPTIONS`; all other HTTP methods return `405 Method Not Allowed`.

**GET /oauth2/{action} routing:**

| Action | What C++ does | Database call |
|--------|--------------|---------------|
| `authorize` / `auth` | Validates `client_id`, `redirect_uri`, `response_type`, `scope`, `access_type`, `prompt` against in-memory provider config. Redirects to the login page URL from `sites.conf` (`oauth2.identifier` or `oauth2.secret`). | None |
| `code` | Receives authorization code from external provider redirect. For external providers (e.g. Google): makes a direct C++ HTTP call to the provider's `token_uri` to exchange the code for a token, then verifies the returned JWT. | `daemon.login(token, agent, host, origin)` |
| `callback` | Redirects to `oauth2.callback` from `sites.conf`. | None |
| `identifier` | Extracts `value` from request body, checks Bearer token. | `daemon.identifier(token, value)` |

**POST /oauth2/{action} routing:**

| Action | What C++ does | Database call |
|--------|--------------|---------------|
| `token` | Parses `client_id`/`client_secret` from body or `Authorization: Basic` header. For `web`/`service` apps: validates `redirect_uri` and `javascript_origins` against provider config. Calls DB with full payload as JSONB. | `daemon.token(client_id, client_secret, payload::jsonb, agent, host)` |
| `identifier` | Same as GET identifier. | `daemon.identifier(token, value)` |

**Token endpoint flow (`POST /oauth2/token`) step by step:**

1. The worker's event loop (epoll) accepts the connection and reads the HTTP request.
2. `CAuthServer` parses the grant type and client credentials from the request body or `Authorization: Basic` header. For the `password` grant without an explicit `client_id`, the default web application client is used automatically.
3. For `web` and `service` applications: C++ validates `redirect_uri` and `javascript_origins` in-process against the provider configuration loaded from `conf/oauth2/` — no database query needed for these checks.
4. It calls `daemon.token(client_id, client_secret, payload, agent, host)` asynchronously. The database handles all grant type logic: token generation, session creation, refresh tokens, token exchange, and external JWT validation.
5. On success: C++ sets three `HttpOnly` cookies (`__Secure-AT`, `__Secure-RT` with 60-day TTL and `SameSite=None; Secure`; `SID` session cookie) and returns the JSON token response to the client.

**JWT handling in C++:**

The module uses the `jwt-cpp` library directly for all cryptographic operations:

* **Verification** — supports all 12 algorithms. For HMAC algorithms (HS256/384/512) the secret is read from the provider config. For asymmetric algorithms (RS*/ES*/PS*) the public key is looked up by `kid` from the in-memory JWKS cache. After asymmetric verification, the token is re-signed with HS256 for uniform internal handling.
* **Creation** — issues a short-lived HS256 token (1-hour TTL) signed with the `web` application secret, with issuer and audience taken from the default provider config.

**Heartbeat (runs every 30 minutes):**

`Heartbeat()` resets all provider key statuses to `ksUnknown`, then fetches fresh JWKS/certificate public keys from each provider's `cert_uri` via a non-blocking C++ HTTP client. On fetch failure, the next retry is scheduled in 5 seconds instead of 30 minutes. Cached keys are used by `VerifyToken()` to validate RS*/ES*/PS* signatures without a round-trip to the database.

Database module
-

AuthServer is tightly coupled to the **`oauth2`** and **`admin`** modules of [db-platform](https://github.com/apostoldevel/db-platform).

All authentication state lives in the database — the C++ module handles only HTTP transport and local JWT signature validation:

| Object | Module | Purpose |
|--------|--------|---------|
| OAuth2 clients | `oauth2` | Registered applications with `client_id` / `client_secret` |
| OAuth2 providers | `oauth2` | External identity providers (Google, ESIA, etc.) with JWKS/cert URIs |
| OAuth2 audiences | `oauth2` | Token audiences linked to clients |
| Authorization codes | `oauth2` | Short-lived codes for the Authorization Code flow |
| Sessions | `admin` | User sessions created on successful authentication |
| Users / passwords | `admin` | User accounts, credential validation |

All grant type logic (token issuance, refresh, exchange, validation) is implemented as PL/pgSQL functions called by the module. Provider public keys are fetched from external URLs and cached locally by the C++ module (refreshed every 30 minutes).

Installation
-

Follow the build and installation instructions for [Apostol](https://github.com/apostoldevel/apostol) + [db-platform](https://github.com/apostoldevel/db-platform) — **Apostol CRM**[^crm].

Configuration
-

```ini
[module/AuthServer]
enable=true
```

Quick Start
-

> For frontend developers — getting a token requires exactly **two possible requests**.

All tokens are issued by a single endpoint. The `Authorization: Basic` header carries `client_id:client_secret` encoded in Base64. Your `client_id`, `client_secret`, and `scope` are provided by the server owner.

---

### 1. Service token (no user)

Use `client_credentials` for backend integrations and service-to-service calls. Token lifetime: **24 hours**.

**Request:**
```http
POST /oauth2/token HTTP/1.1
Host: YOUR-HOST
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=client_credentials&scope=YOUR-SCOPE&access_type=offline
```

**Response `200 OK`:**
```json
{
  "access_token":  "eyJ...",
  "refresh_token": "mZfA...",
  "secret":        "n9RX...",
  "token_type":    "Bearer",
  "expires_in":    86400,
  "session":       "db17c81d..."
}
```

---

### 2. User login (username + password)

Authenticates a specific user. Token lifetime: **1 hour**.

**Request:**
```http
POST /oauth2/token HTTP/1.1
Host: YOUR-HOST
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=password&username=USER&password=PASS&scope=YOUR-SCOPE&access_type=offline
```

**Response `200 OK`:**
```json
{
  "access_token":  "eyJ...",
  "refresh_token": "85Hr...",
  "secret":        "0NTZ...",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "session":       "ca8db8e7..."
}
```

---

Use `access_token` as a `Bearer` token in all subsequent API requests:

```
Authorization: Bearer eyJ...
```

The server also sets `HttpOnly` cookies (`__Secure-AT`, `__Secure-RT`, `SID`) — used automatically by browser clients.

> Full reference: [Authentication and Authorization](#authentication-and-authorization)

Cookie-Based Authentication
-

> For browser SPA developers — zero token management code required.

The server implements the **Token Handler** pattern out of the box. After login, `AuthServer` sets `__Secure-AT` and `__Secure-RT` as `HttpOnly; Secure; SameSite=None` cookies. All subsequent API requests send these cookies automatically — the browser handles everything.

### How it works

```
Browser SPA
  └─ fetch('/api/v1/...', { credentials: 'include' })
       ↓
  Apostol AppServer
    1. Reads __Secure-AT from cookie (no Authorization header needed)
    2. Verifies token — if expired:
       a. Calls daemon.refresh_token() → new tokens
       b. Sets new __Secure-AT, __Secure-RT, SID cookies
       c. Replays the original request transparently
    3. Returns API response + Set-Cookie headers
       ↓
Browser receives data. New cookies set automatically.
No 401. No manual refresh. No setTimeout.
```

### What the frontend must do

Add `credentials: 'include'` to every API request. That's it.

```javascript
// Login
const res = await fetch('/oauth2/token', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'grant_type=password&username=USER&password=PASS&...'
});
// Cookies __Secure-AT, __Secure-RT, SID are set automatically by the browser.

// All subsequent API calls
const data = await fetch('/api/v1/whoami', { credentials: 'include' });
// Token refresh (if needed) is transparent — you always get a 200.
```

### What to do on 401

A `401 Unauthorized` means the session has completely expired (both access and refresh tokens are invalid). Redirect to login:

```javascript
if (response.status === 401) {
  window.location.href = '/login';
}
```

### What NOT to do

| Do NOT | Why |
|--------|-----|
| Store tokens in `localStorage` / `sessionStorage` | Vulnerable to XSS; cookies are `HttpOnly` — JS cannot read them |
| Track `expires_in` and schedule a refresh | AppServer refreshes transparently on every expired request |
| Write refresh logic | Already handled server-side |
| Send `Authorization: Bearer` header | Not needed when using cookies (both modes are supported simultaneously) |

### CORS and security

CORS is enforced by an origin allowlist loaded from `conf/oauth2/*.json` (`javascript_origins` fields). Requests from unknown origins do not receive `Access-Control-Allow-Credentials: true`, so the browser blocks cross-origin cookie sending from untrusted sites.

To allow your frontend origin, add it to `javascript_origins` in your provider config:

```json
{
  "web": {
    "javascript_origins": [
      "https://your-app.com",
      "http://localhost:3000"
    ]
  }
}
```

Documentation
-

## Authentication and Authorization

### Using the OAuth 2.0 Protocol for User Authorization

The protocol defines four roles:

* **Resource owner** — the user of the system (a natural person);
* **Client** — the application that requests access to a protected resource on behalf of its owner;
* **Authorization server** — the server that issues identity tokens with the resource owner's permissions to the client, as well as access tokens that allow access to data;
* **Resource server** — the server that provides access to the protected resource based on verification of identity tokens and access tokens (for example, to user identity data).

In this implementation, the `authorization server` and the `resource server` are the same server.

To interact with the server, a **Client** must obtain a client identifier (`client_id`) and a client secret (`client_secret`).

All interaction occurs through the `RESTful` API described in the [RFC 6749](https://tools.ietf.org/html/rfc6749) specification.

#### Using OpenID Connect for User Authentication

The general authentication flow using OpenID Connect is as follows:

* The **Client** prepares an authentication request with the required parameters;
* The **Client** sends a `GET` request to the authorization server;
* The **Authorization server** authenticates the user (the user enters their username and password);
* The **Authorization server** obtains the user's consent to authenticate within this system;
* The **Authorization server** redirects the user back to the **Client** and provides an authorization code;
* The **Client** sends a `POST` request using the authorization code to obtain an identity token;
* The **Client** receives a response containing the required identity token (exchanges the authorization code for an access token);
* The **Client** validates the identity token and extracts the user identifier from it.

The sections below describe in detail the requests formed by the **Client** and the responses returned by the **Authorization Server**.

## Authorization Server API Endpoints

For authorization:
```http request
GET /oauth2/authorize
```
For obtaining an access token:
```http request
POST /oauth2/token
```

### Grant Types

**OAuth 2** defines four standard **authorization grant types**, each suited to different use cases, plus two extended grant types supported by this implementation:

1. **Authorization Code** — used with server-side applications.
2. **Implicit** — used with mobile or web (JavaScript) applications running on the user's device.
3. **Resource Owner Password Credentials** — used with trusted applications that are part of the service itself.
4. **Client Credentials** — used when the client (application) accesses the API without a user authorization context.
5. **Token Exchange** ([RFC 8693](https://tools.ietf.org/html/rfc8693)) — used to obtain a new access token before the current one expires.
6. **JWT Bearer** — used to authenticate using a JWT token issued by an external system (e.g., Google).

## Authorization Grant Types

### Authorization Code

Authorization Code is one of the most commonly used grant types because it is well suited for server-side applications where the application source code and the client secret are not exposed to outside parties. The flow is redirect-based, which means the application must be able to interact with the user agent (e.g., a web browser) and receive authorization codes redirected through the user agent.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client (application) identifier. |
| redirect_uri | `redirect_uri` | **Required.** The URI to which the authorization server will redirect the user agent (browser) along with the authorization code. |
| response_type | code | **Required.** Indicates that the application is requesting access using an authorization code. |
| scope | `scope` | **Recommended.** A space-separated list of scopes that define the resources your application can access on behalf of the user. |
| access_type | `access_type` | **Recommended.** Specifies whether your application can refresh access tokens when the user is not present in the browser. Accepted values: `online` (default) and `offline`. |
| state | `state` | **Recommended.** A set of random characters that will be returned by the server to the client (used to protect against replay attacks). |
| prompt | `prompt` | **Optional.** Controls the login page shown to the user. Accepted values: `signin` (default), `secret` (password page), `consent`, `select_account`, `none`. When `secret` is specified, the user is redirected to the password-entry page (`oauth2.secret` in `sites.conf`) instead of the identifier page. |

**Example request:**
```http request
GET /oauth2/authorize?client_id=YOUR-CLIENT-ID&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcode&scope=api&response_type=code&access_type=online&state=c2FmZXR HTTP/1.1
Host: localhost:8080
```

```
http://localhost:8080/oauth2/authorize?
  client_id=YOUR-CLIENT-ID&
  redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcode&
  response_type=code&
  access_type=online&
  scope=api&
  state=c2FmZXR
```

If authentication succeeds, the authorization server will redirect the user to the URI specified in `redirect_uri` and return two mandatory parameters:
* `code` — the authorization code;
* `state` — the value of the `state` parameter that was sent in the authentication request.

The **Client** must compare the `state` value it sent with the value it received.

**Authorization code response:**
```
http://localhost:8080/oauth2/code?code=b%2F8NpjbB4eLaukGr68tE7maTCeBISO%2FC7hWxKGuKb8I4Ysc7uw8a2MRUMWnO3Nzt
```

* Note that the code (`b/8NpjbB4eLaukGr68tE7maTCeBISO/C7hWxKGuKb8I4Ysc7uw8a2MRUMWnO3Nzt`) is [URL-encoded](https://www.urlencoder.org/) and must be [URL-decoded](https://www.urldecoder.org/) before use.

If an error occurs during authentication, the authorization server will redirect the user to the URI specified in `redirect_uri` with error information:
```
http://localhost:8080/oauth2/code?code=403&error=access_denied&error_description=Access%20denied.
```

To exchange the authorization code for an access token, the **Client** must form a `POST` request.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client identifier. |
| client_secret | `client_secret` | **Required.** The client secret. |
| grant_type | authorization_code | **Required.** As defined in the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-4.1.3), this field must contain the value `authorization_code`. |
| code | `code` | **Required.** The authorization code returned from the initial request. |
| redirect_uri | `redirect_uri` | **Required.** The redirect URI (must match the `redirect_uri` from the initial request). |

* According to the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-2.3.1), the client authentication parameters (`client_id` and `client_secret`) may be passed either in the request body or in the HTTP `Authorization` header (HTTP Basic authentication):

```
Authorization: Basic d2ViLXNlcnZpY2UucnU6Y2xpZW50IHNlY3JldA==
```

In response, the authorization server will return a JSON object containing a short-lived access token and a refresh token.

**Response fields:**

| Field | Type | Description |
| --- | --- | --- |
| access_token | STRING | Short-lived access token (valid for 1 hour). |
| expires_in | INTEGER | Remaining lifetime of the access token in seconds. |
| token_type | STRING | Type of the returned token. Always `Bearer`. |
| session | STRING | User session identifier. |
| refresh_token | STRING | * Token that can be used to obtain a new access token. |
| id_token | STRING | * User identity token. |

* Note: the refresh token is only returned if your application set `access_type` to `offline` in the initial request.
* Note: the identity token (`id_token`) is only returned if your application included one of the following values in `scope`: `openid`, `profile`, or `email`.

**Example request:**

```http request
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR-CLIENT-ID&
client_secret=YOUR-CLIENT-SECRET&
grant_type=authorization_code&
code=b%2F8NpjbB4eLaukGr68tE7maTCeBISO%2FC7hWxKGuKb8I4Ysc7uw8a2MRUMWnO3Nzt&
redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcode
```

###### * Although not required by the specification, the authorization server also accepts requests in JSON format (`Content-Type: application/json`).

**Example response:**

```json
{
  "access_token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[payload].[signature]",
  "token_type" : "Bearer",
  "expires_in" : 3600,
  "session" : "dfe05b78a76b6ad8e0fcbef270671793b86aa848"
}
```

### Implicit

The Implicit grant type is used by mobile and web applications (JavaScript applications running in a web browser) where the confidentiality of the client secret cannot be guaranteed. This grant type is also redirect-based; the access token is passed directly to the user agent for forwarding to the application. This makes the token available to the user and to other applications on the user's device. This grant type does not perform authentication of the application's identity; instead, it relies on the redirect URI registered with the authorization server.

* Identity tokens (`id_token`) are not included in the redirect fragment. Refresh tokens (`refresh_token`) are included in the redirect only if returned by the database.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client (application) identifier. |
| redirect_uri | `redirect_uri` | **Required.** The URI to which the authorization server will redirect the user agent (browser) along with the access token. |
| response_type | token | **Required.** JavaScript applications must set this parameter to `token`. This value instructs the authorization server to return the access token as a `name=value` pair in the URI fragment identifier (`#`) to which the user is redirected after the authorization process completes. |
| scope | `scope` | **Recommended.** A space-separated list of scopes that define the resources your application can access on behalf of the user. |
| state | `state` | **Recommended.** A set of random characters that will be returned by the server to the client (used to protect against replay attacks). |

**Example request:**
```http request
GET /oauth2/authorize?client_id=YOUR-CLIENT-ID&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcallback&scope=api&response_type=token&state=c2FmZXR HTTP/1.1
Host: localhost:8080
```

```
http://localhost:8080/oauth2/authorize?
  client_id=YOUR-CLIENT-ID&
  redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcallback&
  response_type=token&
  scope=api&
  state=c2FmZXR
```

The access token or error message is returned in the hash fragment of the redirect URI:

**Access token response:**
```
http://localhost:8080/callback#token_type=Bearer&expires_in=3600&session=dfe05b78a76b6ad8e0fcbef270671793b86aa848&access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[payload].[signature]
```

* In addition to `access_token`, the fragment string also contains `token_type` (always `Bearer`) and `expires_in` (lifetime of the token in seconds). If the `state` parameter was included in the access token request, its value is also included in the response.

* The redirect URI — in this case `http://localhost:8080/callback/index.html` — must point to a web page that contains a script capable of extracting the access token from the redirect URI.

**Error response:**
```
http://localhost:8080/callback#code=403&error=access_denied&error_description=Access%20denied.
```

###### The authorization server supports a hybrid response mode. If both values `code token` (space-separated) are specified in the `response_type` parameter, the authorization server will return both an authorization code and an access token in a single response.

### Resource Owner Password Credentials

With this grant type, the user provides their credentials (username and password) directly to the application. The application then uses the received user credentials to obtain an access token from the authorization server. This grant type should only be used when no other option is available, and only when the application is fully trusted by the user (for example, when it is part of the service itself).

After the user provides their credentials to the application, the application requests an access token from the authorization server using a `POST` request.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client identifier. |
| client_secret | `client_secret` | **Required.** The client secret. |
| grant_type | password | **Required.** As defined in the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-4.3.1), this field must contain the value `password`. |
| username | `username` | **Conditional.** The user's login. Ignored if `secret` is provided. |
| password | `password` | **Conditional.** The user's password. Ignored if `secret` is provided. |
| secret | `secret` | **Conditional.** A secret code. If provided, the `username` and `password` fields are not required. |
| scope | `scope` | **Recommended.** A space-separated list of scopes that define the resources your application can access on behalf of the user. |

* According to the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-2.3.1), the client authentication parameters (`client_id` and `client_secret`) may be passed either in the request body or in the HTTP `Authorization` header (HTTP Basic authentication):

```
Authorization: Basic d2ViLXNlcnZpY2UucnU6Y2xpZW50IHNlY3JldA==
```

In response, the authorization server will return a JSON object containing a short-lived access token and a refresh token.

**Response fields:**

| Field | Type | Description |
| --- | --- | --- |
| access_token | STRING | Short-lived access token (valid for 1 hour). |
| expires_in | INTEGER | Remaining lifetime of the access token in seconds. |
| token_type | STRING | Type of the returned token. Always `Bearer`. |
| session | STRING | User session identifier. |
| refresh_token | STRING | Token that can be used to obtain a new access token. |
| id_token | STRING | * User identity token. |

* Note: the identity token (`id_token`) is only returned if your application included one of the following values in `scope`: `openid`, `profile`, or `email`.

**Example request:**

```http request
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR-CLIENT-ID&
client_secret=YOUR-CLIENT-SECRET&
grant_type=password&
username=admin&
password=admin
```

###### * Although not required by the specification, the authorization server also accepts requests in JSON format (`Content-Type: application/json`).

If both the client and user credentials are valid, the authorization server will return an access token for the application.

### Client Credentials

The Client Credentials grant type allows an application to access its own service account. This can be useful, for example, when an application wants to update its own registration information on the service or the redirect URIs, or to access other information stored in the application's service account via the API.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client identifier. |
| client_secret | `client_secret` | **Required.** The client secret. |
| grant_type | client_credentials | **Required.** As defined in the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-4.4.2), this field must contain the value `client_credentials`. |
| scope | `scope` | **Recommended.** A space-separated list of scopes that define the resources your application can access on behalf of the user. |

* According to the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-2.3.1), the client authentication parameters (`client_id` and `client_secret`) may be passed either in the request body or in the HTTP `Authorization` header (HTTP Basic authentication):

```
Authorization: Basic d2ViLXNlcnZpY2UucnU6Y2xpZW50IHNlY3JldA==
```

In response, the authorization server will return a JSON object containing an access token and a refresh token.

**Response fields:**

| Field | Type | Description |
| --- | --- | --- |
| access_token | STRING | Access token (valid for 1 day). |
| expires_in | INTEGER | Remaining lifetime of the access token in seconds. |
| token_type | STRING | Type of the returned token. Always `Bearer`. |
| session | STRING | User session identifier. |
| refresh_token | STRING | Token that can be used to obtain a new access token. |
| id_token | STRING | * User identity token. |

* Note: the identity token (`id_token`) is only returned if your application included one of the following values in `scope`: `openid`, `profile`, or `email`.

**Example request:**

```http request
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR-CLIENT-ID&
client_secret=YOUR-CLIENT-SECRET&
grant_type=client_credentials
```

### Refreshing an Access Token

After an access token expires, all API requests using it will return an error with code `403` ("Token expired"). If a refresh token (`refresh_token`) was issued alongside the access token, it can be used to obtain a new access token from the authorization server.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client identifier. |
| client_secret | `client_secret` | **Required.** The client secret. |
| grant_type | refresh_token | **Required.** As defined in the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-6), this field must contain the value `refresh_token`. |
| refresh_token | `refresh_token` | **Required.** The refresh token previously issued. |
| scope | `scope` | **Recommended.** A space-separated list of scopes that define the resources your application can access on behalf of the user. |

* According to the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-2.3.1), the client authentication parameters (`client_id` and `client_secret`) may be passed either in the request body or in the HTTP `Authorization` header (HTTP Basic authentication):

```
Authorization: Basic d2ViLXNlcnZpY2UucnU6Y2xpZW50IHNlY3JldA==
```

**Example request:**

```http request
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR-CLIENT-ID&
client_secret=YOUR-CLIENT-SECRET&
grant_type=refresh_token&
refresh_token=e%2FdtGmXCIzHvPMURn%2FTH9udTPxtKpR5FFifx2uvH1WqT4myXLtgyjkLgYDy7g3Ik5MrFRR82
```

###### * Although not required by the specification, the authorization server also accepts requests in JSON format (`Content-Type: application/json`).

If the client credentials are valid, the authorization server will return a new short-lived access token and a new refresh token.

### Token Exchange (RFC 8693)

The Token Exchange grant type ([RFC 8693](https://tools.ietf.org/html/rfc8693)) allows obtaining a new access token before the current one expires.

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Required.** The client identifier. |
| client_secret | `client_secret` | **Required.** The client secret. |
| grant_type | urn:ietf:params:oauth:grant-type:token-exchange | **Required.** As defined in the [specification](https://tools.ietf.org/html/rfc8693#appendix-A.2), this field must contain the value `urn:ietf:params:oauth:grant-type:token-exchange`. |
| subject_token | `subject_token` | **Required.** The previously issued token. |
| subject_token_type | `subject_token_type` | **Recommended.** The type of the provided token. Available values: `urn:ietf:params:oauth:token-type:jwt` (default), `urn:ietf:params:oauth:token-type:access_token`, `urn:ietf:params:oauth:token-type:refresh_token`, `urn:ietf:params:oauth:token-type:id_token`. |
| scope | `scope` | **Recommended.** A space-separated list of scopes that define the resources your application can access on behalf of the user. |

* According to the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-2.3.1), the client authentication parameters (`client_id` and `client_secret`) may be passed either in the request body or in the HTTP `Authorization` header (HTTP Basic authentication):

```
Authorization: Basic d2ViLXNlcnZpY2UucnU6Y2xpZW50IHNlY3JldA==
```

**Example request:**

```http request
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR-CLIENT-ID&
client_secret=YOUR-CLIENT-SECRET&
grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&
subject_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[abbreviated for brevity].NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg&
subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt
```

###### * Although not required by the specification, the authorization server also accepts requests in JSON format (`Content-Type: application/json`).

If the client credentials are valid and the provided token has not expired, the authorization server will return a new short-lived access token and a new refresh token.

### JWT Bearer Grant

This grant type allows authentication using a JWT token issued by an external system (for example, Google).

**Request parameters:**

| Field | Value | Description |
| --- | :---: | --- |
| client_id | `client_id` | **Recommended.** The client identifier. Not validated at the transport layer for this grant type — the full payload is forwarded to the database. |
| client_secret | `client_secret` | **Recommended.** The client secret. Not validated at the transport layer for this grant type — the full payload is forwarded to the database. |
| grant_type | urn:ietf:params:oauth:grant-type:jwt-bearer | **Required.** This field must contain the value `urn:ietf:params:oauth:grant-type:jwt-bearer`. |
| assertion | `assertion` | **Required.** The JWT token issued by the external system. |

* According to the OAuth 2.0 [specification](https://tools.ietf.org/html/rfc6749#section-2.3.1), the client authentication parameters (`client_id` and `client_secret`) may be passed either in the request body or in the HTTP `Authorization` header (HTTP Basic authentication):

```
Authorization: Basic d2ViLXNlcnZpY2UucnU6Y2xpZW50IHNlY3JldA==
```

**Example request:**

```http request
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR-CLIENT-ID&
client_secret=YOUR-CLIENT-SECRET&
grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&
assertion=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[abbreviated for brevity].NorYsi-Ht826HUFCEArVZ60_dEUmYiJYXubnTyweIMg
```

[^crm]: **Apostol CRM** is an abstract term, not a standalone product. It refers to any project that uses both the [Apostol](https://github.com/apostoldevel/apostol) C++ framework and [db-platform](https://github.com/apostoldevel/db-platform) together through purpose-built modules and processes. Each framework can be used independently; combined, they form a full-stack backend platform.
