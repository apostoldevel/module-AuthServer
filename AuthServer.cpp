#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "AuthServer.hpp"
#include "apostol/application.hpp"

#include "apostol/http_utils.hpp"
#include "apostol/jwt.hpp"
#include "apostol/logger.hpp"
#include "apostol/db_platform.hpp"
#include "apostol/pg_utils.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>


namespace apostol
{

static std::string join_strings(const std::vector<std::string>& v, std::string_view sep)
{
    if (v.empty()) return {};
    std::string result = v[0];
    for (std::size_t i = 1; i < v.size(); ++i) {
        result += sep;
        result += v[i];
    }
    return result;
}

// Extract a JSON value as string regardless of its actual type (number → string).
static std::string json_string(const nlohmann::json& j, const char* key)
{
    auto it = j.find(key);
    if (it == j.end() || it->is_null())
        return {};
    if (it->is_string())
        return it->get<std::string>();
    return it->dump();   // number, bool, etc. → their textual representation
}

// Identifies this module in db.session.agent and the event log.
static constexpr const char* kUserAgent = "AuthServer/2.0";

// Recorded as db.session.host for the service session. Loopback: the grant is
// issued by this process against its own database, not on behalf of a client.
static constexpr const char* kServiceHost = "127.0.0.1";

static constexpr const char* WEB_APP   = "web";
static constexpr const char* SVC_APP   = "service";

static constexpr auto kHeartbeatInterval = std::chrono::minutes(30);
static constexpr auto kRetryInterval     = std::chrono::seconds(5);

static constexpr const char* kCookieAT  = "__Secure-AT";
static constexpr const char* kCookieRT  = "__Secure-RT";
static constexpr const char* kCookieSAT = "__Secure-SAT";
static constexpr const char* kCookieSRT = "__Secure-SRT";
static constexpr const char* kCookieSID = "SID";

// Double-submit token for POST /oauth2/consent. Written by the consent screen and
// echoed back in the form body; see do_consent for why it exists and why Origin
// does not. The __Host- prefix is load-bearing: it forbids a Domain attribute, so
// only this exact host can set the cookie — a sibling subdomain cannot plant one.
static constexpr const char* kCookieConsentToken = "__Host-CT";
static constexpr int kCookieMaxAge      = 60 * 86400; // 60 days

// ─── Construction ────────────────────────────────────────────────────────────

AuthServer::AuthServer(Application& app)
    : pool_(app.db_pool())
    , fetch_(app.worker_loop())
    , log_(app.logger())
    , providers_(app.providers())
    , sites_(app.sites())
    , enabled_(true)
    , next_heartbeat_(std::chrono::system_clock::now())
{
    load_allowed_origins(providers_);
}

// ─── check_location ─────────────────────────────────────────────────────────

bool AuthServer::check_location(const HttpRequest& req) const
{
    return req.path.size() >= 8 && req.path.substr(0, 8) == "/oauth2/";
}

// ─── init_methods ───────────────────────────────────────────────────────────

void AuthServer::init_methods()
{
    add_method("GET",  [this](auto& req, auto& resp) { do_get(req, resp); });
    add_method("POST", [this](auto& req, auto& resp) { do_post(req, resp); });

    add_allowed_header("Authorization");
    load_allowed_origins(providers_);
}

// ─── heartbeat ──────────────────────────────────────────────────────────────

void AuthServer::on_stop()
{
    // Every client_credentials grant writes a row to db.session and nothing
    // collects them; leaving without this leaks one per worker per restart.
    // By token, not by session code. This pool's role is daemon, which reaches the
    // daemon schema and not api — closing by code answers "permission denied for
    // schema api", which is why these sessions used to survive every restart.
    db_platform::close_session(pool_, service_token_.token(), &log_, "[AuthServer]");
    service_token_.invalidate();
}

// ─── refresh_service_token ──────────────────────────────────────────────────
//
// Which credentials to use; db_platform::refresh_service_token issues the request.

void AuthServer::refresh_service_token()
{
    // Read the credentials now rather than at construction: providers are loaded by
    // the application, and a value cached once at start-up is a value that can be
    // cached before it exists.
    const auto* svc = providers_.find_default(SVC_APP);

    if (!svc) {
        // Only worth saying when something is due, or it repeats every beat.
        if (service_token_.needs_refresh()) {
            log_.error("[AuthServer] no \"{}\" client in conf/oauth2: /oauth2/identifier "
                       "will refuse unauthenticated callers", SVC_APP);
            service_token_.failed();
        }
        return;
    }

    // The scope is named rather than left to the server's default. They resolve to
    // the same set today, but a token's scope decides what it may reach.
    db_platform::refresh_service_token(pool_, service_token_, log_, "[AuthServer]",
                                       svc->client_id, svc->client_secret,
                                       join_strings(svc->scopes, " "),
                                       kUserAgent, kServiceHost);
}

void AuthServer::heartbeat(std::chrono::system_clock::time_point now)
{
    // Every beat: cheap when the token is still good, and the only thing that
    // keeps it available to do_identifier without blocking a request on a query.
    refresh_service_token();

    if (now >= next_heartbeat_) {
        next_heartbeat_ = now + kHeartbeatInterval;
        check_providers();
        fetch_providers();
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

std::string AuthServer::extract_action(std::string_view path)
{
    // "/oauth2/<action>[/extra]" → "<action>"
    if (path.size() < 9 || path.substr(0, 8) != "/oauth2/")
        return {};
    auto rest = path.substr(8); // after "/oauth2/"
    auto slash = rest.find('/');
    return std::string(rest.substr(0, slash));
}

std::string AuthServer::extract_provider(std::string_view path)
{
    // "/oauth2/code/<provider>" → "<provider>"
    if (path.size() < 9)
        return {};
    auto rest = path.substr(8); // after "/oauth2/"
    auto slash = rest.find('/');
    if (slash == std::string_view::npos || slash + 1 >= rest.size())
        return {};
    return std::string(rest.substr(slash + 1));
}

void AuthServer::parse_string_list(std::string_view input,
                                   const std::vector<std::string>& allowed,
                                   std::vector<std::string>& valid,
                                   std::vector<std::string>& invalid)
{
    valid.clear();
    invalid.clear();

    if (input.empty())
        return;

    // Split on space, comma, or both
    std::string_view rest = input;
    while (!rest.empty()) {
        auto pos = rest.find_first_of(" ,");
        auto token = rest.substr(0, pos);
        if (!token.empty()) {
            bool found = false;
            for (const auto& a : allowed) {
                if (a == token) { found = true; break; }
            }
            if (found)
                valid.emplace_back(token);
            else
                invalid.emplace_back(token);
        }
        if (pos == std::string_view::npos) break;
        rest = rest.substr(pos + 1);
    }
}

// ─── OAuth2 error responses ─────────────────────────────────────────────────

void AuthServer::reply_oauth2_error(HttpResponse& resp, HttpStatus status,
                                    std::string_view error,
                                    std::string_view description)
{
    if (status == HttpStatus::unauthorized) {
        // RFC 6750 §3 defines three codes for this header — invalid_request,
        // invalid_token, insufficient_scope — and nothing else. The header used to
        // say access_denied whatever had happened, which is an RFC 6749 code from a
        // different vocabulary: a client that reads WWW-Authenticate to decide
        // whether to refresh finds a word it does not know and gives up.
        //
        // Anything outside that vocabulary becomes invalid_token, which is what a
        // 401 from a bearer-token endpoint means when it means anything.
        auto scheme_error = error;
        if (scheme_error != "invalid_request" && scheme_error != "insufficient_scope")
            scheme_error = "invalid_token";

        resp.set_header("WWW-Authenticate",
                        fmt::format("Bearer error=\"{}\", "
                                    "error_description=\"{}\"",
                                    json_escape(scheme_error),
                                    json_escape(description)));
    }

    resp.set_status(status)
        .set_body(fmt::format(R"({{"error":"{}","error_description":"{}"}})",
                              json_escape(error), json_escape(description)),
                  "application/json");
}

void AuthServer::redirect_error(HttpResponse& resp, std::string_view location,
                                int code, std::string_view error,
                                std::string_view message)
{
    if (location.empty()) {
        // No site config for this host — return JSON error instead of a relative
        // redirect that would loop back to the same handler.
        reply_oauth2_error(resp, error_code_to_status(code), error, message);
        return;
    }
    // Both values encoded, and error is the one that matters: it arrives from a
    // query parameter on /oauth2/code, from an external identity provider's JSON,
    // and from the database — three sources outside this process — and lands in a
    // Location header. Unencoded, a CR LF in it ended the header and let the caller
    // write further headers of its own onto this origin. libapostol now truncates
    // header values at the first control byte, so this is the second of two locks
    // on the same door; it is also simply how a query string is built.
    auto url = fmt::format("{}?code={}&error={}&error_description={}",
                           location, code, url_encode(error),
                           url_encode(message));
    redirect(resp, url);
}

void AuthServer::set_secure_cookies(HttpResponse& resp,
                                    std::string_view access_token,
                                    std::string_view refresh_token,
                                    std::string_view session,
                                    std::string_view domain)
{
    if (!access_token.empty())
        resp.set_cookie(kCookieAT, access_token, "/", kCookieMaxAge,
                        true, "None", true, domain);

    if (!refresh_token.empty())
        resp.set_cookie(kCookieRT, refresh_token, "/", kCookieMaxAge,
                        true, "None", true, domain);

    if (!session.empty())
        resp.set_cookie(kCookieSID, session, "/", kCookieMaxAge,
                        true, "Lax", true);
}

void AuthServer::set_service_cookies(HttpResponse& resp,
                                     std::string_view access_token,
                                     std::string_view refresh_token)
{
    if (!access_token.empty())
        resp.set_cookie(kCookieSAT, access_token, "/", kCookieMaxAge,
                        true, "None", true);

    if (!refresh_token.empty())
        resp.set_cookie(kCookieSRT, refresh_token, "/", kCookieMaxAge,
                        true, "None", true);
}

// ─── JWT ────────────────────────────────────────────────────────────────────

std::string AuthServer::get_public_key(std::string_view kid) const
{
    for (const auto& [provider_name, cache] : key_cache_) {
        if (cache.status == ProviderKeyCache::Status::success) {
            auto it = cache.keys.find(std::string(kid));
            if (it != cache.keys.end())
                return it->second;
        }
    }
    return {};
}

// ─── do_get ─────────────────────────────────────────────────────────────────

void AuthServer::do_get(const HttpRequest& req, HttpResponse& resp)
{
    const auto action = extract_action(req.path);

    const auto host = get_host(req);
    const auto* site = sites_.find(host);

    const std::string redirect_identifier = site ? site->oauth2.identifier : "";
    const std::string redirect_secret     = site ? site->oauth2.secret     : "";
    const std::string redirect_consent    = site ? site->oauth2.consent    : "";
    const std::string redirect_callback   = site ? site->oauth2.callback   : "";
    const std::string redirect_err        = site ? site->oauth2.error      : "";
    const std::string redirect_debug      = site ? site->oauth2.debug      : "";

    static const std::vector<std::string> kResponseTypes{"code", "token"};
    static const std::vector<std::string> kAccessTypes{"online", "offline"};
    // "login" is the OpenID Connect Core §3.1.2.1 spelling; "signin" is this
    // server's, kept because clients use it. Both name the same screen — see
    // wants_prompt below, which reads them as one.
    static const std::vector<std::string> kPrompts{
        "none", "login", "signin", "secret", "consent", "select_account"};

    std::vector<std::string> valid, invalid;

    if (action == "authorize" || action == "auth") {

        const auto& response_type = req.param("response_type");
        const auto& client_id     = req.param("client_id");
        const auto& access_type   = req.param("access_type");
        const auto& redirect_uri  = req.param("redirect_uri");
        const auto& scope         = req.param("scope");
        const auto& state         = req.param("state");
        const auto& prompt        = req.param("prompt");
        const auto& max_age       = req.param("max_age");

        if (redirect_uri.empty()) {
            redirect_error(resp, redirect_err, 400, "invalid_request",
                           "Parameter value redirect_uri cannot be empty.");
            return;
        }

        // Client, redirect_uri and scope — checked together, and against the local
        // provider's registration only.
        auto* app = validate_client(resp, redirect_err, client_id, redirect_uri, scope);
        if (!app)
            return;

        // prompt is read first, before anything else is validated, because it
        // decides how every error below is answered: prompt=none means the client
        // asked to be told rather than to have its user interrupted, and an error
        // page is an interruption. Its own token list, not the shared valid/invalid
        // pair — response_type is parsed after this and would overwrite it.
        std::vector<std::string> prompts, bad_prompts;

        parse_string_list(prompt, kPrompts, prompts, bad_prompts);
        if (!bad_prompts.empty()) {
            // Whether this client would have accepted a silent answer cannot be
            // known from a prompt that did not parse, so this one keeps the screen.
            redirect_error(resp, redirect_err, 400, "unsupported_prompt_type",
                           fmt::format("Some requested prompt type were invalid: "
                                       "{{valid=[{}], invalid=[{}]}}",
                                       join_strings(prompts, ", "),
                                       join_strings(bad_prompts, ", ")));
            return;
        }

        // A prompt that names a screen means the client wants that screen shown,
        // even when the user is already signed in.
        const auto wants_prompt = [&prompts](std::string_view value) {
            return std::find(prompts.begin(), prompts.end(), value) != prompts.end();
        };

        const bool wants_signin = wants_prompt("signin") || wants_prompt("login");

        const bool silent = wants_prompt("none");

        // Where a rejected request goes. client_id and redirect_uri are validated
        // above, which is what RFC 6749 §4.1.2.1 and OpenID Connect Core §3.1.2.6
        // require before an error may be sent to the client's own address instead of
        // shown to the user. Below that line the answer is the error page, as before.
        const auto fail = [&](int code, std::string_view error,
                              std::string_view description) {
            if (silent)
                redirect_client_error(resp, redirect_uri, error, description, state);
            else
                redirect_error(resp, redirect_err, code, error, description);
        };

        // prompt=none says "show the user nothing at all". Pairing it with a value
        // that names a screen asks for both, and OpenID Connect Core §3.1.2.1 makes
        // that an error rather than letting the server pick a winner.
        if (silent && prompts.size() > 1) {
            fail(400, "invalid_request",
                 "prompt=none must not be combined with any other prompt value.");
            return;
        }

        // Validate response_type
        parse_string_list(response_type, kResponseTypes, valid, invalid);
        if (!invalid.empty()) {
            fail(400, "unsupported_response_type",
                 fmt::format("Some requested response type were invalid: "
                             "{{valid=[{}], invalid=[{}]}}",
                             join_strings(valid, ", "),
                             join_strings(invalid, ", ")));
            return;
        }

        // `valid` is reused by the parses below — capture what we need now.
        const bool wants_code =
            std::find(valid.begin(), valid.end(), "code") != valid.end();
        const bool wants_token =
            std::find(valid.begin(), valid.end(), "token") != valid.end();

        // Validate access_type.
        //
        // Meaningless only when the response is purely implicit: there is no code to
        // exchange, so there is no refresh token for offline access to describe.
        // A hybrid "code token" still has the code half, and access_type still
        // applies to it — which the previous whole-string comparison happened to get
        // right and a plain token-wise test would have got wrong.
        auto access_types = kAccessTypes;
        if (wants_token && !wants_code)
            access_types.clear();

        if (!access_type.empty()) {
            bool at_ok = false;
            for (const auto& at : access_types) {
                if (at == access_type) { at_ok = true; break; }
            }
            if (!at_ok) {
                fail(400, "invalid_request",
                     fmt::format("Invalid access_type: {}", access_type));
                return;
            }
        }

        // Validate max_age. OpenID Connect defines it as "Non-negative integer
        // Seconds"; a value that is not one is a malformed request, not a hint to
        // ignore — ignoring it would answer a demand for a fresh sign-in with a
        // stale session and look like it had complied.
        if (!max_age.empty()) {
            // Digits, and few enough of them to be an integer on the other side.
            // daemon.authorization_code takes pMaxAge integer: "99999999999999" is
            // all digits, passes a syntax check, and then overflows in the database
            // — answering a malformed request with server_error, which says the
            // server broke when in fact the client sent nonsense.
            const bool digits =
                max_age.find_first_not_of("0123456789") == std::string::npos;
            const bool in_range =
                max_age.size() <= 10 && (max_age.size() < 10 || max_age <= "2147483647");

            if (!digits || !in_range) {
                fail(400, "invalid_request",
                     "max_age must be a non-negative integer number of seconds.");
                return;
            }
        }

        const bool interactive = wants_signin || wants_prompt("secret") ||
                                 wants_prompt("consent") || wants_prompt("select_account");

        // The original request, ready to be appended to whichever page we send
        // the browser to — so that the flow resumes where it left off.
        // Encoded like every other parameter here. These two were the exception, and
        // the result goes straight into a Location header — parse_string_list keeps
        // response_type to a known word, but client_id is whatever was registered,
        // and a header is no place to find out that assumption was wrong.
        auto query = fmt::format("?client_id={}&response_type={}",
                                 url_encode(client_id), url_encode(response_type));

        if (!redirect_uri.empty())
            query += "&redirect_uri=" + url_encode(redirect_uri);
        if (!access_type.empty())
            query += "&access_type=" + url_encode(access_type);
        if (!scope.empty())
            query += "&scope=" + url_encode(scope);
        if (!prompt.empty())
            query += "&prompt=" + url_encode(prompt);
        if (!max_age.empty())
            query += "&max_age=" + url_encode(max_age);
        if (!state.empty())
            query += "&state=" + url_encode(state);

        // wants_prompt, not prompt == "secret": prompt is a space-separated list, so
        // comparing the whole string means "prompt=secret signin" matches neither
        // branch and lands on the identifier page — the one screen the client did
        // not ask for. The same list is already read token-wise three lines above.
        const std::string redirect_login =
            (wants_prompt("secret") ? redirect_secret : redirect_identifier) + query;

        // What the user will be asked to agree to. An empty scope is not "nothing" —
        // the database expands it to every scope there is — so resolve it here, to
        // the list this client is registered for. The consent screen then shows the
        // same list that gets recorded, and neither is a blank cheque.
        const std::string consent_scope =
            scope.empty() ? join_strings(app->scopes, " ") : scope;

        auto consent_query = fmt::format("?client_id={}&response_type={}",
                                         url_encode(client_id), url_encode(response_type));

        consent_query += "&redirect_uri=" + url_encode(redirect_uri);
        if (!access_type.empty())
            consent_query += "&access_type=" + url_encode(access_type);
        if (!consent_scope.empty())
            consent_query += "&scope=" + url_encode(consent_scope);
        if (!prompt.empty())
            consent_query += "&prompt=" + url_encode(prompt);
        if (!max_age.empty())
            consent_query += "&max_age=" + url_encode(max_age);
        if (!state.empty())
            consent_query += "&state=" + url_encode(state);

        // Where the consent screen lives. There is deliberately no fallback path:
        // guessing one sends the browser to a URL on whichever host it happened to
        // ask, and the screen only exists on the host that serves the SPA. A site
        // that has not named oauth2.consent cannot ask the question, and saying so
        // to the client beats a redirect into a 404.
        const std::string consent_page =
            redirect_consent.empty() ? std::string() : redirect_consent + consent_query;

        // Signed in already and nothing to ask: hand the client its code and be done.
        // Without this the consent screen can never complete — its "Allow" button
        // comes back here, and every answer used to be "go to the login page".
        // Whether the user has actually granted this client access is decided in
        // daemon.authorization_code, which answers consent_required when they have not.
        // Read once: on a request with no SID cookie this verifies a JWT, and the
        // silent branch below asks the same question again.
        const auto session = session_from_request(req);

        if (wants_code && !interactive) {
            if (!session.empty()) {
                issue_authorization_code(req, resp, session, client_id, redirect_uri,
                                         scope, state, access_type,
                                         redirect_login, consent_page, redirect_err,
                                         /* consent */ false, max_age, silent);
                return;
            }
        }

        // Nothing above could be answered without a screen, and prompt=none forbids
        // one. The client hears why on its own redirect_uri: it asked to be told
        // rather than to have its user interrupted, and OpenID Connect Core §3.1.2.1
        // names both answers. login_required when there is no session to work from;
        // interaction_required when the response type this server can issue silently
        // — an authorization code — was not the one asked for.
        if (silent) {
            // Two ways to get here. Without a session there is nobody to answer for,
            // and the client must send its user to sign in. With one, the response
            // type asked for is not the authorization code this server issues
            // silently — which is a statement about the request, not about the user,
            // so unsupported_response_type says more than interaction_required would.
            if (session.empty())
                fail(401, "login_required", "The user is not signed in.");
            else
                fail(400, "unsupported_response_type",
                     "Only response_type=code can be answered without user interaction.");
            return;
        }

        // Redirect to the login — or, when asked for, the consent — page
        if (wants_prompt("consent")) {
            if (consent_page.empty()) {
                redirect_client_error(resp, redirect_uri, "consent_required",
                                      "This server has no consent screen configured.",
                                      state);
                return;
            }
            redirect(resp, consent_page);
            return;
        }

        redirect(resp, redirect_login);

    } else if (action == "code") {

        const auto& code  = req.param("code");
        const auto& error = req.param("error");

        // Check for provider error first (e.g. Google returns ?error=...&error_description=...)
        if (!error.empty()) {
            redirect_error(resp, redirect_err, 400, error,
                           req.param("error_description"));
            return;
        }

        if (code.empty()) {
            redirect_error(resp, redirect_err, 400, "invalid_request",
                           "Parameter \"code\" not found.");
            return;
        }

        const auto& state = req.param("state");
        auto provider_name = extract_provider(req.path);
        if (provider_name.empty())
            provider_name = "default";

        auto* app = providers_.find(provider_name, WEB_APP);
        if (!app) {
            redirect_error(resp, redirect_err, 400, "invalid_request",
                           fmt::format("Provider \"{}\" not found.", provider_name));
            return;
        }

        auto conn = std::static_pointer_cast<HttpConnection>(req.connection_ctx);
        resp.set_deferred(true);

        auto redir = (state == "debug") ? redirect_debug : redirect_callback;
        auto agent = get_user_agent(req, "AuthServer/2.0");
        auto real_ip = get_real_ip(req);
        auto full_origin = get_protocol(req) + "://" + host;
        fetch_access_token(conn, *app, code, full_origin,
                           redir, redirect_err, agent, real_ip);
        return;

    } else if (action == "callback") {

        redirect(resp, redirect_callback);

    } else if (action == "identifier") {

        do_identifier(req, resp);
        return;

    } else {
        resp.set_status(HttpStatus::not_found)
            .set_body("", "text/plain");
        return;
    }
}

// ─── do_post ────────────────────────────────────────────────────────────────

void AuthServer::do_post(const HttpRequest& req, HttpResponse& resp)
{
    const auto action = extract_action(req.path);

    if (action == "token") {
        do_token(req, resp);
    } else if (action == "identifier") {
        do_identifier(req, resp);
    } else if (action == "consent") {
        do_consent(req, resp);
    } else {
        reply_oauth2_error(resp, HttpStatus::not_found,
                           "invalid_request", "Not found.");
    }
}

// ─── do_token ───────────────────────────────────────────────────────────────

void AuthServer::do_token(const HttpRequest& req, HttpResponse& resp)
{
    auto json = content_to_json(req);

    const auto grant_type    = json.value("grant_type", "");
    const auto client_id     = json.value("client_id", "");
    const auto client_secret = json.value("client_secret", "");
    const auto redirect_uri  = json.value("redirect_uri", "");

    std::string auth_username;
    std::string auth_password;

    if (grant_type != "urn:ietf:params:oauth:grant-type:jwt-bearer") {

        const auto auth_header = req.header("Authorization");
        const auto origin = get_origin(req);

        if (auth_header.empty()) {
            auth_username = client_id;
            auth_password = client_secret;
        } else {
            auto auth = parse_authorization(auth_header);
            if (auth.schema != Authorization::Schema::basic) {
                reply_oauth2_error(resp, HttpStatus::bad_request,
                                   "invalid_request", "Invalid authorization schema.");
                return;
            }
            auth_username = std::move(auth.username);
            auth_password = std::move(auth.password);
        }

        if (auth_username.empty()) {
            if (grant_type != "password") {
                reply_oauth2_error(resp, HttpStatus::bad_request,
                                   "invalid_request",
                                   "Parameter value client_id cannot be empty.");
                return;
            }
            // Default to the web app's client_id (client_id omitted by browser
            // to avoid exposing client_secret in DevTools).  When allowed_ips
            // is configured, only requests from those IPs may use this shortcut.
            auto* default_app = providers_.find_default(WEB_APP);
            if (default_app) {
                // allowed_ips guards the no-client_id shortcut by peer_ip
                // (who connected to our socket — nginx or direct client).
                // Default: loopback + private networks (RFC 1918).
                const auto& peer = req.peer_ip;
                bool ip_ok = false;
                if (default_app->allowed_ips.empty()) {
                    ip_ok = is_private_ip(peer);
                } else {
                    for (const auto& entry : default_app->allowed_ips) {
                        if (peer == entry || peer.starts_with(entry)) {
                            ip_ok = true;
                            break;
                        }
                    }
                }
                if (!ip_ok) {
                    reply_oauth2_error(resp, HttpStatus::bad_request,
                                       "invalid_request",
                                       "Parameter value client_id cannot be empty.");
                    return;
                }
                auth_username = default_app->client_id;
            }
        }

        if (auth_password.empty()) {
            auto* app = providers_.find_by_client_id(auth_username);
            if (app && (app->name == WEB_APP || app->name == SVC_APP)) {

                // Validate redirect_uri if provided
                if (!redirect_uri.empty()) {
                    bool uri_ok = false;
                    for (const auto& uri : app->redirect_uris) {
                        if (uri == redirect_uri) { uri_ok = true; break; }
                    }
                    if (!uri_ok) {
                        reply_oauth2_error(resp, HttpStatus::bad_request,
                                           "invalid_request",
                                           fmt::format("Invalid parameter value for redirect_uri: "
                                                       "Non-public domains not allowed: {}",
                                                       redirect_uri));
                        return;
                    }
                }

                // Validate javascript_origins
                bool origin_ok = false;
                for (const auto& jo : app->javascript_origins) {
                    if (jo == origin) { origin_ok = true; break; }
                }
                if (!origin_ok) {
                    reply_oauth2_error(resp, HttpStatus::bad_request,
                                       "invalid_request",
                                       fmt::format("The JavaScript origin in the request, {}, "
                                                   "does not match the ones authorized for "
                                                   "the OAuth client.", origin));
                    return;
                }

                auth_password = app->client_secret;
            }
        }

        if (auth_password.empty()) {
            reply_oauth2_error(resp, HttpStatus::bad_request,
                               "invalid_request",
                               "Parameter value client_secret cannot be empty.");
            return;
        }
    }

    const auto agent = get_user_agent(req, "AuthServer/2.0");
    const auto host  = get_real_ip(req);
    const auto hostname = get_host(req);

    auto sql = fmt::format("SELECT * FROM daemon.token({}, {}, {}::jsonb, {}, {});",
                           pq_quote_literal(auth_username),
                           pq_quote_literal(auth_password),
                           pq_quote_literal(json.dump()),
                           pq_quote_literal(agent),
                           pq_quote_literal(host));

    resp.set_deferred(true);
    auto conn = std::static_pointer_cast<HttpConnection>(req.connection_ctx);

    const bool is_service = (grant_type == "client_credentials");

    // quiet: the statement carries daemon.token's arguments — the end user's
    // password on grant_type=password, a client secret on client_credentials.
    pool_.execute(std::move(sql),
        // on_result
        [conn, hostname, is_service](std::vector<PgResult> results) {
            HttpResponse r;

            if (results.empty() || !results[0].ok()) {
                auto msg = results.empty() ? "no results"
                                           : results[0].error_message();
                reply_oauth2_error(r, HttpStatus::internal_server_error,
                                   "server_error", msg);
                conn->send_response(r);
                return;
            }

            auto body = results[0].value(0, 0);

            try {
                auto result_json = nlohmann::json::parse(body);

                // Check for OAuth2 error in PG result
                if (result_json.contains("error")) {
                    auto& err_obj = result_json["error"];
                    int code = err_obj.value("code", 400);
                    auto error = err_obj.value("error", "invalid_request");
                    auto message = err_obj.value("message", "Invalid request.");
                    // ParseMessage already answers with a three-digit code; this
                    // divided one that never arrives.

                    if (code < 0) code = 400;

                    auto status = error_code_to_status(code);
                    reply_oauth2_error(r, status, error, message);
                    conn->send_response(r);
                    return;
                }

                auto access_token  = result_json.value("access_token", "");
                auto refresh_token = result_json.value("refresh_token", "");
                auto session       = result_json.value("session", "");

                if (is_service) {
                    set_service_cookies(r, access_token, refresh_token);
                } else {
                    set_secure_cookies(r, access_token, refresh_token,
                                       session, "");
                }

                r.set_status(HttpStatus::ok)
                 .set_body(body, "application/json");

            } catch (const std::exception& e) {
                reply_oauth2_error(r, HttpStatus::internal_server_error,
                                   "server_error", e.what());
            }

            conn->send_response(r);
        },
        // on_exception
        [conn](std::string_view error) {
            HttpResponse r;
            reply_oauth2_error(r, HttpStatus::internal_server_error,
                               "server_error", error);
            conn->send_response(r);
        },
        /*quiet=*/true);
}

// ─── session_from_request ───────────────────────────────────────────────────

std::string AuthServer::session_from_request(const HttpRequest& req) const
{
    // SID carries the session code itself.
    auto sid = req.cookie(kCookieSID);
    if (!sid.empty())
        return sid;

    // Otherwise take it from the access token: "sub" is the session code.
    auto token = req.cookie(kCookieAT);
    if (token.empty())
        return {};

    JwtKeyResolver key_resolver = [this](std::string_view kid) {
        return get_public_key(kid);
    };

    try {
        return verify_jwt(token, providers_, key_resolver).sub;
    } catch (const std::exception&) {
        // Expired or unverifiable — treat as "not signed in".
        return {};
    }
}

// ─── redirect_client_error ──────────────────────────────────────────────────

// An OAuth2 error that belongs to the *client*, delivered where the spec says it
// goes: back to its redirect_uri. Distinct from redirect_error, which sends the
// browser to the site's own error page — right for a request we cannot attribute
// to a registered client, wrong once we can, because then the client is the party
// that has to see what went wrong.
void AuthServer::redirect_client_error(HttpResponse& resp,
                                       const std::string& redirect_uri,
                                       std::string_view error,
                                       std::string_view description,
                                       const std::string& state)
{
    auto location = redirect_uri;
    location += (location.find('?') == std::string::npos) ? '?' : '&';
    location += "error=" + url_encode(std::string(error));
    location += "&error_description=" + url_encode(std::string(description));
    if (!state.empty())
        location += "&state=" + url_encode(state);

    redirect(resp, location);
}

// ─── validate_client ────────────────────────────────────────────────────────

const OAuthApp* AuthServer::validate_client(HttpResponse& resp,
                                            const std::string& redirect_err,
                                            const std::string& client_id,
                                            const std::string& redirect_uri,
                                            const std::string& scope) const
{
    // Local provider only. find_by_client_id searches every provider, so an entry
    // under google or yandex would answer here too — and that entry exists to let
    // us verify *their* tokens, not to make its holder a client of ours with a
    // say over our users' accounts.
    auto* app = providers_.find_default_by_client_id(client_id);
    if (!app) {
        redirect_error(resp, redirect_err, 401, "invalid_client",
                       "The OAuth client was not found.");
        return nullptr;
    }

    // Validate redirect_uri
    bool redirect_ok = false;
    for (const auto& uri : app->redirect_uris) {
        if (uri == redirect_uri) { redirect_ok = true; break; }
    }
    if (!redirect_ok) {
        redirect_error(resp, redirect_err, 400, "invalid_request",
                       fmt::format("Invalid parameter value for redirect_uri: "
                                   "Non-public domains not allowed: {}",
                                   redirect_uri));
        return nullptr;
    }

    // Validate scope
    std::vector<std::string> valid, invalid;
    parse_string_list(scope, app->scopes, valid, invalid);
    if (!invalid.empty()) {
        redirect_error(resp, redirect_err, 400, "invalid_scope",
                       fmt::format("Some requested scopes were invalid: "
                                   "{{valid=[{}], invalid=[{}]}}",
                                   join_strings(valid, ", "),
                                   join_strings(invalid, ", ")));
        return nullptr;
    }

    return app;
}

// ─── do_consent ─────────────────────────────────────────────────────────────

void AuthServer::do_consent(const HttpRequest& req, HttpResponse& resp)
{
    const auto host = get_host(req);
    const auto* site = sites_.find(host);

    const std::string redirect_identifier = site ? site->oauth2.identifier : "";
    const std::string redirect_consent    = site ? site->oauth2.consent    : "";
    const std::string redirect_err        = site ? site->oauth2.error      : "";

    // Body only. content_to_json falls back to the query string when the body is
    // empty, and a token that can arrive in a URL ends up in access logs, Referer
    // headers and browser history. The consent screen posts a form; anything else
    // is not the consent screen.
    if (req.body.empty()) {
        redirect_error(resp, redirect_err, 400, "invalid_request",
                       "The consent answer must be submitted as a request body.");
        return;
    }

    auto json = content_to_json(req);

    const auto client_id     = json.value("client_id", "");
    const auto redirect_uri  = json.value("redirect_uri", "");
    const auto scope         = json.value("scope", "");
    const auto state         = json.value("state", "");
    const auto access_type   = json.value("access_type", "");
    const auto response_type = json.value("response_type", "code");

    if (redirect_uri.empty()) {
        redirect_error(resp, redirect_err, 400, "invalid_request",
                       "Parameter value redirect_uri cannot be empty.");
        return;
    }

    auto* app = validate_client(resp, redirect_err, client_id, redirect_uri, scope);
    if (!app)
        return;

    // Consent answers an authorization *code* request. Letting response_type through
    // unchecked would mean a client that asked for an implicit token, was sent to the
    // consent screen by prompt=consent, and came back here, silently receives a code
    // instead — a different grant than the one it asked for.
    if (response_type != "code") {
        redirect_client_error(resp, redirect_uri, "unsupported_response_type",
                              "Consent applies to the authorization code flow.", state);
        return;
    }

    if (!access_type.empty() && access_type != "online" && access_type != "offline") {
        redirect_client_error(resp, redirect_uri, "invalid_request",
                              "Invalid access_type.", state);
        return;
    }

    // CSRF. A signed-in browser carries its cookies wherever a third-party page
    // sends it, and __Secure-AT is SameSite=None, so it rides along on a cross-site
    // POST as well. Something has to separate the user's own click on the consent
    // screen from someone else's page recording a consent in their name.
    //
    // That something is NOT the Origin header, however natural it looks here. The
    // deployment recipe every project in this ecosystem uses rewrites it:
    //
    //     location ^~ /oauth2/ { proxy_set_header Origin "https://$host"; }
    //
    // and it cannot simply be dropped — handing the web client its client_secret in
    // do_token is built on that substitution. So by the time a request reaches this
    // function, Origin always reads as our own, whoever actually sent it. A check
    // against it would pass for the attacker too: not bypassed, just blind.
    //
    // What survives the proxy is the cookie jar. The consent screen mints a random
    // token, stores it in a SameSite=Strict __Host- cookie and echoes it in the form
    // body; here the two must match. A cross-site POST fails twice over: SameSite
    // keeps the cookie at home, and an attacker on another origin can neither read
    // our cookie to copy it into the body nor write one under the __Host- prefix.
    //
    // Sec-Fetch-Site comes on top where the browser sends it — it is not rewritten
    // by the proxy either, and it answers the question directly.
    const auto fetch_site = req.header("Sec-Fetch-Site");
    if (!fetch_site.empty() && fetch_site != "same-origin" && fetch_site != "none") {
        redirect_error(resp, redirect_err, 403, "access_denied",
                       "The request did not originate from the consent screen.");
        return;
    }

    const auto token_cookie = req.cookie(kCookieConsentToken);
    const auto token_form   = json.value("consent_token", "");

    if (token_cookie.empty() || token_form.empty() || token_cookie != token_form) {
        // The two refusals mean different things and the difference is worth having
        // in the log: a missing half is usually our own doing — a consent screen on
        // another origin, a cookie dropped because the site is not served over TLS,
        // a remount between minting and submitting. Two halves that disagree is
        // someone else's request. The user is told the same thing either way; there
        // is nothing for them to act on, and nothing to hand an attacker.
        if (token_cookie.empty() || token_form.empty()) {
            log_.warn("[AuthServer] consent refused: token {} missing (client_id={})",
                      token_cookie.empty() ? "cookie" : "form field", client_id);
        } else {
            log_.warn("[AuthServer] consent refused: token mismatch (client_id={})",
                      client_id);
        }

        redirect_error(resp, redirect_err, 403, "access_denied",
                       "The request did not originate from the consent screen.");
        return;
    }

    // The original request, so that whichever page we send the browser to can
    // resume the flow where it left off.
    auto query = fmt::format("?client_id={}&response_type=code", url_encode(client_id));

    query += "&redirect_uri=" + url_encode(redirect_uri);
    if (!access_type.empty())
        query += "&access_type=" + url_encode(access_type);
    if (!scope.empty())
        query += "&scope=" + url_encode(scope);
    if (!state.empty())
        query += "&state=" + url_encode(state);

    // Same reasoning as in do_get: no invented fallback path, and no relative
    // location either — an empty oauth2.identifier would make redirect_login read
    // as "?client_id=…", which the browser resolves against /oauth2/consent and
    // lands back on this endpoint as a GET, i.e. a 404.
    const std::string redirect_login =
        redirect_identifier.empty() ? std::string() : redirect_identifier + query;
    const std::string consent_page =
        redirect_consent.empty() ? std::string() : redirect_consent + query;

    auto session = session_from_request(req);
    if (session.empty()) {
        // No session to consent with — sign in first, then come back.
        if (redirect_login.empty()) {
            redirect_client_error(resp, redirect_uri, "access_denied",
                                  "Not signed in.", state);
            return;
        }
        redirect(resp, redirect_login);
        return;
    }

    issue_authorization_code(req, resp, session, client_id, redirect_uri,
                             scope, state, access_type,
                             redirect_login, consent_page, redirect_err,
                             /* consent */ true, json.value("max_age", ""));
}

// ─── issue_authorization_code ───────────────────────────────────────────────

void AuthServer::issue_authorization_code(const HttpRequest& req, HttpResponse& resp,
                                          const std::string& session,
                                          const std::string& client_id,
                                          const std::string& redirect_uri,
                                          const std::string& scope,
                                          const std::string& state,
                                          const std::string& access_type,
                                          const std::string& redirect_login,
                                          const std::string& redirect_consent,
                                          const std::string& redirect_error_uri,
                                          bool consent,
                                          const std::string& max_age,
                                          bool silent)
{
    const auto agent = get_user_agent(req, "AuthServer/2.0");
    const auto host  = get_real_ip(req);

    auto sql = fmt::format("SELECT * FROM daemon.authorization_code({}, {}, {}, {}, {}, {}, {}, {}, {}, {});",
                           pq_quote_literal(session),
                           pq_quote_literal(client_id),
                           pq_quote_literal(redirect_uri),
                           scope.empty() ? "null" : pq_quote_literal(scope),
                           state.empty() ? "null" : pq_quote_literal(state),
                           access_type.empty() ? "null" : pq_quote_literal(access_type),
                           pq_quote_literal(agent),
                           pq_quote_literal(host),
                           consent ? "true" : "false",
                           max_age.empty() ? "null" : pq_quote_literal(max_age));

    resp.set_deferred(true);
    auto conn = std::static_pointer_cast<HttpConnection>(req.connection_ctx);

    // Everything the callback needs, by value — the request is gone by then.
    auto* self = this;
    auto login = redirect_login;
    auto consent_page = redirect_consent;
    auto err_uri = redirect_error_uri;
    auto target = redirect_uri;
    auto req_state = state;

    // quiet: the statement carries the user's session code.
    pool_.execute(std::move(sql),
        // on_result
        [self, conn, target, login, consent_page, err_uri, req_state, silent](std::vector<PgResult> results) {
            HttpResponse r;

            if (results.empty() || !results[0].ok()) {
                // The server's own text does not go into the redirect. It ends up in
                // the address bar, the Referer of whatever the page loads next, and
                // the browser history — and a PostgreSQL message names schemas,
                // functions and sometimes values. The log is where it belongs.
                if (self)
                    self->log_.error("[AuthServer] authorization_code: {}",
                                     results.empty() ? "no results"
                                                     : results[0].error_message());
                redirect_error(r, err_uri, 500, "server_error",
                               "The authorization server could not complete the request.");
                conn->send_response(r);
                return;
            }

            try {
                auto result_json = nlohmann::json::parse(results[0].value(0, 0));

                if (result_json.contains("error")) {
                    auto& err_obj = result_json["error"];
                    int code = err_obj.value("code", 400);
                    auto error = err_obj.value("error", "invalid_request");
                    auto message = err_obj.value("message", "Invalid request.");
                    // ParseMessage already answers with a three-digit code; this
                    // divided one that never arrives.

                    if (code < 0) code = 400;

                    // prompt=none forbids a screen, so every outcome goes to the
                    // client on its own redirect_uri — not only the three that have
                    // a screen to skip. OpenID Connect Core §3.1.2.6 asks for this
                    // once client_id and redirect_uri have been validated, and they
                    // were, before this statement was ever built. Without it a
                    // silent refresh in a hidden iframe loaded our error page and
                    // hung until the relying party timed out — the one outcome
                    // prompt=none exists to prevent.
                    //
                    // Written as a fall-through rather than as cases, so that a new
                    // error code in daemon.authorization_code cannot reopen it.
                    //
                    // The database's own message is not passed on: it names schemas,
                    // functions and sometimes values, and this text ends up in the
                    // client's address bar. Same policy as the branch above.
                    if (silent) {
                        std::string_view client_error = error;
                        std::string_view desc =
                            "The authorization request could not be completed.";

                        if (error == "login_required") {
                            desc = "The session is older than the requested max_age.";
                        } else if (error == "access_denied") {
                            // Silently, a session that did not hold up is
                            // indistinguishable from no session at all, and the
                            // answer is the same: send the user to sign in.
                            // access_denied would say the user refused, which is
                            // not what happened.
                            client_error = "login_required";
                            desc = "The user is not signed in.";
                        } else if (error == "consent_required") {
                            desc = "The user has not granted this client access.";
                        }

                        redirect_client_error(r, target, client_error, desc, req_state);
                        conn->send_response(r);
                        return;
                    }

                    // The relying party asked for a fresher sign-in than this
                    // session can offer. Sending it to the login page is what
                    // satisfies the request; an error page would only tell the user
                    // something went wrong when nothing did.
                    if (error == "login_required" && !login.empty()) {
                        redirect(r, login);
                        conn->send_response(r);
                        return;
                    }

                    // The session did not hold up — ask the user to sign in again
                    // rather than showing an error page.
                    if (error == "access_denied" && !login.empty()) {
                        redirect(r, login);
                        conn->send_response(r);
                        return;
                    }

                    // The user has not granted this client access. That is a
                    // question, not a failure: show the consent screen. Where the
                    // site has none configured the question cannot be put, and the
                    // client is told so on its own redirect_uri rather than the
                    // user landing on our error page over someone else's problem.
                    if (error == "consent_required") {
                        if (consent_page.empty()) {
                            redirect_client_error(r, target, "consent_required",
                                                  "This server has no consent screen configured.",
                                                  req_state);
                        } else {
                            redirect(r, consent_page);
                        }
                        conn->send_response(r);
                        return;
                    }

                    redirect_error(r, err_uri, code, error, message);
                    conn->send_response(r);
                    return;
                }

                auto code  = json_string(result_json, "code");
                auto state = json_string(result_json, "state");

                if (code.empty()) {
                    redirect_error(r, err_uri, 500, "server_error",
                                   "Authorization code was not issued.");
                    conn->send_response(r);
                    return;
                }

                auto location = target;
                location += (location.find('?') == std::string::npos) ? '?' : '&';
                location += "code=" + url_encode(code);
                if (!state.empty())
                    location += "&state=" + url_encode(state);

                redirect(r, location);

            } catch (const std::exception& e) {
                if (self)
                    self->log_.error("[AuthServer] authorization_code: unparsable "
                                     "result: {}", e.what());
                redirect_error(r, err_uri, 500, "server_error",
                               "The authorization server could not complete the request.");
            }

            conn->send_response(r);
        },
        // on_exception
        [self, conn, err_uri](std::string_view error) {
            HttpResponse r;
            if (self)
                self->log_.error("[AuthServer] authorization_code: {}", error);
            redirect_error(r, err_uri, 500, "server_error",
                           "The authorization server could not complete the request.");
            conn->send_response(r);
        },
        /*quiet=*/true);
}

// ─── do_identifier ──────────────────────────────────────────────────────────

void AuthServer::do_identifier(const HttpRequest& req, HttpResponse& resp)
{
    auto json = content_to_json(req);
    const auto identifier = json.value("value", "");

    if (identifier.empty()) {
        reply_oauth2_error(resp, HttpStatus::bad_request,
                           "invalid_request", "Invalid request.");
        return;
    }

    // Check authorization: Bearer JWT, Session+Secret headers, or Cookie
    const auto auth_header = req.header("Authorization");
    std::string auth_token;

    // Whether the module is vouching for this call with its own token. If the
    // server rejects that token we must drop it, or every later request repeats
    // the failure until its nominal life runs out.
    bool anonymous = false;

    JwtKeyResolver key_resolver = [this](std::string_view kid) {
        return get_public_key(kid);
    };

    if (!auth_header.empty()) {
        // Priority 1: Authorization Bearer header
        auto auth = parse_authorization(auth_header);

        if (auth.schema != Authorization::Schema::bearer) {
            reply_oauth2_error(resp, HttpStatus::unauthorized,
                               "unauthorized", "Unauthorized.");
            return;
        }

        try {
            verify_jwt(auth.token, providers_, key_resolver);
        } catch (const JwtExpiredError&) {
            reply_oauth2_error(resp, HttpStatus::forbidden,
                               "forbidden", "Token expired.");
            return;
        } catch (const JwtVerificationError& e) {
            reply_oauth2_error(resp, HttpStatus::bad_request,
                               "invalid_request", e.what());
            return;
        } catch (const std::exception& e) {
            reply_oauth2_error(resp, HttpStatus::bad_request,
                               "invalid_request", e.what());
            return;
        }

        auth_token = std::move(auth.token);
    } else {
        // Priority 2: Session + Secret headers (inter-service auth)
        const auto session_id = req.header("Session");
        const auto secret     = req.header("Secret");

        if (!session_id.empty() && !secret.empty()) {
            auth_token = session_id;
        } else {
            // Priority 3: Cookie-based token (user or service, selected by X-Auth-Context)
            auto context = req.header("X-Auth-Context");
            bool is_service = (context == "service");
            auto cookie_token = req.cookie(is_service ? kCookieSAT : kCookieAT);

            if (cookie_token.empty()) {
                // Nothing presented at all. This is the login and registration
                // screens asking whether an identifier is taken, before anyone has
                // signed in — there is no user credential to offer yet, and a page
                // cannot hold a client credential either: RFC 6749 §2.1 makes a
                // browser-based application a public client, and §4.4 reserves the
                // client credentials grant to confidential ones. So the module,
                // which is a confidential client, asks on its own behalf.
                //
                // The endpoint is therefore anonymous by design rather than by
                // accident. Anyone could already reach it — the page used to mint a
                // service token first, and nothing stopped another caller doing the
                // same — so no new capability appears here. What does disappear is
                // the cost of a probe and the trail it left: minting a token wrote
                // rows to db.session and db.token, and an anonymous POST writes
                // nothing. Rate-limiting this route is now the only control over
                // enumeration; see README, Deployment.
                if (!service_token_.valid()) {
                    reply_oauth2_error(resp, HttpStatus::service_unavailable,
                                       "temporarily_unavailable",
                                       "The service account is not available.");
                    return;
                }

                auth_token = service_token_.token();
                anonymous  = true;

            } else {
                // A cookie was presented, so it has to hold up. This verification
                // belongs to the cookie alone: running it on the anonymous path
                // would hand verify_jwt an empty string, and the module's own token
                // — already in auth_token above — needs no checking by us.
                try {
                    verify_jwt(cookie_token, providers_, key_resolver);
                } catch (const JwtExpiredError&) {
                    reply_oauth2_error(resp, HttpStatus::forbidden,
                                       "forbidden", "Token expired.");
                    return;
                } catch (const JwtVerificationError& e) {
                    reply_oauth2_error(resp, HttpStatus::unauthorized,
                                       "unauthorized", "Unauthorized.");
                    return;
                } catch (const std::exception& e) {
                    reply_oauth2_error(resp, HttpStatus::unauthorized,
                                       "unauthorized", "Unauthorized.");
                    return;
                }

                auth_token = std::move(cookie_token);
            }
        }
    }

    auto sql = fmt::format("SELECT * FROM daemon.identifier({}, {});",
                           pq_quote_literal(auth_token),
                           pq_quote_literal(identifier));

    resp.set_deferred(true);
    auto conn = std::static_pointer_cast<HttpConnection>(req.connection_ctx);

    // quiet: the statement carries a bearer token — the caller's or the module's.
    // PgPool logs statement text, and a dedicated postgres.log keeps it at debug
    // by design; a token has no business being in either.
    pool_.execute(std::move(sql),
        // on_result
        [this, conn, anonymous](std::vector<PgResult> results) {
            HttpResponse r;

            if (results.empty() || !results[0].ok()
                || results[0].rows() == 0 || results[0].columns() == 0) {
                auto msg = results.empty() ? "no results"
                                           : results[0].error_message();
                reply_error(r, HttpStatus::internal_server_error, msg);
                conn->send_response(r);
                return;
            }

            const char* val = results[0].value(0, 0);
            const std::string body = val ? val : "";

            // daemon.identifier catches its own exceptions and answers with an
            // error object over a *successful* query — a rejected token included.
            // Passing that through as 200 would have the caller read {"error":…}
            // as a result: `data.id !== null` is true for an absent id, so the
            // registration screen would report every address as taken.
            bool failed = false;
            try {
                auto j = nlohmann::json::parse(body);
                failed = j.contains("error");
            } catch (...) {
                failed = true;
            }

            if (failed) {
                if (anonymous) {
                    // Most likely our own token: drop it so the next heartbeat
                    // fetches a new one instead of repeating this for its whole life.
                    service_token_.invalidate();
                    log_.warn("[AuthServer] identifier: service token rejected, dropped");
                    reply_oauth2_error(r, HttpStatus::service_unavailable,
                                       "temporarily_unavailable",
                                       "The service account is not available.");
                } else {
                    r.set_status(HttpStatus::bad_request)
                     .set_body(body, "application/json");
                }
                conn->send_response(r);
                return;
            }

            r.set_status(HttpStatus::ok)
             .set_body(body, "application/json");
            conn->send_response(r);
        },
        // on_exception
        [conn](std::string_view error) {
            HttpResponse r;
            reply_error(r, HttpStatus::internal_server_error, error);
            conn->send_response(r);
        },
        /*quiet=*/true);
}

// ─── External providers ─────────────────────────────────────────────────────

void AuthServer::login(std::shared_ptr<HttpConnection> conn,
                       const std::string& redir,
                       const std::string& redir_error,
                       const std::string& agent,
                       const std::string& host,
                       const std::string& origin,
                       const nlohmann::json& token_json)
{
    // Extract hostname from origin (e.g., "https://example.com" → "example.com")
    std::string hostname;
    auto scheme_end = origin.find("://");
    hostname = (scheme_end != std::string::npos)
             ? origin.substr(scheme_end + 3) : origin;

    try {
        const auto token_type = token_json.value("token_type", "");
        const auto id_token   = token_json.value("id_token", "");

        auto auth = parse_authorization(token_type + " " + id_token);

        if (auth.schema != Authorization::Schema::bearer) {
            HttpResponse r;
            redirect_error(r, redir_error, 401, "unauthorized_client",
                           "Invalid token type.");
            conn->send_response(r);
            return;
        }

        JwtKeyResolver key_resolver = [this](std::string_view kid) {
            return get_public_key(kid);
        };

        std::string clean_token;
        try {
            clean_token = verify_and_resign_jwt(auth.token, providers_, key_resolver);
        } catch (const JwtExpiredError& e) {
            // 401, not 403. RFC 6750 §3.1 gives invalid_token to a token that is
            // "expired, revoked, malformed, or invalid for any other reason" and asks
            // for 401 — the caller was not authenticated and can fix that by
            // presenting a good token. 403 says the token was understood and the
            // answer is still no, which tells a client to stop rather than refresh.
            //
            // The reason stays in the log. It names the issuer, the key id and the
            // times involved, and the caller puts error_description in a redirect —
            // where it reaches the address bar, the Referer of whatever loads next,
            // and the browser history.
            log_.warn("[AuthServer] token expired: {}", e.what());
            HttpResponse r;
            redirect_error(r, redir_error, 401, "invalid_token",
                           "The access token has expired.");
            conn->send_response(r);
            return;
        } catch (const JwtVerificationError& e) {
            log_.warn("[AuthServer] token verification failed: {}", e.what());
            HttpResponse r;
            redirect_error(r, redir_error, 401, "invalid_token",
                           "The access token could not be verified.");
            conn->send_response(r);
            return;
        } catch (const std::exception& e) {
            // A token that is not a token at all: jwt-cpp's own decode throws before
            // verify_jwt reaches any of its typed errors, so a value with the wrong
            // number of segments or broken base64 lands here. RFC 6750 §3.1 counts
            // "malformed" among the reasons for invalid_token and asks for 401 —
            // 400 called a rejected token a malformed request, which it is not.
            log_.warn("[AuthServer] token rejected: {}", e.what());
            HttpResponse r;
            redirect_error(r, redir_error, 401, "invalid_token",
                           "The access token is malformed.");
            conn->send_response(r);
            return;
        }

        auto sql = fmt::format("SELECT * FROM daemon.login({}, {}, {}, {});",
                               pq_quote_literal(clean_token),
                               pq_quote_literal(agent),
                               pq_quote_literal(host),
                               pq_quote_literal(origin));

        // quiet: the statement carries the provider's JWT.
        pool_.execute(std::move(sql),
            // on_result
            [this, conn, redir, redir_error, hostname](std::vector<PgResult> results) {
                HttpResponse r;

                if (results.empty() || !results[0].ok()) {
                    auto msg = results.empty() ? "no results"
                                               : results[0].error_message();
                    redirect_error(r, redir_error, 500, "server_error", msg);
                    conn->send_response(r);
                    return;
                }

                auto body = results[0].value(0, 0);

                try {
                    auto payload = nlohmann::json::parse(body);

                    // Check for error
                    std::string error_message;
                    int error_code = check_pg_error(body, error_message);
                    if (error_code != 0) {
                        auto status = error_code_to_status(error_code);
                        switch (status) {
                        case HttpStatus::unauthorized:
                            // access_denied, not unauthorized_client. RFC 6749
                            // §4.1.2.1 gives unauthorized_client one meaning — this
                            // client may not request an authorization code — and a
                            // 401 here is almost never that: it is an expired token,
                            // a locked account, an expired password. Saying the
                            // client is at fault sends the caller to fix the wrong
                            // thing.
                            //
                            // The precise answer would be invalid_token for an
                            // expired token and something else for a locked account,
                            // and that cannot be told apart here: daemon.* returns
                            // {code, message} and no error identifier, so 401-008
                            // and 401-005 arrive indistinguishable. Carrying the
                            // identifier through is a change to the daemon error
                            // contract across every project, not something to slip
                            // in here.
                            redirect_error(r, redir_error, 401, "access_denied", error_message);
                            break;
                        case HttpStatus::forbidden:
                            redirect_error(r, redir_error, 403, "access_denied", error_message);
                            break;
                        case HttpStatus::internal_server_error:
                            // Not error_message. The others carry a catalogue text —
                            // curated, localised, written to be read by whoever hit
                            // the error. This one carries whatever ParseMessage made
                            // of an arbitrary exception, which names schemas,
                            // functions and sometimes values, and error_description
                            // ends up in the address bar and the browser history.
                            log_.error("[AuthServer] login: {}", error_message);
                            redirect_error(r, redir_error, 500, "server_error",
                                           "The authorization server could not complete the request.");
                            break;
                        default:
                            redirect_error(r, redir_error, 400, "invalid_request", error_message);
                            break;
                        }
                        conn->send_response(r);
                        return;
                    }

                    // Success: set cookies and redirect
                    auto access_token  = json_string(payload, "access_token");
                    auto refresh_token = json_string(payload, "refresh_token");
                    auto session       = json_string(payload, "session");
                    auto token_type    = json_string(payload, "token_type");
                    auto expires_in    = json_string(payload, "expires_in");
                    auto state         = json_string(payload, "state");

                    set_secure_cookies(r, access_token, refresh_token, session, "");

                    // Build redirect with token info in fragment
                    auto redirect_url = redir + "#access_token=" + access_token;
                    if (!refresh_token.empty())
                        redirect_url += "&refresh_token=" + url_encode(refresh_token);
                    redirect_url += "&token_type=" + token_type;
                    redirect_url += "&expires_in=" + expires_in;
                    redirect_url += "&session=" + session;
                    if (!state.empty())
                        redirect_url += "&state=" + url_encode(state);

                    redirect(r, redirect_url);

                } catch (const std::exception& e) {
                    redirect_error(r, redir_error, 500, "server_error", e.what());
                }

                conn->send_response(r);
            },
            // on_exception
            [conn, redir_error](std::string_view error) {
                HttpResponse r;
                redirect_error(r, redir_error, 503, "temporarily_unavailable",
                               "Temporarily unavailable.");
                conn->send_response(r);
                (void)error;
            },
            /*quiet=*/true);

    } catch (const std::exception& e) {
        HttpResponse r;
        redirect_error(r, redir_error, 500, "server_error", e.what());
        conn->send_response(r);
    }
}

void AuthServer::fetch_access_token(std::shared_ptr<HttpConnection> conn,
                                    const OAuthApp& app,
                                    std::string_view code,
                                    const std::string& origin,
                                    const std::string& redir,
                                    const std::string& redir_error,
                                    const std::string& agent,
                                    const std::string& host)
{
    if (app.token_uri.empty()) {
        HttpResponse r;
        redirect_error(r, redir_error, 400, "invalid_request",
                       "Parameter \"token_uri\" not found in provider configuration.");
        conn->send_response(r);
        return;
    }

    auto token_uri = app.token_uri;
    if (!token_uri.empty() && token_uri[0] == '/') {
        token_uri = origin + token_uri;
    }

    auto post_body = fmt::format(
        "client_id={}&client_secret={}&grant_type=authorization_code&code={}&redirect_uri={}",
        url_encode(app.client_id),
        url_encode(app.client_secret),
        url_encode(code),
        url_encode(origin + "/oauth2/code/" + app.provider));

    auto provider_name = app.provider;

    fetch_.post(token_uri, post_body,
        {{"Content-Type", "application/x-www-form-urlencoded"}},
        // on_done
        [this, conn, redir, redir_error, provider_name, agent, host, origin](FetchResponse resp) {
            // Extract hostname from origin for cookie domain
            std::string hostname;
            auto scheme_end = origin.find("://");
            hostname = (scheme_end != std::string::npos)
                     ? origin.substr(scheme_end + 3) : origin;

            if (resp.status_code == 200) {
                try {
                    auto json = nlohmann::json::parse(resp.body);
                    if (provider_name == "google") {
                        login(conn, redir, redir_error, agent, host, origin, json);
                    } else {
                        // Non-Google provider: set cookies + redirect directly
                        HttpResponse r;

                        auto access_token  = json_string(json, "access_token");
                        auto refresh_token = json_string(json, "refresh_token");
                        auto session       = json_string(json, "session");
                        auto token_type    = json_string(json, "token_type");
                        auto expires_in    = json_string(json, "expires_in");
                        auto state         = json_string(json, "state");

                        set_secure_cookies(r, access_token, refresh_token, session, "");

                        auto redirect_url = redir + "#access_token=" + access_token;
                        if (!refresh_token.empty())
                            redirect_url += "&refresh_token=" + url_encode(refresh_token);
                        redirect_url += "&token_type=" + token_type;
                        redirect_url += "&expires_in=" + expires_in;
                        redirect_url += "&session=" + session;
                        if (!state.empty())
                            redirect_url += "&state=" + url_encode(state);

                        redirect(r, redirect_url);
                        conn->send_response(r);
                    }
                } catch (const std::exception& e) {
                    HttpResponse r;
                    redirect_error(r, redir_error, 500, "server_error", e.what());
                    conn->send_response(r);
                }
            } else {
                std::string error = "server_error";
                std::string error_desc = "Token exchange failed.";
                try {
                    auto json = nlohmann::json::parse(resp.body);
                    error = json.value("error", "server_error");
                    error_desc = json.value("error_description",
                                            "Token exchange failed.");
                } catch (...) {}

                HttpResponse r;
                redirect_error(r, redir_error, resp.status_code, error, error_desc);
                conn->send_response(r);
            }
        },
        // on_error
        [conn, redir_error](std::string_view error) {
            HttpResponse r;
            redirect_error(r, redir_error, 500, "server_error", error);
            conn->send_response(r);
        });
}

void AuthServer::fetch_certs(const std::string& provider_name,
                             const std::string& cert_uri)
{
    if (cert_uri.empty())
        return;

    auto& cache = key_cache_[provider_name];
    cache.status = ProviderKeyCache::Status::fetching;
    cache.status_time = std::chrono::system_clock::now();

    fetch_.get(cert_uri, {},
        // on_done
        [this, provider_name](FetchResponse resp) {
            auto& cache = key_cache_[provider_name];
            if (resp.status_code == 200) {
                try {
                    auto json = nlohmann::json::parse(resp.body);

                    cache.keys.clear();

                    // Google JWKS format: {"keys":[{"kid":"...","n":"...","e":"...", ...}]}
                    // or simple format: {"kid":"PEM", ...}
                    if (json.contains("keys") && json["keys"].is_array()) {
                        for (const auto& key : json["keys"]) {
                            if (key.contains("kid")) {
                                auto kid = key["kid"].get<std::string>();
                                // Store raw JSON for the key — jwt-cpp can parse JWK
                                cache.keys[kid] = key.dump();
                            }
                        }
                    } else {
                        // Simple kid → PEM mapping
                        for (auto& [kid, pem] : json.items()) {
                            cache.keys[kid] = pem.get<std::string>();
                        }
                    }

                    cache.status = ProviderKeyCache::Status::success;
                    cache.status_time = std::chrono::system_clock::now();
                } catch (const std::exception&) {
                    cache.status = ProviderKeyCache::Status::failed;
                    cache.status_time = std::chrono::system_clock::now();
                }
            } else {
                cache.status = ProviderKeyCache::Status::failed;
                cache.status_time = std::chrono::system_clock::now();
            }
        },
        // on_error
        [this, provider_name](std::string_view /*error*/) {
            auto& cache = key_cache_[provider_name];
            cache.status = ProviderKeyCache::Status::failed;
            cache.status_time = std::chrono::system_clock::now();
            // Retry sooner
            next_heartbeat_ = std::chrono::system_clock::now() + kRetryInterval;
        });
}

void AuthServer::fetch_providers()
{
    for (const auto& app : providers_.apps()) {
        if (app.name == WEB_APP && !app.cert_uri.empty()) {
            auto it = key_cache_.find(app.provider);
            if (it == key_cache_.end() ||
                it->second.status == ProviderKeyCache::Status::unknown)
            {
                fetch_certs(app.provider, app.cert_uri);
            }
        }
    }
}

void AuthServer::check_providers()
{
    for (auto& [name, cache] : key_cache_) {
        if (cache.status != ProviderKeyCache::Status::unknown) {
            cache.status = ProviderKeyCache::Status::unknown;
            cache.status_time = std::chrono::system_clock::now();
        }
    }
}

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
