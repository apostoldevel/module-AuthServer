#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "AuthServer.hpp"
#include "apostol/application.hpp"

#include "apostol/http_utils.hpp"
#include "apostol/jwt.hpp"
#include "apostol/pg_utils.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>


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

static constexpr const char* WEB_APP   = "web";
static constexpr const char* SVC_APP   = "service";

static constexpr auto kHeartbeatInterval = std::chrono::minutes(30);
static constexpr auto kRetryInterval     = std::chrono::seconds(5);
static constexpr int  kCookieMaxAge      = 60 * 86400; // 60 days

// ─── Construction ────────────────────────────────────────────────────────────

AuthServer::AuthServer(Application& app)
    : pool_(app.db_pool())
    , fetch_(app.worker_loop())
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

void AuthServer::heartbeat(std::chrono::system_clock::time_point now)
{
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
        resp.set_header("WWW-Authenticate",
                        fmt::format("Bearer error=\"access_denied\", "
                                    "error_description=\"{}\"",
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
    auto url = fmt::format("{}?code={}&error={}&error_description={}",
                           location, code, error, url_encode(message));
    redirect(resp, url);
}

void AuthServer::set_secure_cookies(HttpResponse& resp,
                                    std::string_view access_token,
                                    std::string_view refresh_token,
                                    std::string_view session,
                                    std::string_view domain)
{
    if (!access_token.empty())
        resp.set_cookie("__Secure-AT", access_token, "/", kCookieMaxAge,
                        true, "None", true, domain);

    if (!refresh_token.empty())
        resp.set_cookie("__Secure-RT", refresh_token, "/", kCookieMaxAge,
                        true, "None", true, domain);

    if (!session.empty())
        resp.set_cookie("SID", session, "/", kCookieMaxAge);
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
    const std::string redirect_callback   = site ? site->oauth2.callback   : "";
    const std::string redirect_err        = site ? site->oauth2.error      : "";
    const std::string redirect_debug      = site ? site->oauth2.debug      : "";

    static const std::vector<std::string> kResponseTypes{"code", "token"};
    static const std::vector<std::string> kAccessTypes{"online", "offline"};
    static const std::vector<std::string> kPrompts{
        "none", "signin", "secret", "consent", "select_account"};

    std::vector<std::string> valid, invalid;

    if (action == "authorize" || action == "auth") {

        const auto& response_type = req.param("response_type");
        const auto& client_id     = req.param("client_id");
        const auto& access_type   = req.param("access_type");
        const auto& redirect_uri  = req.param("redirect_uri");
        const auto& scope         = req.param("scope");
        const auto& state         = req.param("state");
        const auto& prompt        = req.param("prompt");

        if (redirect_uri.empty()) {
            redirect_error(resp, redirect_err, 400, "invalid_request",
                           "Parameter value redirect_uri cannot be empty.");
            return;
        }

        auto* app = providers_.find_by_client_id(client_id);
        if (!app) {
            redirect_error(resp, redirect_err, 401, "invalid_client",
                           "The OAuth client was not found.");
            return;
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
            return;
        }

        // Validate response_type
        parse_string_list(response_type, kResponseTypes, valid, invalid);
        if (!invalid.empty()) {
            redirect_error(resp, redirect_err, 400, "unsupported_response_type",
                           fmt::format("Some requested response type were invalid: "
                                       "{{valid=[{}], invalid=[{}]}}",
                                       join_strings(valid, ", "),
                                       join_strings(invalid, ", ")));
            return;
        }

        // Validate access_type
        auto access_types = kAccessTypes;
        if (response_type == "token")
            access_types.clear();

        if (!access_type.empty()) {
            bool at_ok = false;
            for (const auto& at : access_types) {
                if (at == access_type) { at_ok = true; break; }
            }
            if (!at_ok) {
                redirect_error(resp, redirect_err, 400, "invalid_request",
                               fmt::format("Invalid access_type: {}", access_type));
                return;
            }
        }

        // Validate scope
        parse_string_list(scope, app->scopes, valid, invalid);
        if (!invalid.empty()) {
            redirect_error(resp, redirect_err, 400, "invalid_scope",
                           fmt::format("Some requested scopes were invalid: "
                                       "{{valid=[{}], invalid=[{}]}}",
                                       join_strings(valid, ", "),
                                       join_strings(invalid, ", ")));
            return;
        }

        // Validate prompt
        parse_string_list(prompt, kPrompts, valid, invalid);
        if (!invalid.empty()) {
            redirect_error(resp, redirect_err, 400, "unsupported_prompt_type",
                           fmt::format("Some requested prompt type were invalid: "
                                       "{{valid=[{}], invalid=[{}]}}",
                                       join_strings(valid, ", "),
                                       join_strings(invalid, ", ")));
            return;
        }

        // Build redirect to login page
        auto location = (prompt == "secret") ? redirect_secret : redirect_identifier;

        location += fmt::format("?client_id={}&response_type={}", client_id, response_type);

        if (!redirect_uri.empty())
            location += "&redirect_uri=" + url_encode(redirect_uri);
        if (!access_type.empty())
            location += "&access_type=" + access_type;
        if (!scope.empty())
            location += "&scope=" + url_encode(scope);
        if (!prompt.empty())
            location += "&prompt=" + url_encode(prompt);
        if (!state.empty())
            location += "&state=" + url_encode(state);

        redirect(resp, location);

    } else if (action == "code") {

        const auto& code  = req.param("code");
        const auto& error = req.param("error");

        if (code.empty()) {
            redirect_error(resp, redirect_err, 400, "invalid_request",
                           "Parameter \"code\" not found.");
            return;
        }

        if (!error.empty()) {
            int error_code = 400;
            try { error_code = std::stoi(code); } catch (...) {}
            redirect_error(resp, redirect_err, error_code, error,
                           req.param("error_description"));
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
            // Default to the web app's client_id
            auto* default_app = providers_.find_default(WEB_APP);
            if (default_app)
                auth_username = default_app->client_id;
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

    pool_.execute(std::move(sql),
        // on_result
        [conn, hostname](std::vector<PgResult> results) {
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
                    if (code >= 10000) code = code / 100;
                    if (code < 0) code = 400;

                    auto status = error_code_to_status(code);
                    reply_oauth2_error(r, status, error, message);
                    conn->send_response(r);
                    return;
                }

                auto access_token  = result_json.value("access_token", "");
                auto refresh_token = result_json.value("refresh_token", "");
                auto session       = result_json.value("session", "");

                set_secure_cookies(r, access_token, refresh_token,
                                   session, hostname);

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
        });
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

    // Check Bearer authorization
    const auto auth_header = req.header("Authorization");
    auto auth = parse_authorization(auth_header);

    if (auth.schema != Authorization::Schema::bearer) {
        if (auth.schema == Authorization::Schema::basic) {
            reply_oauth2_error(resp, HttpStatus::unauthorized,
                               "unauthorized", "Unauthorized.");
        } else {
            reply_oauth2_error(resp, HttpStatus::unauthorized,
                               "unauthorized", "Unauthorized.");
        }
        return;
    }

    // Verify Bearer token
    JwtKeyResolver key_resolver = [this](std::string_view kid) {
        return get_public_key(kid);
    };

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

    auto sql = fmt::format("SELECT * FROM daemon.identifier({}, {});",
                           pq_quote_literal(auth.token),
                           pq_quote_literal(identifier));

    resp.set_deferred(true);
    auto conn = std::static_pointer_cast<HttpConnection>(req.connection_ctx);

    pool_.execute(std::move(sql),
        // on_result
        [conn](std::vector<PgResult> results) {
            HttpResponse r;

            if (results.empty() || !results[0].ok()) {
                auto msg = results.empty() ? "no results"
                                           : results[0].error_message();
                reply_error(r, HttpStatus::internal_server_error, msg);
                conn->send_response(r);
                return;
            }

            r.set_status(HttpStatus::ok)
             .set_body(results[0].value(0, 0), "application/json");
            conn->send_response(r);
        },
        // on_exception
        [conn](std::string_view error) {
            HttpResponse r;
            reply_error(r, HttpStatus::internal_server_error, error);
            conn->send_response(r);
        });
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
            HttpResponse r;
            redirect_error(r, redir_error, 403, "invalid_token", e.what());
            conn->send_response(r);
            return;
        } catch (const JwtVerificationError& e) {
            HttpResponse r;
            redirect_error(r, redir_error, 400, "invalid_token", e.what());
            conn->send_response(r);
            return;
        } catch (const std::exception& e) {
            HttpResponse r;
            redirect_error(r, redir_error, 400, "invalid_token", e.what());
            conn->send_response(r);
            return;
        }

        auto sql = fmt::format("SELECT * FROM daemon.login({}, {}, {}, {});",
                               pq_quote_literal(clean_token),
                               pq_quote_literal(agent),
                               pq_quote_literal(host),
                               pq_quote_literal(origin));

        pool_.execute(std::move(sql),
            // on_result
            [this, conn, redir, redir_error](std::vector<PgResult> results) {
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
                            redirect_error(r, redir_error, 401, "unauthorized_client", error_message);
                            break;
                        case HttpStatus::forbidden:
                            redirect_error(r, redir_error, 403, "access_denied", error_message);
                            break;
                        case HttpStatus::internal_server_error:
                            redirect_error(r, redir_error, 500, "server_error", error_message);
                            break;
                        default:
                            redirect_error(r, redir_error, 400, "invalid_request", error_message);
                            break;
                        }
                        conn->send_response(r);
                        return;
                    }

                    // Success: set cookies and redirect
                    auto access_token  = payload.value("access_token", "");
                    auto refresh_token = payload.value("refresh_token", "");
                    auto session       = payload.value("session", "");
                    auto token_type    = payload.value("token_type", "");
                    auto expires_in    = payload.value("expires_in", "");
                    auto state         = payload.value("state", "");

                    // Extract domain from redirect URL (approximate)
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
            });

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
            if (resp.status_code == 200) {
                try {
                    auto json = nlohmann::json::parse(resp.body);
                    if (provider_name == "google") {
                        login(conn, redir, redir_error, agent, host, origin, json);
                    } else {
                        // Non-Google provider: set cookies + redirect directly
                        HttpResponse r;

                        auto access_token  = json.value("access_token", "");
                        auto refresh_token = json.value("refresh_token", "");
                        auto session       = json.value("session", "");
                        auto token_type    = json.value("token_type", "");
                        auto expires_in    = json.value("expires_in", "");
                        auto state         = json.value("state", "");

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
