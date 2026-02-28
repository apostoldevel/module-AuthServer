#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/http.hpp"
#include "apostol/apostol_module.hpp"
#include "apostol/jwt.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"
#include "apostol/site_config.hpp"

#include "apostol/fetch_client.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <unordered_map>

namespace apostol
{

class Application;

// ─── AuthServer ──────────────────────────────────────────────────────────────
//
// OAuth 2.0 Authorization Server — ports v1 CAuthServer.
//
// Handles all requests under /oauth2/:
//   GET  /oauth2/authorize  — redirect to login page
//   GET  /oauth2/code[/provider] — exchange auth code from external provider
//   GET  /oauth2/callback   — redirect to callback URL
//   GET  /oauth2/identifier — GET form of identifier lookup
//   POST /oauth2/token      — token endpoint (all grant types)
//   POST /oauth2/identifier — identifier lookup
//
// Guard: WITH_POSTGRESQL && WITH_SSL.
// External providers (Google OAuth): additionally WITH_CURL.
//
class AuthServer final : public ApostolModule
{
public:
    explicit AuthServer(Application& app);

    std::string_view name() const override { return "AuthServer"; }
    bool enabled() const override { return enabled_; }
    bool check_location(const HttpRequest& req) const override;
    void heartbeat(std::chrono::system_clock::time_point now) override;

protected:
    void init_methods() override;

private:
    // ── GET routes ───────────────────────────────────────────────────────────
    void do_get(const HttpRequest& req, HttpResponse& resp);

    // ── POST routes ──────────────────────────────────────────────────────────
    void do_post(const HttpRequest& req, HttpResponse& resp);

    // ── Endpoints ────────────────────────────────────────────────────────────
    void do_token(const HttpRequest& req, HttpResponse& resp);
    void do_identifier(const HttpRequest& req, HttpResponse& resp);

    // ── OAuth2 error responses (RFC 6749 format) ─────────────────────────────
    static void reply_oauth2_error(HttpResponse& resp, HttpStatus status,
                                   std::string_view error,
                                   std::string_view description);

    static void redirect_error(HttpResponse& resp, std::string_view location,
                               int code, std::string_view error,
                               std::string_view message);

    static void set_secure_cookies(HttpResponse& resp,
                                   std::string_view access_token,
                                   std::string_view refresh_token,
                                   std::string_view session,
                                   std::string_view domain);

    // ── JWT ──────────────────────────────────────────────────────────────────
    std::string get_public_key(std::string_view kid) const;

    // ── External providers ──────────────────────────────────────────────────
    void login(std::shared_ptr<HttpConnection> conn,
               const std::string& redirect,
               const std::string& redirect_error,
               const std::string& agent,
               const std::string& host,
               const std::string& origin,
               const nlohmann::json& token_json);

    void fetch_access_token(std::shared_ptr<HttpConnection> conn,
                            const OAuthApp& app,
                            std::string_view code,
                            const std::string& origin,
                            const std::string& redirect,
                            const std::string& redirect_error,
                            const std::string& agent,
                            const std::string& host);

    void fetch_certs(const std::string& provider_name, const std::string& cert_uri);
    void fetch_providers();
    void check_providers();

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Extract action from "/oauth2/<action>[/extra]".
    static std::string extract_action(std::string_view path);

    /// Extract third segment: "/oauth2/code/<provider>" → "provider".
    static std::string extract_provider(std::string_view path);

    /// Parse comma/space separated string, split into valid/invalid against allowed list.
    static void parse_string_list(std::string_view input,
                                  const std::vector<std::string>& allowed,
                                  std::vector<std::string>& valid,
                                  std::vector<std::string>& invalid);

    // ── State ────────────────────────────────────────────────────────────────
    PgPool& pool_;
    FetchClient fetch_;
    const OAuthProviders& providers_;
    const SiteConfigs& sites_;
    bool enabled_;

    // JWKS key cache (runtime, per-provider)
    struct ProviderKeyCache {
        enum class Status { unknown, fetching, success, failed };
        Status status = Status::unknown;
        std::chrono::system_clock::time_point status_time;
        std::unordered_map<std::string, std::string> keys; // kid → PEM
    };
    std::unordered_map<std::string, ProviderKeyCache> key_cache_;
    std::chrono::system_clock::time_point next_heartbeat_;
};

} // namespace apostol

#endif // WITH_POSTGRESQL && WITH_SSL
