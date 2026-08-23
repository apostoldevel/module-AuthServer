#pragma once

#if defined(WITH_POSTGRESQL) && defined(WITH_SSL)

#include "apostol/http.hpp"
#include "apostol/apostol_module.hpp"
#include "apostol/jwt.hpp"
#include "apostol/oauth_providers.hpp"
#include "apostol/pg.hpp"
#include "apostol/service_token.hpp"
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
//   GET  /oauth2/authorize  — issue code to a signed-in user, else login/consent page
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

    /// Closes the service session. Every client_credentials grant creates a row in
    /// db.session and nothing collects them, so leaving without this leaks one per
    /// worker per restart.
    void on_stop() override;

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

    /// POST /oauth2/consent — the answer to the consent screen. Records the user's
    /// consent for this client, then issues the code and redirects, exactly as the
    /// authorize endpoint would have done had the consent already stood.
    ///
    /// POST, not GET, and guarded by a double-submit token: a signed-in browser
    /// carries its cookies wherever a third-party page sends it, and __Secure-AT is
    /// SameSite=None, so it rides along on a cross-site POST too. The Origin header
    /// cannot be the guard here — the ecosystem's own nginx recipe overwrites it on
    /// every /oauth2/ request, so it always reads as ours. See do_consent.
    void do_consent(const HttpRequest& req, HttpResponse& resp);

    /// Look up the client and validate redirect_uri and scope against its
    /// registration. Returns nullptr after filling @p resp with the RFC 6749 error.
    ///
    /// The lookup is restricted to clients of the local provider: an entry under an
    /// external provider registers that provider's tokens for verification and is
    /// not a client of ours, so it must not reach the endpoints that act on behalf
    /// of a signed-in user.
    const OAuthApp* validate_client(HttpResponse& resp,
                                    const std::string& redirect_err,
                                    const std::string& client_id,
                                    const std::string& redirect_uri,
                                    const std::string& scope) const;

    /// Issue an authorization code for an already signed-in user and redirect the
    /// browser to @p redirect_uri with ?code=&state=. Deferred (async DB call).
    /// @p redirect_login is a complete login-page URL, used when the session
    /// turns out to be stale; @p redirect_consent a complete consent-page URL, used
    /// when the user has not yet granted this client access. When @p consent is
    /// true the user has just answered that screen and the consent is recorded.
    void issue_authorization_code(const HttpRequest& req, HttpResponse& resp,
                                  const std::string& session,
                                  const std::string& client_id,
                                  const std::string& redirect_uri,
                                  const std::string& scope,
                                  const std::string& state,
                                  const std::string& access_type,
                                  const std::string& redirect_login,
                                  const std::string& redirect_consent,
                                  const std::string& redirect_error,
                                  bool consent,
                                  const std::string& max_age = {});

    /// Ask db-platform for a service token when ServiceToken says one is due, and
    /// report the outcome back to it. Called from heartbeat().
    void refresh_service_token();

    /// Session code of the signed-in user, or empty if there is none.
    /// Reads the SID cookie; falls back to the "sub" claim of __Secure-AT.
    std::string session_from_request(const HttpRequest& req) const;

    // ── OAuth2 error responses (RFC 6749 format) ─────────────────────────────
    static void reply_oauth2_error(HttpResponse& resp, HttpStatus status,
                                   std::string_view error,
                                   std::string_view description);

    static void redirect_error(HttpResponse& resp, std::string_view location,
                               int code, std::string_view error,
                               std::string_view message);

    /// Deliver an OAuth2 error to the *client*, on its own redirect_uri, as
    /// RFC 6749 §4.1.2.1 requires. Use once the client is known and its
    /// redirect_uri validated; redirect_error sends the user to the site's error
    /// page instead, which is right only while the client is not yet established.
    static void redirect_client_error(HttpResponse& resp,
                                      const std::string& redirect_uri,
                                      std::string_view error,
                                      std::string_view description,
                                      const std::string& state);

    static void set_secure_cookies(HttpResponse& resp,
                                   std::string_view access_token,
                                   std::string_view refresh_token,
                                   std::string_view session,
                                   std::string_view domain);

    static void set_service_cookies(HttpResponse& resp,
                                    std::string_view access_token,
                                    std::string_view refresh_token);

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

    /// The module's own access token, for work a caller cannot authenticate for
    /// yet — see do_identifier. Obtained server-side with the client credentials
    /// grant, which RFC 6749 §4.4 permits only to confidential clients: this
    /// module is one, the page it serves is not.
    ///
    /// ServiceToken itself holds only the lifecycle — when the token is good, when
    /// to renew, how long to back off. Obtaining one is db-platform's business
    /// (daemon.token, api.signout) and therefore lives here, in a module that
    /// depends on db-platform, not in the framework, which does not.
    ServiceToken service_token_;

    Logger& log_;
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
