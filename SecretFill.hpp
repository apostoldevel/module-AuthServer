#pragma once

#include "apostol/oauth_providers.hpp"

#include <string_view>

namespace apostol {

// Application (section) names within a provider file.
inline constexpr const char* WEB_APP = "web";
inline constexpr const char* SVC_APP = "service";

/// The application whose client_secret /oauth2/token may fill in on the
/// strength of the request's Origin, or nullptr when it may not.
///
/// A browser client cannot keep a secret, so for our own `web` and `service`
/// applications the server supplies it once the Origin matches the
/// application's javascript_origins (checked by the caller). That is a grant of
/// standing: whoever holds the client_id and sends the right Origin becomes a
/// client of ours — and where nginx sets Origin itself (the auth host does), the
/// client_id alone is enough.
///
/// So it goes to applications of this installation only, never to an external
/// provider's (T331). find_by_client_id searches every provider, and the Yandex
/// application is called `web` too: without this check its client_id alone,
/// with no secret, bought a session on the external provider's audience, and
/// with it the half of db-platform's external-sign-in test that rests on the
/// audience (T319). An external provider is registered so that we can verify
/// *its* tokens; its holder has no standing here.
///
/// Not "the default provider only", which is where /oauth2/authorize draws its
/// line (validate_client): a local provider of its own — `bridge`, the ship's
/// console — has a `web` application that lives on this very fill.
///
/// `external` is a flag of the application (the section), not of the file:
/// a section that does not set it is taken for a local one even in an external
/// provider's file, and so is a flag set at file level or as a string (T334).
inline const OAuthApp* secret_fill_app(const OAuthProviders& providers,
                                       std::string_view client_id)
{
    const auto* app = providers.find_by_client_id(client_id);
    if (app == nullptr || app->external)
        return nullptr;
    if (app->name != WEB_APP && app->name != SVC_APP)
        return nullptr;
    return app;
}

} // namespace apostol
