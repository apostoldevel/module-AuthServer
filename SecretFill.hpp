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
/// A browser client cannot keep a secret, so for our own `web` application the
/// server supplies it once the Origin matches the application's
/// javascript_origins (checked by the caller). Origin is a request header, not
/// proof of identity: the match gates the fill, it does not authenticate the
/// client.
///
/// Never to `service`: it is a server-to-server application whose token
/// audience is the platform's own, so its callers send the secret themselves.
/// No browser signs in as `service`: the SPAs and the consoles use `web`, and
/// AppServer runs guest routes with its own token.
///
/// So it goes to applications of this installation only, never to an external
/// provider's. find_by_client_id searches every provider, and the Yandex
/// application is called `web` too: without this check its client_id alone,
/// with no secret, bought a session on the external provider's audience, and
/// with it the half of db-platform's external-sign-in test that rests on the
/// audience. An external provider is registered so that we can verify
/// *its* tokens; its holder has no standing here.
///
/// Not "the default provider only", which is where /oauth2/authorize draws its
/// line (validate_client): a local provider of its own — `bridge` — has a `web`
/// application that lives on this very fill.
///
/// `external` is a flag of the application (the section), not of the file:
/// a section that does not set it is taken for a local one even in an external
/// provider's file, and so is a flag set at file level or as a string.
inline const OAuthApp* secret_fill_app(const OAuthProviders& providers,
                                       std::string_view client_id)
{
    const auto* app = providers.find_by_client_id(client_id);
    if (app == nullptr || app->external)
        return nullptr;
    if (app->name != WEB_APP)
        return nullptr;
    return app;
}

} // namespace apostol
