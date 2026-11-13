#pragma once

#include "apostol/oauth_providers.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace apostol {

/// Compares two secrets without an early exit on the first differing byte.
/// The length is not hidden: strings of different lengths compare unequal at
/// once. An empty secret never matches.
inline bool secret_equals(std::string_view given, std::string_view expected)
{
    if (given.empty() || given.size() != expected.size())
        return false;
    return CRYPTO_memcmp(given.data(), expected.data(), given.size()) == 0;
}

/// The application a JWT bearer grant (RFC 7523 §2.1) on /oauth2/token is
/// authenticated as, or nullptr when the client did not authenticate.
///
/// The client proves who it is with its own client_id and client_secret.
/// Credentials come from the client only; nothing is filled in from request
/// headers.
///
/// Only applications of the default provider qualify — the clients this
/// installation issues credentials to (find_default_by_client_id). Entries of
/// other providers exist to verify those providers' tokens and are not clients
/// here; an application marked external is refused as well.
inline const OAuthApp* jwt_bearer_client(const OAuthProviders& providers,
                                         std::string_view client_id,
                                         std::string_view client_secret)
{
    if (client_id.empty())
        return nullptr;

    const auto* app = providers.find_default_by_client_id(client_id);
    if (app == nullptr || app->external)
        return nullptr;

    if (!secret_equals(client_secret, app->client_secret))
        return nullptr;

    return app;
}

/// Whether an authenticated client may use the JWT bearer grant: its
/// client_id is in the list (module.AuthServer.jwt_bearer_clients), compared
/// byte for byte. Asked only after jwt_bearer_client has authenticated it.
inline bool jwt_bearer_client_allowed(const std::vector<std::string>& allowed,
                                      std::string_view client_id)
{
    return !client_id.empty()
        && std::find(allowed.begin(), allowed.end(), client_id) != allowed.end();
}

} // namespace apostol
