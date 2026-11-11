#pragma once

// RFC 7009 token revocation, the body form of /oauth2/revoke: which values reach
// the database, the statement sent and the reading of its answer. Kept apart
// from AuthServer.cpp so that the part deciding between 200, 400 and 503 can
// be tested without a database.
//
// Needs daemon.session_revoke — db-platform 1.2.32 or later.

#include "apostol/pg_utils.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace apostol {

/// What daemon.session_revoke answered.
struct RevokeAnswer
{
    enum class Status
    {
        revoked,     ///< the token was live; its session is closed now
        not_found,   ///< no live token of ours by that value: nothing to do (§2.2)
        failed,      ///< anything else — the client must assume the token lives (§2.2.1)
    };

    Status      status = Status::failed;
    std::string message;   ///< the database's or the reader's words, for a log line
};

/// Whether @p token can be a token of ours at all. Every token the database
/// issues is printable ASCII (a JWT, or an opaque base64 string); anything else —
/// a NUL, a control character, a byte above 0x7E — is answered "not found" here
/// rather than sent: a NUL cuts the statement short and invalid UTF-8 is refused
/// by the server, and either would read as the database failing (503, and a
/// client told to retry for ever).
inline bool plausible_token(std::string_view token)
{
    if (token.empty())
        return false;
    for (const unsigned char c : token)
        if (c < 0x21 || c > 0x7E)
            return false;
    return true;
}

/// The longest token value passed to the database, in bytes.
///
/// A token is carried in a request header (Authorization: Bearer) or in a URL
/// (id_token_hint), and a common front proxy takes at most 8 KiB for either
/// (nginx: large_client_header_buffers 4 8k), so no token that can be used
/// through one is longer. An id token has no upper bound of its own, though —
/// with the profile scope it carries the user's profile — so a value past this
/// limit is refused out loud (400), never answered as revoked.
inline constexpr std::size_t k_max_revoke_token = 8192;

/// What becomes of the token of a body-form revocation before the database.
struct RevokeTokenCheck
{
    enum class Verdict
    {
        send,        ///< pass it to the database
        malformed,   ///< the request itself is wrong: 400 invalid_request
    };

    Verdict     verdict = Verdict::malformed;
    const char* description = "";   ///< error_description of a 400; never null
};

/// Decide what to do with @p token, the value of the body's "token" parameter
/// as decoded.
///
/// A value no token can have — a space, a control character, a byte outside
/// printable ASCII — is a malformed request, not a token that is not ours: every
/// token issued is printable ASCII, so such a value is one mangled on its way
/// here. A base64 token holds '+', which a form body must send as %2B and which
/// decodes to a space when sent bare; a token read from a file brings its line
/// feed. Answered 200, such a request would tell the client its token is
/// revoked while the token lives on.
inline RevokeTokenCheck check_revoke_token(std::string_view token)
{
    using Verdict = RevokeTokenCheck::Verdict;

    if (token.empty())
        return {Verdict::malformed, "Parameter value token cannot be empty."};

    if (token.size() > k_max_revoke_token)
        return {Verdict::malformed, "Parameter value token is too long."};

    if (token.find(' ') != std::string_view::npos)
        return {Verdict::malformed,
                "Parameter value token contains a space; in a form body a '+' "
                "must be sent as %2B."};

    if (!plausible_token(token))
        return {Verdict::malformed,
                "Parameter value token is not printable ASCII; no token is."};

    return {Verdict::send, ""};
}

/// SELECT * FROM daemon.session_revoke(token, hint). The database looks the
/// token up among access, refresh and id tokens alike and only accepts the hint
/// (§2.1 lets the server search past it). So only the two hints RFC 7009 defines
/// are passed on; any other value, and none, is sent as NULL — an advisory field
/// must not be able to make the statement fail.
///
/// The statement carries the token: run it quiet. @p token is expected to have
/// passed check_revoke_token() with Verdict::send.
inline std::string session_revoke_sql(std::string_view token, std::string_view hint)
{
    const bool known = hint == "access_token" || hint == "refresh_token";
    return fmt::format("SELECT * FROM daemon.session_revoke({}, {})",
                       pq_quote_literal(token),
                       known ? pq_quote_literal(hint) : std::string("NULL"));
}

/// The HTTP status for an answer: 200 whether the token was revoked or not
/// found (§2.2), 503 for a failure (§2.2.1) — never 200 with the token alive.
inline int revoke_http_status(const RevokeAnswer& answer)
{
    return answer.status == RevokeAnswer::Status::failed ? 503 : 200;
}

/// Read the first column of the first row of daemon.session_revoke's answer.
/// @p value is null when there was no value to read.
///
/// The function answers {"revoked": true|false}; everything that is not ours or
/// not live already comes back as false. So there is no third, "refused" class
/// that could be answered 200: an error object of any code — the function
/// catches every exception and reports it that way — and any answer of another
/// shape are failures, and a failure is 503, never 200 with the token alive.
inline RevokeAnswer read_session_revoke(const char* value)
{
    using Status = RevokeAnswer::Status;

    if (value == nullptr)
        return {Status::failed, "null answer"};

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(value);
    } catch (const std::exception&) {
        return {Status::failed, "the answer is not json"};
    }

    if (!j.is_object())
        return {Status::failed, j.dump()};

    if (j.contains("error")) {
        const auto& e = j["error"];
        if (e.is_object() && e.contains("message") && e["message"].is_string())
            return {Status::failed, e["message"].get<std::string>()};
        return {Status::failed, j.dump()};
    }

    const auto it = j.find("revoked");
    if (it == j.end() || !it->is_boolean())
        return {Status::failed, j.dump()};

    return {it->get<bool>() ? Status::revoked : Status::not_found, {}};
}

} // namespace apostol
