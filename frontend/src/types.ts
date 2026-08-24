export interface WhoAmIResponse {
  userid: string
  username: string
  name: string
  locale?: { code: string }
  scope?: { code: string }
  interface?: { code: string }
  [key: string]: unknown
}

export interface AuthorizeParams {
  client_id: string
  redirect_uri: string
  response_type: string
  scope?: string
  state?: string
  access_type?: string
  prompt?: string
}

/** One external sign-in provider, as GET /oauth2/providers returns it.
 *  Strict projection: the backend never serialises the whole OAuthApp — see
 *  AuthServer::do_providers. Every field here is public (it ends up in the
 *  provider redirect URL); there is deliberately no client_secret. */
export interface Provider {
  provider: string       // path segment: /oauth2/code/<provider>
  display_name: string   // button label
  icon: string           // icon URL or data URI (may be empty)
  client_id: string      // public OAuth2 client id at the provider
  auth_uri: string       // the provider's authorization endpoint
  login_scope: string    // the provider's OAuth scope string
}
