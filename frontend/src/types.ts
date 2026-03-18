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
