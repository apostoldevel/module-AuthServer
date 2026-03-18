import type { AuthorizeParams } from '@/types'

export function parseAuthorizeParams(query: Record<string, string>): AuthorizeParams | null {
  const { client_id, redirect_uri, response_type, scope, state, access_type, prompt } = query
  if (!client_id || !redirect_uri || !response_type) return null
  return { client_id, redirect_uri, response_type, scope, state, access_type, prompt }
}

export function validateRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri)
    return url.protocol === 'https:' || url.hostname === 'localhost'
  } catch {
    return false
  }
}
