import { ref, readonly } from 'vue'
import { config } from '@/config'
import type { WhoAmIResponse } from '@/types'

const session = ref<WhoAmIResponse | null>(null)
const loading = ref(false)

export function useAuth() {
  /**
   * POST /oauth2/token with grant_type=password
   * Uses credentials: 'include' (cookies).
   * Does NOT store token in JS — relies on HttpOnly cookies.
   */
  async function signIn(username: string, password: string): Promise<void> {
    loading.value = true
    try {
      const resp = await fetch(`${config.apiHost}/oauth2/token`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'password',
          username,
          password,
          access_type: 'offline',
          scope: config.scope,
          client_id: config.clientId,
        }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err.error_description || err.error?.message || 'Login failed')
      }
      await getSession()
    } finally {
      loading.value = false
    }
  }

  /** POST /api/v1/sign/out */
  async function signOut(): Promise<void> {
    try {
      await fetch(`${config.apiHost}/api/v1/sign/out`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session: session.value?.userid }),
      })
    } catch {
      // ignore
    } finally {
      session.value = null
    }
  }

  /** GET /api/v1/whoami — check if user is logged in */
  async function getSession(): Promise<WhoAmIResponse | null> {
    try {
      const resp = await fetch(`${config.apiHost}/api/v1/whoami`, {
        credentials: 'include',
      })
      if (!resp.ok) {
        session.value = null
        return null
      }
      const data: WhoAmIResponse = await resp.json()
      session.value = data
      return data
    } catch {
      session.value = null
      return null
    }
  }

  /**
   * POST /oauth2/token with grant_type=client_credentials
   * Returns access_token string (for service-level API calls).
   */
  async function getServiceToken(): Promise<string> {
    const resp = await fetch(`${config.apiHost}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: config.clientId,
        scope: config.scope,
      }),
    })
    if (!resp.ok) throw new Error('Failed to get service token')
    const data = await resp.json()
    return data.access_token
  }

  /** POST /oauth2/identifier — check if email/phone/username exists */
  async function checkIdentifier(
    value: string,
  ): Promise<{ exists: boolean; username: string | null }> {
    const token = await getServiceToken()
    const resp = await fetch(`${config.apiHost}/oauth2/identifier`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ value }),
    })
    if (!resp.ok) throw new Error('Identifier check failed')
    const data = await resp.json()
    return {
      exists: data.id !== null,
      username: data.username ?? null,
    }
  }

  /** POST /api/v1/user/registration/code — send verification code to email */
  async function requestVerificationCode(email: string): Promise<string> {
    const token = await getServiceToken()
    const resp = await fetch(`${config.apiHost}/api/v1/user/registration/code`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ email }),
    })
    if (!resp.ok) throw new Error('Failed to send verification code')
    const data = await resp.json()
    return data.ticket
  }

  /** POST /api/v1/user/registration/check — verify code against ticket */
  async function checkRegistrationCode(
    ticket: string,
    code: string,
  ): Promise<{ result: boolean; message: string }> {
    const token = await getServiceToken()
    const resp = await fetch(`${config.apiHost}/api/v1/user/registration/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ticket, code }),
    })
    if (!resp.ok) throw new Error('Code verification failed')
    return resp.json()
  }

  /** POST /api/v1/sign/up — register new user */
  async function signUp(data: {
    username: string
    password: string
    name: { first: string; last: string }
    email: string
  }): Promise<void> {
    const token = await getServiceToken()
    await fetch(`${config.apiHost}/api/v1/sign/up`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        type: 'cpo',
        username: data.username,
        password: data.password,
        name: data.name,
        email: data.email,
      }),
    })
  }

  return {
    session: readonly(session),
    loading: readonly(loading),
    signIn,
    signOut,
    getSession,
    getServiceToken,
    checkIdentifier,
    requestVerificationCode,
    checkRegistrationCode,
    signUp,
  }
}
