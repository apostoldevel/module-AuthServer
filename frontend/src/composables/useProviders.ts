import { ref } from 'vue'
import { config } from '@/config'
import type { Provider } from '@/types'

// The external sign-in providers the login screen offers. Loaded from the backend
// (GET /oauth2/providers), not baked into the bundle: one build serves every
// deployment, and adding a provider is a config change, not a rebuild. The endpoint
// is unauthenticated — the screen has no session yet — and returns a strict
// projection with no secrets (AuthServer::do_providers).
export function useProviders() {
  const providers = ref<Provider[]>([])
  const loaded = ref(false)

  async function load() {
    try {
      const res = await fetch(`${config.apiHost || window.location.origin}/oauth2/providers`, {
        headers: { Accept: 'application/json' },
      })
      if (res.ok) {
        const data = await res.json()
        if (Array.isArray(data)) providers.value = data
      }
      // A non-200, malformed body, or a network error leaves the list empty: the
      // password form still works, and there is simply no external button to show.
    } catch {
      // swallowed on purpose — see above
    } finally {
      loaded.value = true
    }
  }

  return { providers, loaded, load }
}
