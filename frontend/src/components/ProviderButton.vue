<template>
  <button class="btn btn-outline provider-btn" @click="startLogin" :disabled="loading">
    <img v-if="provider.icon" class="provider-icon" :src="provider.icon" alt="" width="18" height="18" />
    <span>{{ t('login.withProvider', { name: provider.display_name }) }}</span>
  </button>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { config } from '@/config'
import type { Provider } from '@/types'

const { t } = useI18n()
const props = defineProps<{ provider: Provider; loading?: boolean }>()

// CSRF state for the external sign-in (RFC 6749 §10.12). The exact shape of the
// consent token (ConsentScreen.vue), and it holds for the same reason: the value
// goes to the provider as ?state= and into a __Host- cookie the backend reads back
// on return (do_get, action "code"). A page on another origin can neither read our
// cookie to forge a matching state nor plant one under the __Host- prefix.
//
// SameSite=Lax, NOT Strict as the consent token is: the return from the provider is
// a top-level cross-site navigation, which a Strict cookie would not accompany —
// every real sign-in would then fail the backend's check. __Host- still requires
// Secure and Path=/, which the login screen is served under.
function mintState(): string {
  const state =
    typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')

  document.cookie = `__Host-OAuthState=${state}; Path=/; Secure; SameSite=Lax; Max-Age=600`
  return state
}

function startLogin() {
  // The provider's own authorization endpoint and scope come from the list the
  // backend served (GET /oauth2/providers) — nothing about the provider is baked
  // into this bundle, so one build serves every deployment.
  const redirectUri = `${config.apiHost || window.location.origin}/oauth2/code/${props.provider.provider}`

  const params = new URLSearchParams({
    client_id: props.provider.client_id,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: props.provider.login_scope,
    state: mintState(),
  })

  window.location.href = `${props.provider.auth_uri}?${params}`
}
</script>

<style scoped>
.provider-btn {
  gap: 0.5rem;
}
.provider-icon {
  flex-shrink: 0;
}
</style>
