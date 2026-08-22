<template>
  <div class="auth-card">
    <h2>{{ t('consent.title') }}</h2>

    <p style="text-align: center; margin-bottom: 1.25rem; color: var(--color-text-muted);">
      {{ t('consent.description', { app: params.client_id }) }}
    </p>

    <p v-if="scopes.length" style="margin-bottom: 0.5rem; color: var(--color-text-muted); font-size: 0.875rem;">
      {{ t('consent.scopeIntro') }}
    </p>

    <ul style="margin-bottom: 1.5rem; padding-left: 1.25rem; color: var(--color-text-muted); font-size: 0.875rem;">
      <li v-for="scope in scopes" :key="scope">{{ scope }}</li>
      <li v-if="!scopes.length">{{ t('consent.scopeRead') }}</li>
    </ul>

    <div style="display: flex; gap: 0.75rem;">
      <button class="btn btn-outline" @click="handleDeny">
        {{ t('consent.deny') }}
      </button>
      <button class="btn btn-primary" @click="handleAllow">
        {{ t('consent.allow') }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { config } from '@/config'
import type { AuthorizeParams } from '@/types'

const { t } = useI18n()

const props = defineProps<{
  params: AuthorizeParams
}>()

// What the user is about to agree to, shown as it will be recorded. The backend
// resolves an omitted scope to the client's registered list before sending the
// browser here, precisely so that this list and the consent stored in
// db.oauth2_consent are the same thing — a screen that shows one permission while
// granting every one of them is worse than no screen at all.
const scopes = computed(() =>
  (props.params.scope ?? '').split(' ').filter((s) => s.length > 0)
)

// Double-submit CSRF token. The backend cannot trust Origin on this route — the
// nginx recipe these projects deploy with rewrites it to our own host on every
// /oauth2/ request — so proof that the POST came from this page has to travel in
// the cookie jar instead: the same random value in a SameSite=Strict __Host-
// cookie and in the form body. A page on another origin can do neither half.
function mintConsentToken(): string {
  const token =
    typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')

  // __Host- forbids a Domain attribute and demands Secure and Path=/, so only this
  // exact host can have set it. Short-lived: it is spent on the next click.
  document.cookie = `__Host-CT=${token}; Path=/; Secure; SameSite=Strict; Max-Age=600`

  return token
}

function handleAllow() {
  const fields: Record<string, string> = {
    client_id: props.params.client_id,
    redirect_uri: props.params.redirect_uri,
    response_type: props.params.response_type,
    consent_token: mintConsentToken(),
  }
  if (props.params.scope) fields.scope = props.params.scope
  if (props.params.state) fields.state = props.params.state
  if (props.params.access_type) fields.access_type = props.params.access_type

  // A real form POST, not a link. A GET would let any page that can make the
  // browser navigate record the consent — cookies travel with a navigation either
  // way — and the token above only rides along on a POST body.
  //
  // The browser follows the backend's redirect to redirect_uri on its own, so
  // there is nothing to read back here.
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = `${config.apiHost}/oauth2/consent`

  for (const [name, value] of Object.entries(fields)) {
    const input = document.createElement('input')
    input.type = 'hidden'
    input.name = name
    input.value = value
    form.appendChild(input)
  }

  document.body.appendChild(form)
  form.submit()
}

function handleDeny() {
  const uri = new URL(props.params.redirect_uri)
  uri.searchParams.set('error', 'access_denied')
  if (props.params.state) uri.searchParams.set('state', props.params.state)
  window.location.href = uri.toString()
}
</script>
