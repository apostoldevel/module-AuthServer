<template>
  <div class="auth-card">
    <h2>{{ t('error.title') }}</h2>

    <p v-if="errorCode" style="text-align: center; margin-bottom: 0.5rem; font-family: monospace; color: var(--color-text-muted);">
      {{ errorCode }}
    </p>

    <p style="text-align: center; margin-bottom: 1.5rem; color: var(--color-text-muted);">
      {{ errorDescription }}
    </p>

    <div class="auth-footer">
      <router-link to="/login">{{ t('error.backToLogin') }}</router-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

const { t, te, locale } = useI18n()
const route = useRoute()

// Both values, but only after validation — never raw. Both come from the query string,
// i.e. from whoever crafted the link, so printing them unchecked turns this page into a
// text-phishing surface on our own origin ("Session expired. Call +7…" under our logo).
// Vue escapes markup, so it is not XSS, but T048 forbids arbitrary prose here for exactly
// this reason, and a raw `code` reopens it. So: the numeric status only when it really is
// one (three digits, 100–599 — a phone number or a sentence fits neither), and the OAuth
// code only when it is one we know, by the same te() check the message uses. An unknown
// or array-valued code prints nothing; its detail is in console.warn instead (T050 review).
const errorCode = computed(() => {
  const parts: string[] = []
  const status = route.query.code
  if (typeof status === 'string' && /^[1-5]\d\d$/.test(status)) parts.push(status)
  const error = route.query.error
  if (typeof error === 'string' && te(`error.codes.${error}`, locale.value)) parts.push(error)
  return parts.join(' ')
})

// Localise by the error CODE, not by the server's error_description. That description
// arrives as English prose from AuthServer.cpp and cannot be translated on the front —
// it is exactly what showed English text on a Russian page (T050). A code we know is shown
// in the active locale; anything else — unknown or array-valued — falls to the generic
// message, still localised. The raw prose is deliberately never shown. te() is checked
// against the active locale, not the en fallback, so a locale without these keys shows its
// own generic rather than English.
const errorDescription = computed(() => {
  const error = route.query.error
  const key = typeof error === 'string' ? `error.codes.${error}` : ''
  return key && te(key, locale.value) ? t(key) : t('error.generic')
})

// The description carried a distinction the code alone does not (one code, several
// server-side causes). It must not reach the screen — that is the whole point of T048 —
// but dropping it entirely would leave support nothing to go on. Keep it in the console,
// never in the DOM. The authoritative record is the AuthServer log; this is the crumb a
// user can read back over the phone.
onMounted(() => {
  const { code, error, error_description } = route.query
  if (error || error_description) {
    // eslint-disable-next-line no-console
    console.warn('[auth] sign-in refused', { code, error, error_description })
  }
})
</script>
