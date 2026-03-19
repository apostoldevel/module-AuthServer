<template>
  <div class="auth-card debug-page">
    <h2>{{ title }}</h2>

    <div v-if="loading" style="text-align: center; color: var(--color-text-muted);">
      {{ t('common.loading') }}
    </div>

    <template v-else-if="session">
      <p style="text-align: center; margin-bottom: 1rem; color: var(--color-success, #4caf50);">
        {{ t('debug.success') }}
      </p>

      <table class="debug-table">
        <tr v-if="tokenType">
          <td>token_type</td>
          <td>{{ tokenType }}</td>
        </tr>
        <tr v-if="session">
          <td>session</td>
          <td>{{ session }}</td>
        </tr>
        <tr v-if="expiresIn">
          <td>expires_in</td>
          <td>{{ expiresIn }}s</td>
        </tr>
        <tr v-if="state">
          <td>state</td>
          <td>{{ state }}</td>
        </tr>
        <tr v-if="accessToken">
          <td>access_token</td>
          <td class="token-cell">{{ accessToken }}</td>
        </tr>
        <tr v-if="refreshToken">
          <td>refresh_token</td>
          <td class="token-cell">{{ refreshToken }}</td>
        </tr>
      </table>
    </template>

    <template v-else-if="error">
      <p style="text-align: center; margin-bottom: 0.5rem; font-family: monospace; color: var(--color-text-muted);">
        {{ error }}
      </p>
      <p style="text-align: center; margin-bottom: 1rem; color: var(--color-text-muted);">
        {{ errorDescription }}
      </p>
    </template>

    <template v-else>
      <p style="text-align: center; color: var(--color-text-muted);">
        {{ t('debug.noData') }}
      </p>
    </template>

    <div class="auth-footer">
      <router-link to="/login">{{ t('error.backToLogin') }}</router-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

const { t } = useI18n()
const route = useRoute()

const loading = ref(true)
const accessToken = ref('')
const refreshToken = ref('')
const tokenType = ref('')
const expiresIn = ref('')
const session = ref('')
const state = ref('')
const error = ref('')
const errorDescription = ref('')

const title = ref('OAuth2 Debug')

onMounted(() => {
  // Parse from hash fragment (#access_token=...&session=...)
  const hash = window.location.hash.substring(1)
  const hashParams = new URLSearchParams(hash)

  // Also check query params (?code=...&error=...)
  const queryError = route.query.error as string
  const queryCode = route.query.code as string

  if (queryError) {
    error.value = queryError
    errorDescription.value = (route.query.error_description as string) || queryError
  } else if (hashParams.has('access_token') || hashParams.has('session')) {
    accessToken.value = hashParams.get('access_token') || ''
    refreshToken.value = hashParams.get('refresh_token') || ''
    tokenType.value = hashParams.get('token_type') || ''
    expiresIn.value = hashParams.get('expires_in') || ''
    session.value = hashParams.get('session') || ''
    state.value = hashParams.get('state') || ''
  } else if (queryCode && !queryError) {
    // Authorization code returned
    session.value = queryCode
    title.value = 'Authorization Code'
  }

  loading.value = false
})
</script>

<style scoped>
:global(#auth-app:has(.debug-page)) {
  max-width: 720px;
}
.debug-table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 1rem;
  font-size: 0.85rem;
}
.debug-table td {
  padding: 0.4rem 0.5rem;
  border-bottom: 1px solid var(--color-border, #333);
  vertical-align: top;
}
.debug-table td:first-child {
  font-family: monospace;
  white-space: nowrap;
  color: var(--color-text-muted);
  width: 1%;
}
.token-cell {
  word-break: break-all;
  font-family: monospace;
  font-size: 0.75rem;
}
</style>
