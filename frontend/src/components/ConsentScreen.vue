<template>
  <div class="auth-card">
    <h2>{{ t('consent.title') }}</h2>

    <p style="text-align: center; margin-bottom: 1.25rem; color: var(--color-text-muted);">
      {{ t('consent.description', { app: params.client_id }) }}
    </p>

    <ul style="margin-bottom: 1.5rem; padding-left: 1.25rem; color: var(--color-text-muted); font-size: 0.875rem;">
      <li>{{ t('consent.scopeRead') }}</li>
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
import { useI18n } from 'vue-i18n'
import { config } from '@/config'
import type { AuthorizeParams } from '@/types'

const { t } = useI18n()

const props = defineProps<{
  params: AuthorizeParams
}>()

function handleAllow() {
  const query = new URLSearchParams()
  query.set('client_id', props.params.client_id)
  query.set('redirect_uri', props.params.redirect_uri)
  query.set('response_type', props.params.response_type)
  if (props.params.scope) query.set('scope', props.params.scope)
  if (props.params.state) query.set('state', props.params.state)
  if (props.params.access_type) query.set('access_type', props.params.access_type)

  // Redirect to backend — cookies are sent automatically
  window.location.href = `${config.apiHost}/oauth2/authorize?${query.toString()}`
}

function handleDeny() {
  const uri = new URL(props.params.redirect_uri)
  uri.searchParams.set('error', 'access_denied')
  if (props.params.state) uri.searchParams.set('state', props.params.state)
  window.location.href = uri.toString()
}
</script>
