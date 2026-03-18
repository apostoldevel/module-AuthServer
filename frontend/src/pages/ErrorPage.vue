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
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

const { t } = useI18n()
const route = useRoute()

const errorCode = computed(() => (route.query.code as string) || (route.query.error as string) || '')

const errorDescription = computed(() => {
  const desc = route.query.error_description as string
  if (desc) return decodeURIComponent(desc)
  const error = route.query.error as string
  if (error) return error
  return t('error.generic')
})
</script>
