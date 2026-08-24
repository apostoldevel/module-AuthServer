<template>
  <form class="auth-card" @submit.prevent="handleSubmit">
    <h2>{{ t('login.title') }}</h2>

    <div class="form-group">
      <label>{{ t('login.email') }}</label>
      <input
        v-model="form.username"
        type="text"
        class="form-input"
        :class="{ error: errors.username }"
        autocomplete="username"
        autofocus
      />
      <div v-if="errors.username" class="form-error">{{ errors.username }}</div>
    </div>

    <div class="form-group">
      <label>{{ t('login.password') }}</label>
      <input
        v-model="form.password"
        type="password"
        class="form-input"
        :class="{ error: errors.password }"
        autocomplete="current-password"
      />
      <div v-if="errors.password" class="form-error">{{ errors.password }}</div>
    </div>

    <div v-if="errors.general" class="form-error" style="margin-bottom: 1rem; text-align: center;">
      {{ errors.general }}
    </div>

    <button type="submit" class="btn btn-primary" :disabled="loading">
      {{ loading ? t('common.loading') : t('login.submit') }}
    </button>

    <template v-if="providers.length">
      <div class="divider">{{ t('common.or') }}</div>

      <ProviderButton
        v-for="p in providers"
        :key="p.provider"
        :provider="p"
        :loading="loading"
      />
    </template>

    <div class="auth-footer">
      <router-link to="/recover">{{ t('login.forgot') }}</router-link>
    </div>

    <div class="auth-footer">
      {{ t('login.noAccount') }}
      <router-link to="/register">{{ t('login.register') }}</router-link>
    </div>
  </form>
</template>

<script setup lang="ts">
import { reactive, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter, useRoute } from 'vue-router'
import { useAuth } from '@/composables/useAuth'
import { useProviders } from '@/composables/useProviders'
import ProviderButton from './ProviderButton.vue'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const { signIn, checkIdentifier, loading } = useAuth()

// External sign-in providers, fetched from the backend. Empty until loaded and
// empty when none are configured — the divider and buttons stay hidden in both
// cases (v-if on providers.length), so the password form is never crowded by an
// "or" rule with nothing under it.
const { providers, load: loadProviders } = useProviders()
onMounted(loadProviders)

const form = reactive({ username: '', password: '' })
const errors = reactive({ username: '', password: '', general: '' })

async function handleSubmit() {
  errors.username = ''
  errors.password = ''
  errors.general = ''

  if (!form.username.trim()) { errors.username = 'Required'; return }
  if (!form.password) { errors.password = 'Required'; return }

  try {
    let username = form.username.trim()

    // Resolve email/phone to username
    if (username.includes('@') || /^\+?\d{7,}$/.test(username)) {
      const { exists, username: resolved } = await checkIdentifier(username)
      if (!exists || !resolved) {
        errors.username = t('login.error')
        return
      }
      username = resolved
    }

    await signIn(username, form.password)

    // Redirect to return URL or authorize page
    const returnTo = route.query.return as string
    if (returnTo) {
      router.push(returnTo + (route.query.client_id ? `?${new URLSearchParams(route.query as Record<string, string>)}` : ''))
    } else {
      // If no return URL, redirect to a safe default
      window.location.href = '/'
    }
  } catch (e: any) {
    errors.general = e.message || t('login.error')
  }
}
</script>
