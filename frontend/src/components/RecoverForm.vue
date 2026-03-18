<template>
  <form class="auth-card" @submit.prevent="handleSubmit">
    <h2>{{ t('recover.title') }}</h2>

    <!-- Step 1: Email -->
    <template v-if="step === 'email'">
      <div class="form-group">
        <label>{{ t('recover.email') }}</label>
        <input
          ref="emailRef"
          v-model="form.email"
          type="email"
          class="form-input"
          :class="{ error: errors.email }"
          autocomplete="email"
          autofocus
        />
        <div v-if="errors.email" class="form-error">{{ errors.email }}</div>
      </div>

      <div v-if="errors.general" class="form-error" style="margin-bottom: 1rem; text-align: center;">
        {{ errors.general }}
      </div>

      <button type="submit" class="btn btn-primary" :disabled="submitting">
        {{ submitting ? t('common.loading') : t('recover.sendCode') }}
      </button>
    </template>

    <!-- Step 2: Verification code -->
    <template v-if="step === 'code'">
      <div class="form-group">
        <label>{{ t('recover.code') }}</label>
        <input
          ref="codeRef"
          v-model="form.code"
          type="text"
          inputmode="numeric"
          maxlength="6"
          class="form-input"
          :class="{ error: errors.code }"
          autocomplete="one-time-code"
        />
        <div v-if="errors.code" class="form-error">{{ errors.code }}</div>
      </div>

      <div v-if="errors.general" class="form-error" style="margin-bottom: 1rem; text-align: center;">
        {{ errors.general }}
      </div>

      <button type="submit" class="btn btn-primary" :disabled="submitting">
        {{ submitting ? t('common.loading') : t('recover.verify') }}
      </button>
    </template>

    <!-- Step 3: New password -->
    <template v-if="step === 'password'">
      <div class="form-group">
        <label>{{ t('recover.newPassword') }}</label>
        <input
          ref="passwordRef"
          v-model="form.password"
          type="password"
          class="form-input"
          :class="{ error: errors.password }"
          autocomplete="new-password"
        />
        <div v-if="errors.password" class="form-error">{{ errors.password }}</div>
      </div>

      <div class="form-group">
        <label>{{ t('recover.confirmPassword') }}</label>
        <input
          v-model="form.confirmPassword"
          type="password"
          class="form-input"
          :class="{ error: errors.confirmPassword }"
          autocomplete="new-password"
        />
        <div v-if="errors.confirmPassword" class="form-error">{{ errors.confirmPassword }}</div>
      </div>

      <div v-if="errors.general" class="form-error" style="margin-bottom: 1rem; text-align: center;">
        {{ errors.general }}
      </div>

      <button type="submit" class="btn btn-primary" :disabled="submitting">
        {{ submitting ? t('common.loading') : t('recover.submit') }}
      </button>
    </template>

    <!-- Success -->
    <template v-if="step === 'success'">
      <p style="text-align: center; margin-bottom: 1rem; color: var(--color-text-muted);">
        {{ t('recover.success') }}
      </p>
    </template>

    <div class="auth-footer">
      <router-link to="/login">{{ t('recover.backToLogin') }}</router-link>
    </div>
  </form>
</template>

<script setup lang="ts">
import { ref, reactive, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuth } from '@/composables/useAuth'
import { config } from '@/config'

const { t } = useI18n()
const { getServiceToken } = useAuth()

const step = ref<'email' | 'code' | 'password' | 'success'>('email')
const ticket = ref('')
const submitting = ref(false)

const emailRef = ref<HTMLInputElement | null>(null)
const codeRef = ref<HTMLInputElement | null>(null)
const passwordRef = ref<HTMLInputElement | null>(null)

const form = reactive({
  email: '',
  code: '',
  password: '',
  confirmPassword: '',
})

const errors = reactive({
  email: '',
  code: '',
  password: '',
  confirmPassword: '',
  general: '',
})

function clearErrors() {
  errors.email = ''
  errors.code = ''
  errors.password = ''
  errors.confirmPassword = ''
  errors.general = ''
}

async function handleSubmit() {
  clearErrors()

  if (step.value === 'email') {
    await handleEmailStep()
  } else if (step.value === 'code') {
    await handleCodeStep()
  } else if (step.value === 'password') {
    await handlePasswordStep()
  }
}

async function handleEmailStep() {
  const email = form.email.trim()
  if (!email) { errors.email = 'Required'; return }

  submitting.value = true
  try {
    const token = await getServiceToken()
    const resp = await fetch(`${config.apiHost}/api/v1/user/password/recovery`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ identifier: email }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      throw new Error(err.error_description || err.error?.message || 'Failed to send recovery code')
    }
    const data = await resp.json()
    ticket.value = data.ticket

    step.value = 'code'
    await nextTick()
    codeRef.value?.focus()
  } catch (e: any) {
    errors.general = e.message
  } finally {
    submitting.value = false
  }
}

async function handleCodeStep() {
  const code = form.code.trim()
  if (!code) { errors.code = 'Required'; return }

  submitting.value = true
  try {
    const token = await getServiceToken()
    const resp = await fetch(`${config.apiHost}/api/v1/user/password/recovery/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ticket: ticket.value, code }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      throw new Error(err.error_description || err.error?.message || 'Invalid code')
    }

    step.value = 'password'
    await nextTick()
    passwordRef.value?.focus()
  } catch (e: any) {
    errors.general = e.message
  } finally {
    submitting.value = false
  }
}

async function handlePasswordStep() {
  if (!form.password) { errors.password = 'Required'; return }
  if (form.password !== form.confirmPassword) {
    errors.confirmPassword = 'Passwords do not match'
    return
  }

  submitting.value = true
  try {
    const token = await getServiceToken()
    const resp = await fetch(`${config.apiHost}/api/v1/user/password/reset`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ticket: ticket.value,
        code: form.code.trim(),
        password: form.password,
      }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}))
      throw new Error(err.error_description || err.error?.message || 'Failed to reset password')
    }

    step.value = 'success'
  } catch (e: any) {
    errors.general = e.message
  } finally {
    submitting.value = false
  }
}
</script>
