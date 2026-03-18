<template>
  <form class="auth-card" @submit.prevent="handleSubmit">
    <h2>{{ t('register.title') }}</h2>

    <!-- Step 1: Email -->
    <template v-if="step === 'email'">
      <div class="form-group">
        <label>{{ t('register.email') }}</label>
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
        {{ submitting ? t('common.loading') : t('register.sendCode') }}
      </button>
    </template>

    <!-- Step 2: Verification code -->
    <template v-if="step === 'code'">
      <p style="text-align: center; margin-bottom: 1rem; color: var(--color-text-muted); font-size: 0.875rem;">
        {{ t('register.codeSent', { email: form.email }) }}
      </p>

      <div class="form-group">
        <label>{{ t('register.code') }}</label>
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
        {{ submitting ? t('common.loading') : t('register.verify') }}
      </button>
    </template>

    <!-- Step 3: Details -->
    <template v-if="step === 'details'">
      <div class="form-group">
        <label>{{ t('register.name') }}</label>
        <div style="display: flex; gap: 0.5rem;">
          <input
            ref="firstNameRef"
            v-model="form.firstName"
            type="text"
            class="form-input"
            :class="{ error: errors.firstName }"
            :placeholder="t('register.name')"
            autocomplete="given-name"
          />
          <input
            v-model="form.lastName"
            type="text"
            class="form-input"
            :class="{ error: errors.lastName }"
            autocomplete="family-name"
          />
        </div>
        <div v-if="errors.firstName" class="form-error">{{ errors.firstName }}</div>
      </div>

      <div class="form-group">
        <label>{{ t('register.password') }}</label>
        <input
          v-model="form.password"
          type="password"
          class="form-input"
          :class="{ error: errors.password }"
          autocomplete="new-password"
        />
        <div v-if="errors.password" class="form-error">{{ errors.password }}</div>
      </div>

      <div class="form-group">
        <label>{{ t('register.confirmPassword') }}</label>
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
        {{ submitting ? t('common.loading') : t('register.submit') }}
      </button>
    </template>

    <div class="auth-footer">
      {{ t('register.hasAccount') }}
      <router-link to="/login">{{ t('register.signIn') }}</router-link>
    </div>
  </form>
</template>

<script setup lang="ts">
import { ref, reactive, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter, useRoute } from 'vue-router'
import { useAuth } from '@/composables/useAuth'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const { checkIdentifier, requestVerificationCode, checkRegistrationCode, signUp, signIn } = useAuth()

const step = ref<'email' | 'code' | 'details'>('email')
const ticket = ref('')
const submitting = ref(false)

const emailRef = ref<HTMLInputElement | null>(null)
const codeRef = ref<HTMLInputElement | null>(null)
const firstNameRef = ref<HTMLInputElement | null>(null)

const form = reactive({
  email: '',
  code: '',
  firstName: '',
  lastName: '',
  password: '',
  confirmPassword: '',
})

const errors = reactive({
  email: '',
  code: '',
  firstName: '',
  lastName: '',
  password: '',
  confirmPassword: '',
  general: '',
})

function clearErrors() {
  errors.email = ''
  errors.code = ''
  errors.firstName = ''
  errors.lastName = ''
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
  } else {
    await handleDetailsStep()
  }
}

async function handleEmailStep() {
  const email = form.email.trim()
  if (!email) { errors.email = 'Required'; return }

  submitting.value = true
  try {
    const { exists } = await checkIdentifier(email)
    if (exists) {
      errors.email = t('register.emailExists')
      return
    }

    ticket.value = await requestVerificationCode(email)
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
    const result = await checkRegistrationCode(ticket.value, code)
    if (!result.result) {
      errors.code = result.message || 'Invalid code'
      return
    }

    step.value = 'details'
    await nextTick()
    firstNameRef.value?.focus()
  } catch (e: any) {
    errors.general = e.message
  } finally {
    submitting.value = false
  }
}

async function handleDetailsStep() {
  if (!form.firstName.trim()) { errors.firstName = 'Required'; return }
  if (!form.password) { errors.password = 'Required'; return }
  if (form.password !== form.confirmPassword) {
    errors.confirmPassword = 'Passwords do not match'
    return
  }

  submitting.value = true
  try {
    const email = form.email.trim()
    await signUp({
      username: email,
      password: form.password,
      name: { first: form.firstName.trim(), last: form.lastName.trim() },
      email,
    })

    await signIn(email, form.password)

    const returnTo = route.query.return as string
    if (returnTo) {
      router.push(returnTo)
    } else {
      window.location.href = '/'
    }
  } catch (e: any) {
    errors.general = e.message
  } finally {
    submitting.value = false
  }
}
</script>
