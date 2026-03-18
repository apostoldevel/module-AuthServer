<template>
  <ConsentScreen v-if="authorizeParams" :params="authorizeParams" />
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuth } from '@/composables/useAuth'
import { parseAuthorizeParams, validateRedirectUri } from '@/composables/useOAuth'
import ConsentScreen from '@/components/ConsentScreen.vue'
import type { AuthorizeParams } from '@/types'

const router = useRouter()
const route = useRoute()
const { getSession } = useAuth()

const authorizeParams = ref<AuthorizeParams | null>(null)

onMounted(async () => {
  const query = route.query as Record<string, string>

  // 1. Parse and validate params
  const params = parseAuthorizeParams(query)
  if (!params) {
    router.replace({ path: '/error', query: { error: 'invalid_request' } })
    return
  }

  if (!validateRedirectUri(params.redirect_uri)) {
    router.replace({ path: '/error', query: { error: 'invalid_redirect' } })
    return
  }

  // 2. Check if user is logged in
  const session = await getSession()
  if (!session) {
    // Redirect to login, preserving all authorize params
    const loginQuery: Record<string, string> = { return: '/authorize' }
    for (const [key, value] of Object.entries(query)) {
      if (value) loginQuery[key] = value
    }
    router.replace({ path: '/login', query: loginQuery })
    return
  }

  // 3. Show consent screen
  authorizeParams.value = params
})
</script>
