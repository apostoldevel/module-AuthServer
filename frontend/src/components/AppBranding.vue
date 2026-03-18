<template>
  <div class="branding">
    <img :src="config.appLogo" :alt="config.appTitle" class="branding-logo" />
    <h1 class="branding-title">{{ config.appTitle }}</h1>
  </div>
</template>

<script setup lang="ts">
import { config } from '@/config'
</script>

<style scoped>
.branding {
  text-align: center;
  margin-bottom: 1.5rem;
}
.branding-logo {
  width: 48px;
  height: 48px;
  margin-bottom: 0.5rem;
}
.branding-title {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--color-text);
}
</style>
