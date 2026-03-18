import { createI18n } from 'vue-i18n'
import { config } from '@/config'
import en from './en.json'
import ru from './ru.json'

export const i18n = createI18n({
  legacy: false,
  locale: config.defaultLocale,
  fallbackLocale: 'en',
  messages: { en, ru }
})
