import { createI18n } from 'vue-i18n'
import en from './en.json'
import ru from './ru.json'
import fr from './fr.json'
import es from './es.json'
import de from './de.json'
import it from './it.json'
import cs from './cs.json'
import sk from './sk.json'

const supportedLocales = ['en', 'ru', 'fr', 'es', 'de', 'it', 'cs', 'sk'] as const

function detectLocale(): string {
  const langs = navigator.languages ?? [navigator.language]
  for (const lang of langs) {
    const code = lang.split('-')[0].toLowerCase()
    if ((supportedLocales as readonly string[]).includes(code)) return code
  }
  return 'en'
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  messages: { en, ru, fr, es, de, it, cs, sk }
})
