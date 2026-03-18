export const config = {
  apiHost: import.meta.env.VITE_API_HOST || '',
  clientId: import.meta.env.VITE_CLIENT_ID || '',
  scope: import.meta.env.VITE_SCOPE || '',
  appTitle: import.meta.env.VITE_APP_TITLE || 'Apostol',
  appLogo: import.meta.env.VITE_APP_LOGO || '/assets/logo.svg',
  googleClientId: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
  defaultLocale: import.meta.env.VITE_DEFAULT_LOCALE || 'en',
} as const
