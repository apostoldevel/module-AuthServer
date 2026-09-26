export const config = {
  apiHost: import.meta.env.VITE_API_HOST || '',
  clientId: import.meta.env.VITE_CLIENT_ID || '',
  scope: import.meta.env.VITE_SCOPE || '',
  appTitle: import.meta.env.VITE_APP_TITLE || 'Apostol',
  appLogo: import.meta.env.VITE_APP_LOGO || '/assets/logo.svg',
  // The `type` the sign-up form sends to /api/v1/sign/up. Each project's
  // api.signup accepts its own set; 'cpo' is the value this screen always sent.
  signupType: import.meta.env.VITE_SIGNUP_TYPE || 'cpo',
} as const
