import { createRouter, createWebHistory } from 'vue-router'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/pages/LoginPage.vue') },
    { path: '/register', name: 'register', component: () => import('@/pages/RegisterPage.vue') },
    { path: '/recover', name: 'recover', component: () => import('@/pages/RecoverPage.vue') },
    { path: '/authorize', name: 'authorize', component: () => import('@/pages/AuthorizePage.vue') },
    { path: '/error', name: 'error', component: () => import('@/pages/ErrorPage.vue') },
    { path: '/', redirect: '/login' },
  ]
})
