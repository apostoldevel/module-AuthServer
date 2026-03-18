import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': resolve(__dirname, 'src') }
  },
  server: {
    port: 3100,
    proxy: {
      '/oauth2': { target: 'http://localhost:8080', changeOrigin: true },
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: undefined  // keep it simple — single chunk for small app
      }
    }
  }
})
