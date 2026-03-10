import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: './',   // ← CRITICAL: Chrome extensions need relative URLs, not absolute /
  build: {
    rollupOptions: {
      input: {
        popup: 'index.html',
        dashboard: 'dashboard.html',
        background: 'src/background/index.ts',
        content: 'src/content/index.ts'
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: '[name].[ext]'
      }
    }
  }
})


