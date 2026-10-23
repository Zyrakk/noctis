import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    outDir: '../internal/webassets/static',
    emptyOutDir: true,
    rollupOptions: {
      input: 'index.html',
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
        format: 'es',
      },
    },
  },
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': 'http://localhost:3000',
    },
  },
  preview: { host: '127.0.0.1' },
})
