import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    outDir: '../internal/dashboard/static',
    emptyOutDir: true,
    rollupOptions: {
      input: 'index.html',
      external: [
        'react',
        'react-dom/client',
        'react/jsx-runtime',
        'react-router-dom',
        'recharts',
        'lucide-react',
        'd3-force',
      ],
      output: {
        entryFileNames: 'app.js',
        assetFileNames: '[name][extname]',
        format: 'es',
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:3000',
    },
  },
})
