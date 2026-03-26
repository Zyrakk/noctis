import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    outDir: '../internal/dashboard/static',
    emptyOutDir: true,
    rollupOptions: {
      input: 'index.html',
      external: [
        'react',
        'react-dom',
        'react-dom/client',
        'react/jsx-runtime',
        'react-router-dom',
        'recharts',
        'lucide-react',
      ],
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
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
