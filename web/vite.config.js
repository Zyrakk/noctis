import { defineConfig } from 'vite'

// Public landing and private application are separate documents, including in dev.
function applicationRoutes() {
  const middleware = (req, _res, next) => {
    const pathname = (req.url || '/').split('?')[0]
    if (pathname !== '/' && pathname !== '/index.html' && !pathname.startsWith('/api/') && !pathname.startsWith('/@') && !pathname.startsWith('/src/') && !pathname.startsWith('/node_modules/') && !pathname.split('/').pop().includes('.')) {
      req.url = '/app.html' + ((req.url || '').includes('?') ? '?' + req.url.split('?')[1] : '')
    }
    next()
  }
  return {name:'noctis-application-routes',configureServer(server){server.middlewares.use(middleware)},configurePreviewServer(server){server.middlewares.use(middleware)}}
}

export default defineConfig({
  plugins: [applicationRoutes()],
  build: {
    outDir: '../internal/webassets/static',
    emptyOutDir: true,
    rollupOptions: {
      input: { landing: 'index.html', app: 'app.html' },
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
