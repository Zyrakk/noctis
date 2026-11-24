import React, { useState, useEffect, useCallback } from 'react'
import Presentation from './presentation/Presentation.jsx'
import V2App from './v2/App.jsx'
import PublicProduct from './v2/Demo.jsx'

// Simple client-side router (avoids react-router CDN version issues)
function useRouter() {
  const [path, setPath] = useState(window.location.pathname)

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  const navigate = useCallback((to) => {
    window.history.pushState({}, '', to)
    setPath(to)
  }, [])

  return { path, navigate }
}

function PublicPresentation() {
  const { path, navigate } = useRouter()
  useEffect(() => { document.title = 'Noctis — Presentation' }, [])
  return React.createElement(Presentation, { path, navigate })
}

export default function App() {
  if (window.location.pathname === '/' || window.location.pathname === '/demo' || window.location.pathname.startsWith('/demo/')) {
    return React.createElement(PublicProduct)
  }
  if (window.location.pathname === '/v2' || window.location.pathname.startsWith('/v2/')) {
    return React.createElement(V2App)
  }
  if (window.location.pathname === '/presentation' || window.location.pathname.startsWith('/presentation/')) {
    return React.createElement(PublicPresentation)
  }
  const p = window.location.pathname
  if (p === '/login') { window.location.replace('/v2/login'); return null }
  if (p === '/dashboard' || p.startsWith('/dashboard/')) { window.location.replace('/v2/today'); return null }
  window.location.replace('/')
  return null
}
