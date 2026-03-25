import React, { useState, useEffect, useCallback } from 'react'
import { AuthProvider, useAuth } from './context/AuthContext.jsx'
import Layout from './components/Layout.jsx'
import Landing from './pages/Landing.jsx'
import Login from './pages/Login.jsx'
import Overview from './pages/Overview.jsx'
import Findings from './pages/Findings.jsx'
import IOCs from './pages/IOCs.jsx'
import Sources from './pages/Sources.jsx'
import Graph from './pages/Graph.jsx'
import Correlations from './pages/Correlations.jsx'
import AnalyticalNotes from './pages/AnalyticalNotes.jsx'
import Briefs from './pages/Briefs.jsx'
import SystemStatus from './pages/SystemStatus.jsx'
import Vulnerabilities from './pages/Vulnerabilities.jsx'
import Query from './pages/Query.jsx'
import Intelligence from './pages/Intelligence.jsx'

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

function ProtectedRoute({ children, navigate }) {
  const { isAuthenticated } = useAuth()

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login')
    }
  }, [isAuthenticated, navigate])

  if (!isAuthenticated) return null
  return children
}

function AppRoutes() {
  const { path, navigate } = useRouter()

  // Public routes
  if (path === '/' || path === '/index.html') {
    return React.createElement(Landing, { navigate })
  }

  if (path === '/login') {
    return React.createElement(Login, { navigate })
  }

  // Protected dashboard routes
  const dashboardPages = {
    '/dashboard': Overview,
    '/dashboard/intelligence': Intelligence,
    '/dashboard/findings': Findings,
    '/dashboard/iocs': IOCs,
    '/dashboard/sources': Sources,
    '/dashboard/graph': Graph,
    '/dashboard/correlations': Correlations,
    '/dashboard/notes': AnalyticalNotes,
    '/dashboard/vulns': Vulnerabilities,
    '/dashboard/briefs': Briefs,
    '/dashboard/system': SystemStatus,
    '/dashboard/query': Query,
  }

  const PageComponent = dashboardPages[path]

  if (PageComponent) {
    return React.createElement(ProtectedRoute, { navigate },
      React.createElement(Layout, { currentPath: path, navigate },
        React.createElement(PageComponent, { navigate }),
      ),
    )
  }

  // 404 fallback - redirect to landing
  if (path.startsWith('/dashboard')) {
    return React.createElement(ProtectedRoute, { navigate },
      React.createElement(Layout, { currentPath: path, navigate },
        React.createElement(Overview, { navigate }),
      ),
    )
  }

  return React.createElement(Landing, { navigate })
}

export default function App() {
  return React.createElement(AuthProvider, null,
    React.createElement(AppRoutes),
  )
}
