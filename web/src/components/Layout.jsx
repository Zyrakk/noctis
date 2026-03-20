import React from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import {
  LayoutDashboard, Search, Shield, Globe, Network, LogOut, Activity
} from 'lucide-react'

const navItems = [
  { path: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { path: '/dashboard/findings', label: 'Findings', icon: Search },
  { path: '/dashboard/iocs', label: 'IOC Explorer', icon: Shield },
  { path: '/dashboard/sources', label: 'Sources', icon: Globe },
  { path: '/dashboard/graph', label: 'Entity Graph', icon: Network },
]

export default function Layout({ children, currentPath, navigate }) {
  const { logout } = useAuth()

  const sidebar = React.createElement('aside', {
    className: 'fixed top-0 left-0 h-screen w-56 bg-noctis-surface border-r border-noctis-border flex flex-col z-30'
  },
    // Logo
    React.createElement('div', {
      className: 'h-16 flex items-center px-5 border-b border-noctis-border'
    },
      React.createElement(Activity, { className: 'w-5 h-5 text-noctis-purple mr-2' }),
      React.createElement('span', {
        className: 'font-heading font-bold text-lg tracking-tight text-noctis-text'
      }, 'NOCTIS'),
    ),

    // Nav
    React.createElement('nav', { className: 'flex-1 py-4 px-3 space-y-1' },
      navItems.map(item =>
        React.createElement('button', {
          key: item.path,
          onClick: () => navigate(item.path),
          className: `w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium cursor-pointer transition-colors duration-200 ${
            currentPath === item.path || (item.path !== '/dashboard' && currentPath?.startsWith(item.path))
              ? 'bg-noctis-purple/15 text-noctis-purple-light'
              : 'text-noctis-muted hover:text-noctis-text hover:bg-noctis-surface2'
          }`
        },
          React.createElement(item.icon, { className: 'w-4 h-4 flex-shrink-0' }),
          item.label,
        )
      )
    ),

    // Logout
    React.createElement('div', { className: 'p-3 border-t border-noctis-border' },
      React.createElement('button', {
        onClick: logout,
        className: 'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-noctis-dim hover:text-red-400 hover:bg-red-500/10 cursor-pointer transition-colors duration-200'
      },
        React.createElement(LogOut, { className: 'w-4 h-4' }),
        'Logout',
      )
    ),
  )

  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg' },
    sidebar,
    React.createElement('main', { className: 'ml-56 min-h-screen' },
      React.createElement('div', { className: 'p-6' }, children)
    ),
  )
}
