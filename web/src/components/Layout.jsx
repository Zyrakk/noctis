import React from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import {
  LayoutDashboard, Search, Shield, Globe, Network, LogOut, Activity, Menu, X
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
  const [mobileOpen, setMobileOpen] = React.useState(false)

  const sidebar = React.createElement('aside', {
    className: `fixed top-0 left-0 h-screen w-52 bg-noctis-bg border-r border-noctis-border/50 flex flex-col z-30 transition-transform duration-200 ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`
  },
    // Logo
    React.createElement('div', {
      className: 'h-14 flex items-center px-5 border-b border-noctis-border/50'
    },
      React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple mr-2' }),
      React.createElement('span', {
        className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text'
      }, 'Noctis'),
    ),

    // Nav
    React.createElement('nav', { className: 'flex-1 py-3 px-3 space-y-0.5' },
      navItems.map(item =>
        React.createElement('button', {
          key: item.path,
          onClick: () => { navigate(item.path); setMobileOpen(false) },
          className: `w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium cursor-pointer transition-all duration-150 ${
            currentPath === item.path || (item.path !== '/dashboard' && currentPath?.startsWith(item.path))
              ? 'bg-noctis-surface text-noctis-text border-l-2 border-noctis-purple pl-[11px]'
              : 'text-noctis-muted hover:text-noctis-text hover:bg-noctis-surface/50'
          }`
        },
          React.createElement(item.icon, { className: 'w-3.5 h-3.5 flex-shrink-0' }),
          item.label,
        )
      )
    ),

    // Logout
    React.createElement('div', { className: 'p-3 border-t border-noctis-border/50' },
      React.createElement('button', {
        onClick: logout,
        className: 'w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium text-noctis-dim hover:text-red-400 hover:bg-red-500/5 cursor-pointer transition-colors duration-200'
      },
        React.createElement(LogOut, { className: 'w-3.5 h-3.5' }),
        'Logout',
      )
    ),
  )

  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg' },
    mobileOpen && React.createElement('div', {
      className: 'fixed inset-0 bg-black/50 z-20 lg:hidden',
      onClick: () => setMobileOpen(false),
    }),
    sidebar,
    React.createElement('main', { className: 'ml-0 lg:ml-52 min-h-screen' },
      React.createElement('div', { className: 'lg:hidden flex items-center gap-3 px-4 py-3 border-b border-noctis-border/50' },
        React.createElement('button', {
          onClick: () => setMobileOpen(true),
          className: 'p-1 cursor-pointer'
        },
          React.createElement(Menu, { className: 'w-5 h-5 text-noctis-muted' }),
        ),
        React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple' }),
        React.createElement('span', { className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text' }, 'Noctis'),
      ),
      React.createElement('div', { className: 'p-4 lg:p-6' }, children),
    ),
  )
}
