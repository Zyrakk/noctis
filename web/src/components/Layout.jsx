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

const bottomNavItems = [
  { path: '/dashboard', label: 'Overview', shortLabel: 'Home', icon: LayoutDashboard },
  { path: '/dashboard/findings', label: 'Findings', shortLabel: 'Findings', icon: Search },
  { path: '/dashboard/iocs', label: 'IOCs', shortLabel: 'IOCs', icon: Shield },
  { path: '/dashboard/sources', label: 'Sources', shortLabel: 'Sources', icon: Globe },
  { path: '/dashboard/graph', label: 'Graph', shortLabel: 'Graph', icon: Network },
]

function isActive(itemPath, currentPath) {
  if (itemPath === '/dashboard') return currentPath === '/dashboard'
  return currentPath?.startsWith(itemPath)
}

export default function Layout({ children, currentPath, navigate }) {
  const { logout } = useAuth()
  const [mobileOpen, setMobileOpen] = React.useState(false)

  // Desktop sidebar (lg:translate-x-0, hidden on mobile unless hamburger opens it)
  const sidebar = React.createElement('aside', {
    className: `fixed top-0 left-0 h-screen w-52 bg-noctis-bg border-r border-noctis-border/50 flex flex-col z-50 transition-transform duration-200 ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`
  },
    // Logo
    React.createElement('div', {
      className: 'h-14 flex items-center justify-between px-5 border-b border-noctis-border/50'
    },
      React.createElement('div', { className: 'flex items-center' },
        React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple mr-2' }),
        React.createElement('span', {
          className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text'
        }, 'Noctis'),
      ),
      // Close button (mobile only)
      React.createElement('button', {
        onClick: () => setMobileOpen(false),
        className: 'p-1 cursor-pointer lg:hidden'
      },
        React.createElement(X, { className: 'w-5 h-5 text-noctis-muted' }),
      ),
    ),

    // Nav
    React.createElement('nav', { className: 'flex-1 py-3 px-3 space-y-0.5' },
      navItems.map(item =>
        React.createElement('button', {
          key: item.path,
          onClick: () => { navigate(item.path); setMobileOpen(false) },
          className: `w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium cursor-pointer transition-all duration-150 ${
            isActive(item.path, currentPath)
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

  // Overlay backdrop for mobile sidebar
  const overlay = mobileOpen && React.createElement('div', {
    className: 'fixed inset-0 bg-black/50 z-40 lg:hidden',
    onClick: () => setMobileOpen(false),
  })

  // Mobile top bar (lg:hidden)
  const topBar = React.createElement('header', {
    className: 'fixed top-0 left-0 right-0 h-14 bg-noctis-bg/95 backdrop-blur-sm border-b border-noctis-border/50 flex items-center justify-between px-4 z-40 lg:hidden'
  },
    // Left: logo
    React.createElement('div', { className: 'flex items-center' },
      React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple mr-2' }),
      React.createElement('span', {
        className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text'
      }, 'Noctis'),
    ),
    // Right: hamburger
    React.createElement('button', {
      onClick: () => setMobileOpen(true),
      className: 'p-2 cursor-pointer rounded hover:bg-noctis-surface/50 transition-colors',
      'aria-label': 'Open menu',
    },
      React.createElement(Menu, { className: 'w-5 h-5 text-noctis-muted' }),
    ),
  )

  // Mobile bottom navigation (lg:hidden)
  const bottomNav = React.createElement('nav', {
    className: 'fixed bottom-0 left-0 right-0 bg-noctis-bg border-t border-noctis-border/50 z-40 lg:hidden',
    style: { paddingBottom: 'max(0.5rem, env(safe-area-inset-bottom))' },
  },
    React.createElement('div', { className: 'flex items-stretch' },
      bottomNavItems.map(item => {
        const active = isActive(item.path, currentPath)
        return React.createElement('button', {
          key: item.path,
          onClick: () => navigate(item.path),
          className: `flex-1 flex flex-col items-center justify-center py-2 cursor-pointer transition-colors duration-150 ${
            active ? 'text-noctis-purple' : 'text-noctis-dim'
          }`,
          style: { minHeight: '44px' },
        },
          React.createElement(item.icon, {
            className: `w-5 h-5 ${active ? 'text-noctis-purple' : 'text-noctis-dim'}`,
          }),
          React.createElement('span', {
            className: `text-[10px] font-medium mt-0.5 ${active ? 'text-noctis-purple' : 'text-noctis-dim'}`,
          }, item.shortLabel),
        )
      })
    )
  )

  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg' },
    // Mobile top bar
    topBar,
    // Overlay
    overlay,
    // Sidebar (desktop visible, mobile via hamburger)
    sidebar,
    // Main content
    React.createElement('main', {
      className: 'ml-0 lg:ml-52 min-h-screen pt-14 lg:pt-0 pb-20 lg:pb-0'
    },
      React.createElement('div', { className: 'p-4 lg:p-6' }, children),
    ),
    // Mobile bottom nav
    bottomNav,
  )
}
