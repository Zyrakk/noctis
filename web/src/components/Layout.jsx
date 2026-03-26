import React from 'react'
import { useAuth } from '../context/AuthContext.jsx'
import {
  LayoutDashboard, Search, Shield, Globe, Network, LogOut, Activity, Menu, X, MonitorCheck, FileText, GitBranch, BookOpen, Bug, MessageSquare, Radar, ChevronsLeft, ChevronsRight
} from 'lucide-react'

const navItems = [
  { path: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { path: '/dashboard/intelligence', label: 'Intelligence', icon: Radar },
  { path: '/dashboard/findings', label: 'Findings', icon: Search },
  { path: '/dashboard/iocs', label: 'IOC Explorer', icon: Shield },
  { path: '/dashboard/sources', label: 'Sources', icon: Globe },
  { path: '/dashboard/graph', label: 'Entity Graph', icon: Network },
  { path: '/dashboard/correlations', label: 'Correlations', icon: GitBranch },
  { path: '/dashboard/notes', label: 'Notes', icon: FileText },
  { path: '/dashboard/vulns', label: 'Vulnerabilities', icon: Bug },
  { path: '/dashboard/briefs', label: 'Briefs', icon: BookOpen },
  { path: '/dashboard/query', label: 'Query', icon: MessageSquare },
  { path: '/dashboard/system', label: 'System', icon: MonitorCheck },
]

function isActive(itemPath, currentPath) {
  if (itemPath === '/dashboard') return currentPath === '/dashboard'
  return currentPath?.startsWith(itemPath)
}

export default function Layout({ children, currentPath, navigate }) {
  const { logout } = useAuth()
  const [mobileOpen, setMobileOpen] = React.useState(false)
  const [collapsed, setCollapsed] = React.useState(() => {
    try { return localStorage.getItem('noctis-sidebar-collapsed') === 'true' } catch { return false }
  })
  const toggleCollapsed = () => {
    setCollapsed(prev => {
      const next = !prev
      try { localStorage.setItem('noctis-sidebar-collapsed', String(next)) } catch {}
      return next
    })
  }

  const sidebar = React.createElement('aside', {
    className: `fixed top-0 left-0 h-screen w-52 ${collapsed ? 'lg:w-14' : ''} bg-noctis-bg border-r border-white/[0.08] flex flex-col z-50 overflow-hidden transition-all duration-200 ease-out ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`
  },
    // Logo
    React.createElement('div', {
      className: `h-14 flex items-center justify-between px-5 border-b border-white/[0.08] ${collapsed ? 'lg:justify-center lg:px-2' : ''}`
    },
      React.createElement('div', { className: `flex items-center ${collapsed ? 'lg:justify-center' : ''}` },
        React.createElement(Activity, { className: `w-4 h-4 text-noctis-purple ${collapsed ? 'lg:mr-0' : 'mr-2'}` }),
        React.createElement('span', {
          className: `font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text ${collapsed ? 'lg:hidden' : ''}`
        }, 'Noctis'),
      ),
      React.createElement('button', {
        onClick: () => setMobileOpen(false),
        className: 'p-1 cursor-pointer lg:hidden'
      },
        React.createElement(X, { className: 'w-5 h-5 text-noctis-muted' }),
      ),
    ),

    // Nav
    React.createElement('nav', { className: `flex-1 py-3 space-y-0.5 overflow-y-auto ${collapsed ? 'lg:px-1.5 px-3' : 'px-3'}` },
      navItems.map(item => {
        const active = isActive(item.path, currentPath)
        return React.createElement('button', {
          key: item.path,
          onClick: () => { navigate(item.path); setMobileOpen(false) },
          title: item.label,
          className: `w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium cursor-pointer whitespace-nowrap transition-all duration-150 ${collapsed ? 'lg:justify-center lg:px-0 lg:gap-0' : ''} ${
            active
              ? `bg-noctis-surface text-noctis-text border-l-2 border-noctis-purple pl-[10px] ${collapsed ? 'lg:pl-0 lg:border-l-0 lg:bg-noctis-purple/10' : ''}`
              : 'text-noctis-muted hover:text-noctis-text hover:bg-noctis-surface/50'
          }`
        },
          React.createElement(item.icon, { className: `w-3.5 h-3.5 flex-shrink-0 ${active && collapsed ? 'lg:text-noctis-purple-light' : ''}` }),
          React.createElement('span', {
            className: collapsed ? 'lg:hidden' : ''
          }, item.label),
        )
      })
    ),

    // Collapse toggle (desktop only)
    React.createElement('div', {
      className: 'hidden lg:flex px-3 py-1',
    },
      React.createElement('button', {
        onClick: toggleCollapsed,
        className: `w-full flex items-center py-2 rounded-md text-xs font-medium text-noctis-dim hover:text-noctis-muted hover:bg-noctis-surface/50 cursor-pointer whitespace-nowrap transition-colors duration-150 ${collapsed ? 'justify-center px-0' : 'gap-2.5 px-3'}`,
        title: collapsed ? 'Expand sidebar' : 'Collapse sidebar',
      },
        React.createElement(collapsed ? ChevronsRight : ChevronsLeft, { className: 'w-3.5 h-3.5 flex-shrink-0' }),
        !collapsed && 'Collapse',
      ),
    ),

    // Logout
    React.createElement('div', { className: `border-t border-white/[0.08] ${collapsed ? 'lg:p-1.5 p-3' : 'p-3'}` },
      React.createElement('button', {
        onClick: logout,
        title: 'Logout',
        className: `w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium text-noctis-dim hover:text-red-400 hover:bg-red-500/5 cursor-pointer whitespace-nowrap transition-colors duration-200 ${collapsed ? 'lg:justify-center lg:px-0 lg:gap-0' : ''}`
      },
        React.createElement(LogOut, { className: 'w-3.5 h-3.5' }),
        React.createElement('span', { className: collapsed ? 'lg:hidden' : '' }, 'Logout'),
      )
    ),
  )

  const overlay = mobileOpen && React.createElement('div', {
    className: 'fixed inset-0 bg-black/50 z-40 lg:hidden',
    onClick: () => setMobileOpen(false),
  })

  const topBar = React.createElement('header', {
    className: 'fixed top-0 left-0 right-0 h-14 bg-noctis-bg/95 backdrop-blur-sm border-b border-white/[0.08] flex items-center justify-between px-4 z-40 lg:hidden'
  },
    React.createElement('div', { className: 'flex items-center' },
      React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple mr-2' }),
      React.createElement('span', {
        className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text'
      }, 'Noctis'),
    ),
    React.createElement('button', {
      onClick: () => setMobileOpen(true),
      className: 'p-2 cursor-pointer rounded-md hover:bg-noctis-surface/50 transition-colors',
      'aria-label': 'Open menu',
    },
      React.createElement(Menu, { className: 'w-5 h-5 text-noctis-muted' }),
    ),
  )

  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg' },
    topBar,
    overlay,
    sidebar,
    React.createElement('main', {
      className: `ml-0 ${collapsed ? 'lg:ml-14' : 'lg:ml-52'} min-h-screen pt-14 lg:pt-0 transition-[margin] duration-200`
    },
      React.createElement('div', { key: currentPath, className: 'p-3 lg:p-6 animate-page-enter' }, children),
    ),
  )
}
