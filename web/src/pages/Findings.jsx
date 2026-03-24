import React, { useState, useEffect, useCallback } from 'react'
import { useApi, apiFetch } from '../hooks/useApi.js'
import { useAuth } from '../context/AuthContext.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { Search, X, ChevronLeft, ChevronRight, Filter, Shield, ExternalLink } from 'lucide-react'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const PAGE_SIZE = 30

export default function Findings() {
  const { apiKey } = useAuth()
  const [filters, setFilters] = useState({ category: '', subCategory: '', severity: '', source: '', q: '' })
  const [page, setPage] = useState(0)
  const [selectedId, setSelectedId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [copiedIOC, setCopiedIOC] = useState(null)
  const [filtersOpen, setFiltersOpen] = useState(false)

  // Swipe-to-dismiss state for detail panel
  const [panelDragY, setPanelDragY] = React.useState(0)
  const [panelDragging, setPanelDragging] = React.useState(false)
  const panelTouchStart = React.useRef(null)

  // Swipe-to-dismiss state for filter sheet
  const [sheetDragY, setSheetDragY] = React.useState(0)
  const [sheetDragging, setSheetDragging] = React.useState(false)
  const sheetTouchStart = React.useRef(null)

  const params = new URLSearchParams()
  if (filters.category) params.set('category', filters.category)
  if (filters.subCategory) params.set('sub_category', filters.subCategory)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.source) params.set('source', filters.source)
  if (filters.q) params.set('q', filters.q)
  params.set('limit', PAGE_SIZE)
  params.set('offset', page * PAGE_SIZE)

  const { data, loading, error } = useApi(`/api/findings?${params.toString()}`)
  const { data: categories } = useApi('/api/categories')
  const { data: subcategories } = useApi('/api/subcategories')

  const findings = data?.findings || []
  const total = data?.total || 0
  const totalPages = Math.ceil(total / PAGE_SIZE)

  const loadDetail = useCallback(async (id) => {
    setSelectedId(id)
    setDetailLoading(true)
    try {
      const d = await apiFetch(apiKey, `/api/findings/${id}`)
      setDetail(d)
    } catch {
      setDetail(null)
    }
    setDetailLoading(false)
  }, [apiKey])

  const updateFilter = (key, value) => {
    setFilters(f => ({ ...f, [key]: value }))
    setPage(0)
  }

  // Panel swipe-to-dismiss handlers
  const handlePanelTouchStart = (e) => {
    panelTouchStart.current = e.touches[0].clientY
    setPanelDragging(true)
  }

  const handlePanelTouchMove = (e) => {
    if (panelTouchStart.current === null) return
    const deltaY = e.touches[0].clientY - panelTouchStart.current
    if (deltaY > 0) {
      setPanelDragY(deltaY)
    }
  }

  const handlePanelTouchEnd = () => {
    if (panelDragY > 100) {
      setSelectedId(null)
      setDetail(null)
    }
    setPanelDragY(0)
    setPanelDragging(false)
    panelTouchStart.current = null
  }

  // Filter sheet swipe-to-dismiss handlers
  const handleSheetTouchStart = (e) => {
    sheetTouchStart.current = e.touches[0].clientY
    setSheetDragging(true)
  }

  const handleSheetTouchMove = (e) => {
    if (sheetTouchStart.current === null) return
    const deltaY = e.touches[0].clientY - sheetTouchStart.current
    if (deltaY > 0) {
      setSheetDragY(deltaY)
    }
  }

  const handleSheetTouchEnd = () => {
    if (sheetDragY > 100) {
      setFiltersOpen(false)
    }
    setSheetDragY(0)
    setSheetDragging(false)
    sheetTouchStart.current = null
  }

  return React.createElement('div', { className: 'flex gap-6 min-h-[calc(100vh-3rem)]' },
    // Filters sidebar (desktop only)
    React.createElement('div', {
      className: 'hidden lg:block w-56 flex-shrink-0 space-y-5'
    },
      React.createElement('div', { className: 'flex items-center gap-2 text-sm font-medium text-noctis-muted' },
        React.createElement(Filter, { className: 'w-4 h-4' }),
        'Filters',
      ),

      // Search
      React.createElement('div', { className: 'relative' },
        React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
        React.createElement('input', {
          type: 'text',
          value: filters.q,
          onChange: e => updateFilter('q', e.target.value),
          placeholder: 'Search content...',
          className: 'w-full pl-9 pr-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple transition-colors duration-200'
        }),
      ),

      // Category
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Category'),
        React.createElement('select', {
          value: filters.category,
          onChange: e => updateFilter('category', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Categories'),
          (categories || []).map(c =>
            React.createElement('option', { key: c.category, value: c.category },
              c.category?.replace(/_/g, ' '),
            )
          ),
        ),
      ),

      // Sub-Category
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Sub-Category'),
        React.createElement('select', {
          value: filters.subCategory,
          onChange: e => updateFilter('subCategory', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Sub-Categories'),
          (subcategories || [])
            .filter(sc => !filters.category || sc.category === filters.category)
            .map(sc =>
              React.createElement('option', { key: sc.sub_category, value: sc.sub_category },
                sc.sub_category?.replace(/_/g, ' ') + ` (${sc.count})`,
              )
            ),
        ),
      ),

      // Severity
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Severity'),
        React.createElement('select', {
          value: filters.severity,
          onChange: e => updateFilter('severity', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Severities'),
          SEVERITIES.map(s =>
            React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
          ),
        ),
      ),

      // Source type
      React.createElement('div', null,
        React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Source'),
        React.createElement('select', {
          value: filters.source,
          onChange: e => updateFilter('source', e.target.value),
          className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
        },
          React.createElement('option', { value: '' }, 'All Sources'),
          ['telegram', 'paste', 'forum', 'web', 'rss'].map(s =>
            React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
          ),
        ),
      ),

      // Clear
      (filters.category || filters.subCategory || filters.severity || filters.source || filters.q) &&
        React.createElement('button', {
          onClick: () => { setFilters({ category: '', subCategory: '', severity: '', source: '', q: '' }); setPage(0) },
          className: 'text-xs text-noctis-purple-light hover:text-noctis-purple cursor-pointer'
        }, 'Clear all filters'),
    ),

    // Main content
    React.createElement('div', { className: 'flex-1 min-w-0' },
      // Header
      React.createElement('div', { className: 'flex flex-col sm:flex-row items-start sm:items-center justify-between gap-1 mb-4' },
        React.createElement('h1', { className: 'font-heading font-normal text-xl' }, 'Findings'),
        React.createElement('span', { className: 'text-sm text-noctis-muted' },
          `${total.toLocaleString()} results`,
        ),
      ),

      // Mobile filter button
      React.createElement('button', {
        onClick: () => setFiltersOpen(true),
        className: 'lg:hidden flex items-center gap-2 px-3 py-2 border border-noctis-border/50 rounded text-sm text-noctis-muted mb-4 cursor-pointer'
      },
        React.createElement(Filter, { className: 'w-4 h-4' }),
        'Filters',
        (filters.category || filters.severity || filters.source || filters.q) &&
          React.createElement('span', { className: 'w-2 h-2 rounded-full bg-noctis-purple' }),
      ),

      // Table (desktop only)
      React.createElement('div', { className: 'hidden lg:block' },
      React.createElement('div', {
        className: 'border border-noctis-border/50 rounded overflow-x-auto'
      },
        React.createElement('table', { className: 'w-full text-sm' },
          React.createElement('thead', null,
            React.createElement('tr', { className: 'border-b border-noctis-border bg-noctis-surface/30' },
              ['Time', 'Source', 'Category', 'Sub-Cat', 'Severity', 'Summary'].map(h =>
                React.createElement('th', {
                  key: h,
                  className: 'px-4 py-3 text-left text-xs font-medium text-noctis-dim uppercase tracking-wider'
                }, h)
              ),
            ),
          ),
          React.createElement('tbody', null,
            loading
              ? Array.from({ length: 10 }).map((_, i) =>
                  React.createElement('tr', { key: i, className: 'border-b border-noctis-border/50' },
                    Array.from({ length: 6 }).map((_, j) =>
                      React.createElement('td', { key: j, className: 'px-4 py-3' },
                        React.createElement('div', { className: 'skeleton h-4 w-full' }),
                      )
                    ),
                  )
                )
              : findings.map((f, i) =>
                  React.createElement('tr', {
                    key: f.id,
                    onClick: () => loadDetail(f.id),
                    className: `border-b border-noctis-border/50 cursor-pointer transition-colors duration-150 hover:bg-white/[0.04] ${selectedId === f.id ? 'bg-noctis-purple/5' : i % 2 === 0 ? '' : 'bg-white/[0.02]'}`
                  },
                    React.createElement('td', { className: 'px-4 py-3 text-xs font-mono text-noctis-dim whitespace-nowrap' },
                      new Date(f.collectedAt).toLocaleString(),
                    ),
                    React.createElement('td', { className: 'px-4 py-3' },
                      React.createElement('span', { className: 'text-xs px-2 py-0.5 bg-noctis-bg rounded text-noctis-muted' }, f.sourceType),
                    ),
                    React.createElement('td', { className: 'px-4 py-3 text-xs text-noctis-muted' },
                      f.category?.replace(/_/g, ' ') || '-',
                    ),
                    React.createElement('td', { className: 'px-4 py-3' },
                      f.subCategory
                        ? React.createElement('span', {
                            className: 'text-[10px] px-1.5 py-0.5 bg-noctis-cyan/10 border border-noctis-cyan/30 rounded text-cyan-400'
                          }, f.subCategory.replace(/_/g, ' '))
                        : '-',
                    ),
                    React.createElement('td', { className: 'px-4 py-3' },
                      f.severity ? React.createElement(SeverityBadge, { severity: f.severity }) : '-',
                    ),
                    React.createElement('td', { className: 'px-4 py-3 text-sm text-noctis-text truncate max-w-md' },
                      f.summary || 'Pending classification\u2026',
                    ),
                  )
                ),
          ),
        ),

        // Empty state
        !loading && findings.length === 0 &&
          React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
            'No findings match your filters.',
          ),
      ),
      ), // end hidden lg:block wrapper

      // Mobile card list
      React.createElement('div', { className: 'lg:hidden space-y-3' },
        loading
          ? Array.from({ length: 6 }).map((_, i) =>
              React.createElement('div', { key: i, className: 'skeleton h-20 w-full rounded-lg' })
            )
          : findings.map((f) =>
              React.createElement('div', {
                key: f.id,
                onClick: () => loadDetail(f.id),
                className: `p-4 rounded-lg border border-noctis-border/30 cursor-pointer transition-all duration-150 active:scale-[0.98] active:bg-noctis-surface ${selectedId === f.id ? 'bg-noctis-purple/5 border-noctis-purple/30' : ''}`
              },
                // Top row: severity badge + category
                React.createElement('div', { className: 'flex items-center justify-between mb-1.5' },
                  f.severity ? React.createElement(SeverityBadge, { severity: f.severity }) : null,
                  React.createElement('span', { className: 'text-xs text-noctis-dim' }, f.category?.replace(/_/g, ' ') || ''),
                ),
                // Summary
                React.createElement('p', { className: 'text-sm text-noctis-text line-clamp-2 mb-1.5' }, f.summary || 'Pending classification\u2026'),
                // Bottom row: source + time
                React.createElement('div', { className: 'flex items-center justify-between text-xs text-noctis-dim' },
                  React.createElement('span', { className: 'px-1.5 py-0.5 bg-noctis-bg rounded' }, f.sourceType),
                  React.createElement('span', { className: 'font-mono' }, new Date(f.collectedAt).toLocaleDateString()),
                ),
              )
            ),
        !loading && findings.length === 0 &&
          React.createElement('div', { className: 'py-12 text-center text-sm text-noctis-dim' },
            'No findings match your filters.',
          ),
      ),

      // Pagination
      totalPages > 1 && React.createElement('div', {
        className: 'flex items-center justify-between mt-4'
      },
        React.createElement('span', { className: 'text-sm text-noctis-dim' },
          `Page ${page + 1} of ${totalPages}`,
        ),
        React.createElement('div', { className: 'flex gap-2' },
          React.createElement('button', {
            onClick: () => setPage(p => Math.max(0, p - 1)),
            disabled: page === 0,
            className: 'p-2 bg-noctis-surface border border-noctis-border rounded-lg disabled:opacity-30 cursor-pointer hover:bg-noctis-surface2 transition-colors duration-150'
          },
            React.createElement(ChevronLeft, { className: 'w-4 h-4' }),
          ),
          React.createElement('button', {
            onClick: () => setPage(p => Math.min(totalPages - 1, p + 1)),
            disabled: page >= totalPages - 1,
            className: 'p-2 bg-noctis-surface border border-noctis-border rounded-lg disabled:opacity-30 cursor-pointer hover:bg-noctis-surface2 transition-colors duration-150'
          },
            React.createElement(ChevronRight, { className: 'w-4 h-4' }),
          ),
        ),
      ),
    ),

    // Detail panel
    selectedId && React.createElement('div', {
      className: 'fixed inset-0 z-40 bg-noctis-bg overflow-y-auto lg:relative lg:inset-auto lg:z-auto lg:w-96 lg:flex-shrink-0 lg:border lg:border-noctis-border/50 lg:rounded lg:max-h-[calc(100vh-3rem)] lg:sticky lg:top-0 p-5 pt-12 lg:pt-5 animate-slide-up lg:animate-slide-in',
      onTouchStart: handlePanelTouchStart,
      onTouchMove: handlePanelTouchMove,
      onTouchEnd: handlePanelTouchEnd,
      style: panelDragY > 0 ? {
        transform: `translateY(${panelDragY}px)`,
        opacity: Math.max(0, 1 - panelDragY / 300),
        transition: panelDragging ? 'none' : 'transform 200ms ease-out, opacity 200ms ease-out',
      } : undefined,
    },
      // Drag handle (mobile only)
      React.createElement('div', { className: 'flex justify-center mb-3 lg:hidden' },
        React.createElement('div', { className: 'w-8 h-1 rounded-full bg-noctis-border' }),
      ),
      React.createElement('div', { className: 'flex items-center justify-between mb-4' },
        React.createElement('h3', { className: 'text-sm font-medium text-noctis-muted' }, 'Finding Detail'),
        React.createElement('button', {
          onClick: () => { setSelectedId(null); setDetail(null) },
          className: 'p-1 hover:bg-noctis-surface2 rounded cursor-pointer transition-colors duration-150'
        },
          React.createElement(X, { className: 'w-4 h-4 text-noctis-dim' }),
        ),
      ),

      detailLoading
        ? React.createElement('div', { className: 'space-y-3' },
            Array.from({ length: 6 }).map((_, i) =>
              React.createElement('div', { key: i, className: 'skeleton h-4 w-full' })
            ),
          )
        : detail && React.createElement('div', { className: 'space-y-4' },
            // Metadata
            React.createElement('div', { className: 'flex items-center gap-2 flex-wrap' },
              detail.severity && React.createElement(SeverityBadge, { severity: detail.severity }),
              detail.category && React.createElement('span', {
                className: 'text-xs px-2 py-0.5 bg-noctis-bg rounded text-noctis-muted'
              }, detail.category.replace(/_/g, ' ')),
              React.createElement('span', {
                className: 'text-xs text-noctis-dim font-mono'
              }, new Date(detail.collectedAt).toLocaleString()),
            ),

            // Sub-Category
            detail.subCategory && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'Sub-Category'),
              React.createElement('span', {
                className: 'text-xs px-2 py-0.5 bg-noctis-cyan/10 border border-noctis-cyan/30 rounded text-cyan-400'
              }, detail.subCategory.replace(/_/g, ' ')),
            ),

            // Sub-Metadata
            detail.subMetadata && Object.keys(detail.subMetadata).length > 0 && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'Detail Metadata'),
              React.createElement('div', { className: 'space-y-1' },
                Object.entries(detail.subMetadata).map(([k, v]) =>
                  React.createElement('div', { key: k, className: 'flex gap-2 text-xs' },
                    React.createElement('span', { className: 'text-noctis-dim min-w-[100px]' }, k.replace(/_/g, ' ')),
                    React.createElement('span', { className: 'text-noctis-text font-mono' },
                      Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v),
                    ),
                  )
                ),
              ),
            ),

            // Summary
            detail.summary && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'AI Summary'),
              React.createElement('p', { className: 'text-sm text-noctis-text leading-relaxed' }, detail.summary),
            ),

            // Tags
            detail.tags?.length > 0 && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'Tags'),
              React.createElement('div', { className: 'flex flex-wrap gap-1.5' },
                detail.tags.map(t =>
                  React.createElement('span', {
                    key: t,
                    className: 'text-xs px-2 py-0.5 bg-noctis-purple/10 border border-noctis-purple/30 rounded text-noctis-purple-light'
                  }, t)
                ),
              ),
            ),

            // IOCs
            detail.iocs?.length > 0 && React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-2' },
                `IOCs (${detail.iocs.length})`,
              ),
              React.createElement('div', { className: 'space-y-1.5' },
                detail.iocs.map((ioc, i) =>
                  React.createElement('div', {
                    key: i,
                    onClick: () => {
                      navigator.clipboard.writeText(ioc.value).then(() => {
                        setCopiedIOC(ioc.value)
                        setTimeout(() => setCopiedIOC(null), 2000)
                      })
                    },
                    className: 'flex items-center gap-2 p-2 bg-noctis-bg rounded-lg cursor-pointer hover:bg-noctis-surface transition-colors duration-150',
                    title: 'Click to copy',
                  },
                    React.createElement(Shield, { className: 'w-3.5 h-3.5 text-noctis-cyan flex-shrink-0' }),
                    React.createElement('span', { className: 'text-xs px-1.5 py-0.5 bg-noctis-surface2 rounded text-noctis-dim' }, ioc.type),
                    React.createElement('span', { className: 'text-xs font-mono text-noctis-text truncate' }, ioc.value),
                    copiedIOC === ioc.value && React.createElement('span', { className: 'text-[10px] text-green-400 flex-shrink-0' }, 'copied'),
                  )
                ),
              ),
            ),

            // Content
            React.createElement('div', null,
              React.createElement('h4', { className: 'text-xs text-noctis-dim mb-1' }, 'Raw Content'),
              React.createElement('pre', {
                className: 'text-xs font-mono text-noctis-muted bg-noctis-bg p-3 rounded-lg overflow-auto max-h-60 whitespace-pre-wrap break-words border border-noctis-border'
              }, detail.content),
            ),

            // URL
            detail.url && React.createElement('a', {
              href: detail.url,
              target: '_blank',
              rel: 'noopener noreferrer',
              className: 'inline-flex items-center gap-1 text-xs text-noctis-blue hover:text-noctis-blue-light cursor-pointer'
            },
              React.createElement(ExternalLink, { className: 'w-3 h-3' }),
              'Original URL',
            ),
          ),
    ),

    // Mobile filter bottom sheet
    filtersOpen && React.createElement('div', {
      className: 'lg:hidden fixed inset-0 z-50',
      onClick: (e) => { if (e.target === e.currentTarget) setFiltersOpen(false) }
    },
      React.createElement('div', { className: 'fixed inset-0 bg-black/50' }),
      React.createElement('div', {
        className: 'fixed bottom-0 left-0 right-0 bg-noctis-bg border-t border-noctis-border/50 rounded-t-xl p-5 z-10 max-h-[70vh] overflow-y-auto animate-slide-up',
        onTouchStart: handleSheetTouchStart,
        onTouchMove: handleSheetTouchMove,
        onTouchEnd: handleSheetTouchEnd,
        style: sheetDragY > 0 ? {
          transform: `translateY(${sheetDragY}px)`,
          opacity: Math.max(0, 1 - sheetDragY / 300),
          transition: sheetDragging ? 'none' : 'transform 200ms ease-out, opacity 200ms ease-out',
        } : undefined,
      },
        // Drag handle
        React.createElement('div', { className: 'flex justify-center mb-3' },
          React.createElement('div', { className: 'w-8 h-1 rounded-full bg-noctis-border' }),
        ),
        React.createElement('div', { className: 'flex items-center justify-between mb-4' },
          React.createElement('span', { className: 'text-sm font-medium text-noctis-muted' }, 'Filters'),
          React.createElement('button', {
            onClick: () => setFiltersOpen(false),
            className: 'p-1 cursor-pointer'
          }, React.createElement(X, { className: 'w-4 h-4 text-noctis-dim' })),
        ),

        // Search
        React.createElement('div', { className: 'relative mb-4' },
          React.createElement(Search, { className: 'absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-noctis-dim' }),
          React.createElement('input', {
            type: 'text',
            value: filters.q,
            onChange: e => updateFilter('q', e.target.value),
            placeholder: 'Search content...',
            className: 'w-full pl-9 pr-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text placeholder-noctis-dim focus:outline-none focus:border-noctis-purple transition-colors duration-200'
          }),
        ),

        // Category
        React.createElement('div', { className: 'mb-4' },
          React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Category'),
          React.createElement('select', {
            value: filters.category,
            onChange: e => updateFilter('category', e.target.value),
            className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
          },
            React.createElement('option', { value: '' }, 'All Categories'),
            (categories || []).map(c =>
              React.createElement('option', { key: c.category, value: c.category },
                c.category?.replace(/_/g, ' '),
              )
            ),
          ),
        ),

        // Sub-Category (mobile)
        React.createElement('div', { className: 'mb-4' },
          React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Sub-Category'),
          React.createElement('select', {
            value: filters.subCategory,
            onChange: e => updateFilter('subCategory', e.target.value),
            className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
          },
            React.createElement('option', { value: '' }, 'All Sub-Categories'),
            (subcategories || [])
              .filter(sc => !filters.category || sc.category === filters.category)
              .map(sc =>
                React.createElement('option', { key: sc.sub_category, value: sc.sub_category },
                  sc.sub_category?.replace(/_/g, ' ') + ` (${sc.count})`,
                )
              ),
          ),
        ),

        // Severity
        React.createElement('div', { className: 'mb-4' },
          React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Severity'),
          React.createElement('select', {
            value: filters.severity,
            onChange: e => updateFilter('severity', e.target.value),
            className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
          },
            React.createElement('option', { value: '' }, 'All Severities'),
            SEVERITIES.map(s =>
              React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
            ),
          ),
        ),

        // Source type
        React.createElement('div', { className: 'mb-4' },
          React.createElement('label', { className: 'block text-xs text-noctis-dim mb-1.5' }, 'Source'),
          React.createElement('select', {
            value: filters.source,
            onChange: e => updateFilter('source', e.target.value),
            className: 'w-full px-3 py-2 bg-noctis-surface border border-noctis-border rounded-lg text-sm text-noctis-text cursor-pointer focus:outline-none focus:border-noctis-purple'
          },
            React.createElement('option', { value: '' }, 'All Sources'),
            ['telegram', 'paste', 'forum', 'web', 'rss'].map(s =>
              React.createElement('option', { key: s, value: s }, s.charAt(0).toUpperCase() + s.slice(1))
            ),
          ),
        ),

        // Clear
        (filters.category || filters.severity || filters.source || filters.q) &&
          React.createElement('button', {
            onClick: () => { setFilters({ category: '', severity: '', source: '', q: '' }); setPage(0) },
            className: 'text-xs text-noctis-purple-light hover:text-noctis-purple cursor-pointer'
          }, 'Clear all filters'),
      ),
    ),
  )
}
