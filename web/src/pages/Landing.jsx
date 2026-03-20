import React, { useState, useEffect } from 'react'
import {
  Activity, Radio, Brain, Shield, Network, Bell, Radar,
  ArrowRight, ExternalLink
} from 'lucide-react'

const features = [
  {
    icon: Radio,
    title: 'Multi-Source Collection',
    color: 'bg-blue-500/10',
    iconColor: 'text-blue-400',
    desc: 'Telegram MTProto, dark web forums via Tor, paste sites, RSS/Atom feeds. Concurrent collectors with per-source dedup and circuit breakers.',
  },
  {
    icon: Brain,
    title: 'LLM Classification',
    color: 'bg-purple-500/10',
    iconColor: 'text-purple-400',
    desc: 'Every collected item is classified by category and severity via an OpenAI-compatible LLM. Background workers process the queue continuously.',
  },
  {
    icon: Shield,
    title: 'IOC Extraction',
    color: 'bg-amber-500/10',
    iconColor: 'text-amber-400',
    desc: 'IPs, domains, hashes, CVEs, emails, crypto wallets. Only confirmed malicious indicators are stored — research references are filtered out.',
  },
  {
    icon: Network,
    title: 'Entity Graph',
    color: 'bg-cyan-500/10',
    iconColor: 'text-cyan-400',
    desc: 'Actors, IOCs, channels, and findings linked in a traversable graph. BFS queries expose relationship chains across the dataset.',
  },
  {
    icon: Bell,
    title: 'Real-Time Alerts',
    color: 'bg-red-500/10',
    iconColor: 'text-red-400',
    desc: 'Keyword and regex rule engine evaluates every finding inline. Matched content triggers webhooks, Wazuh alerts, or Kubernetes NetworkPolicies.',
  },
  {
    icon: Radar,
    title: 'Autonomous Discovery',
    color: 'bg-green-500/10',
    iconColor: 'text-green-400',
    desc: 'URLs extracted from collected content are classified and queued as new sources. The intelligence net grows itself. Operator approval required by default.',
  },
]

const sevColors = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  info: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
}

export default function Landing({ navigate }) {
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState(null)

  useEffect(() => {
    fetch('/api/public-stats').then(r => r.ok ? r.json() : null).then(setStats).catch(() => {})
    fetch('/api/public-recent').then(r => r.ok ? r.json() : null).then(setRecent).catch(() => {})
  }, [])

  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg text-noctis-text font-body' },

    // Nav — minimal
    React.createElement('nav', {
      className: 'fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 bg-noctis-bg/90 backdrop-blur-sm border-b border-white/5'
    },
      React.createElement('div', { className: 'flex items-center gap-2.5' },
        React.createElement(Activity, { className: 'w-4 h-4 text-noctis-purple' }),
        React.createElement('span', { className: 'font-heading font-semibold text-sm tracking-widest uppercase text-noctis-text' }, 'Noctis'),
      ),
      React.createElement('button', {
        onClick: () => navigate('/login'),
        className: 'text-sm text-noctis-muted hover:text-noctis-text cursor-pointer transition-colors duration-200 flex items-center gap-1.5'
      },
        'Dashboard',
        React.createElement(ArrowRight, { className: 'w-3.5 h-3.5' }),
      ),
    ),

    // Hero
    React.createElement('section', {
      className: 'relative pt-28 pb-20 px-8 overflow-hidden'
    },
      // Subtle grid
      React.createElement('div', {
        className: 'absolute inset-0 opacity-[0.04]',
        style: {
          backgroundImage: 'linear-gradient(rgba(124,58,237,1) 1px, transparent 1px), linear-gradient(90deg, rgba(124,58,237,1) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
        },
      }),
      // Ambient blobs
      React.createElement('div', { className: 'hero-blob-1' }),
      React.createElement('div', { className: 'hero-blob-2' }),

      React.createElement('div', { className: 'max-w-6xl mx-auto relative z-10 grid grid-cols-1 lg:grid-cols-2 gap-12 items-center' },
        // Left: text
        React.createElement('div', null,
          React.createElement('h1', {
            className: 'font-heading font-normal text-3xl md:text-4xl leading-tight tracking-tight text-noctis-text mb-5'
          }, 'Autonomous Threat Intelligence Collection & Analysis'),
          React.createElement('p', {
            className: 'text-sm md:text-base text-noctis-muted leading-relaxed max-w-lg mb-8'
          },
            'Noctis continuously monitors Telegram channels, dark web forums, paste sites, and RSS feeds \u2014 classifying threats, extracting IOCs, and building entity graphs with AI. Self-hosted. Open source.',
          ),
          React.createElement('div', { className: 'flex items-center gap-6' },
            React.createElement('button', {
              onClick: () => navigate('/login'),
              className: 'px-5 py-2.5 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-purple/60 rounded cursor-pointer transition-all duration-200'
            }, 'Access Dashboard'),
            React.createElement('a', {
              href: 'https://github.com/Zyrakk/noctis',
              target: '_blank',
              rel: 'noopener noreferrer',
              className: 'group text-sm text-noctis-dim hover:text-noctis-muted cursor-pointer transition-colors duration-200 flex items-center gap-1.5'
            },
              'View on GitHub',
              React.createElement(ExternalLink, { className: 'w-3 h-3 transition-transform duration-200 group-hover:translate-x-1' }),
            ),
          ),
        ),

        // Right: browser mockup
        React.createElement('div', {
          className: 'hidden lg:block p-6',
          style: { perspective: '1200px' },
        },
          React.createElement('div', {
            className: 'rounded overflow-hidden border border-noctis-border/40',
            style: {
              transform: 'rotateY(-6deg)',
              boxShadow: '0 25px 60px -12px rgba(124, 58, 237, 0.15), 0 0 120px rgba(124, 58, 237, 0.06)',
            },
          },
            // Chrome bar
            React.createElement('div', { className: 'bg-noctis-surface/80 px-3 py-2 flex items-center gap-1.5 border-b border-noctis-border/30' },
              React.createElement('div', { className: 'w-2 h-2 rounded-full bg-red-500/40' }),
              React.createElement('div', { className: 'w-2 h-2 rounded-full bg-yellow-500/40' }),
              React.createElement('div', { className: 'w-2 h-2 rounded-full bg-green-500/40' }),
              React.createElement('div', { className: 'ml-3 text-[9px] text-noctis-dim font-mono' }, 'noctis.zyrak.cloud/dashboard'),
            ),
            // Mock dashboard content
            React.createElement('div', { className: 'bg-noctis-bg p-4 space-y-3' },
              // Stat row
              React.createElement('div', { className: 'grid grid-cols-4 gap-2' },
                [
                  { label: 'Findings', value: '674' },
                  { label: 'Classified', value: '674' },
                  { label: 'IOCs', value: '607' },
                  { label: 'Sources', value: '13' },
                ].map((s, i) =>
                  React.createElement('div', {
                    key: i,
                    className: 'border-l border-noctis-border/40 pl-2'
                  },
                    React.createElement('div', { className: 'text-[8px] text-noctis-dim' }, s.label),
                    React.createElement('div', { className: 'text-xs font-mono text-noctis-text' }, s.value),
                  )
                ),
              ),
              // Mini area chart (SVG)
              React.createElement('div', { className: 'border border-noctis-border/30 rounded p-2' },
                React.createElement('div', { className: 'text-[8px] text-noctis-dim mb-1' }, 'Findings Timeline'),
                React.createElement('svg', { viewBox: '0 0 200 40', className: 'w-full h-8' },
                  React.createElement('defs', null,
                    React.createElement('linearGradient', { id: 'mockGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
                      React.createElement('stop', { offset: '0%', stopColor: '#7c3aed', stopOpacity: '0.2' }),
                      React.createElement('stop', { offset: '100%', stopColor: '#7c3aed', stopOpacity: '0' }),
                    ),
                  ),
                  React.createElement('path', {
                    d: 'M0,35 L20,28 L40,32 L60,20 L80,25 L100,15 L120,22 L140,12 L160,18 L180,8 L200,14 L200,40 L0,40Z',
                    fill: 'url(#mockGrad)',
                  }),
                  React.createElement('path', {
                    d: 'M0,35 L20,28 L40,32 L60,20 L80,25 L100,15 L120,22 L140,12 L160,18 L180,8 L200,14',
                    fill: 'none', stroke: '#7c3aed', strokeWidth: '1.5',
                  }),
                ),
              ),
              // Mini findings table
              React.createElement('div', { className: 'border border-noctis-border/30 rounded overflow-hidden' },
                React.createElement('div', { className: 'text-[8px] text-noctis-dim px-2 pt-1.5' }, 'Recent Findings'),
                React.createElement('table', { className: 'w-full text-[8px]' },
                  React.createElement('tbody', null,
                    [
                      { sev: 'high', sevC: 'text-orange-400', cat: 'malware', src: 'telegram', sum: 'PoC exploit for CVE-2024-7479...' },
                      { sev: 'high', sevC: 'text-orange-400', cat: 'threat_actor', src: 'telegram', sum: 'Defense evasion via tdsskiller.exe...' },
                      { sev: 'medium', sevC: 'text-yellow-400', cat: 'credential', src: 'web', sum: 'XAMN Pro forensics tool leak...' },
                    ].map((r, i) =>
                      React.createElement('tr', { key: i, className: 'border-t border-noctis-border/20' },
                        React.createElement('td', { className: `px-2 py-1 ${r.sevC} font-mono` }, r.sev),
                        React.createElement('td', { className: 'px-2 py-1 text-noctis-dim' }, r.cat),
                        React.createElement('td', { className: 'px-2 py-1 text-noctis-dim' }, r.src),
                        React.createElement('td', { className: 'px-2 py-1 text-noctis-muted truncate max-w-[140px]' }, r.sum),
                      )
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    ),

    // Live stats bar
    stats && React.createElement('div', {
      className: 'px-8 pb-16'
    },
      React.createElement('div', {
        className: 'max-w-3xl mx-auto flex items-center gap-6 text-xs text-noctis-dim font-mono'
      },
        React.createElement('span', null,
          React.createElement('span', { className: 'text-white' }, stats.totalFindings.toLocaleString()),
          ' findings collected',
        ),
        React.createElement('span', { className: 'text-noctis-border' }, '\u00b7'),
        React.createElement('span', null,
          React.createElement('span', { className: 'text-white' }, stats.totalIocs.toLocaleString()),
          ' IOCs extracted',
        ),
        React.createElement('span', { className: 'text-noctis-border' }, '\u00b7'),
        React.createElement('span', null,
          React.createElement('span', { className: 'text-white' }, stats.activeSources),
          ' active sources',
        ),
        stats.totalEntities > 0 && React.createElement('span', { className: 'text-noctis-border' }, '\u00b7'),
        stats.totalEntities > 0 && React.createElement('span', null,
          React.createElement('span', { className: 'text-white' }, stats.totalEntities.toLocaleString()),
          ' entities mapped',
        ),
      ),
    ),

    // Gradient divider
    React.createElement('div', {
      className: 'max-w-3xl mx-auto h-px my-4',
      style: { background: 'linear-gradient(to right, transparent, rgba(124,58,237,0.3), transparent)' },
    }),

    // Features
    React.createElement('section', {
      className: 'py-20 px-8 border-t border-noctis-border/50'
    },
      React.createElement('div', { className: 'max-w-5xl mx-auto' },
        React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6' },
          features.map((f, i) =>
            React.createElement('div', {
              key: i,
              className: 'py-4 pl-4 border-l-2 border-noctis-border hover:border-noctis-purple/60 transition-colors duration-200'
            },
              React.createElement('div', { className: 'flex items-center gap-2.5 mb-2' },
                React.createElement('div', { className: `w-7 h-7 rounded-full ${f.color} flex items-center justify-center` },
                  React.createElement(f.icon, { className: `w-3.5 h-3.5 ${f.iconColor}` }),
                ),
                React.createElement('h3', {
                  className: 'font-heading font-medium text-sm text-noctis-text'
                }, f.title),
              ),
              React.createElement('p', {
                className: 'text-xs text-noctis-muted leading-relaxed'
              }, f.desc),
            )
          ),
        ),
      ),
    ),

    // Recent findings preview
    recent && recent.length > 0 && React.createElement('section', {
      className: 'py-16 px-8 border-t border-noctis-border/50'
    },
      React.createElement('div', { className: 'max-w-5xl mx-auto' },
        React.createElement('h2', {
          className: 'font-heading font-normal text-sm uppercase tracking-widest text-noctis-dim mb-6'
        }, 'Recent Classified Findings'),
        React.createElement('div', {
          className: 'border border-noctis-border/50 rounded overflow-hidden'
        },
          React.createElement('table', { className: 'w-full text-xs' },
            React.createElement('thead', null,
              React.createElement('tr', { className: 'bg-noctis-surface/50 border-b border-noctis-border/50' },
                ['Category', 'Severity', 'Source', 'Summary'].map(h =>
                  React.createElement('th', {
                    key: h,
                    className: 'px-4 py-2.5 text-left font-medium text-noctis-dim uppercase tracking-wider'
                  }, h)
                ),
              ),
            ),
            React.createElement('tbody', null,
              recent.map((f, i) => {
                const sev = f.severity?.toLowerCase() || 'info'
                const sevClass = sevColors[sev] || sevColors.info
                return React.createElement('tr', {
                  key: i,
                  className: 'border-b border-noctis-border/30 last:border-0'
                },
                  React.createElement('td', { className: 'px-4 py-2.5 text-noctis-muted font-mono' },
                    f.category?.replace(/_/g, ' ') || '-',
                  ),
                  React.createElement('td', { className: 'px-4 py-2.5' },
                    React.createElement('span', {
                      className: `inline-block px-1.5 py-0.5 text-[10px] font-mono font-medium rounded border ${sevClass}`
                    }, sev),
                  ),
                  React.createElement('td', { className: 'px-4 py-2.5 text-noctis-dim' }, f.sourceType),
                  React.createElement('td', { className: 'px-4 py-2.5 text-noctis-muted max-w-md truncate' }, f.summary),
                )
              }),
            ),
          ),
        ),
      ),
    ),

    // CTA
    React.createElement('section', {
      className: 'py-20 px-8 border-t border-noctis-border/50'
    },
      React.createElement('div', { className: 'max-w-3xl mx-auto' },
        React.createElement('h2', {
          className: 'font-heading font-normal text-2xl md:text-3xl text-noctis-text mb-3'
        }, 'Deploy Noctis on your infrastructure.'),
        React.createElement('p', {
          className: 'text-noctis-muted text-base mb-8'
        }, 'Monitor your threat landscape with a single binary. Kubernetes-native, PostgreSQL-backed, MIT licensed.'),
        React.createElement('div', { className: 'flex items-center gap-6' },
          React.createElement('a', {
            href: 'https://github.com/Zyrakk/noctis',
            target: '_blank',
            rel: 'noopener noreferrer',
            className: 'px-5 py-2.5 border border-noctis-muted/40 text-sm text-noctis-text hover:bg-noctis-surface hover:border-noctis-purple/60 rounded cursor-pointer transition-all duration-200 flex items-center gap-2'
          },
            'View on GitHub',
            React.createElement(ExternalLink, { className: 'w-3.5 h-3.5' }),
          ),
          React.createElement('button', {
            onClick: () => navigate('/login'),
            className: 'text-sm text-noctis-muted hover:text-noctis-text cursor-pointer transition-colors duration-200 flex items-center gap-1.5'
          },
            'Access Dashboard',
            React.createElement(ArrowRight, { className: 'w-3.5 h-3.5' }),
          ),
        ),
      ),
    ),

    // Footer
    React.createElement('footer', {
      className: 'py-8 px-8 border-t border-noctis-border/30'
    },
      React.createElement('div', { className: 'max-w-5xl mx-auto flex items-center justify-between text-xs text-noctis-dim' },
        React.createElement('span', null, 'Noctis'),
        React.createElement('div', { className: 'flex items-center gap-4' },
          React.createElement('span', null, 'MIT License'),
          React.createElement('a', {
            href: 'https://github.com/Zyrakk/noctis',
            target: '_blank',
            rel: 'noopener noreferrer',
            className: 'hover:text-noctis-muted transition-colors duration-200 cursor-pointer'
          }, 'GitHub'),
        ),
      ),
    ),
  )
}
