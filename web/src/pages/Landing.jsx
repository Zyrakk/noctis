import React, { useState, useEffect } from 'react'
import {
  Activity, Radio, Brain, Shield, Network, Bell,
  ChevronRight, Zap, Eye, Database
} from 'lucide-react'

const features = [
  {
    icon: Radio,
    title: 'Multi-Source Collection',
    desc: 'Telegram channels, dark web forums, paste sites, RSS feeds. Real-time ingestion from dozens of threat intelligence sources.',
  },
  {
    icon: Brain,
    title: 'AI Classification',
    desc: 'LLM-powered classification categorizes every piece of content: credential leaks, malware samples, access broker ads, and more.',
  },
  {
    icon: Shield,
    title: 'IOC Extraction',
    desc: 'Automated extraction of IPs, domains, hashes, CVEs, emails, and crypto wallets with full context preservation.',
  },
  {
    icon: Network,
    title: 'Entity Graph',
    desc: 'Knowledge graph connecting actors, IOCs, and sources. Traverse relationships to uncover threat clusters.',
  },
  {
    icon: Bell,
    title: 'Real-Time Alerts',
    desc: 'Webhook dispatch, Wazuh integration, and Kubernetes network policy generation. Automated response at machine speed.',
  },
]

function AnimatedCounter({ end, duration = 2000, prefix = '', suffix = '' }) {
  const [count, setCount] = useState(0)
  useEffect(() => {
    let start = 0
    const increment = end / (duration / 16)
    const timer = setInterval(() => {
      start += increment
      if (start >= end) {
        setCount(end)
        clearInterval(timer)
      } else {
        setCount(Math.floor(start))
      }
    }, 16)
    return () => clearInterval(timer)
  }, [end, duration])
  return React.createElement('span', null, `${prefix}${count.toLocaleString()}${suffix}`)
}

export default function Landing({ navigate }) {
  return React.createElement('div', { className: 'min-h-screen bg-noctis-bg text-noctis-text' },

    // Hero
    React.createElement('section', {
      className: 'animated-gradient grid-bg relative min-h-screen flex flex-col items-center justify-center px-6 text-center'
    },
      // Floating nav
      React.createElement('nav', {
        className: 'fixed top-4 left-4 right-4 z-50 flex items-center justify-between px-6 py-3 bg-noctis-surface/80 backdrop-blur-md border border-noctis-border rounded-xl'
      },
        React.createElement('div', { className: 'flex items-center gap-2' },
          React.createElement(Activity, { className: 'w-5 h-5 text-noctis-purple' }),
          React.createElement('span', { className: 'font-heading font-bold text-lg tracking-tight' }, 'NOCTIS'),
        ),
        React.createElement('button', {
          onClick: () => navigate('/login'),
          className: 'px-4 py-2 bg-noctis-purple hover:bg-noctis-purple-light text-white text-sm font-medium rounded-lg cursor-pointer transition-colors duration-200'
        }, 'Access Dashboard'),
      ),

      // Hero content
      React.createElement('div', { className: 'max-w-4xl mx-auto relative z-10 mt-20' },
        React.createElement('div', {
          className: 'inline-flex items-center gap-2 px-4 py-1.5 bg-noctis-purple/10 border border-noctis-purple/30 rounded-full text-sm text-noctis-purple-light mb-8'
        },
          React.createElement(Zap, { className: 'w-3.5 h-3.5' }),
          'AI-Powered Threat Intelligence',
        ),
        React.createElement('h1', {
          className: 'font-heading font-bold text-5xl md:text-7xl leading-tight tracking-tight mb-6'
        },
          React.createElement('span', { className: 'text-noctis-text' }, 'See the threats'),
          React.createElement('br'),
          React.createElement('span', {
            className: 'bg-gradient-to-r from-noctis-purple to-noctis-blue bg-clip-text text-transparent'
          }, 'before they strike.'),
        ),
        React.createElement('p', {
          className: 'text-lg md:text-xl text-noctis-muted max-w-2xl mx-auto mb-10 leading-relaxed'
        },
          'Noctis monitors dark web forums, Telegram channels, paste sites, and RSS feeds. AI classifies every finding, extracts IOCs, and maps entity relationships in real time.',
        ),
        React.createElement('div', { className: 'flex items-center justify-center gap-4' },
          React.createElement('button', {
            onClick: () => navigate('/login'),
            className: 'flex items-center gap-2 px-8 py-3.5 bg-noctis-purple hover:bg-noctis-purple-light text-white font-semibold rounded-xl cursor-pointer transition-all duration-200 glow-purple'
          },
            'Access Dashboard',
            React.createElement(ChevronRight, { className: 'w-4 h-4' }),
          ),
        ),
      ),

      // Scroll indicator
      React.createElement('div', {
        className: 'absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce'
      },
        React.createElement('div', { className: 'w-6 h-10 border-2 border-noctis-border rounded-full flex items-start justify-center p-1.5' },
          React.createElement('div', { className: 'w-1.5 h-1.5 bg-noctis-purple rounded-full animate-pulse' }),
        ),
      ),
    ),

    // Features
    React.createElement('section', {
      className: 'py-24 px-6 border-t border-noctis-border'
    },
      React.createElement('div', { className: 'max-w-6xl mx-auto' },
        React.createElement('div', { className: 'text-center mb-16' },
          React.createElement('h2', {
            className: 'font-heading font-bold text-3xl md:text-4xl mb-4'
          }, 'Full-Spectrum Intelligence'),
          React.createElement('p', {
            className: 'text-noctis-muted text-lg max-w-2xl mx-auto'
          }, 'From raw collection to actionable insight, every step is automated.'),
        ),
        React.createElement('div', {
          className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'
        },
          features.map((f, i) =>
            React.createElement('div', {
              key: i,
              className: 'group p-6 bg-noctis-surface border border-noctis-border rounded-xl cursor-pointer transition-all duration-200 hover:border-noctis-purple/40 hover:-translate-y-1'
            },
              React.createElement('div', {
                className: 'w-10 h-10 flex items-center justify-center bg-noctis-purple/10 rounded-lg mb-4'
              },
                React.createElement(f.icon, { className: 'w-5 h-5 text-noctis-purple-light' }),
              ),
              React.createElement('h3', {
                className: 'font-heading font-semibold text-lg mb-2 text-noctis-text'
              }, f.title),
              React.createElement('p', {
                className: 'text-sm text-noctis-muted leading-relaxed'
              }, f.desc),
            )
          ),
        ),
      ),
    ),

    // Stats
    React.createElement('section', {
      className: 'py-20 px-6 bg-noctis-surface border-y border-noctis-border'
    },
      React.createElement('div', {
        className: 'max-w-5xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8'
      },
        [
          { icon: Eye, value: 150, suffix: '+', label: 'Sources Monitored' },
          { icon: Database, value: 50000, suffix: '+', label: 'Findings Classified' },
          { icon: Shield, value: 12000, suffix: '+', label: 'IOCs Extracted' },
          { icon: Network, value: 8500, suffix: '+', label: 'Entity Relationships' },
        ].map((s, i) =>
          React.createElement('div', {
            key: i,
            className: 'text-center'
          },
            React.createElement('div', { className: 'flex justify-center mb-3' },
              React.createElement(s.icon, { className: 'w-6 h-6 text-noctis-purple-light' }),
            ),
            React.createElement('div', {
              className: 'font-mono font-bold text-3xl md:text-4xl text-noctis-text mb-1'
            },
              React.createElement(AnimatedCounter, { end: s.value, suffix: s.suffix }),
            ),
            React.createElement('div', {
              className: 'text-sm text-noctis-muted'
            }, s.label),
          )
        ),
      ),
    ),

    // CTA
    React.createElement('section', {
      className: 'py-24 px-6 text-center'
    },
      React.createElement('div', { className: 'max-w-2xl mx-auto' },
        React.createElement('h2', {
          className: 'font-heading font-bold text-3xl md:text-4xl mb-6'
        }, 'Ready to see what\'s out there?'),
        React.createElement('p', {
          className: 'text-noctis-muted text-lg mb-8'
        }, 'Access the Noctis dashboard and start monitoring your threat landscape.'),
        React.createElement('button', {
          onClick: () => navigate('/login'),
          className: 'inline-flex items-center gap-2 px-8 py-4 bg-noctis-purple hover:bg-noctis-purple-light text-white font-semibold text-lg rounded-xl cursor-pointer transition-all duration-200 glow-purple'
        },
          'Access Dashboard',
          React.createElement(ChevronRight, { className: 'w-5 h-5' }),
        ),
      ),
    ),

    // Footer
    React.createElement('footer', {
      className: 'py-8 px-6 border-t border-noctis-border text-center'
    },
      React.createElement('div', { className: 'flex items-center justify-center gap-2 text-noctis-dim text-sm' },
        React.createElement(Activity, { className: 'w-4 h-4' }),
        'Noctis Threat Intelligence Platform',
      ),
    ),
  )
}
