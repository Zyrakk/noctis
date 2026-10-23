export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        noctis: {
          bg: '#0a0a0f', surface: '#12121a', surface2: '#1a1a2e', border: '#2a2a3e',
          purple: '#7c3aed', 'purple-light': '#8b5cf6', 'purple-glow': '#a78bfa',
          blue: '#3b82f6', 'blue-light': '#60a5fa', cyan: '#06b6d4', green: '#10b981',
          text: '#e2e8f0', muted: '#94a3b8', dim: '#64748b',
        },
        severity: { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' },
      },
      fontFamily: { heading: ['Fira Sans', 'sans-serif'], body: ['Fira Sans', 'sans-serif'], mono: ['Fira Code', 'monospace'] },
    },
  },
}
