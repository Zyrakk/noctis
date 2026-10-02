import React, { useEffect, useMemo } from 'react'
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Brain,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Database,
  GitBranch,
  Layers3,
  Network,
  Radio,
  Route,
  Search,
  ShieldCheck,
  Sparkles,
  Target,
  Waypoints,
  Workflow,
  Zap,
} from 'lucide-react'
import './presentation.css'

const DEMO_NOTICE = 'SYNTHETIC DEMO DATA · PRESENTATION SAFE'

const navItems = [
  { path: '/presentation', label: 'Overview', short: '01' },
  { path: '/presentation/brief', label: 'Brief', short: '02' },
  { path: '/presentation/correlation', label: 'Correlation', short: '03' },
  { path: '/presentation/architecture', label: 'Architecture', short: '04' },
  { path: '/presentation/lessons', label: 'Lessons / rebuild', short: '05' },
]

const rawSignals = [
  { id: 'sig-041', source: 'telegram', sourceLabel: 'Telegram / channel', text: 'new loader discussion + pasted hash', state: 'noise', tag: 'low context' },
  { id: 'sig-042', source: 'forum', sourceLabel: 'Forum / thread', text: 'synthetic vulnerability reference with a shared token', state: 'matched', tag: 'high · vulnerability' },
  { id: 'sig-043', source: 'rss', sourceLabel: 'RSS / security feed', text: 'generic weekly roundup', state: 'noise', tag: 'duplicate' },
  { id: 'sig-044', source: 'paste', sourceLabel: 'Paste / public', text: 'alias appears beside a synthetic domain', state: 'matched', tag: 'medium · actor' },
  { id: 'sig-045', source: 'telegram', sourceLabel: 'Telegram / group', text: 'operational detail without corroboration', state: 'queued', tag: 'candidate' },
]

const demoFinding = {
  id: 'finding.demo-042',
  category: 'vulnerability',
  severity: 'high',
  provenance: 'third_party_reporting',
  source: 'Forum / thread',
  summary: 'A synthetic vulnerability reference shares an indicator with a separate synthetic source. No real incident or victim is represented here.',
  ioc: 'CVE-2099-0042',
  entity: 'night-ferry',
}

const layers = [
  {
    number: '01',
    title: 'Collectors',
    status: 'implemented',
    icon: Radio,
    color: 'blue',
    items: ['Telegram MTProto', 'Paste sites', 'Forums via HTTP / Tor', 'RSS / web feeds'],
    detail: 'Each collector emits a models.Finding into the manager fan-in.',
  },
  {
    number: '02',
    title: 'Ingest',
    status: 'implemented',
    icon: Database,
    color: 'cyan',
    items: ['Archive every item', 'Content-hash dedup', 'Keyword / regex matcher', 'Alert path'],
    detail: 'The synchronous ingest path persists raw_content before matching.',
  },
  {
    number: '03',
    title: 'Processing engine',
    status: 'implemented',
    icon: Workflow,
    color: 'purple',
    items: ['Classifier', 'Summarizer', 'IOC extractor', 'Entity extractor + graph bridge'],
    detail: 'Background workers classify, summarize, extract IOCs and entities, then write graph relationships.',
  },
  {
    number: '04',
    title: 'Intelligence brain',
    status: 'implemented',
    icon: Brain,
    color: 'amber',
    items: ['Rule correlator', 'LLM analyst', 'Daily brief generator', 'Natural-language query'],
    detail: 'Candidates can be promoted, rejected or deferred with an auditable decision trail.',
  },
  {
    number: '05',
    title: 'Infrastructure + UI',
    status: 'implemented',
    icon: Layers3,
    color: 'green',
    items: ['NVD / EPSS / KEV', 'IOC enrichment', 'Source discovery', 'React dashboard'],
    detail: 'The Go daemon embeds the React dashboard and serves the API over the configured port.',
  },
]

function StatusPill({ children, tone = 'neutral' }) {
  return React.createElement('span', { className: `pres-status pres-status-${tone}` }, children)
}

function DemoBadge() {
  return React.createElement('span', { className: 'pres-demo-badge' },
    React.createElement(Sparkles, { size: 12 }), DEMO_NOTICE,
  )
}

function Header({ currentPath, navigate }) {
  const currentIndex = Math.max(0, navItems.findIndex(item => item.path === currentPath))

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === 'ArrowRight') {
        const next = navItems[Math.min(navItems.length - 1, currentIndex + 1)]
        navigate(next.path)
      }
      if (event.key === 'ArrowLeft') {
        const previous = navItems[Math.max(0, currentIndex - 1)]
        navigate(previous.path)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [currentIndex, navigate])

  return React.createElement('header', { className: 'pres-header' },
    React.createElement('div', { className: 'pres-brand' },
      React.createElement('div', { className: 'pres-brand-mark' }, React.createElement(Activity, { size: 16 })),
      React.createElement('div', null,
        React.createElement('div', { className: 'pres-brand-name' }, 'Noctis'),
        React.createElement('div', { className: 'pres-brand-subtitle' }, 'presentation mode'),
      ),
    ),
    React.createElement('nav', { className: 'pres-nav', 'aria-label': 'Presentation navigation' },
      navItems.map((item, index) => React.createElement('button', {
        key: item.path,
        onClick: () => navigate(item.path),
        className: `pres-nav-item ${item.path === currentPath ? 'is-active' : ''}`,
        'aria-current': item.path === currentPath ? 'page' : undefined,
      },
        React.createElement('span', { className: 'pres-nav-index' }, item.short),
        React.createElement('span', { className: 'pres-nav-label' }, item.label),
        index < navItems.length - 1 && React.createElement('span', { className: 'pres-nav-dot' }),
      )),
    ),
    React.createElement(DemoBadge),
  )
}

function FooterNav({ currentPath, navigate }) {
  const index = Math.max(0, navItems.findIndex(item => item.path === currentPath))
  const previous = navItems[index - 1]
  const next = navItems[index + 1]
  return React.createElement('div', { className: 'pres-footer-nav' },
    previous
      ? React.createElement('button', { className: 'pres-step-button', onClick: () => navigate(previous.path) },
          React.createElement(ChevronLeft, { size: 16 }), React.createElement('span', null, previous.label),
        )
      : React.createElement('span', { className: 'pres-step-hint' }, 'Use ← / → to move through the story'),
    React.createElement('div', { className: 'pres-step-count' }, `${String(index + 1).padStart(2, '0')} / ${String(navItems.length).padStart(2, '0')}`),
    next
      ? React.createElement('button', { className: 'pres-step-button pres-step-button-next', onClick: () => navigate(next.path) },
          React.createElement('span', null, next.label), React.createElement(ChevronRight, { size: 16 }),
        )
      : React.createElement('span', { className: 'pres-step-hint' }, 'End of presentation path'),
  )
}

function SectionHeader({ eyebrow, title, copy, action }) {
  return React.createElement('div', { className: 'pres-section-header' },
    React.createElement('div', null,
      eyebrow && React.createElement('div', { className: 'pres-eyebrow' }, eyebrow),
      React.createElement('h1', { className: 'pres-title' }, title),
      copy && React.createElement('p', { className: 'pres-copy' }, copy),
    ),
    action,
  )
}

function MiniFlow({ compact = false }) {
  const steps = [
    ['raw signal', Radio],
    ['processed', Zap],
    ['entity / IOC', Target],
    ['finding', ShieldCheck],
  ]
  return React.createElement('div', { className: `pres-mini-flow ${compact ? 'is-compact' : ''}` },
    steps.map(([label, Icon], index) => React.createElement(React.Fragment, { key: label },
      React.createElement('div', { className: 'pres-mini-flow-step' },
        React.createElement('div', { className: 'pres-mini-flow-icon' }, React.createElement(Icon, { size: 14 })),
        React.createElement('span', null, label),
      ),
      index < steps.length - 1 && React.createElement(ArrowRight, { className: 'pres-flow-arrow', size: 15 }),
    )),
  )
}

function Overview({ navigate }) {
  return React.createElement(React.Fragment, null,
    React.createElement(SectionHeader, {
      eyebrow: 'THE QUESTION THAT STARTED IT',
      title: 'How do you turn a noisy stream into something a person can verify?',
      copy: 'Noctis is a long-running threat intelligence daemon I built to collect, classify and connect signals from several sources. This view uses deterministic synthetic data so the story can be recorded safely.',
      action: React.createElement('button', { className: 'pres-outline-button', onClick: () => navigate('/presentation/brief') }, 'Open a brief', React.createElement(ArrowUpRight, { size: 15 })),
    }),
    React.createElement('div', { className: 'pres-metric-grid' },
      [
        ['128', 'raw signals', 'incoming archive'],
        ['34', 'matched / processed', 'after ingest + workers'],
        ['12', 'entities + IOCs', 'graph-ready objects'],
        ['01', 'candidate path', 'kept for review'],
      ].map(([value, label, detail]) => React.createElement('div', { key: label, className: 'pres-metric-card' },
        React.createElement('div', { className: 'pres-metric-value' }, value),
        React.createElement('div', { className: 'pres-metric-label' }, label),
        React.createElement('div', { className: 'pres-metric-detail' }, detail),
      )),
    ),
    React.createElement('div', { className: 'pres-overview-grid' },
      React.createElement('section', { className: 'pres-panel pres-signal-panel' },
        React.createElement('div', { className: 'pres-panel-heading' },
          React.createElement('div', null,
            React.createElement('div', { className: 'pres-panel-kicker' }, 'Signal field'),
            React.createElement('h2', { className: 'pres-panel-title' }, 'Many observations, fewer useful objects'),
          ),
          React.createElement(StatusPill, { tone: 'synthetic' }, 'illustrative'),
        ),
        React.createElement('div', { className: 'pres-signal-table' },
          rawSignals.map(signal => React.createElement('div', { key: signal.id, className: `pres-signal-row is-${signal.state}` },
            React.createElement('div', { className: 'pres-signal-id' }, signal.id),
            React.createElement('div', { className: 'pres-signal-source' },
              React.createElement('span', { className: `pres-source-dot source-${signal.source}` }), signal.sourceLabel,
            ),
            React.createElement('div', { className: 'pres-signal-text' }, signal.text),
            React.createElement('span', { className: `pres-signal-tag tag-${signal.state}` }, signal.tag),
          )),
        ),
        React.createElement('div', { className: 'pres-table-footnote' },
          React.createElement(Search, { size: 13 }), 'Archive first. Interpretation happens in later workers.',
        ),
      ),
      React.createElement('section', { className: 'pres-panel pres-funnel-panel' },
        React.createElement('div', { className: 'pres-panel-kicker' }, 'The shape of the system'),
        React.createElement('h2', { className: 'pres-panel-title' }, 'The useful set is deliberately smaller'),
        React.createElement('div', { className: 'pres-funnel' },
          [
            ['128', 'raw_content', 'archive every item'],
            ['34', 'classified / summarized', 'background workers'],
            ['12', 'IOCs + entities', 'graph bridge'],
            ['01', 'correlation candidate', 'analyst review'],
          ].map(([count, label, detail], index) => React.createElement('div', { key: label, className: 'pres-funnel-row' },
            React.createElement('div', { className: 'pres-funnel-count' }, count),
            React.createElement('div', { className: 'pres-funnel-bar-wrap' },
              React.createElement('div', { className: `pres-funnel-bar bar-${index}` }),
              React.createElement('div', { className: 'pres-funnel-label' }, label),
              React.createElement('div', { className: 'pres-funnel-detail' }, detail),
            ),
          )),
        ),
        React.createElement(MiniFlow, null),
      ),
    ),
    React.createElement('section', { className: 'pres-callout pres-callout-purple' },
      React.createElement('div', { className: 'pres-callout-icon' }, React.createElement(Network, { size: 17 })),
      React.createElement('div', null,
        React.createElement('div', { className: 'pres-callout-title' }, 'The interesting part is the path, not the single message.'),
        React.createElement('div', { className: 'pres-callout-copy' }, 'A weak observation can become useful when another source, entity or timestamp gives it context. The next screen follows one synthetic example.'),
      ),
      React.createElement('button', { className: 'pres-callout-link', onClick: () => navigate('/presentation/brief') }, 'Follow the path', React.createElement(ArrowRight, { size: 14 })),
    ),
  )
}

function Brief({ navigate }) {
  return React.createElement(React.Fragment, null,
    React.createElement(SectionHeader, {
      eyebrow: '02 · FROM SIGNAL TO FINDING',
      title: 'A brief keeps the evidence close to the conclusion.',
      copy: 'This is a synthetic finding shaped like the objects Noctis stores: category, severity, provenance, extracted indicators and a short analyst-readable summary.',
      action: React.createElement(StatusPill, { tone: 'synthetic' }, 'synthetic finding'),
    }),
    React.createElement('div', { className: 'pres-brief-grid' },
      React.createElement('section', { className: 'pres-panel pres-brief-main' },
        React.createElement('div', { className: 'pres-brief-meta' },
          React.createElement('span', { className: 'pres-mono-label' }, demoFinding.id),
          React.createElement('span', { className: 'pres-meta-separator' }, '•'),
          React.createElement('span', null, demoFinding.source),
          React.createElement('span', { className: 'pres-meta-separator' }, '•'),
          React.createElement('span', null, 'demo timestamp 2026-06-18 09:20 UTC'),
        ),
        React.createElement('div', { className: 'pres-brief-title-row' },
          React.createElement('h2', { className: 'pres-brief-title' }, 'Shared indicator around a synthetic vulnerability reference'),
          React.createElement(StatusPill, { tone: 'high' }, 'high'),
        ),
        React.createElement('div', { className: 'pres-tag-row' },
          React.createElement(StatusPill, { tone: 'purple' }, demoFinding.category),
          React.createElement(StatusPill, { tone: 'neutral' }, demoFinding.provenance),
          React.createElement(StatusPill, { tone: 'cyan' }, 'classified'),
        ),
        React.createElement('p', { className: 'pres-brief-summary' }, demoFinding.summary),
        React.createElement('div', { className: 'pres-evidence-block' },
          React.createElement('div', { className: 'pres-panel-kicker' }, 'Structured evidence retained'),
          React.createElement('div', { className: 'pres-evidence-grid' },
            [
              ['IOC', demoFinding.ioc, 'extracted · synthetic'],
              ['Entity', demoFinding.entity, 'named entity · synthetic'],
              ['Source', 'forum / thread', 'provenance: third-party'],
              ['Reasoning', 'shared token + temporal proximity', 'candidate signal'],
            ].map(([key, value, detail]) => React.createElement('div', { key: key, className: 'pres-evidence-item' },
              React.createElement('div', { className: 'pres-evidence-key' }, key),
              React.createElement('div', { className: 'pres-evidence-value' }, value),
              React.createElement('div', { className: 'pres-evidence-detail' }, detail),
            )),
          ),
        ),
        React.createElement('button', { className: 'pres-primary-button', onClick: () => navigate('/presentation/correlation') }, 'Trace the correlation path', React.createElement(ArrowRight, { size: 16 })),
      ),
      React.createElement('aside', { className: 'pres-panel pres-brief-side' },
        React.createElement('div', { className: 'pres-panel-kicker' }, 'Daily brief shape'),
        React.createElement('h2', { className: 'pres-panel-title' }, 'What a brief is for'),
        React.createElement('p', { className: 'pres-side-copy' }, 'The daily brief generator synthesizes a collection window into a short report with key threats, correlation insights, emerging trends, collection gaps and recommended actions.'),
        React.createElement('div', { className: 'pres-side-metrics' },
          [['24', 'signals in window'], ['07', 'classified'], ['04', 'IOCs'], ['01', 'new candidate']].map(([value, label]) => React.createElement('div', { key: label, className: 'pres-side-metric' },
            React.createElement('span', { className: 'pres-side-metric-value' }, value),
            React.createElement('span', { className: 'pres-side-metric-label' }, label),
          )),
        ),
        React.createElement('div', { className: 'pres-side-note' },
          React.createElement(CheckCircle2, { size: 15 }),
          React.createElement('span', null, 'This screen is a shape demo. It contains no historical Noctis evidence.'),
        ),
      ),
    ),
  )
}

function Correlation({ navigate }) {
  const nodes = [
    { label: 'sig-042', sub: 'forum / thread', tone: 'blue', icon: Radio },
    { label: 'CVE-2099-0042', sub: 'IOC · synthetic', tone: 'cyan', icon: Target },
    { label: 'night-ferry', sub: 'entity · synthetic', tone: 'red', icon: Waypoints },
    { label: 'sig-044', sub: 'paste / public', tone: 'purple', icon: Radio },
  ]
  return React.createElement(React.Fragment, null,
    React.createElement(SectionHeader, {
      eyebrow: '03 · CORRELATION',
      title: 'One path, with its uncertainty still visible.',
      copy: 'Noctis first finds candidates with deterministic rules. The Analyst can then promote, reject or defer a candidate and store the reasoning alongside the decision.',
      action: React.createElement(StatusPill, { tone: 'candidate' }, 'candidate · synthetic'),
    }),
    React.createElement('div', { className: 'pres-correlation-grid' },
      React.createElement('section', { className: 'pres-panel pres-path-panel' },
        React.createElement('div', { className: 'pres-panel-heading' },
          React.createElement('div', null,
            React.createElement('div', { className: 'pres-panel-kicker' }, 'Candidate path'),
            React.createElement('h2', { className: 'pres-panel-title' }, 'Shared IOC + temporal overlap'),
          ),
          React.createElement('div', { className: 'pres-confidence' },
            React.createElement('span', null, 'confidence'), React.createElement('strong', null, '0.78'),
          ),
        ),
        React.createElement('div', { className: 'pres-path-canvas' },
          React.createElement('div', { className: 'pres-path-line path-line-one' }),
          React.createElement('div', { className: 'pres-path-line path-line-two' }),
          React.createElement('div', { className: 'pres-path-line path-line-three' }),
          nodes.map(({ label, sub, tone, icon: Icon }, index) => React.createElement('div', { key: label, className: `pres-path-node node-${index}` },
            React.createElement('div', { className: `pres-path-node-icon tone-${tone}` }, React.createElement(Icon, { size: 17 })),
            React.createElement('div', { className: 'pres-path-node-label' }, label),
            React.createElement('div', { className: 'pres-path-node-sub' }, sub),
          )),
        ),
        React.createElement('div', { className: 'pres-rule-row' },
          [['shared_ioc', 'same IOC appears across sources'], ['temporal_ioc_overlap', 'two sources within the configured window'], ['analyst review', 'decision is retained with rationale']].map(([label, text]) => React.createElement('div', { key: label, className: 'pres-rule-item' },
            React.createElement('span', { className: 'pres-rule-marker' }),
            React.createElement('span', { className: 'pres-rule-label' }, label),
            React.createElement('span', { className: 'pres-rule-text' }, text),
          )),
        ),
      ),
      React.createElement('aside', { className: 'pres-panel pres-decision-panel' },
        React.createElement('div', { className: 'pres-panel-kicker' }, 'Decision trail'),
        React.createElement('h2', { className: 'pres-panel-title' }, 'Evidence before confidence'),
        React.createElement('div', { className: 'pres-decision-status' },
          React.createElement(Bell, { size: 15 }), React.createElement('span', null, 'Awaiting analyst decision'),
        ),
        React.createElement('div', { className: 'pres-decision-list' },
          [
            ['Input', '2 findings / 2 sources', 'stored context snapshot'],
            ['Rule', 'shared_ioc + temporal overlap', 'deterministic candidate'],
            ['Model', 'brain client', 'evaluation step documented'],
            ['Output', 'promote · reject · defer', 'analytical note + audit trail'],
          ].map(([label, value, detail]) => React.createElement('div', { key: label, className: 'pres-decision-item' },
            React.createElement('div', { className: 'pres-decision-label' }, label),
            React.createElement('div', { className: 'pres-decision-value' }, value),
            React.createElement('div', { className: 'pres-decision-detail' }, detail),
          )),
        ),
        React.createElement('div', { className: 'pres-decision-note' }, 'Automation surfaces a path. It does not turn the path into truth by itself.'),
      ),
    ),
    React.createElement('div', { className: 'pres-inline-actions' },
      React.createElement('button', { className: 'pres-outline-button', onClick: () => navigate('/presentation/architecture') }, 'Show the real pipeline', React.createElement(ArrowRight, { size: 15 })),
    ),
  )
}

function Architecture({ navigate }) {
  return React.createElement(React.Fragment, null,
    React.createElement(SectionHeader, {
      eyebrow: '04 · ARCHITECTURE',
      title: 'The pipeline documented in the repository.',
      copy: 'This is the five-layer architecture from Noctis’ docs, simplified for a short explanation. The labels describe implemented modules; the rebuild direction is separated below.',
      action: React.createElement(StatusPill, { tone: 'implemented' }, 'implemented path'),
    }),
    React.createElement('section', { className: 'pres-architecture-panel pres-panel' },
      React.createElement('div', { className: 'pres-layer-stack' },
        layers.map((layer, index) => React.createElement(React.Fragment, { key: layer.number },
          React.createElement('div', { className: `pres-layer layer-${layer.color}` },
            React.createElement('div', { className: 'pres-layer-index' }, layer.number),
            React.createElement('div', { className: 'pres-layer-icon' }, React.createElement(layer.icon, { size: 18 })),
            React.createElement('div', { className: 'pres-layer-content' },
              React.createElement('div', { className: 'pres-layer-heading' },
                React.createElement('h2', { className: 'pres-layer-title' }, layer.title),
                React.createElement(StatusPill, { tone: 'implemented' }, layer.status),
              ),
              React.createElement('div', { className: 'pres-layer-items' }, layer.items.map(item => React.createElement('span', { key: item }, item))),
              React.createElement('div', { className: 'pres-layer-detail' }, layer.detail),
            ),
          ),
          index < layers.length - 1 && React.createElement('div', { className: 'pres-layer-connector' }, React.createElement(ArrowRight, { size: 16 })),
        )),
      ),
      React.createElement('div', { className: 'pres-architecture-footer' },
        React.createElement(MiniFlow, { compact: true }),
        React.createElement('div', { className: 'pres-architecture-note' }, 'PostgreSQL is the shared store. The Go daemon embeds and serves the React dashboard.'),
      ),
    ),
    React.createElement('section', { className: 'pres-loop-panel' },
      React.createElement('div', { className: 'pres-panel-kicker' }, 'The loop I cared about'),
      React.createElement('div', { className: 'pres-loop-row' },
        [['raw signal', Radio], ['entity / IOC', Target], ['relationship', GitBranch], ['candidate', Route], ['human verification', ShieldCheck]].map(([label, Icon], index) => React.createElement(React.Fragment, { key: label },
          React.createElement('div', { className: 'pres-loop-node' }, React.createElement(Icon, { size: 15 }), React.createElement('span', null, label)),
          index < 4 && React.createElement(ArrowRight, { size: 14, className: 'pres-loop-arrow' }),
        )),
      ),
    ),
    React.createElement('div', { className: 'pres-inline-actions' },
      React.createElement('button', { className: 'pres-outline-button', onClick: () => navigate('/presentation/lessons') }, 'Show the rebuild direction', React.createElement(ArrowRight, { size: 15 })),
    ),
  )
}

function Lessons() {
  return React.createElement(React.Fragment, null,
    React.createElement(SectionHeader, {
      eyebrow: '05 · PAUSE / REBUILD',
      title: 'The project showed me where the harder problem was.',
      copy: 'Collection worked. The weak point was interpretation: the practical signal-to-noise ratio was not good enough to treat every model output as intelligence.',
      action: React.createElement(StatusPill, { tone: 'planned' }, 'rebuild direction'),
    }),
    React.createElement('div', { className: 'pres-lesson-grid' },
      React.createElement('section', { className: 'pres-panel pres-lesson-main' },
        React.createElement('div', { className: 'pres-panel-kicker' }, 'What I learned'),
        React.createElement('div', { className: 'pres-lesson-cards' },
          [
            ['Signal is not intelligence', 'Large archives are easy to grow. Context, confidence, provenance and evidence are harder.', Radio, 'blue'],
            ['Automation needs an audit trail', 'A classifier saying X is not the same as X being true. The why has to survive the pipeline.', ShieldCheck, 'cyan'],
            ['Specialized context matters', 'The next system needs better data, evaluation and domain-specific interpretation before more features.', Brain, 'purple'],
          ].map(([title, text, Icon, tone]) => React.createElement('div', { key: title, className: 'pres-lesson-card' },
            React.createElement('div', { className: `pres-lesson-icon tone-${tone}` }, React.createElement(Icon, { size: 16 })),
            React.createElement('h2', { className: 'pres-lesson-title' }, title),
            React.createElement('p', { className: 'pres-lesson-copy' }, text),
          )),
        ),
      ),
      React.createElement('aside', { className: 'pres-panel pres-pause-panel' },
        React.createElement('div', { className: 'pres-panel-kicker' }, 'Why I paused'),
        React.createElement('div', { className: 'pres-pause-stat' },
          React.createElement('span', { className: 'pres-pause-stat-value' }, '20–25%'),
          React.createElement('span', { className: 'pres-pause-stat-label' }, 'personal operating estimate of noise still getting through'),
        ),
        React.createElement('p', { className: 'pres-side-copy' }, 'The estimate is empirical, from running the system, and not a benchmark. I did not want to keep adding features on top of a processing layer I did not trust enough.'),
        React.createElement('div', { className: 'pres-pause-divider' }),
        React.createElement('div', { className: 'pres-panel-kicker' }, 'Documented rebuild direction'),
        React.createElement('div', { className: 'pres-rebuild-list' },
          [
            ['01', 'Relabel and validate', 'gold set + review worksheets'],
            ['02', 'Build a clean dataset', 'exclusions, dedup, temporal split, IOC masking'],
            ['03', 'Measure a baseline', 'two-stage relevance gate + six-class classifier'],
            ['04', 'Return to a specialized agent', 'after evaluation and better data'],
          ].map(([number, title, detail]) => React.createElement('div', { key: number, className: 'pres-rebuild-item' },
            React.createElement('span', { className: 'pres-rebuild-number' }, number),
            React.createElement('div', null,
              React.createElement('div', { className: 'pres-rebuild-title' }, title),
              React.createElement('div', { className: 'pres-rebuild-detail' }, detail),
            ),
          )),
        ),
      ),
    ),
    React.createElement('section', { className: 'pres-final-callout' },
      React.createElement('div', { className: 'pres-final-mark' }, React.createElement(Target, { size: 18 })),
      React.createElement('div', null,
        React.createElement('div', { className: 'pres-callout-title' }, 'What I want to return to'),
        React.createElement('div', { className: 'pres-callout-copy' }, 'A self-hosted, pocket-sized intelligence system where important conclusions stay understandable and verifiable, even when the collection layer is mostly automated.'),
      ),
    ),
  )
}

export default function Presentation({ path, navigate }) {
  const currentPath = useMemo(() => navItems.some(item => item.path === path) ? path : '/presentation', [path])
  useEffect(() => {
    const previousOverflowX = document.body.style.overflowX
    document.body.style.overflowX = 'hidden'
    return () => {
      document.body.style.overflowX = previousOverflowX
    }
  }, [])
  const content = currentPath === '/presentation/brief'
    ? React.createElement(Brief, { navigate })
    : currentPath === '/presentation/correlation'
      ? React.createElement(Correlation, { navigate })
      : currentPath === '/presentation/architecture'
        ? React.createElement(Architecture, { navigate })
        : currentPath === '/presentation/lessons'
          ? React.createElement(Lessons, { navigate })
          : React.createElement(Overview, { navigate })

  return React.createElement('div', { className: 'pres-shell' },
    React.createElement('div', { className: 'pres-ambient pres-ambient-one' }),
    React.createElement('div', { className: 'pres-ambient pres-ambient-two' }),
    React.createElement(Header, { currentPath, navigate }),
    React.createElement('main', { className: 'pres-main' }, content),
    React.createElement(FooterNav, { currentPath, navigate }),
  )
}
