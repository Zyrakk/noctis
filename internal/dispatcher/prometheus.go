package dispatcher

import (
	"time"

	"github.com/Zyrakk/noctis/internal/models"
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics holds all noctis_* Prometheus counters, gauges, and
// histograms. Create one instance per process via NewPrometheusMetrics.
type PrometheusMetrics struct {
	findingsTotal        *prometheus.CounterVec
	collectorLastSuccess *prometheus.GaugeVec
	collectorErrorsTotal *prometheus.CounterVec
	matcherMatchedTotal  *prometheus.CounterVec
	matcherDroppedTotal  prometheus.Counter
	llmRequestsTotal     *prometheus.CounterVec
	llmLatencySeconds    *prometheus.HistogramVec
	llmErrorsTotal       *prometheus.CounterVec
	canaryActiveTotal    prometheus.Gauge
	canaryTriggeredTotal prometheus.Counter
	channelMessagesTotal *prometheus.CounterVec
	actorPostsTotal      *prometheus.CounterVec
	actorSeverityScore   *prometheus.GaugeVec
	iocExtractedTotal    *prometheus.CounterVec
	networkPolicyActive  prometheus.Gauge
	graphEntitiesTotal   *prometheus.GaugeVec
	graphEdgesTotal      *prometheus.GaugeVec
}

// NewPrometheusMetrics creates and registers all noctis_* metrics with the
// provided Registerer. Use prometheus.NewRegistry() in tests to keep
// registrations isolated.
func NewPrometheusMetrics(reg prometheus.Registerer) *PrometheusMetrics {
	m := &PrometheusMetrics{}

	m.findingsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_findings_total",
		Help: "Total number of enriched findings processed, by source, severity, and category.",
	}, []string{"source", "severity", "category"})

	m.collectorLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "noctis_collector_last_success",
		Help: "Unix timestamp of the last successful collection run, by source.",
	}, []string{"source"})

	m.collectorErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_collector_errors_total",
		Help: "Total number of collection errors, by source.",
	}, []string{"source"})

	m.matcherMatchedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_matcher_matched_total",
		Help: "Total number of findings matched by each rule.",
	}, []string{"rule"})

	m.matcherDroppedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "noctis_matcher_dropped_total",
		Help: "Total number of findings dropped by the matcher (no rule matched).",
	})

	m.llmRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_llm_requests_total",
		Help: "Total number of LLM requests, by provider and task.",
	}, []string{"provider", "task"})

	m.llmLatencySeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "noctis_llm_latency_seconds",
		Help:    "LLM request latency in seconds, by provider and task.",
		Buckets: []float64{0.5, 1, 2, 4, 8, 16, 32, 64},
	}, []string{"provider", "task"})

	m.llmErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_llm_errors_total",
		Help: "Total number of LLM errors, by provider.",
	}, []string{"provider"})

	m.canaryActiveTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "noctis_canary_active_total",
		Help: "Number of active canary tokens currently deployed.",
	})

	m.canaryTriggeredTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "noctis_canary_triggered_total",
		Help: "Total number of canary token trigger events observed.",
	})

	m.channelMessagesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_channel_messages_total",
		Help: "Total number of messages processed per channel.",
	}, []string{"channel"})

	m.actorPostsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_actor_posts_total",
		Help: "Total number of findings attributed to each actor.",
	}, []string{"actor"})

	m.actorSeverityScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "noctis_actor_severity_score",
		Help: "Current threat level score for each known actor.",
	}, []string{"actor"})

	m.iocExtractedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "noctis_ioc_extracted_total",
		Help: "Total number of IOCs extracted from findings, by type.",
	}, []string{"type"})

	m.networkPolicyActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "noctis_network_policy_active",
		Help: "Number of active network policies currently enforced.",
	})

	m.graphEntitiesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "noctis_graph_entities_total",
		Help: "Total number of entities in the knowledge graph, by type.",
	}, []string{"type"})

	m.graphEdgesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "noctis_graph_edges_total",
		Help: "Total number of edges in the knowledge graph, by relationship.",
	}, []string{"relationship"})

	reg.MustRegister(
		m.findingsTotal,
		m.collectorLastSuccess,
		m.collectorErrorsTotal,
		m.matcherMatchedTotal,
		m.matcherDroppedTotal,
		m.llmRequestsTotal,
		m.llmLatencySeconds,
		m.llmErrorsTotal,
		m.canaryActiveTotal,
		m.canaryTriggeredTotal,
		m.channelMessagesTotal,
		m.actorPostsTotal,
		m.actorSeverityScore,
		m.iocExtractedTotal,
		m.networkPolicyActive,
		m.graphEntitiesTotal,
		m.graphEdgesTotal,
	)

	return m
}

// RecordFinding updates counters derived from an enriched finding:
//   - increments findingsTotal for the finding's source, severity, and category
//   - increments iocExtractedTotal once per IOC, keyed by IOC type
//   - increments channelMessagesTotal when the source is telegram
//   - increments actorPostsTotal when the finding has a non-empty Author
func (m *PrometheusMetrics) RecordFinding(ef models.EnrichedFinding) {
	m.findingsTotal.WithLabelValues(
		ef.Source,
		ef.Severity.String(),
		string(ef.Category),
	).Inc()

	for _, ioc := range ef.IOCs {
		m.iocExtractedTotal.WithLabelValues(ioc.Type).Inc()
	}

	if ef.Source == models.SourceTypeTelegram {
		m.channelMessagesTotal.WithLabelValues(ef.SourceName).Inc()
	}

	if ef.Author != "" {
		m.actorPostsTotal.WithLabelValues(ef.Author).Inc()
	}
}

// RecordMatcherMatch increments the matcherMatchedTotal counter for the given
// rule name.
func (m *PrometheusMetrics) RecordMatcherMatch(rule string) {
	m.matcherMatchedTotal.WithLabelValues(rule).Inc()
}

// RecordMatcherDrop increments the matcherDroppedTotal counter.
func (m *PrometheusMetrics) RecordMatcherDrop() {
	m.matcherDroppedTotal.Inc()
}

// RecordCollectorSuccess sets collectorLastSuccess to the current Unix
// timestamp for the given source.
func (m *PrometheusMetrics) RecordCollectorSuccess(source string) {
	m.collectorLastSuccess.WithLabelValues(source).Set(float64(time.Now().Unix()))
}

// RecordCollectorError increments the collectorErrorsTotal counter for the
// given source.
func (m *PrometheusMetrics) RecordCollectorError(source string) {
	m.collectorErrorsTotal.WithLabelValues(source).Inc()
}

// RecordLLMRequest increments llmRequestsTotal and records latencySeconds in
// the llmLatencySeconds histogram for the given provider and task.
func (m *PrometheusMetrics) RecordLLMRequest(provider, task string, latencySeconds float64) {
	m.llmRequestsTotal.WithLabelValues(provider, task).Inc()
	m.llmLatencySeconds.WithLabelValues(provider, task).Observe(latencySeconds)
}

// RecordLLMError increments the llmErrorsTotal counter for the given provider.
func (m *PrometheusMetrics) RecordLLMError(provider string) {
	m.llmErrorsTotal.WithLabelValues(provider).Inc()
}
