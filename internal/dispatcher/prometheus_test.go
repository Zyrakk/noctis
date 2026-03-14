package dispatcher

import (
	"testing"

	"github.com/Zyrakk/noctis/internal/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newIsolatedMetrics creates a PrometheusMetrics instance backed by a fresh,
// isolated registry so tests do not share or pollute the global default registry.
func newIsolatedMetrics() *PrometheusMetrics {
	return NewPrometheusMetrics(prometheus.NewRegistry())
}

// TestPrometheusMetrics_RecordFinding verifies that RecordFinding correctly
// increments the relevant counters for a telegram finding with two IOCs.
func TestPrometheusMetrics_RecordFinding(t *testing.T) {
	m := newIsolatedMetrics()

	ef := models.EnrichedFinding{
		Finding: models.Finding{
			Source:     models.SourceTypeTelegram,
			SourceName: "test-channel",
			Author:     "threat-actor-42",
		},
		Severity: models.SeverityCritical,
		Category: models.CategoryCredentialLeak,
		IOCs: []models.IOC{
			{Type: models.IOCTypeIP, Value: "1.2.3.4"},
			{Type: models.IOCTypeDomain, Value: "evil.example.com"},
		},
	}

	m.RecordFinding(ef)

	// findingsTotal{source="telegram", severity="critical", category="credential_leak"} == 1
	if got := testutil.ToFloat64(m.findingsTotal.WithLabelValues(
		models.SourceTypeTelegram,
		models.SeverityCritical.String(),
		string(models.CategoryCredentialLeak),
	)); got != 1 {
		t.Errorf("findingsTotal = %v; want 1", got)
	}

	// iocExtractedTotal{type="ip"} == 1
	if got := testutil.ToFloat64(m.iocExtractedTotal.WithLabelValues(models.IOCTypeIP)); got != 1 {
		t.Errorf("iocExtractedTotal{ip} = %v; want 1", got)
	}

	// iocExtractedTotal{type="domain"} == 1
	if got := testutil.ToFloat64(m.iocExtractedTotal.WithLabelValues(models.IOCTypeDomain)); got != 1 {
		t.Errorf("iocExtractedTotal{domain} = %v; want 1", got)
	}

	// channelMessagesTotal should be incremented because source is telegram
	if got := testutil.ToFloat64(m.channelMessagesTotal.WithLabelValues("test-channel")); got != 1 {
		t.Errorf("channelMessagesTotal{test-channel} = %v; want 1", got)
	}

	// actorPostsTotal should be incremented because Author is non-empty
	if got := testutil.ToFloat64(m.actorPostsTotal.WithLabelValues("threat-actor-42")); got != 1 {
		t.Errorf("actorPostsTotal{threat-actor-42} = %v; want 1", got)
	}
}

// TestPrometheusMetrics_RecordMatcherResult verifies that RecordMatcherMatch
// and RecordMatcherDrop update their respective counters correctly.
func TestPrometheusMetrics_RecordMatcherResult(t *testing.T) {
	m := newIsolatedMetrics()

	m.RecordMatcherMatch("rule-x")
	m.RecordMatcherMatch("rule-x")
	m.RecordMatcherDrop()

	// matcherMatchedTotal{rule="rule-x"} == 2
	if got := testutil.ToFloat64(m.matcherMatchedTotal.WithLabelValues("rule-x")); got != 2 {
		t.Errorf("matcherMatchedTotal{rule-x} = %v; want 2", got)
	}

	// matcherDroppedTotal == 1
	if got := testutil.ToFloat64(m.matcherDroppedTotal); got != 1 {
		t.Errorf("matcherDroppedTotal = %v; want 1", got)
	}
}
