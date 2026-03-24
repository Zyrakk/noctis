package brain

import (
	"context"
	"strings"
	"testing"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
)

// ---------------------------------------------------------------------------
// mockCorrStore — in-memory mock for CorrelationStore interface
// ---------------------------------------------------------------------------

type mockCorrStore struct {
	sharedIOCs      []archive.SharedIOCResult
	handleReuse     []archive.HandleReuseResult
	temporalOverlap []archive.TemporalOverlapResult
	entityClusters  map[string][]archive.EntityClusterResult

	upsertedCorrelations []*archive.Correlation
	upsertedCandidates   []*archive.CorrelationCandidate
	upsertedEntities     map[string]string // id -> type
}

func newMockCorrStore() *mockCorrStore {
	return &mockCorrStore{
		entityClusters:   make(map[string][]archive.EntityClusterResult),
		upsertedEntities: make(map[string]string),
	}
}

func (m *mockCorrStore) FindSharedIOCs(_ context.Context, _ int) ([]archive.SharedIOCResult, error) {
	return m.sharedIOCs, nil
}
func (m *mockCorrStore) FindHandleReuse(_ context.Context, _ int) ([]archive.HandleReuseResult, error) {
	return m.handleReuse, nil
}
func (m *mockCorrStore) FindTemporalIOCOverlap(_ context.Context, _ int, _ int) ([]archive.TemporalOverlapResult, error) {
	return m.temporalOverlap, nil
}
func (m *mockCorrStore) FindEntityClusters(_ context.Context, entityType string, _ int) ([]archive.EntityClusterResult, error) {
	return m.entityClusters[entityType], nil
}
func (m *mockCorrStore) UpsertCorrelation(_ context.Context, c *archive.Correlation) error {
	m.upsertedCorrelations = append(m.upsertedCorrelations, c)
	return nil
}
func (m *mockCorrStore) UpsertCandidate(_ context.Context, c *archive.CorrelationCandidate) error {
	m.upsertedCandidates = append(m.upsertedCandidates, c)
	return nil
}
func (m *mockCorrStore) UpsertEntity(_ context.Context, id, entityType string, _ map[string]any) error {
	m.upsertedEntities[id] = entityType
	return nil
}

// ---------------------------------------------------------------------------
// Helper tests
// ---------------------------------------------------------------------------

func TestCorrClusterID_Deterministic(t *testing.T) {
	id1 := corrClusterID("shared_ioc", "ip:1.2.3.4")
	id2 := corrClusterID("shared_ioc", "ip:1.2.3.4")
	if id1 != id2 {
		t.Errorf("same input produced different IDs: %s != %s", id1, id2)
	}
	if !strings.HasPrefix(id1, "corr:shared_ioc:") {
		t.Errorf("unexpected prefix: %s", id1)
	}
}

func TestCorrClusterID_DifferentTypeDifferentID(t *testing.T) {
	id1 := corrClusterID("shared_ioc", "ip:1.2.3.4")
	id2 := corrClusterID("handle_reuse", "ip:1.2.3.4")
	if id1 == id2 {
		t.Error("different types should produce different IDs")
	}
}

func TestClampConfidence(t *testing.T) {
	tests := []struct {
		input, want float64
	}{
		{0.5, 0.5},
		{1.5, 1.0},
		{-0.1, 0.0},
		{0.0, 0.0},
		{1.0, 1.0},
	}
	for _, tt := range tests {
		got := clampConfidence(tt.input)
		if got != tt.want {
			t.Errorf("clampConfidence(%f) = %f, want %f", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Rule tests
// ---------------------------------------------------------------------------

func makeTestCorrelator(mock *mockCorrStore) *Correlator {
	return NewCorrelator(mock, config.CorrelationConfig{
		Enabled:              true,
		MinEvidenceThreshold: 3,
		TemporalWindowHours:  48,
	})
}

func TestCorrelateSharedIOCs_AboveThreshold(t *testing.T) {
	mock := newMockCorrStore()
	mock.sharedIOCs = []archive.SharedIOCResult{
		{IOCType: "ip", IOCValue: "1.2.3.4", Sources: []string{"a", "b", "c"}, FindingIDs: []string{"f1", "f2", "f3"}, SourceCount: 3},
	}
	c := makeTestCorrelator(mock)

	corrs, cands := c.correlateSharedIOCs(context.Background())
	if corrs != 1 {
		t.Errorf("correlations = %d, want 1", corrs)
	}
	if cands != 0 {
		t.Errorf("candidates = %d, want 0", cands)
	}
	if len(mock.upsertedCorrelations) != 1 {
		t.Fatalf("upserted correlations = %d, want 1", len(mock.upsertedCorrelations))
	}
	cr := mock.upsertedCorrelations[0]
	if cr.CorrelationType != "shared_ioc" {
		t.Errorf("type = %s, want shared_ioc", cr.CorrelationType)
	}
	if cr.Confidence <= 0 || cr.Confidence > 1.0 {
		t.Errorf("confidence = %f, out of range", cr.Confidence)
	}
	if cr.Method != "rule" {
		t.Errorf("method = %s, want rule", cr.Method)
	}
}

func TestCorrelateSharedIOCs_BelowThreshold(t *testing.T) {
	mock := newMockCorrStore()
	mock.sharedIOCs = []archive.SharedIOCResult{
		{IOCType: "domain", IOCValue: "evil.com", Sources: []string{"a", "b"}, FindingIDs: []string{"f1", "f2"}, SourceCount: 2},
	}
	c := makeTestCorrelator(mock)

	corrs, cands := c.correlateSharedIOCs(context.Background())
	if corrs != 0 {
		t.Errorf("correlations = %d, want 0", corrs)
	}
	if cands != 1 {
		t.Errorf("candidates = %d, want 1", cands)
	}
}

func TestCorrelateSharedIOCs_EmptyResults(t *testing.T) {
	mock := newMockCorrStore()
	c := makeTestCorrelator(mock)

	corrs, cands := c.correlateSharedIOCs(context.Background())
	if corrs != 0 || cands != 0 {
		t.Errorf("expected 0,0 for empty results, got %d,%d", corrs, cands)
	}
}

func TestCorrelateHandleReuse_AboveThreshold(t *testing.T) {
	mock := newMockCorrStore()
	mock.handleReuse = []archive.HandleReuseResult{
		{Author: "IntelBroker", AuthorID: "ib_123", Sources: []string{"a", "b", "c"}, SourceIDs: []string{"s1", "s2", "s3"}, FindingIDs: []string{"f1", "f2", "f3"}, SourceCount: 3},
	}
	c := makeTestCorrelator(mock)

	corrs, cands := c.correlateHandleReuse(context.Background())
	if corrs != 1 {
		t.Errorf("correlations = %d, want 1", corrs)
	}
	if cands != 0 {
		t.Errorf("candidates = %d, want 0", cands)
	}
	// Should create an entity with normalized ID.
	expectedEntityID := "entity:threat_actor:intelbroker"
	if _, ok := mock.upsertedEntities[expectedEntityID]; !ok {
		t.Errorf("expected entity %s to be upserted, got keys: %v", expectedEntityID, mock.upsertedEntities)
	}
}

func TestCorrelateTemporalOverlap_AboveThreshold(t *testing.T) {
	mock := newMockCorrStore()
	mock.temporalOverlap = []archive.TemporalOverlapResult{
		{FindingA: "f1", FindingB: "f2", SourceA: "src_a", SourceB: "src_b", SharedIOCs: []string{"ip:1.2.3.4", "domain:evil.com", "ip:5.6.7.8"}, SharedCount: 3},
	}
	c := makeTestCorrelator(mock)

	corrs, cands := c.correlateTemporalOverlap(context.Background())
	if corrs != 1 {
		t.Errorf("correlations = %d, want 1", corrs)
	}
	if cands != 0 {
		t.Errorf("candidates = %d, want 0", cands)
	}
}

func TestCorrelateEntityClusters_MixedThreshold(t *testing.T) {
	mock := newMockCorrStore()
	mock.entityClusters["threat_actor"] = []archive.EntityClusterResult{
		{EntityA: "e:actor:a", NameA: "ActorA", EntityB: "e:actor:b", NameB: "ActorB", SharedIDs: []string{"m1", "m2", "m3"}, SharedNames: []string{"Malware1", "Malware2", "Malware3"}, SharedCount: 3},
	}
	mock.entityClusters["malware"] = []archive.EntityClusterResult{
		{EntityA: "e:malware:x", NameA: "MalX", EntityB: "e:malware:y", NameB: "MalY", SharedIDs: []string{"c2_1"}, SharedNames: []string{"C2Server"}, SharedCount: 1},
	}
	c := makeTestCorrelator(mock)

	corrs, cands := c.correlateEntityClusters(context.Background())
	if corrs != 1 {
		t.Errorf("correlations = %d, want 1 (actor cluster above threshold)", corrs)
	}
	if cands != 1 {
		t.Errorf("candidates = %d, want 1 (malware cluster below threshold)", cands)
	}
}

func TestCorrelationCycle_AggregatesCounts(t *testing.T) {
	mock := newMockCorrStore()
	mock.sharedIOCs = []archive.SharedIOCResult{
		{IOCType: "ip", IOCValue: "1.1.1.1", Sources: []string{"a", "b", "c"}, FindingIDs: []string{"f1", "f2", "f3"}, SourceCount: 3},
	}
	mock.handleReuse = []archive.HandleReuseResult{
		{Author: "actor1", Sources: []string{"x", "y"}, SourceIDs: []string{"s1", "s2"}, FindingIDs: []string{"f4", "f5"}, SourceCount: 2},
	}
	c := makeTestCorrelator(mock)

	c.runCycle(context.Background())

	// 1 correlation (shared_ioc above threshold) + 1 candidate (handle below threshold)
	if len(mock.upsertedCorrelations) != 1 {
		t.Errorf("upserted correlations = %d, want 1", len(mock.upsertedCorrelations))
	}
	if len(mock.upsertedCandidates) != 1 {
		t.Errorf("upserted candidates = %d, want 1", len(mock.upsertedCandidates))
	}
}
