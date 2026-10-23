package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditedQuarantineExactAttemptAndNoRefund(t *testing.T) {
	path := campaignTestPath(t)
	c, e := openCampaign(path, "v1", true)
	if e != nil {
		t.Fatal(e)
	}
	id := uuid.NewString()
	if e = c.reserve("synthetic_v2", 3_000_000_000); e != nil {
		t.Fatal(e)
	}
	if e = c.finish(id, 0, false); e != nil {
		t.Fatal(e)
	}
	c.close()
	raw, _ := os.ReadFile(path)
	q := campaignQuarantine{Attempt: id, Fingerprint: "v1", PriorSHA: fmt.Sprintf("%x", sha256.Sum256(raw)), Reason: "explicit acknowledged uncertain billing; independent evaluation only", Time: time.Now().UTC().Format(time.RFC3339Nano), BinarySHA: strings.Repeat("a", 64)}
	for _, mutate := range []func(*campaignQuarantine){func(q *campaignQuarantine) { q.Attempt = uuid.NewString() }, func(q *campaignQuarantine) { q.PriorSHA = strings.Repeat("0", 64) }, func(q *campaignQuarantine) { q.Fingerprint = "wrong" }, func(q *campaignQuarantine) { q.Reason = "" }} {
		bad := q
		mutate(&bad)
		if c, e = openCampaignAudited(path, "v1", false, &bad); e == nil {
			c.close()
			t.Fatal("invalid quarantine accepted")
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(raw) {
			t.Fatal("rejected audit changed state")
		}
	}
	c, e = openCampaignAudited(path, "v1", false, &q)
	if e != nil {
		t.Fatal(e)
	}
	if c.state.Entries[0].Complete || c.state.Entries[0].Actual != 0 || !c.quarantined(id) {
		t.Fatal("uncertainty rewritten")
	}
	c.close()
	if c, e = openCampaignAudited(path, "v1", false, &q); e == nil {
		c.close()
		t.Fatal("audit replay accepted")
	}
	c, e = openCampaign(path, "v1", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.reserve("synthetic_v2", 2_000_000_001); e == nil {
		t.Fatal("quarantine refunded exposure")
	}
	if e = c.reserve("synthetic_v2", 2_000_000_000); e != nil {
		t.Fatal(e)
	}
	if e = c.finish(uuid.NewString(), 0, false); e != nil {
		t.Fatal(e)
	}
	c.close()
	if c, e = openCampaign(path, "v1", false); e == nil {
		c.close()
		t.Fatal("new uncertainty bypassed old quarantine")
	}
}

func TestAuditedQuarantineCrashUnknownAttemptCannotBeAcknowledged(t *testing.T) {
	path := campaignTestPath(t)
	c, e := openCampaign(path, "v1", true)
	if e != nil {
		t.Fatal(e)
	}
	c.reserve("synthetic_v2", 100)
	c.close()
	raw, _ := os.ReadFile(path)
	q := campaignQuarantine{Attempt: uuid.NewString(), Fingerprint: "v1", PriorSHA: fmt.Sprintf("%x", sha256.Sum256(raw)), Reason: "crash", Time: time.Now().UTC().Format(time.RFC3339Nano), BinarySHA: strings.Repeat("a", 64)}
	if c, e = openCampaignAudited(path, "v1", false, &q); e == nil {
		c.close()
		t.Fatal("unknown crash attempt fabricated")
	}
}

func campaignTestPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return filepath.Join(dir, "campaign.json")
}
func TestCampaignRestartAndNoRolloverRefund(t *testing.T) {
	path := campaignTestPath(t)
	c, e := openCampaign(path, "tariff-v1", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.reserve("synthetic_v2_day1", 3_000_000_000); e != nil {
		t.Fatal(e)
	}
	if e = c.finish("attempt1", 100, true); e != nil {
		t.Fatal(e)
	}
	c.close()
	// A different database/day/month does not reset the same authorization.
	c, e = openCampaign(path, "tariff-v1", false)
	if e != nil {
		t.Fatal(e)
	}
	defer c.close()
	if e = c.reserve("synthetic_v2_next_month", 2_000_000_001); e == nil {
		t.Fatal("rollover or small actual refunded reservation")
	}
	if e = c.reserve("synthetic_v2_next_month", 2_000_000_000); e != nil {
		t.Fatal(e)
	}
	if e = c.finish("attempt2", 10, true); e != nil {
		t.Fatal(e)
	}
	if e = c.reserve("synthetic_v2_next_month", 1); e == nil {
		t.Fatal("exceeded all-time USD5")
	}
}
func TestCampaignUnknownExposureFailsClosedAfterRestart(t *testing.T) {
	for _, finish := range []bool{false, true} {
		t.Run(map[bool]string{false: "crash_after_reserve", true: "timeout_without_usage"}[finish], func(t *testing.T) {
			path := campaignTestPath(t)
			c, e := openCampaign(path, "v1", true)
			if e != nil {
				t.Fatal(e)
			}
			if e = c.reserve("synthetic_v2", 200); e != nil {
				t.Fatal(e)
			}
			if finish {
				if e = c.finish("attempt-unknown", 0, false); e != nil {
					t.Fatal(e)
				}
			}
			if total, e := c.exposure(); e != nil || total != 200 {
				t.Fatal("unknown exposure lost")
			}
			c.close()
			if c, e = openCampaign(path, "v1", false); e == nil {
				c.close()
				t.Fatal("restart allowed unknown execution")
			}
		})
	}
}
func TestCampaignLockMissingStateAndFingerprint(t *testing.T) {
	path := campaignTestPath(t)
	if c, e := openCampaign(path, "v1", false); e == nil {
		c.close()
		t.Fatal("missing state silently initialized")
	}
	c, e := openCampaign(path, "v1", true)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := openCampaign(path, "v1", false); e == nil {
		second.close()
		t.Fatal("second process acquired lock")
	}
	c.close()
	if c, e = openCampaign(path, "v2", false); e == nil {
		c.close()
		t.Fatal("tariff/provider changes ignored")
	}
	if e = os.WriteFile(path, []byte(`{"version":1,"config_fingerprint":"v1","entries":[],"unknown":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if c, e = openCampaign(path, "v1", false); e == nil {
		c.close()
		t.Fatal("corrupt state accepted")
	}
}
func TestCampaignTwentyAttemptsCumulative(t *testing.T) {
	path := campaignTestPath(t)
	for i := 0; i < campaignAttempts; i++ {
		c, e := openCampaign(path, "v1", i == 0)
		if e != nil {
			t.Fatal(e)
		}
		if e = c.reserve("synthetic_v2", 1); e != nil {
			t.Fatal(e)
		}
		if e = c.finish("attempt", 0, true); e != nil {
			t.Fatal(e)
		}
		c.close()
	}
	c, e := openCampaign(path, "v1", false)
	if e != nil {
		t.Fatal(e)
	}
	defer c.close()
	if e = c.reserve("synthetic_v2", 1); e == nil {
		t.Fatal("21st physical attempt permitted after restarts")
	}
}
func TestCampaignUnderestimateStopsAndRetainsActual(t *testing.T) {
	c, e := openCampaign(campaignTestPath(t), "v1", true)
	if e != nil {
		t.Fatal(e)
	}
	defer c.close()
	if e = c.reserve("synthetic_v2", 100); e != nil {
		t.Fatal(e)
	}
	if e = c.finish("attempt", 200, true); e != nil {
		t.Fatal(e)
	}
	if total, e := c.exposure(); e != nil || total != 200 {
		t.Fatal("must retain max(maximum,actual)")
	}
	if e = c.reserve("synthetic_v2", 1); e == nil {
		t.Fatal("accounting exception did not stop campaign")
	}
}
func TestRealInputsRequireExplicitReviewedContract(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "synthetic.key")
	if e := os.WriteFile(key, []byte("SYNTHETIC-NEVER-REAL"), 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "inputs.json")
	body := `{"adapter":"openai-responses","provider":"synthetic","endpoint":"https://example.invalid/v1/responses","model":"synthetic","api_key_file":"` + key + `","price":{"version":"test","input_units_per_token":1,"output_units_per_token":2},"limits":{"max_input_tokens":1024,"max_output_tokens":512,"deadline_ms":30000},"provider_contract_reviewed":false}`
	if e := os.WriteFile(path, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := loadRealAIInputs(path, false); e != nil {
		t.Fatal(e)
	}
	if _, e := loadRealAIInputs(path, true); e == nil {
		t.Fatal("unreviewed provider enabled wire")
	}
	if e := os.Chmod(key, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := loadRealAIInputs(path, false); e == nil {
		t.Fatal("insecure keyfile accepted")
	}
}

func TestCampaignOverCapReceiptPersists(t *testing.T) {
	c, e := openCampaign(campaignTestPath(t), "overcap", true)
	if e != nil {
		t.Fatal(e)
	}
	defer c.close()
	if e = c.reserve("synthetic", 100); e != nil {
		t.Fatal(e)
	}
	if e = c.finish("synthetic-attempt", campaignLimit+1, true); e != nil {
		t.Fatal(e)
	}
	if total, e := c.exposure(); e != nil || total != campaignLimit+1 {
		t.Fatal("overcap exposure lost", total, e)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	actual := campaignLimit + 1
	g := realGuard{campaign: c, receiptPath: path, stopped: true, attempts: []realAttempt{{Actual: &actual}}}
	if e = g.receipt(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var receipt map[string]any
	if json.Unmarshal(raw, &receipt) != nil || receipt["campaign_conservative_exposure_units"] != float64(actual) || receipt["known_tariff_units_this_database"] != float64(actual) {
		t.Fatal("known/exposure receipt lost")
	}
	if e = c.reserve("synthetic", 1); e == nil {
		t.Fatal("overcap reservation")
	}
}

func TestRealAdapterFingerprintAndRequired(t *testing.T) {
	a := realAIInputs{Adapter: "openai-chat"}
	b := a
	b.Adapter = "openai-responses"
	if realFingerprint(a) == realFingerprint(b) {
		t.Fatal("adapter missing from campaign identity")
	}
}
