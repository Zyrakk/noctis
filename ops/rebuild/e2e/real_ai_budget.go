package main

// Campaign accounting deliberately never refunds reservations. This is separate
// from the production daily/monthly ledger: a new UTC day cannot buy more calls.
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const campaignLimit int64 = 5_000_000_000 // nanodollars = USD 5 total
const campaignAttempts = 20

type campaignEntry struct {
	Database string `json:"database"`
	Maximum  int64  `json:"maximum_units"`
	Actual   int64  `json:"actual_units"`
	Attempt  string `json:"attempt_id,omitempty"`
	Complete bool   `json:"complete"`
}
type campaignState struct {
	Version      int                              `json:"version"`
	Fingerprint  string                           `json:"config_fingerprint"`
	Stopped      bool                             `json:"stopped"`
	Entries      []campaignEntry                  `json:"entries"`
	Quarantines  []campaignQuarantine             `json:"quarantines,omitempty"`
	Publications []campaignPublicationDisposition `json:"publication_dispositions,omitempty"`
	LatestAudit  *campaignAuditRef                `json:"latest_audit,omitempty"`
}
type campaignAuditRef struct {
	Kind    string `json:"kind"`
	Attempt string `json:"attempt_id"`
}
type campaignQuarantine struct {
	Attempt     string `json:"attempt_id"`
	Fingerprint string `json:"config_fingerprint"`
	PriorSHA    string `json:"prior_campaign_sha256"`
	Reason      string `json:"reason"`
	Time        string `json:"time"`
	BinarySHA   string `json:"corrected_binary_sha256"`
}

func (c *campaign) quarantined(id string) bool {
	if id == "" {
		return false
	}
	for _, q := range c.state.Quarantines {
		if q.Attempt == id {
			return true
		}
	}
	return false
}

type campaign struct {
	path  string
	lock  *os.File
	state campaignState
}

// init is deliberately explicit. Resume NEVER creates missing state; callers
// must retain the same campaign path for all executions of the authorization.
func openCampaign(path, fingerprint string, init bool) (*campaign, error) {
	return openCampaignAudited(path, fingerprint, init, nil)
}
func openCampaignAudited(path, fingerprint string, init bool, audit *campaignQuarantine) (*campaign, error) {
	return openCampaignWithAudit(path, fingerprint, init, audit, nil, nil)
}
func openCampaignWithAudit(path, fingerprint string, init bool, audit *campaignQuarantine, publication *campaignPublicationDisposition, validate func(*campaign, campaignPublicationDisposition) error) (*campaign, error) {
	if !filepath.IsAbs(path) || fingerprint == "" {
		return nil, errors.New("absolute campaign path and fingerprint required")
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("campaign directory must be private (0700)")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("campaign lock unavailable")
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("campaign already locked")
	}
	c := &campaign{path: path, lock: lock}
	fail := func() (*campaign, error) {
		c.close()
		return nil, errors.New("campaign state missing, unsafe, incompatible or unfinished; no invocation authorized")
	}
	if init {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return fail()
		}
		f.Close()
		c.state = campaignState{Version: 1, Fingerprint: fingerprint, Entries: []campaignEntry{}}
		if c.save() != nil {
			return fail()
		}
	} else {
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fail()
		}
		raw, e := os.ReadFile(path)
		if e != nil || strictCampaign(raw, &c.state) != nil {
			return fail()
		}
	}
	if c.state.Version != 1 || c.state.Fingerprint != fingerprint || len(c.state.Entries) > campaignAttempts {
		return fail()
	}
	if audit != nil {
		raw, err := os.ReadFile(path)
		if err != nil || init || !c.state.Stopped || audit.Fingerprint != fingerprint || audit.PriorSHA != fmt.Sprintf("%x", sha256.Sum256(raw)) || uuid.Validate(audit.Attempt) != nil || strings.TrimSpace(audit.Reason) == "" || !validSHA(audit.BinarySHA) {
			return fail()
		}
		if _, err := time.Parse(time.RFC3339Nano, audit.Time); err != nil {
			return fail()
		}
		found := false
		for _, entry := range c.state.Entries {
			if !entry.Complete && !c.quarantined(entry.Attempt) {
				if entry.Attempt != audit.Attempt || entry.Actual != 0 {
					return fail()
				}
				found = true
			}
		}
		if !found || c.quarantined(audit.Attempt) {
			return fail()
		}
		c.state.Quarantines = append(c.state.Quarantines, *audit)
		c.state.LatestAudit = &campaignAuditRef{Kind: "uncertain", Attempt: audit.Attempt}
		c.state.Stopped = false
	}
	if publication != nil {
		raw, err := os.ReadFile(path)
		if err != nil || init || audit != nil || !c.state.Stopped || !validPublicationDisposition(*publication, fingerprint) || publication.PriorSHA != fmt.Sprintf("%x", sha256.Sum256(raw)) || c.publicationAcknowledged(publication.Attempt) || c.quarantined(publication.Attempt) || validate == nil {
			return fail()
		}
		found := false
		for _, entry := range c.state.Entries {
			if entry.Attempt == publication.Attempt && entry.Maximum == publication.Maximum && entry.Actual == publication.Actual {
				found = true
			}
		}
		if !found || validate(c, *publication) != nil {
			return fail()
		}
		c.state.Publications = append(c.state.Publications, *publication)
		c.state.LatestAudit = &campaignAuditRef{Kind: "settled_publication_rejected", Attempt: publication.Attempt}
		c.state.Stopped = false
	}
	if c.state.Stopped {
		return fail()
	}
	seen := map[string]bool{}
	for _, q := range c.state.Quarantines {
		if seen[q.Attempt] || uuid.Validate(q.Attempt) != nil || q.Fingerprint != fingerprint || !validSHA(q.PriorSHA) || !validSHA(q.BinarySHA) || strings.TrimSpace(q.Reason) == "" {
			return fail()
		}
		if _, err := time.Parse(time.RFC3339Nano, q.Time); err != nil {
			return fail()
		}
		seen[q.Attempt] = true
		matched := 0
		for _, entry := range c.state.Entries {
			if entry.Attempt == q.Attempt && !entry.Complete && entry.Actual == 0 {
				matched++
			}
		}
		if matched != 1 {
			return fail()
		}
	}
	for _, entry := range c.state.Entries {
		if (!entry.Complete && !c.quarantined(entry.Attempt) && !c.publicationAcknowledged(entry.Attempt)) || entry.Database == "" || entry.Maximum <= 0 || entry.Actual < 0 {
			return fail()
		}
	}
	for _, p := range c.state.Publications {
		if seen[p.Attempt] || !validPublicationDisposition(p, fingerprint) {
			return fail()
		}
		seen[p.Attempt] = true
		matched := 0
		for _, entry := range c.state.Entries {
			if entry.Attempt == p.Attempt && entry.Maximum == p.Maximum && entry.Actual == p.Actual {
				matched++
			}
		}
		if matched != 1 {
			return fail()
		}
	}
	if c.state.LatestAudit != nil {
		if !seen[c.state.LatestAudit.Attempt] || (c.state.LatestAudit.Kind != "uncertain" && c.state.LatestAudit.Kind != "settled_publication_rejected") {
			return fail()
		}
		if c.state.LatestAudit.Kind == "uncertain" && (len(c.state.Quarantines) == 0 || c.state.Quarantines[len(c.state.Quarantines)-1].Attempt != c.state.LatestAudit.Attempt) {
			return fail()
		}
		if c.state.LatestAudit.Kind == "settled_publication_rejected" && (len(c.state.Publications) == 0 || c.state.Publications[len(c.state.Publications)-1].Attempt != c.state.LatestAudit.Attempt) {
			return fail()
		}
	} else if len(c.state.Publications) > 0 {
		return fail()
	}
	if total, err := c.exposure(); err != nil || total > campaignLimit {
		return fail()
	}
	if audit != nil || publication != nil {
		if c.save() != nil {
			return fail()
		}
	}
	return c, nil
}
func validSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
func strictCampaign(raw []byte, state *campaignState) error {
	// Reuse the production strict decoder without allowing extra fields.
	return strictRealJSON(raw, state)
}
func (c *campaign) close() {
	if c.lock != nil {
		syscall.Flock(int(c.lock.Fd()), syscall.LOCK_UN)
		c.lock.Close()
		c.lock = nil
	}
}
func (c *campaign) exposure() (int64, error) {
	var total int64
	for _, entry := range c.state.Entries {
		amount := max(entry.Maximum, entry.Actual)
		if amount <= 0 || amount > math.MaxInt64-total {
			return total, errors.New("campaign invalid exposure")
		}
		total += amount
	}
	return total, nil
}
func (c *campaign) reserve(database string, maximum int64) error {
	total, err := c.exposure()
	if err != nil || c.state.Stopped || database == "" || maximum <= 0 || maximum > campaignLimit-total || len(c.state.Entries) >= campaignAttempts {
		return errors.New("campaign budget or attempt bound exceeded")
	}
	for _, entry := range c.state.Entries {
		if !entry.Complete && !c.quarantined(entry.Attempt) && !c.publicationAcknowledged(entry.Attempt) {
			return errors.New("prior invocation unresolved")
		}
	}
	c.state.Entries = append(c.state.Entries, campaignEntry{Database: database, Maximum: maximum})
	return c.save() // Must reach durable storage BEFORE Store.Once.
}
func (c *campaign) finish(attempt string, actual int64, success bool) error {
	if len(c.state.Entries) == 0 {
		return errors.New("no campaign reservation")
	}
	entry := &c.state.Entries[len(c.state.Entries)-1]
	if entry.Complete || actual < 0 {
		return errors.New("invalid campaign reconciliation")
	}
	entry.Attempt, entry.Actual, entry.Complete = attempt, actual, success
	if !success || actual > entry.Maximum {
		c.state.Stopped = true
	}
	return c.save()
}
func (c *campaign) save() error {
	raw, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), ".campaign-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(raw, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, c.path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(c.path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
