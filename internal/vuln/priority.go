package vuln

import (
	"math"

	"github.com/Zyrakk/noctis/internal/archive"
)

// ComputePriority calculates a composite priority score and label for a vulnerability.
// Weights: KEV=auto-critical, EPSS=0.4, CVSS=0.3, dark_web=0.2, exploit=0.1.
func ComputePriority(vuln *archive.Vulnerability) (score float64, label string) {
	// KEV-listed = automatic critical (confirmed active exploitation).
	if vuln.KEVListed {
		score = 1.0
		return score, "critical"
	}

	// EPSS weight (0-0.4): probability of exploitation.
	if vuln.EPSSScore != nil {
		score += *vuln.EPSSScore * 0.4
	}

	// CVSS weight (0-0.3): technical severity.
	if vuln.CVSSV31Score != nil {
		score += (*vuln.CVSSV31Score / 10.0) * 0.3
	}

	// Dark web activity weight (0-0.2): threat actor interest.
	if vuln.DarkWebMentions > 0 {
		mentionScore := math.Min(float64(vuln.DarkWebMentions)/10.0, 1.0)
		score += mentionScore * 0.2
	}

	// Exploit availability weight (0-0.1).
	if vuln.ExploitAvailable {
		score += 0.1
	}

	switch {
	case score >= 0.8:
		label = "critical"
	case score >= 0.6:
		label = "high"
	case score >= 0.3:
		label = "medium"
	case score >= 0.1:
		label = "low"
	default:
		label = "info"
	}

	return score, label
}
