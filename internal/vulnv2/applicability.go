package vulnv2

import (
	"encoding/json"
	"strconv"
	"strings"
)

type truth int

const (
	unknown truth = iota
	no
	yes
)

type cpeMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
type configNode struct {
	Operator string       `json:"operator"`
	Negate   bool         `json:"negate"`
	Matches  []cpeMatch   `json:"cpeMatch"`
	Nodes    []configNode `json:"nodes"`
	Children []configNode `json:"children"`
}

func numericVersion(v string) ([]uint64, bool) {
	if len(v) > 128 {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]uint64, len(parts))
	for i, p := range parts {
		n, e := strconv.ParseUint(p, 10, 64)
		if e != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}
func compareVersion(a, b string) (int, bool) {
	aa, ok := numericVersion(a)
	if !ok {
		return 0, false
	}
	bb, ok := numericVersion(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < max(len(aa), len(bb)); i++ {
		var x, y uint64
		if i < len(aa) {
			x = aa[i]
		}
		if i < len(bb) {
			y = bb[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}
func matchVersion(m cpeMatch, cpe, version string) truth {
	parts := strings.Split(m.Criteria, ":")
	asset := strings.Split(cpe, ":")
	if len(parts) != 13 || len(asset) != 13 || parts[0] != "cpe" || parts[1] != "2.3" || asset[0] != "cpe" || asset[1] != "2.3" {
		return unknown
	}
	for i := 2; i < 13; i++ {
		if i == 5 {
			continue
		}
		if strings.ContainsAny(parts[i], `\?`) {
			return unknown
		}
		if parts[i] != "*" && parts[i] != asset[i] {
			if i <= 4 {
				return no
			}
			return unknown
		}
	}
	if !m.Vulnerable {
		return unknown
	}
	if version == "" {
		return unknown
	}
	if _, ok := numericVersion(version); !ok {
		return unknown
	}
	if parts[5] != "*" {
		cmp, ok := compareVersion(version, parts[5])
		if !ok {
			return unknown
		}
		if cmp != 0 {
			return no
		}
	}
	bounds := []struct {
		value string
		kind  int
	}{{m.StartIncluding, 0}, {m.StartExcluding, 1}, {m.EndIncluding, 2}, {m.EndExcluding, 3}}
	for _, b := range bounds {
		if b.value == "" {
			continue
		}
		cmp, ok := compareVersion(version, b.value)
		if !ok {
			return unknown
		}
		if b.kind == 0 && cmp < 0 || b.kind == 1 && cmp <= 0 || b.kind == 2 && cmp > 0 || b.kind == 3 && cmp >= 0 {
			return no
		}
	}
	return yes
}
func combine(items []truth, operator string) truth {
	if len(items) == 0 {
		return unknown
	}
	hasUnknown := false
	for _, v := range items {
		if v == unknown {
			hasUnknown = true
		}
		if operator == "AND" && v == no {
			return no
		}
		if operator == "OR" && v == yes {
			return yes
		}
	}
	if hasUnknown {
		return unknown
	}
	if operator == "AND" {
		return yes
	}
	if operator == "OR" {
		return no
	}
	return unknown
}
func evalNode(n configNode, cpe, version string, depth int) truth {
	if depth > 8 || len(n.Matches) > 1000 {
		return unknown
	}
	items := []truth{}
	for _, m := range n.Matches {
		items = append(items, matchVersion(m, cpe, version))
	}
	for _, child := range append(n.Nodes, n.Children...) {
		items = append(items, evalNode(child, cpe, version, depth+1))
	}
	operator := n.Operator
	if operator == "" {
		operator = "OR"
	}
	v := combine(items, operator)
	if n.Negate {
		if v == yes {
			return no
		}
		if v == no {
			return yes
		}
	}
	return v
}

// Evaluate supports numeric dotted versions and explicit CPE 2.3 predicates.
// Unsupported versions, complex CPE escaping and missing inventory stay unknown.
func Evaluate(body json.RawMessage, cpe, version string) (string, string) {
	var record struct {
		Configurations []configNode `json:"configurations"`
	}
	if json.Unmarshal(body, &record) != nil {
		return "unknown", "invalid_nvd_record"
	}
	if version == "" {
		return "unknown", "asset_version_unknown"
	}
	items := []truth{}
	for _, n := range record.Configurations {
		items = append(items, evalNode(n, cpe, version, 0))
	}
	switch combine(items, "OR") {
	case yes:
		return "affected_version", "supported_numeric_cpe_range_matches_inventory; exposure_unknown"
	case no:
		return "not_affected_version", "supported_numeric_cpe_range_excludes_inventory; exposure_unknown"
	default:
		return "unknown", "unsupported_or_incomplete_configuration; exposure_unknown"
	}
}
