// Package evidence defines references to immutable representations.
package evidence

import (
	"fmt"
	"unicode/utf8"
)

// Ref uses UTF-8 byte offsets in the half-open interval [Start, End).
type Ref struct {
	ObservationID  string `json:"observation_id"`
	Revision       string `json:"revision"`
	Hash           string `json:"hash"`
	Representation string `json:"representation"`
	Start          int    `json:"start"`
	End            int    `json:"end"`
}

func (r Ref) Validate(text []byte) error {
	if r.ObservationID == "" || r.Revision == "" || r.Hash == "" || r.Representation == "" {
		return fmt.Errorf("incomplete evidence identity")
	}
	if !utf8.Valid(text) || r.Start < 0 || r.End <= r.Start || r.End > len(text) {
		return fmt.Errorf("invalid UTF-8 byte interval")
	}
	if !utf8.Valid(text[:r.Start]) || !utf8.Valid(text[:r.End]) {
		return fmt.Errorf("interval splits UTF-8 character")
	}
	return nil
}
