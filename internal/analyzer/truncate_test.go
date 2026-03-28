package analyzer

import "testing"

func TestTruncateContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		limit int
		want  int // expected length (input or limit, whichever smaller)
	}{
		{"short", "hello", 100, 5},
		{"exact", "hello", 5, 5},
		{"truncated", "hello world this is long", 10, 13}, // 10 + len("...")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateContent(tt.input, tt.limit)
			if len(got) > tt.limit+3 { // +3 for "..."
				t.Errorf("truncateContent(%d) length = %d; want <= %d", tt.limit, len(got), tt.limit+3)
			}
		})
	}
}

func TestTruncateContent_ZeroLimit(t *testing.T) {
	input := "hello"
	got := truncateContent(input, 0)
	if got != input {
		t.Errorf("truncateContent(0) = %q; want %q (no truncation)", got, input)
	}
}
