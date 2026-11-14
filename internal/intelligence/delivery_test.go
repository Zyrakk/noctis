package intelligence

import (
	"context"
	"errors"
	"testing"
)

func TestValidateDeliveryEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://localhost", "http://127.0.0.1:8080/events?kind=brief",
		"https://example.com", "https://example.com:1/events", "https://example.com:65535/",
		"HTTP://example.com/path%20name?q=one%20two#fragment",
		"http://[::1]", "http://[::1]:8080/events", "https://[2001:db8::1]/?q=1",
		"http://[::ffff:127.0.0.1]:80", "http://[fe80::1%25eth0]:8080/",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if err := ValidateDeliveryEndpoint(endpoint); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, endpoint := range []string{
		"", "/events", "//example.com/events", "example.com", "http:events",
		"http://", "https:///events", "http://:80/", "ftp://example.com", "mailto:user@example.com",
		"http://example.com/%zz", "http://example.com/?q=%zz", "http://example.com/#%zz",
		"http://exa%zzmple.com", "http://example.com:\n80", "http://bad host/events",
		"http://example.com:", "http://example.com:abc", "http://example.com:-1",
		"http://example.com:0", "http://example.com:65536", "http://example.com:999999999999999999999999",
		"http://[::1", "http://[::1]:", "http://[::1]:65536", "http://[::1]:abc",
		"http://[]", "http://[localhost]", "http://[127.0.0.1]", "http://[2001:db8::gg]",
		"http://::1", "http://2001:db8::1:8080", "http://example.com]/",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if err := ValidateDeliveryEndpoint(endpoint); !errors.Is(err, ErrInvalidDeliveryEndpoint) {
				t.Fatalf("accepted invalid endpoint: %v", err)
			}
			// An invalid DSN would fail parsing if validation reached PostgreSQL.
			if err := (Worker{DSN: "://invalid-dsn"}).DispatchOnce(context.Background(), endpoint, nil); !errors.Is(err, ErrInvalidDeliveryEndpoint) {
				t.Fatalf("endpoint not rejected before database connection: %v", err)
			}
		})
	}
}
