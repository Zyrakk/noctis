package capture

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebAdaptersIdentityParserPaginationAndHostileHTML(t *testing.T) {
	for _, kind := range []string{"html", "paste", "forum"} {
		t.Run(kind, func(t *testing.T) {
			tag := "article"
			if kind == "paste" {
				tag = "pre"
			}
			cfg := WebConfig{ParserVersion: "p1", MaxItems: 2}
			raw := []byte(fmt.Sprintf(`<%s data-id="native-9">Offer á <script>evil()</script> CVE-2026-12345</%s><a rel="next" href="?page=2">next</a>`, tag, tag))
			page, e := ParseWeb(raw, "https://example.org/topic", kind, cfg, time.Now())
			if e != nil || len(page.Items) != 1 || strings.Contains(string(page.Items[0].Payload), "evil") || page.Next != "https://example.org/topic?page=2" {
				t.Fatal(page, e)
			}
			cfg.ParserVersion = "p2"
			next, e := ParseWeb(raw, "https://example.org/topic", kind, cfg, time.Now())
			if e != nil || next.Items[0].NativeID != page.Items[0].NativeID || next.Items[0].Revision == page.Items[0].Revision {
				t.Fatal("parser identity/revision", next, e)
			}
			cfg.MaxItems = 1
			if _, e = ParseWeb(append(raw, []byte(fmt.Sprintf(`<%s>second</%s>`, tag, tag))...), "https://example.org/topic", kind, cfg, time.Now()); e == nil {
				t.Fatal("item limit silently truncated")
			}
			if _, e = ParseWeb([]byte(`<article>x</article><a rel="next" href="http://169.254.169.254/">next</a>`), "https://example.org/topic", "html", cfg, time.Now()); e == nil {
				t.Fatal("pagination crossed origin")
			}
		})
	}
}

func TestTorSOCKSRemoteDNSRestrictedProfileFailClosed(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	host := strings.Repeat("a", 56) + ".onion"
	targets := make(chan string, 10)
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				greeting := make([]byte, 3)
				if _, e = io.ReadFull(conn, greeting); e != nil {
					return
				}
				conn.Write([]byte{5, 0})
				head := make([]byte, 5)
				if _, e = io.ReadFull(conn, head); e != nil {
					return
				}
				if head[3] != 3 {
					return
				}
				name := make([]byte, int(head[4]))
				io.ReadFull(conn, name)
				port := make([]byte, 2)
				io.ReadFull(conn, port)
				targets <- string(name)
				calls.Add(1)
				conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				req, e := http.ReadRequest(bufio.NewReader(conn))
				if e != nil {
					return
				}
				if req.URL.Path == "/redirect" {
					fmt.Fprintf(conn, "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				} else {
					fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				}
			}()
		}
	}()
	f := Fetcher{Tor: &TorProfile{SOCKSAddress: listener.Addr().String(), Authorities: map[string]bool{host: true}}, lookupIP: func(context.Context, string, string) ([]net.IP, error) {
		t.Error("Tor performed local DNS")
		return nil, nil
	}}
	b, e := f.Get(context.Background(), "http://"+host+"/")
	if e != nil || string(b) != "ok" {
		t.Fatal(string(b), e)
	}
	if <-targets != host {
		t.Fatal("SOCKS hostname lost")
	}
	if _, e = f.Get(context.Background(), "http://"+host+"/redirect"); e == nil || calls.Load() != 2 {
		t.Fatal("unsafe Tor redirect allowed", e, calls.Load())
	}
	<-targets
	if _, e = f.GetWithHeaders(context.Background(), "http://"+host+"/redirect", http.Header{"Authorization": []string{"Bearer synthetic"}}); e == nil || calls.Load() != 3 {
		t.Fatal("credential redirect followed", e)
	}
	<-targets
	if _, e = (Fetcher{}).Get(context.Background(), "http://"+host); e == nil {
		t.Fatal("onion exemption without profile")
	}
	f.Tor.SOCKSAddress = "127.0.0.1:1"
	if _, e = f.Get(context.Background(), "http://"+host); e == nil {
		t.Fatal("unavailable SOCKS fell back direct")
	}
	listener.Close()
	<-done
}
