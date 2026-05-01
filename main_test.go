package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid", Config{ListenAddr: "127.0.0.1:1", Socks5Addr: "127.0.0.1:2"}, false},
		{"missing listen", Config{Socks5Addr: "127.0.0.1:2"}, true},
		{"missing socks5", Config{ListenAddr: "127.0.0.1:1"}, true},
		{"both empty", Config{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateConfig() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid", func(t *testing.T) {
		path := filepath.Join(dir, "valid.json")
		data := `{"listen_addr":"127.0.0.1:5566","socks5_addr":"127.0.0.1:5555","username":"u","password":"p","debug":true}`
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig() = %v", err)
		}
		want := Config{ListenAddr: "127.0.0.1:5566", Socks5Addr: "127.0.0.1:5555", Username: "u", Password: "p", Debug: true}
		if cfg != want {
			t.Fatalf("got %+v, want %+v", cfg, want)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := loadConfig(filepath.Join(dir, "nope.json")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("bad json", func(t *testing.T) {
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("expected error for bad json")
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("expected validation error")
		}
	})
}

func TestParsePort(t *testing.T) {
	cases := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"80", 80, false},
		{"443", 443, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := parsePort(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestBuildConnectRequest(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		got, err := buildConnectRequest("127.0.0.1", 80)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}
		if !bytes.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		got, err := buildConnectRequest("::1", 443)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4+16+2 {
			t.Fatalf("len=%d, want %d", len(got), 4+16+2)
		}
		if got[3] != 0x04 {
			t.Fatalf("atyp = %d, want 0x04", got[3])
		}
		if got[len(got)-2] != 0x01 || got[len(got)-1] != 0xBB {
			t.Fatalf("port bytes = %v, want %v", got[len(got)-2:], []byte{0x01, 0xBB})
		}
	})

	t.Run("hostname", func(t *testing.T) {
		got, err := buildConnectRequest("example.com", 8080)
		if err != nil {
			t.Fatal(err)
		}
		if got[3] != 0x03 {
			t.Fatalf("atyp = %d, want 0x03", got[3])
		}
		hostLen := int(got[4])
		if hostLen != len("example.com") {
			t.Fatalf("len byte = %d", hostLen)
		}
		host := string(got[5 : 5+hostLen])
		if host != "example.com" {
			t.Fatalf("host = %q", host)
		}
		if got[len(got)-2] != 0x1F || got[len(got)-1] != 0x90 {
			t.Fatalf("port bytes = %v, want %v", got[len(got)-2:], []byte{0x1F, 0x90})
		}
	})

	t.Run("hostname too long", func(t *testing.T) {
		long := strings.Repeat("a", 256)
		if _, err := buildConnectRequest(long, 80); err == nil {
			t.Fatal("expected error")
		}
	})
}

// startMockSOCKS5 starts a minimal SOCKS5 server (no-auth, CONNECT only).
// It dials the real target and pipes traffic between client and target.
func startMockSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5(c)
		}
	}()
	return ln.Addr().String()
}

func handleMockSOCKS5(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 262)

	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}
	atyp := buf[3]
	var host string
	switch atyp {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 0x04:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	go func() { _, _ = io.Copy(target, c) }()
	_, _ = io.Copy(c, target)
}

func startProxy(t *testing.T, cfg Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenAddr = ln.Addr().String()
	srv := &http.Server{
		Handler:  buildHandler(cfg),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String()
}

func TestHTTPProxy_PlainHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}))
	defer backend.Close()

	socks5Addr := startMockSOCKS5(t)
	proxyAddr := startProxy(t, Config{Socks5Addr: socks5Addr})

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "hello from /foo"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestHTTPProxy_HTTPSConnect(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "secure %s", r.URL.Path)
	}))
	defer backend.Close()

	socks5Addr := startMockSOCKS5(t)
	proxyAddr := startProxy(t, Config{Socks5Addr: socks5Addr})

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if backendTransport, ok := backend.Client().Transport.(*http.Transport); ok && backendTransport.TLSClientConfig != nil {
		tlsCfg = backendTransport.TLSClientConfig.Clone()
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsCfg,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(backend.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), "secure /x"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestHTTPProxy_BadGatewayWhenSocksDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	proxyAddr := startProxy(t, Config{Socks5Addr: deadAddr})
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}

	resp, err := client.Get("http://example.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}
