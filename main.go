package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
)

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

const (
	defaultListenAddr = "127.0.0.1:5566"
	defaultSocks5Addr = "127.0.0.1:5555"
)

var version = "dev"

type Config struct {
	ListenAddr string `json:"listen_addr"`
	Socks5Addr string `json:"socks5_addr"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Debug      bool   `json:"debug"`
}

func main() {
	var (
		configPath  string
		listenAddr  string
		socks5Addr  string
		username    string
		password    string
		debug       bool
		showVersion bool
	)

	flag.StringVarP(&configPath, "config", "c", "", "path to JSON config file (overrides other flags)")
	flag.StringVarP(&listenAddr, "listen", "l", defaultListenAddr, "HTTP proxy listen address (host:port)")
	flag.StringVarP(&socks5Addr, "socks5", "s", defaultSocks5Addr, "upstream SOCKS5 server (host:port)")
	flag.StringVarP(&username, "user", "u", "", "SOCKS5 username")
	flag.StringVarP(&password, "password", "p", "", "SOCKS5 password")
	flag.BoolVarP(&debug, "debug", "d", false, "enable per-request logging")
	flag.BoolVarP(&showVersion, "version", "v", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	var (
		cfg Config
		err error
	)
	if configPath != "" {
		cfg, err = loadConfig(configPath)
		if err != nil {
			log.Fatalf("failed to load %s: %v", configPath, err)
		}
	} else {
		cfg = Config{
			ListenAddr: listenAddr,
			Socks5Addr: socks5Addr,
			Username:   username,
			Password:   password,
			Debug:      debug,
		}
		if err := validateConfig(cfg); err != nil {
			log.Fatalf("invalid configuration: %v", err)
		}
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           buildHandler(cfg),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("socks2http %s — starting http proxy on %s via socks5 %s", version, cfg.ListenAddr, cfg.Socks5Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http proxy stopped: %v", err)
	}
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg Config) error {
	if cfg.ListenAddr == "" {
		return errors.New("listen_addr is required")
	}
	if err := validateAddr("listen_addr", cfg.ListenAddr, false); err != nil {
		return err
	}
	if cfg.Socks5Addr == "" {
		return errors.New("socks5_addr is required")
	}
	if err := validateAddr("socks5_addr", cfg.Socks5Addr, true); err != nil {
		return err
	}
	return nil
}

func validateAddr(label, addr string, requireHost bool) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q: %w", label, addr, err)
	}
	if requireHost && host == "" {
		return fmt.Errorf("%s %q: host is required", label, addr)
	}
	n, err := strconv.Atoi(portStr)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%s %q: invalid port", label, addr)
	}
	return nil
}

func buildHandler(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		clientAddr := r.RemoteAddr

		if r.Method == http.MethodConnect {
			status := handleConnect(w, r, cfg)
			logRequest(cfg, r, clientAddr, status, started)
			return
		}

		sw := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
		handleHTTP(sw, r, cfg)
		logRequest(cfg, r, clientAddr, sw.statusCode, started)
	})
}

func handleHTTP(w http.ResponseWriter, r *http.Request, cfg Config) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialViaSocks5(ctx, cfg, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func handleConnect(w http.ResponseWriter, r *http.Request, cfg Config) int {
	targetConn, err := dialViaSocks5(r.Context(), cfg, "tcp", r.Host)
	if err != nil {
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		return http.StatusBadGateway
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = targetConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = targetConn.Close()
		return 0
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer targetConn.Close()
		_, _ = io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		defer targetConn.Close()
		_, _ = io.Copy(clientConn, targetConn)
	}()
	wg.Wait()

	return http.StatusOK
}

func dialViaSocks5(ctx context.Context, cfg Config, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", cfg.Socks5Addr)
	if err != nil {
		return nil, err
	}

	if err := socks5Handshake(conn, cfg.Username, cfg.Password, addr); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func socks5Handshake(conn net.Conn, username, password, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", target, err)
	}

	port, err := parsePort(portStr)
	if err != nil {
		return err
	}

	methods := []byte{0x00}
	if username != "" || password != "" {
		methods = []byte{0x00, 0x02}
	}

	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("invalid socks version: %d", reply[0])
	}
	if reply[1] == 0xFF {
		return errors.New("socks5: no acceptable auth method")
	}

	if reply[1] == 0x02 {
		if err := socks5UserPassAuth(conn, username, password); err != nil {
			return err
		}
	}

	req, err := buildConnectRequest(host, port)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed, code=%d", resp[1])
	}

	if err := discardBoundAddr(conn, resp[3]); err != nil {
		return err
	}
	return nil
}

func socks5UserPassAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("username/password too long")
	}

	req := []byte{0x01, byte(len(username))}
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks5 username/password auth failed")
	}
	return nil
}

func buildConnectRequest(host string, port uint16) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req := []byte{0x05, 0x01, 0x00, 0x01}
			req = append(req, ip4...)
			req = append(req, byte(port>>8), byte(port))
			return req, nil
		}
		ip16 := ip.To16()
		req := []byte{0x05, 0x01, 0x00, 0x04}
		req = append(req, ip16...)
		req = append(req, byte(port>>8), byte(port))
		return req, nil
	}

	if len(host) > 255 {
		return nil, errors.New("hostname too long")
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	return req, nil
}

func discardBoundAddr(conn net.Conn, atyp byte) error {
	var toRead int
	switch atyp {
	case 0x01:
		toRead = 4 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		toRead = int(l[0]) + 2
	case 0x04:
		toRead = 16 + 2
	default:
		return fmt.Errorf("unknown atyp: %d", atyp)
	}

	buf := make([]byte, toRead)
	_, err := io.ReadFull(conn, buf)
	return err
}

func parsePort(port string) (uint16, error) {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	if n < 1 || n > 65535 {
		return 0, errors.New("port out of range")
	}
	return uint16(n), nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func removeHopByHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if name := strings.TrimSpace(f); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func logRequest(cfg Config, r *http.Request, clientAddr string, status int, started time.Time) {
	if !cfg.Debug {
		return
	}
	target := r.URL.String()
	if r.Method == http.MethodConnect {
		target = r.Host
	}
	log.Printf("%s %s from=%s status=%d duration=%s", r.Method, target, clientAddr, status, time.Since(started).Round(time.Millisecond))
}

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
