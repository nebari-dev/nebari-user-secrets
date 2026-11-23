package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/auth"
	"github.com/nebari-dev/nebari-user-secrets/internal/config"
	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/httpapi"
	"github.com/nebari-dev/nebari-user-secrets/internal/model"
	"github.com/nebari-dev/nebari-user-secrets/internal/service"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	"github.com/nebari-dev/nebari-user-secrets/internal/telemetry"
)

const (
	managementAddr = ":8444"
	healthAddr     = ":8080"
	maxBackoff     = 30 * time.Second
)

// parseServeFlags parses the serve arguments and returns the config path.
func parseServeFlags(args []string, stderr io.Writer) (string, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to the config file (required)")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *cfgPath == "" {
		return "", errors.New("--config is required")
	}
	return *cfgPath, nil
}

func runServe(args []string, stdout, stderr io.Writer) int {
	cfgPath, err := parseServeFlags(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfgPath, logger); err != nil {
		logger.Error("serve failed", "error", err.Error())
		return 1
	}
	return 0
}

// newHTTPServer returns a server with bounded headers and timeouts. The header
// cap (16 KiB) bounds a bearer token before anything parses it.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func serve(ctx context.Context, cfgPath string, logger *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings() {
		logger.Warn(w, "guard_mode", cfg.Guard.Mode)
	}
	shutdownTel, err := telemetry.Setup(ctx)
	if err != nil {
		return err
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTel(c)
	}()

	reg, err := cfg.BuildRegistry()
	if err != nil {
		return err
	}
	rc, err := restConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	aud := audit.NewSlogAuditSink(logger)
	st := store.NewKubernetesSecretStore(cs, cfg.Namespace, time.Now)
	kek := crypto.NewKubernetesKEK(cs, cfg.Namespace, st, aud)
	sealer := crypto.NewSealer(kek, rand.Reader)
	svc := service.NewSecretService(st, sealer, aud, reg, cfg.Limits, time.Now)

	keys := auth.NewJWKSKeySet(cfg.Keycloak.JWKSURL, &http.Client{Timeout: 10 * time.Second}, time.Now)
	verifier := auth.NewSessionVerifier(keys, cfg.Keycloak.Issuers, cfg.Keycloak.ClientID, time.Now)
	mgmt := httpapi.NewManagementHandler(verifier, svc, reg, httpapi.StubGuardStatus{}, logger)

	certs, err := newCertReloader(cfg.TLS.CertFile, cfg.TLS.KeyFile, logger)
	if err != nil {
		return err
	}
	var kekReady atomic.Bool
	gate := &kekGate{}
	onReady := func() {
		gate.set(mgmt)
		kekReady.Store(true)
		logger.Info("master key ready")
	}

	// Health first, so a slow API server during bootstrap still leaves the
	// pod with /healthz; /readyz stays 503 until the master key is loaded.
	healthSrv := newHTTPServer(healthAddr, healthHandler(&kekReady))
	errc := make(chan error, 2)
	go func() { errc <- healthSrv.ListenAndServe() }()

	if err := kek.Bootstrap(ctx); err != nil {
		if !errors.Is(err, crypto.ErrKEKUnavailable) {
			return fmt.Errorf("master key: %w", err)
		}
		logger.Error("master key unavailable, serving 503 and retrying", "error", err.Error())
		go retryBootstrap(ctx, kek.Bootstrap, sleepCtx, onReady, logger)
	} else {
		onReady()
	}

	tlsSrv := newHTTPServer(managementAddr, gate)
	tlsSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate}

	go func() { errc <- tlsSrv.ListenAndServeTLS("", "") }()
	logger.Info("serving", "management", managementAddr, "health", healthAddr)

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	sc, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, s := range []*http.Server{tlsSrv, healthSrv} {
		_ = s.Shutdown(sc)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// sleepCtx waits d or until ctx ends, and reports whether it waited fully.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// retryBootstrap retries boot with doubling backoff (1 s, capped at 30 s)
// until it succeeds, then calls onReady. It returns when ctx ends.
func retryBootstrap(ctx context.Context, boot func(context.Context) error,
	sleep func(context.Context, time.Duration) bool, onReady func(), logger *slog.Logger) {
	delay := time.Second
	for {
		if !sleep(ctx, delay) {
			return
		}
		err := boot(ctx)
		if err == nil {
			onReady()
			return
		}
		logger.Error("master key bootstrap retry failed", "error", err.Error())
		delay = min(delay*2, maxBackoff)
	}
}

// kekGate answers 503 kek_unavailable until the real handler is set.
type kekGate struct{ real atomic.Pointer[http.Handler] }

func (g *kekGate) set(h http.Handler) { g.real.Store(&h) }

func (g *kekGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := g.real.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(model.APIError{Error: "kek_unavailable"})
}

// healthHandler serves /healthz (process alive) and /readyz (master key
// bootstrapped; the TLS certificate is loaded before anything listens).
func healthHandler(kekReady *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if kekReady.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mux
}

// certReloader serves a TLS certificate and re-reads it when the mtime of
// either file changes. A failed reload keeps the last good certificate.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger

	mu              sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod time.Time
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	cm, km, err := r.mtimes()
	if err != nil {
		return nil, fmt.Errorf("tls files: %w", err)
	}
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls certificate: %w", err)
	}
	r.cert, r.certMod, r.keyMod = &c, cm, km
	return r, nil
}

func (r *certReloader) mtimes() (cert, key time.Time, err error) {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return cert, key, err
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return cert, key, err
	}
	return ci.ModTime(), ki.ModTime(), nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cm, km, err := r.mtimes()
	if err != nil {
		r.log.Error("tls certificate stat failed, serving last good certificate", "error", err.Error())
		return r.cert, nil
	}
	if cm.Equal(r.certMod) && km.Equal(r.keyMod) {
		return r.cert, nil
	}
	// Remember the new mtimes even on failure so a bad file is logged once,
	// not on every handshake; a later fix changes the mtime again.
	r.certMod, r.keyMod = cm, km
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		r.log.Error("tls certificate reload failed, serving last good certificate", "error", err.Error())
		return r.cert, nil
	}
	r.cert = &c
	r.log.Info("tls certificate reloaded")
	return r.cert, nil
}
