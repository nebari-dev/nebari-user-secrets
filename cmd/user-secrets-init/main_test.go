package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runMainEnv makes the test binary act as user-secrets-init, so TestInitMain
// observes real exit codes and a real /proc/self/exe.
const runMainEnv = "USER_SECRETS_INIT_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func resolveServer(t *testing.T, status int, body string) (url, ca string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	ca = filepath.Join(t.TempDir(), "ca-certificates.crt")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL + "/api/v1/resolve", ca
}

func TestInitMain(t *testing.T) {
	const okBody = `{"secrets":[{"env":"NEBARI_SECRET_A","value_b64":"YQBi"}]}`
	const denied = `{"error":"pod_predates_guard"}`
	tests := []struct {
		name       string
		status     int
		body       string
		mode       string // "" leaves --mode unset (soft)
		noCA       bool
		badURL     bool     // --url is not https://<host> (misconfiguration)
		noBinDir   bool     // --bin-dir does not exist, so the wrapper copy fails
		oldSecret  bool     // dir holds NEBARI_SECRET_OLD from an earlier run
		args       []string // replaces the fetch arguments when set
		wantCode   int
		wantStatus string // prefix of .status; "" means no .status
		wantFile   bool
		wantBin    bool
	}{
		{name: "soft success", status: 200, body: okBody, mode: "soft",
			wantCode: 0, wantStatus: "ok 1", wantFile: true, wantBin: true},
		{name: "default mode is soft", status: 200, body: okBody,
			wantCode: 0, wantStatus: "ok 1", wantFile: true, wantBin: true},
		{name: "strict success", status: 200, body: okBody, mode: "strict",
			wantCode: 0, wantStatus: "ok 1", wantFile: true, wantBin: true},
		{name: "soft denied exits 0", status: 403, body: denied, mode: "soft",
			wantCode: 0, wantStatus: "error pod_predates_guard http 403", wantBin: true},
		{name: "strict denied exits 1", status: 403, body: denied, mode: "strict",
			wantCode: 1, wantStatus: "error pod_predates_guard http 403", wantBin: true},
		{name: "soft CA missing exits 0", status: 200, body: okBody, mode: "soft", noCA: true,
			wantCode: 0, wantStatus: "error ca_missing ", wantBin: true},
		{name: "strict CA missing exits 1", status: 200, body: okBody, mode: "strict", noCA: true,
			wantCode: 1, wantStatus: "error ca_missing ", wantBin: true},
		{name: "strict wrapper copy failure exits 1", status: 200, body: okBody, mode: "strict", noBinDir: true,
			wantCode: 1, wantStatus: "ok 1", wantFile: true},
		{name: "soft wrapper copy failure exits 0", status: 200, body: okBody, mode: "soft", noBinDir: true,
			wantCode: 0, wantStatus: "ok 1", wantFile: true},
		{name: "soft CA missing clears old secrets", status: 200, body: okBody, mode: "soft", noCA: true,
			oldSecret: true, wantCode: 0, wantStatus: "error ca_missing ", wantBin: true},
		{name: "strict CA missing clears old secrets", status: 200, body: okBody, mode: "strict", noCA: true,
			oldSecret: true, wantCode: 1, wantStatus: "error ca_missing ", wantBin: true},
		{name: "soft malformed url exits 2", status: 200, body: okBody, mode: "soft", badURL: true,
			oldSecret: true, wantCode: 2, wantStatus: "error bad_config "},
		{name: "strict malformed url exits 2", status: 200, body: okBody, mode: "strict", badURL: true,
			wantCode: 2, wantStatus: "error bad_config "},
		{name: "bad mode is a usage error", status: 200, body: okBody, mode: "loose", wantCode: 2},
		{name: "no subcommand is a usage error", args: []string{}, wantCode: 2},
		{name: "unknown subcommand is a usage error", args: []string{"serve"}, wantCode: 2},
		{name: "missing flags is a usage error", args: []string{"fetch", "--mode", "strict"}, wantCode: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, ca := "", ""
			if tt.status != 0 {
				url, ca = resolveServer(t, tt.status, tt.body)
			}
			if tt.noCA {
				ca = filepath.Join(t.TempDir(), "absent.crt")
			}
			if tt.badURL {
				url = "http://user-secrets.ns.svc:8443/api/v1/resolve"
			}
			dir, binDir := t.TempDir(), t.TempDir()
			if tt.oldSecret {
				if err := os.WriteFile(filepath.Join(dir, "NEBARI_SECRET_OLD"), []byte("old"), 0o440); err != nil {
					t.Fatal(err)
				}
			}
			if tt.noBinDir {
				binDir = filepath.Join(binDir, "missing")
			}
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("tok-SENTINEL"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := tt.args
			if args == nil {
				args = []string{"fetch", "--url", url, "--ca", ca, "--token", token, "--dir", dir, "--bin-dir", binDir}
				if tt.mode != "" {
					args = append(args, "--mode", tt.mode)
				}
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), runMainEnv+"=1")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			if strings.Contains(stderr.String(), "SENTINEL") {
				t.Fatalf("stderr leaks the token: %s", stderr.String())
			}

			status, statusErr := os.ReadFile(filepath.Join(dir, ".status"))
			if tt.wantStatus == "" {
				if statusErr == nil {
					t.Fatalf(".status written: %q", status)
				}
			} else if !strings.HasPrefix(string(status), tt.wantStatus) {
				t.Fatalf(".status = %q, want prefix %q", status, tt.wantStatus)
			}
			if _, err := os.Stat(filepath.Join(dir, "NEBARI_SECRET_A")); (err == nil) != tt.wantFile {
				t.Fatalf("secret file present = %v, want %v", err == nil, tt.wantFile)
			}
			if tt.oldSecret {
				if left, _ := filepath.Glob(filepath.Join(dir, "NEBARI_SECRET_*")); len(left) != 0 {
					t.Fatalf("secret files left after failure: %v", left)
				}
			}
			fi, err := os.Stat(filepath.Join(binDir, wrapperName))
			if (err == nil) != tt.wantBin {
				t.Fatalf("wrapper present = %v, want %v", err == nil, tt.wantBin)
			}
			if tt.wantBin && fi.Mode().Perm() != 0o550 {
				t.Fatalf("wrapper mode = %v, want 0550", fi.Mode().Perm())
			}
		})
	}
}

func TestInstallWrapper(t *testing.T) {
	src := filepath.Join(t.TempDir(), "self")
	if err := os.WriteFile(src, []byte("\x7fELF-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		src     string
		binDir  string
		wantErr bool
	}{
		{name: "copies", src: src, binDir: t.TempDir()},
		{name: "replaces an existing file", src: src, binDir: withFile(t, wrapperName, "old")},
		{name: "source missing", src: filepath.Join(t.TempDir(), "none"), binDir: t.TempDir(), wantErr: true},
		{name: "bin dir missing", src: src, binDir: filepath.Join(t.TempDir(), "none"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := installWrapper(tt.src, tt.binDir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			entries, _ := os.ReadDir(tt.binDir)
			for _, e := range entries {
				if e.Name() != wrapperName {
					t.Fatalf("leftover temp file %s", e.Name())
				}
			}
			if tt.wantErr {
				return
			}
			got, err := os.ReadFile(filepath.Join(tt.binDir, wrapperName))
			if err != nil || string(got) != "\x7fELF-binary" {
				t.Fatalf("wrapper = %q err = %v", got, err)
			}
			fi, _ := os.Stat(filepath.Join(tt.binDir, wrapperName))
			if fi.Mode().Perm() != 0o550 {
				t.Fatalf("mode = %v", fi.Mode().Perm())
			}
		})
	}
}

func withFile(t *testing.T, name, content string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestEnvDispatch runs the test binary under the name user-secrets-env (a
// symlink), so run dispatches on argv[0] and the wrapper really execs. The
// secrets directory does not exist on the test host, so the wrapper warns
// that there is no .status.
func TestEnvDispatch(t *testing.T) {
	link := filepath.Join(t.TempDir(), wrapperName)
	if err := os.Symlink(os.Args[0], link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "execs the command with argv unchanged",
			args:     []string{"--", "sh", "-c", `printf '%s|' "$@"`, "sh", "-x", "a b"},
			wantCode: 0, wantStdout: "-x|a b|", wantStderr: "warning: secrets not delivered: no .status"},
		{name: "the command's exit code is the pod's", args: []string{"--", "sh", "-c", "exit 7"}, wantCode: 7},
		{name: "no -- is a usage error", args: []string{"sh"}, wantCode: 2, wantStderr: "usage: user-secrets-env -- <cmd>"},
		{name: "no command is a usage error", args: []string{"--"}, wantCode: 2},
		{name: "command not found exits 127", args: []string{"--", "user-secrets-no-such-command"}, wantCode: 127,
			wantStderr: "user-secrets-no-such-command"},
		{name: "command not executable exits 126", args: []string{"--", notExecutable(t)}, wantCode: 126},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(link, tt.args...)
			cmd.Env = append(os.Environ(), runMainEnv+"=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d; stderr: %s", code, tt.wantCode, stderr.String())
			}
			if tt.wantStdout != "" && stdout.String() != tt.wantStdout {
				t.Fatalf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// notExecutable returns a path to a file without execute permission.
func notExecutable(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
