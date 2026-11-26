package initfiles

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// execCall is what ExecWithEnv handed to the exec seam.
type execCall struct {
	path string
	argv []string
	env  []string
}

// stubExec replaces the exec seam for one test: it records the call and
// returns err.
func stubExec(t *testing.T, err error) *execCall {
	t.Helper()
	got := &execCall{}
	old := execve
	execve = func(path string, argv, env []string) error {
		got.path, got.argv, got.env = path, argv, env
		return err
	}
	t.Cleanup(func() { execve = old })
	return got
}

func TestExecWithEnv(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	j13 := string(append([]byte(`{"k":"a$$b$(HOME){username}"}`+"\n"), 0xff))
	tests := []struct {
		name       string
		files      map[string]string // name -> exact bytes; ".status" included
		noDir      bool
		environ    []string
		argv       []string
		wantEnv    []string // the exec'd environment, sorted
		wantArgv   []string
		wantStderr []string // each must appear in stderr
		// wantLines is the exact number of stderr lines.
		wantLines int
	}{
		{
			name:    "exports each valid file with the exact bytes",
			files:   map[string]string{"NEBARI_SECRET_A": "a", "NEBARI_SECRET_J13": j13, ".status": "ok 2"},
			environ: []string{"PATH=/bin"},
			argv:    []string{"--", "sh", "-c", "true"},
			wantEnv: []string{"NEBARI_SECRET_A=a", "NEBARI_SECRET_J13=" + j13, "PATH=/bin"},
		},
		{
			name:    "an empty file exports an empty value",
			files:   map[string]string{"NEBARI_SECRET_E": "", ".status": "ok 1"},
			argv:    []string{"--", "sh"},
			wantEnv: []string{"NEBARI_SECRET_E="},
		},
		{
			name: "names outside the delivered name rule are not exported",
			files: map[string]string{
				"NEBARI_SECRET_OK": "1", "NEBARI_SECRET_lower": "2", "LD_PRELOAD": "3",
				"NEBARI_SECRET_": "4", ".tmp-123": "5", ".status": "ok 1",
			},
			argv:    []string{"--", "sh"},
			wantEnv: []string{"NEBARI_SECRET_OK=1"},
		},
		{
			name:    "never replaces a set variable, even an empty one",
			files:   map[string]string{"NEBARI_SECRET_A": "file", "NEBARI_SECRET_B": "file", ".status": "ok 2"},
			environ: []string{"NEBARI_SECRET_A=preset", "NEBARI_SECRET_B="},
			argv:    []string{"--", "sh"},
			wantEnv: []string{"NEBARI_SECRET_A=preset", "NEBARI_SECRET_B="},
		},
		{
			name:       "skips a value with a NUL byte and names it on stderr",
			files:      map[string]string{"NEBARI_SECRET_NUL": "a\x00SENTINEL", "NEBARI_SECRET_OK": "ok", ".status": "ok 2"},
			argv:       []string{"--", "sh"},
			wantEnv:    []string{"NEBARI_SECRET_OK=ok"},
			wantStderr: []string{"NEBARI_SECRET_NUL", "NUL"},
			wantLines:  1,
		},
		{
			name:       "an error status prints one warning and still execs",
			files:      map[string]string{".status": "error unreachable dial tcp: i/o timeout after 7 attempts"},
			argv:       []string{"--", "sh"},
			wantStderr: []string{"warning", "error unreachable dial tcp: i/o timeout after 7 attempts"},
			wantLines:  1,
		},
		{
			name:       "a missing status prints one warning and still execs",
			files:      map[string]string{},
			argv:       []string{"--", "sh"},
			wantStderr: []string{"warning", ".status"},
			wantLines:  1,
		},
		{
			name:       "a missing directory prints one warning and still execs",
			noDir:      true,
			environ:    []string{"HOME=/home/u"},
			argv:       []string{"--", "sh"},
			wantEnv:    []string{"HOME=/home/u"},
			wantStderr: []string{"warning", ".status"},
			wantLines:  1,
		},
		{
			name:     "argv after -- is passed unchanged",
			files:    map[string]string{".status": "ok 0"},
			argv:     []string{"--", "sh", "-c", `echo "$0" "$@"`, "--", "-x", "$HOME", "a b", ""},
			wantArgv: []string{"sh", "-c", `echo "$0" "$@"`, "--", "-x", "$HOME", "a b", ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.noDir {
				dir = filepath.Join(dir, "absent")
			}
			for n, v := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, n), []byte(v), 0o440); err != nil {
					t.Fatal(err)
				}
			}
			got := stubExec(t, nil)
			var stderr bytes.Buffer
			if err := ExecWithEnv(dir, tt.argv, tt.environ, &stderr); err != nil {
				t.Fatalf("ExecWithEnv: %v", err)
			}
			if got.path != sh {
				t.Errorf("exec path = %q, want %q", got.path, sh)
			}
			wantArgv := tt.wantArgv
			if wantArgv == nil {
				wantArgv = tt.argv[1:]
			}
			if !slices.Equal(got.argv, wantArgv) {
				t.Errorf("exec argv = %q, want %q", got.argv, wantArgv)
			}
			if tt.wantEnv != nil {
				env := slices.Sorted(slices.Values(got.env))
				if !slices.Equal(env, tt.wantEnv) {
					t.Errorf("exec env names = %v, want %v", envNames(env), envNames(tt.wantEnv))
					for i := range min(len(env), len(tt.wantEnv)) {
						if env[i] != tt.wantEnv[i] {
							t.Errorf("env entry %d (%s) differs", i, envNames(env[i:i+1]))
						}
					}
				}
			}
			out := stderr.String()
			for _, w := range tt.wantStderr {
				if !strings.Contains(out, w) {
					t.Errorf("stderr %q lacks %q", out, w)
				}
			}
			if n := strings.Count(out, "\n"); n != tt.wantLines {
				t.Errorf("stderr has %d lines, want %d: %q", n, tt.wantLines, out)
			}
			if strings.Contains(out, "SENTINEL") {
				t.Errorf("stderr leaks a value: %q", out)
			}
		})
	}
}

func TestExecWithEnvErrors(t *testing.T) {
	execErr := errors.New("exec format error")
	tests := []struct {
		name      string
		argv      []string
		execErr   error
		wantUsage bool
		wantIs    error
		wantExec  bool
		status    string // .status content; "" means "ok 0"
		// wantWarn is whether stderr carries the .status warning.
		wantWarn bool
	}{
		{name: "no arguments", argv: nil, wantUsage: true},
		{name: "no --", argv: []string{"sh"}, wantUsage: true},
		{name: "-- without a command", argv: []string{"--"}, wantUsage: true},
		{name: "empty command", argv: []string{"--", ""}, wantUsage: true},
		{name: "command not found", argv: []string{"--", "user-secrets-no-such-command"}, wantIs: exec.ErrNotFound},
		{name: "exec fails", argv: []string{"--", "sh"}, execErr: execErr, wantIs: execErr, wantExec: true},
		{name: "command not found still warns about an error status",
			argv: []string{"--", "user-secrets-no-such-command"}, wantIs: exec.ErrNotFound,
			status: "error unreachable dial tcp after 5 attempts", wantWarn: true},
		{name: "command not runnable still warns about an error status",
			argv: []string{"--", "sh"}, execErr: execErr, wantIs: execErr, wantExec: true,
			status: "error unreachable dial tcp after 5 attempts", wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			status := tt.status
			if status == "" {
				status = "ok 0"
			}
			if err := os.WriteFile(filepath.Join(dir, ".status"), []byte(status), 0o440); err != nil {
				t.Fatal(err)
			}
			called := false
			old := execve
			execve = func(string, []string, []string) error { called = true; return tt.execErr }
			t.Cleanup(func() { execve = old })
			var stderr bytes.Buffer
			err := ExecWithEnv(dir, tt.argv, nil, &stderr)
			if err == nil {
				t.Fatal("ExecWithEnv returned nil")
			}
			warned := strings.Contains(stderr.String(), "warning: secrets not delivered: "+status)
			if warned != tt.wantWarn {
				t.Errorf("status warning printed = %v, want %v; stderr %q", warned, tt.wantWarn, stderr.String())
			}
			if got := errors.Is(err, ErrUsage); got != tt.wantUsage {
				t.Errorf("errors.Is(err, ErrUsage) = %v, want %v (err %v)", got, tt.wantUsage, err)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.wantIs)
			}
			if called != tt.wantExec {
				t.Errorf("exec called = %v, want %v", called, tt.wantExec)
			}
		})
	}
}

// envNames returns the names of KEY=value entries, for messages that must not
// print values.
func envNames(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		out = append(out, k)
	}
	return out
}
