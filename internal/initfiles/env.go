package initfiles

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

// envName is the wrapper's name in its messages.
const envName = "user-secrets-env"

// ErrUsage is returned by ExecWithEnv when argv is not "-- <cmd> [args]".
var ErrUsage = errors.New("usage: " + envName + " -- <cmd> [args]")

// execve replaces the process; a variable so tests can observe the call.
var execve = syscall.Exec

// ExecWithEnv runs the command after "--" in argv with each secret file in dir
// added to environ as NEBARI_SECRET_<SUFFIX>=<exact bytes>, by replacing the
// current process. On success it does not return.
//
// Only names matching the delivered name rule are exported. A variable that
// is already set in environ, even to an empty value, is never replaced. A
// value containing a NUL byte cannot be an environment variable: it is skipped
// and its name written to stderr. When .status reports an error, or is
// missing, one warning line goes to stderr and the command still runs. No
// message carries a value.
//
// It returns an error wrapping ErrUsage when argv is not "-- <cmd> [args]",
// one wrapping exec.ErrNotFound when the command is not found, and the exec
// error otherwise.
func ExecWithEnv(dir string, argv []string, environ []string, stderr io.Writer) error {
	if len(argv) < 2 || argv[0] != "--" || argv[1] == "" {
		return ErrUsage
	}
	// Warn before the lookup, so a missing command does not hide the reason
	// the secrets are missing.
	warnStatus(dir, stderr)
	cmd := argv[1:]
	path, err := exec.LookPath(cmd[0])
	if err != nil {
		return fmt.Errorf("%s: %w", envName, err)
	}
	env := append(slices.Clone(environ), secretEnv(dir, environ, stderr)...)
	if err := execve(path, cmd, env); err != nil {
		return fmt.Errorf("%s: exec %s: %w", envName, cmd[0], err)
	}
	return nil
}

// warnStatus writes one warning line when .status is missing, unreadable or
// reports an error.
func warnStatus(dir string, stderr io.Writer) {
	b, err := os.ReadFile(filepath.Join(dir, statusFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		_, _ = fmt.Fprintf(stderr, "%s: warning: secrets not delivered: no %s\n", envName, statusFile)
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "%s: warning: secrets not delivered: %s unreadable (%v)\n",
			envName, statusFile, errors.Unwrap(err))
	case strings.HasPrefix(string(b), "error"):
		line, _, _ := strings.Cut(string(b), "\n")
		_, _ = fmt.Fprintf(stderr, "%s: warning: secrets not delivered: %s\n", envName, oneLine(line))
	}
}

// secretEnv returns NAME=value entries for the valid secret files in dir that
// environ does not already set, in name order.
func secretEnv(dir string, environ []string, stderr io.Writer) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(stderr, "%s: no secrets exported: %v\n", envName, err)
		}
		return nil
	}
	set := make(map[string]bool, len(environ))
	for _, e := range environ {
		if k, _, ok := strings.Cut(e, "="); ok {
			set[k] = true
		}
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !model.ValidDeliveredName(name) || set[name] {
			continue
		}
		v, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s: skipping %s: %v\n", envName, name, errors.Unwrap(err))
			continue
		}
		if bytes.IndexByte(v, 0) >= 0 {
			_, _ = fmt.Fprintf(stderr, "%s: skipping %s: value contains a NUL byte\n", envName, name)
			continue
		}
		out = append(out, name+"="+string(v))
	}
	return out
}
