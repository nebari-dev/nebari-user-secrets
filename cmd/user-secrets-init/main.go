// Command user-secrets-init is the init container binary that delivers user
// secrets into a pod: "user-secrets-init fetch ..." resolves them, writes the
// files and .status, and copies itself to the wrapper volume as
// user-secrets-env. Run under that name, "user-secrets-env -- <cmd> [args]"
// exports the files as environment variables and execs the command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/initfiles"
)

const (
	usage = "usage: user-secrets-init fetch --url URL --ca FILE --token FILE --dir DIR --bin-dir DIR " +
		"[--mode soft|strict]"
	// wrapperName is the name the binary is copied to in --bin-dir.
	wrapperName = "user-secrets-env"
	wrapperMode = 0o550
	// budget is the whole resolve budget; the server bounds its own work to 20 s.
	budget = 30 * time.Second
	// selfExe is this process's own binary.
	selfExe = "/proc/self/exe"
	// secretsDir is where the init container writes the files the wrapper
	// exports (the files volume's mount path in every container).
	secretsDir = "/var/run/nebari/secrets"
)

func main() {
	os.Exit(run(os.Args, os.Stderr))
}

// run dispatches on the name the binary runs under, then on the subcommand,
// and returns the exit code: 0 on success (and on a delivery failure in soft
// mode), 1 on a delivery failure in strict mode, 2 on misconfiguration (a
// usage error or a malformed --url) in every mode. Under the
// name user-secrets-env it execs the wrapped command and returns only when
// that fails (see runEnv).
func run(argv []string, stderr io.Writer) int {
	if len(argv) > 0 && filepath.Base(argv[0]) == wrapperName {
		return runEnv(argv[1:], stderr)
	}
	if len(argv) < 2 || argv[1] != "fetch" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}
	return runFetch(context.Background(), argv[2:], stderr)
}

// runEnv execs the wrapped command with the secrets exported. It returns only
// on failure: 2 on a usage error, 127 when the command is not found, 126 when
// it cannot be executed (the codes env(1) and shells use).
func runEnv(args []string, stderr io.Writer) int {
	err := initfiles.ExecWithEnv(secretsDir, args, os.Environ(), stderr)
	_, _ = fmt.Fprintln(stderr, err)
	switch {
	case errors.Is(err, initfiles.ErrUsage):
		return 2
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, os.ErrNotExist):
		return 127
	default:
		return 126
	}
}

type fetchFlags struct {
	url, ca, token, dir, binDir, mode string
}

func parseFetch(args []string, stderr io.Writer) (fetchFlags, error) {
	var f fetchFlags
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.url, "url", "", "resolve URL, https://user-secrets.<ns>.svc:8443/api/v1/resolve")
	fs.StringVar(&f.ca, "ca", "", "trust bundle (ca-certificates.crt)")
	fs.StringVar(&f.token, "token", "", "projected ServiceAccount token file")
	fs.StringVar(&f.dir, "dir", "", "directory for the secret files and .status")
	fs.StringVar(&f.binDir, "bin-dir", "", "directory to copy "+wrapperName+" into")
	fs.StringVar(&f.mode, "mode", "soft", "failure mode: soft (exit 0) or strict (exit 1)")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() != 0 {
		return f, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if f.url == "" || f.ca == "" || f.token == "" || f.dir == "" || f.binDir == "" {
		return f, errors.New("--url, --ca, --token, --dir and --bin-dir are required")
	}
	if f.mode != "soft" && f.mode != "strict" {
		return f, fmt.Errorf("--mode must be soft or strict, not %q", f.mode)
	}
	return f, nil
}

func runFetch(ctx context.Context, args []string, stderr io.Writer) int {
	f, err := parseFetch(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "user-secrets-init: %v\n%s\n", err, usage)
		return 2
	}
	w := initfiles.NewFileWriter(f.dir)

	var status string
	ok := false
	client, err := initfiles.NewHTTPResolveClient(f.url, f.ca)
	switch {
	case errors.Is(err, initfiles.ErrCAMissing):
		status = initfiles.FailureStatus("ca_missing", f.ca)
	case err != nil:
		status = initfiles.FailureStatus("bad_config", err.Error())
	default:
		status, ok = initfiles.Fetch(ctx, client, f.token, w, budget)
	}
	if err != nil {
		if ferr := w.Fail(status); ferr != nil {
			_, _ = fmt.Fprintf(stderr, "user-secrets-init: record failure: %v\n", ferr)
		}
	}
	_, _ = fmt.Fprintf(stderr, "user-secrets-init: %s\n", status)
	// A malformed --url is misconfiguration, which fails loud in every mode
	// (old values are already cleared and .status records why).
	if err != nil && !errors.Is(err, initfiles.ErrCAMissing) {
		return 2
	}

	// The wrapper is installed whatever the outcome, so it can warn about .status.
	if err := installWrapper(selfExe, f.binDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "user-secrets-init: install %s: %v\n", wrapperName, err)
		ok = false
	}
	if !ok && f.mode == "strict" {
		return 1
	}
	return 0
}

// installWrapper copies src to binDir/user-secrets-env with mode 0550 through
// a temp file and a rename, so a reader never sees a partial binary.
func installWrapper(src, binDir string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.CreateTemp(binDir, ".tmp-")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Chmod(wrapperMode); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(binDir, wrapperName))
}
