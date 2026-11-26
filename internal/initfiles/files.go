// Package initfiles delivers resolved user secrets into a pod as files.
package initfiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

const (
	namePrefix = "NEBARI_SECRET_"
	statusFile = ".status"
	// tempPrefix starts every temporary file name; a leftover one is removed
	// by the next WriteAll or Fail.
	tempPrefix = ".tmp-"
	fileMode   = 0o440
)

// FileWriter writes secret files and the status file into one directory.
// Group ownership comes from the pod's fsGroup on the emptyDir; the writer
// only sets the mode.
type FileWriter struct {
	dir        string
	rename     func(oldpath, newpath string) error
	createTemp func(dir, pattern string) (tempFile, error)
}

// tempFile is the part of *os.File the writer uses, so tests can inject
// write, sync, chmod and close failures.
type tempFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Chmod(os.FileMode) error
	Close() error
}

func osCreateTemp(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) }

// NewFileWriter returns a writer for dir.
func NewFileWriter(dir string) *FileWriter {
	return &FileWriter{dir: dir, rename: os.Rename, createTemp: osCreateTemp}
}

// WriteAll first removes leftover .tmp-* files (a write killed before its
// rename), writes each secret's exact bytes to <dir>/<Env> with mode 0440, then
// removes NEBARI_SECRET_* files that are not in the set. Files that do not
// match the prefix, including .status, are left alone.
//
// A secret whose name is not a valid delivered name is never written. Valid
// secrets are still written and stale files still removed (fail-safe delivery),
// and the returned error names the rejected entries. No error contains a value.
func (w *FileWriter) WriteAll(secrets []model.ResolvedSecret) error {
	var errs []error
	if err := w.removeTemps(); err != nil {
		errs = append(errs, err)
	}
	keep := make(map[string]bool, len(secrets))
	for i, s := range secrets {
		if !model.ValidDeliveredName(s.Env) {
			errs = append(errs, fmt.Errorf("secret %d: invalid delivered name %q", i, s.Env))
			continue
		}
		if err := w.writeFile(s.Env, s.Value); err != nil {
			errs = append(errs, fmt.Errorf("write %s: %w", s.Env, err))
			// keep the previous file rather than deleting it as stale
		}
		keep[s.Env] = true
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list %s: %w", w.dir, err))...)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, namePrefix) || keep[n] {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, n)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove stale %s: %w", n, err))
		}
	}
	return errors.Join(errs...)
}

// removeTemps removes the .tmp-* files a write killed before its rename left
// behind; they can hold a value.
func (w *FileWriter) removeTemps() error {
	left, err := filepath.Glob(filepath.Join(w.dir, tempPrefix+"*"))
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range left {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove leftover %s: %w", filepath.Base(p), err))
		}
	}
	return errors.Join(errs...)
}

// WriteStatus atomically writes the .status file.
func (w *FileWriter) WriteStatus(status string) error {
	return w.writeFile(statusFile, []byte(status))
}

// writeFile writes data to dir/name via a temp file in dir: write, fsync,
// chmod, rename. The temp name does not start with the secret prefix, so a
// crash cannot leave something that looks like a secret.
func (w *FileWriter) writeFile(name string, data []byte) (err error) {
	f, err := w.createTemp(w.dir, tempPrefix)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	// Chmod explicitly: the process umask must not decide the final mode.
	if err = f.Chmod(fileMode); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return w.rename(tmp, filepath.Join(w.dir, name))
}
