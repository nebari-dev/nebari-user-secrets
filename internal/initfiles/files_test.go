package initfiles

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/internal/model"
)

func TestWriteAllExactBytes(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value []byte
	}{
		{"journey 13 bytes", "NEBARI_SECRET_API", append([]byte(`{"k":"a$$b$(HOME){username}"}`+"\n"), 0xff)},
		{"empty value", "NEBARI_SECRET_EMPTY", []byte{}},
		{"binary", "NEBARI_SECRET_BIN", []byte{0x00, 0x01, '\r', '\n', 0xfe}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			w := NewFileWriter(dir)
			if err := w.WriteAll([]model.ResolvedSecret{{Env: tt.env, Value: tt.value}}); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, tt.env)
			got, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.value) {
				t.Fatalf("bytes differ: got %q want %q", got, tt.value)
			}
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o440 {
				t.Fatalf("mode %v, want 0440", fi.Mode().Perm())
			}
		})
	}
}

func TestWriteAllModeIgnoresUmask(t *testing.T) {
	dir := t.TempDir()
	old := setUmask(0o277)
	defer setUmask(old)
	if err := NewFileWriter(dir).WriteAll([]model.ResolvedSecret{{Env: "NEBARI_SECRET_A", Value: []byte("x")}}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "NEBARI_SECRET_A"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o440 {
		t.Fatalf("mode %v, want 0440", fi.Mode().Perm())
	}
}

func TestWriteAllRejectsBadNames(t *testing.T) {
	tests := []struct {
		name string
		env  string
	}{
		{"unprefixed", "LD_PRELOAD"},
		{"lowercase suffix", "NEBARI_SECRET_a"},
		{"traversal", "NEBARI_SECRET_../x"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			secret := []byte("topsecretvalue")
			err := NewFileWriter(dir).WriteAll([]model.ResolvedSecret{
				{Env: tt.env, Value: secret},
				{Env: "NEBARI_SECRET_GOOD", Value: []byte("ok")},
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), string(secret)) {
				t.Fatalf("error leaks value: %v", err)
			}
			entries, _ := os.ReadDir(dir)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			// bad name never written; valid name still delivered (fail-safe)
			if len(names) != 1 || names[0] != "NEBARI_SECRET_GOOD" {
				t.Fatalf("dir contents %v, want only NEBARI_SECRET_GOOD", names)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "x")); err == nil {
				t.Fatal("traversal wrote outside dir")
			}
		})
	}
}

func TestWriteAllRemovesStale(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWriter(dir)
	if err := w.WriteAll([]model.ResolvedSecret{
		{Env: "NEBARI_SECRET_OLD", Value: []byte("o")},
		{Env: "NEBARI_SECRET_KEEP", Value: []byte("k1")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteStatus("ok 2"); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(other, []byte("u"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteAll([]model.ResolvedSecret{{Env: "NEBARI_SECRET_KEEP", Value: []byte("k2")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "NEBARI_SECRET_OLD")); !os.IsNotExist(err) {
		t.Fatalf("stale file still present: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "NEBARI_SECRET_KEEP")); string(b) != "k2" {
		t.Fatalf("KEEP = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".status")); string(b) != "ok 2" {
		t.Fatalf(".status = %q", b)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
}

func TestWriteAllRemovesLeftoverTemps(t *testing.T) {
	tests := []struct {
		name    string
		secrets []model.ResolvedSecret
	}{
		{name: "with secrets", secrets: []model.ResolvedSecret{{Env: "NEBARI_SECRET_A", Value: []byte("a")}}},
		{name: "with no secrets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// A write killed between Write and rename leaves its temp file.
			for _, n := range []string{".tmp-111", ".tmp-222"} {
				if err := os.WriteFile(filepath.Join(dir, n), []byte("old-SENTINEL"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := NewFileWriter(dir).WriteAll(tt.secrets); err != nil {
				t.Fatal(err)
			}
			left, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
			if len(left) != 0 {
				t.Fatalf("temp files left: %v", left)
			}
			if got, _ := filepath.Glob(filepath.Join(dir, "NEBARI_SECRET_*")); len(got) != len(tt.secrets) {
				t.Fatalf("secret files %v, want %d", got, len(tt.secrets))
			}
		})
	}
}

func TestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWriter(dir)
	var tmpDirs []string
	var tmpNames []string
	w.rename = func(oldpath, newpath string) error {
		tmpDirs = append(tmpDirs, filepath.Dir(oldpath))
		tmpNames = append(tmpNames, filepath.Base(oldpath))
		if filepath.Dir(oldpath) != filepath.Dir(newpath) {
			t.Errorf("temp %q not in same dir as %q", oldpath, newpath)
		}
		if oldpath == newpath {
			t.Errorf("rename onto itself")
		}
		if _, err := os.Stat(newpath); err == nil {
			// final must not exist yet on first write
			t.Errorf("final path already exists before rename")
		}
		return os.Rename(oldpath, newpath)
	}
	if err := w.WriteAll([]model.ResolvedSecret{{Env: "NEBARI_SECRET_A", Value: []byte("v")}}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteStatus("ok 1"); err != nil {
		t.Fatal(err)
	}
	if len(tmpDirs) != 2 {
		t.Fatalf("renames = %d, want 2", len(tmpDirs))
	}
	for _, n := range tmpNames {
		if strings.HasPrefix(n, "NEBARI_SECRET_") {
			t.Errorf("temp name %q would be mistaken for a secret", n)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteStatus(t *testing.T) {
	tests := []struct{ name, status string }{
		{"ok", "ok 3"},
		{"error", "error resolve_failed token rejected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			w := NewFileWriter(dir)
			if err := w.WriteStatus(tt.status); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(dir, ".status"))
			if err != nil || string(b) != tt.status {
				t.Fatalf("got %q, %v", b, err)
			}
			fi, _ := os.Stat(filepath.Join(dir, ".status"))
			if fi.Mode().Perm() != 0o440 {
				t.Fatalf("mode %v", fi.Mode().Perm())
			}
		})
	}
}

func TestErrorPaths(t *testing.T) {
	t.Run("missing dir", func(t *testing.T) {
		w := NewFileWriter(filepath.Join(t.TempDir(), "nope"))
		if err := w.WriteAll([]model.ResolvedSecret{{Env: "NEBARI_SECRET_A", Value: []byte("v")}}); err == nil {
			t.Fatal("expected write error")
		}
		if err := w.WriteAll(nil); err == nil {
			t.Fatal("expected list error")
		}
		if err := w.WriteStatus("ok 0"); err == nil {
			t.Fatal("expected status error")
		}
	})
	t.Run("rename failure cleans temp", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFileWriter(dir)
		w.rename = func(string, string) error { return os.ErrPermission }
		if err := w.WriteStatus("ok 0"); err == nil {
			t.Fatal("expected error")
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatalf("temp left: %v", entries)
		}
	})
}

func TestWriteAllStaleRemoveAndWriteFailures(t *testing.T) {
	t.Run("stale entry cannot be removed", func(t *testing.T) {
		dir := t.TempDir()
		d := filepath.Join(dir, "NEBARI_SECRET_DIR")
		if err := os.MkdirAll(filepath.Join(d, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := NewFileWriter(dir).WriteAll(nil); err == nil {
			t.Fatal("expected remove error")
		}
	})
	t.Run("write failure is reported and others still written", func(t *testing.T) {
		dir := t.TempDir()
		w := NewFileWriter(dir)
		w.rename = func(o, n string) error {
			if filepath.Base(n) == "NEBARI_SECRET_A" {
				_ = os.Remove(o)
				return os.ErrPermission
			}
			return os.Rename(o, n)
		}
		err := w.WriteAll([]model.ResolvedSecret{
			{Env: "NEBARI_SECRET_A", Value: []byte("a")},
			{Env: "NEBARI_SECRET_B", Value: []byte("b")},
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "NEBARI_SECRET_B")); string(b) != "b" {
			t.Fatalf("B = %q", b)
		}
	})
}

type failFile struct {
	tempFile
	failAt string
}

func (f failFile) Write(b []byte) (int, error) {
	if f.failAt == "write" {
		return 0, os.ErrInvalid
	}
	return f.tempFile.Write(b)
}

func (f failFile) Sync() error {
	if f.failAt == "sync" {
		return os.ErrInvalid
	}
	return f.tempFile.Sync()
}

func (f failFile) Chmod(m os.FileMode) error {
	if f.failAt == "chmod" {
		return os.ErrInvalid
	}
	return f.tempFile.Chmod(m)
}

func (f failFile) Close() error {
	if f.failAt == "close" {
		_ = f.tempFile.Close()
		return os.ErrInvalid
	}
	return f.tempFile.Close()
}

func TestWriteFileStepFailures(t *testing.T) {
	for _, step := range []string{"write", "sync", "chmod", "close"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			w := NewFileWriter(dir)
			w.createTemp = func(d, p string) (tempFile, error) {
				f, err := osCreateTemp(d, p)
				return failFile{f, step}, err
			}
			if err := w.WriteStatus("ok 0"); err == nil {
				t.Fatal("expected error")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatalf("temp left behind: %v", entries)
			}
		})
	}
}
