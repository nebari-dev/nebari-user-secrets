package main

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/catalog"
)

func TestMergeFilesPolicyResults(t *testing.T) {
	dir := t.TempDir()
	transcript := filepath.Join(dir, "v9.1.0.txt")
	if err := os.WriteFile(transcript, []byte("### v9.1.0\n== a\nPASS  x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "v9.2.0.txt")
	tests := []struct {
		name       string
		list       string
		want       catalog.Results
		wantErr    bool
		wantStderr string
	}{
		{name: "a transcript", list: transcript, want: catalog.Results{"run.sh:a": "pass"}},
		{
			// The tier2-policy job deletes the committed transcript before
			// the matrix runs, so a matrix that never ran leaves no file and
			// its checks show as not run.
			name:       "a missing transcript is no results",
			list:       missing,
			want:       catalog.Results{},
			wantStderr: missing + " not found",
		},
		{
			name:       "a missing transcript beside a present one",
			list:       missing + "," + transcript,
			want:       catalog.Results{"run.sh:a": "pass"},
			wantStderr: missing + " not found",
		},
		{name: "a transcript that cannot be read", list: dir, wantErr: true},
		{name: "no transcripts", list: "", want: catalog.Results{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := catalog.Results{}
			var stderr bytes.Buffer
			err := mergeFiles(got, tt.list, catalog.ParsePolicyTranscript, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mergeFiles(%q) error = %v, wantErr %v", tt.list, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("mergeFiles(%q) results = %v, want %v", tt.list, got, tt.want)
			}
			if tt.wantStderr == "" && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
