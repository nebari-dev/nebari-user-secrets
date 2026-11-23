package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no args"},
		{name: "help flag", args: []string{"--help"}},
		{name: "other args", args: []string{"x", "y"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(tc.args, &out); code != 0 {
				t.Fatalf("code = %d, want 0", code)
			}
			if !strings.Contains(out.String(), "usage: user-secrets-init") {
				t.Fatalf("stdout = %q", out.String())
			}
		})
	}
}
