package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseServeFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr string
	}{
		{name: "config flag", args: []string{"--config", "/etc/c.yaml"}, want: "/etc/c.yaml"},
		{name: "single dash and equals", args: []string{"-config=/x.yaml"}, want: "/x.yaml"},
		{name: "missing config", args: nil, wantErr: "--config is required"},
		{name: "empty config", args: []string{"--config", ""}, wantErr: "--config is required"},
		{name: "unknown flag", args: []string{"--config", "/c", "--bogus"}, wantErr: "bogus"},
		{name: "flag without value", args: []string{"--config"}, wantErr: "needs an argument"},
		{name: "positional argument", args: []string{"--config", "/c", "extra"}, wantErr: "unexpected arguments"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseServeFlags(tc.args, &bytes.Buffer{})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
		wantStdout string
	}{
		{name: "help flag", args: []string{"--help"}, wantCode: 0, wantStdout: "usage"},
		{name: "short help flag", args: []string{"-h"}, wantCode: 0, wantStdout: "usage"},
		{name: "help word", args: []string{"help"}, wantCode: 0, wantStdout: "usage"},
		{name: "no args", args: nil, wantCode: 2, wantStderr: "usage"},
		{name: "unknown subcommand", args: []string{"frobnicate"}, wantCode: 2, wantStderr: `unknown command "frobnicate"`},
		{name: "serve without config", args: []string{"serve"}, wantCode: 2, wantStderr: "--config is required"},
		{name: "serve unknown flag", args: []string{"serve", "--nope"}, wantCode: 2, wantStderr: "nope"},
		{name: "serve missing config file", args: []string{"serve", "--config", "/nonexistent/c.yaml"}, wantCode: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := run(tc.args, &out, &errb); code != tc.wantCode {
				t.Fatalf("code = %d, want %d (stderr %q)", code, tc.wantCode, errb.String())
			}
			if !strings.Contains(errb.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want containing %q", errb.String(), tc.wantStderr)
			}
			if !strings.Contains(out.String(), tc.wantStdout) {
				t.Fatalf("stdout = %q, want containing %q", out.String(), tc.wantStdout)
			}
		})
	}
}
