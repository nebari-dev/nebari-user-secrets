package gate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/gate"
)

// fakeAPI fails the first failures calls of each method, then answers.
type fakeAPI struct {
	failures int
	contains bool
	calls    int
	cmpCalls int
}

func (f *fakeAPI) LatestRelease(context.Context) (string, string, error) {
	f.calls++
	if f.calls <= f.failures {
		return "", "", errors.New("transient")
	}
	return "v1.2.3", "abc", nil
}

func (f *fakeAPI) Contains(context.Context, string, string) (bool, error) {
	f.cmpCalls++
	if f.cmpCalls <= f.failures {
		return false, errors.New("transient")
	}
	return f.contains, nil
}

func TestDecide(t *testing.T) {
	open := gate.Decision{Tag: "v1.2.3", Commit: "abc"}
	blocking := gate.Decision{Tag: "v1.2.3", Commit: "abc", Blocking: true}
	tests := []struct {
		name     string
		api      *fakeAPI
		attempts int
		want     gate.Decision
		wantErr  bool
		wantCall int // LatestRelease calls
	}{
		{"required commit not in release (behind)", &fakeAPI{contains: false}, 3, open, false, 1},
		{"release contains it (ahead or identical)", &fakeAPI{contains: true}, 3, blocking, false, 1},
		{"two transient errors then success", &fakeAPI{failures: 2, contains: true}, 3, blocking, false, 3},
		{"three errors give an error", &fakeAPI{failures: 3, contains: true}, 3, gate.Decision{}, true, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gate.Decide(context.Background(), tt.api, "req", tt.attempts, time.Microsecond)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if tt.api.calls != tt.wantCall {
				t.Errorf("LatestRelease calls = %d, want %d", tt.api.calls, tt.wantCall)
			}
		})
	}
}

func TestGitHubOutput(t *testing.T) {
	const sha = "dfae9f2ea2e89d0ccab464f7e7d5285e6defec59"
	tests := []struct {
		name    string
		d       gate.Decision
		want    string
		wantErr bool
	}{
		{"valid tag and sha", gate.Decision{Tag: "v0.18.0", Commit: sha},
			"blocking=false\nnic-tag=v0.18.0\nnic-commit=" + sha + "\n", false},
		{"blocking", gate.Decision{Tag: "rel/1.2_rc-1", Commit: sha, Blocking: true},
			"blocking=true\nnic-tag=rel/1.2_rc-1\nnic-commit=" + sha + "\n", false},
		{"tag with newline", gate.Decision{Tag: "v1\nblocking=true", Commit: sha}, "", true},
		{"tag with carriage return", gate.Decision{Tag: "v1\rblocking=true", Commit: sha}, "", true},
		{"tag with space", gate.Decision{Tag: "v1 x", Commit: sha}, "", true},
		{"empty tag", gate.Decision{Commit: sha}, "", true},
		{"sha too short", gate.Decision{Tag: "v1", Commit: sha[:39]}, "", true},
		{"sha uppercase", gate.Decision{Tag: "v1", Commit: strings.ToUpper(sha)}, "", true},
		{"sha not hex", gate.Decision{Tag: "v1", Commit: strings.Repeat("g", 40)}, "", true},
		{"sha with newline", gate.Decision{Tag: "v1", Commit: sha[:39] + "\n"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.d.GitHubOutput()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecideStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := gate.Decide(ctx, &fakeAPI{failures: 5}, "req", 3, time.Hour)
	if err == nil {
		t.Fatal("want error on cancelled context")
	}
}

func TestGitHubAPI(t *testing.T) {
	const repo = "o/r"
	tests := []struct {
		name         string
		status       string // compare status
		failPath     string // path suffix answered with failCode
		failCode     int
		wantContains bool
		wantErr      bool
	}{
		{name: "ahead", status: "ahead", wantContains: true},
		{name: "identical", status: "identical", wantContains: true},
		{name: "behind", status: "behind"},
		{name: "diverged", status: "diverged"},
		{name: "unknown status", status: "weird", wantErr: true},
		{name: "403 rate limit", failPath: "/releases/latest", failCode: 403, wantErr: true},
		{name: "500 on commit", failPath: "/commits/v1", failCode: 500, wantErr: true},
		{name: "503 on compare", failPath: "/compare/", failCode: 503, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if got := r.Header.Get("Authorization"); got != "Bearer tok" {
					t.Errorf("Authorization = %q", got)
				}
				if tt.failPath != "" && strings.Contains(r.URL.Path, tt.failPath) {
					w.WriteHeader(tt.failCode)
					return
				}
				switch r.URL.Path {
				case "/repos/o/r/releases/latest":
					_, _ = w.Write([]byte(`{"tag_name":"v1"}`))
				case "/repos/o/r/commits/v1":
					_, _ = w.Write([]byte(`{"sha":"deadbeef"}`))
				case "/repos/o/r/compare/req...v1":
					_, _ = w.Write([]byte(`{"status":"` + tt.status + `"}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			api := gate.NewGitHubAPI(srv.Client(), srv.URL, repo, "tok")
			tag, commit, err := api.LatestRelease(context.Background())
			if err == nil {
				if tag != "v1" || commit != "deadbeef" {
					t.Errorf("release = %s %s", tag, commit)
				}
				var ok bool
				ok, err = api.Contains(context.Background(), tag, "req")
				if err == nil && ok != tt.wantContains {
					t.Errorf("contains = %v, want %v", ok, tt.wantContains)
				}
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
