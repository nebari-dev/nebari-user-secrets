// Package gate decides whether Tier 3 blocks merges: it blocks only once the
// latest NIC release contains the commit that added the cluster CA.
package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ReleaseAPI is the slice of the GitHub API the gate needs.
type ReleaseAPI interface {
	// LatestRelease returns the latest release's tag and the commit it points at.
	LatestRelease(ctx context.Context) (tag, commit string, err error)
	// Contains reports whether tag contains commit.
	Contains(ctx context.Context, tag, commit string) (bool, error)
}

// Decision is the gate's verdict.
type Decision struct {
	Tag, Commit string
	// Blocking is true when the latest release contains the required commit.
	Blocking bool
}

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tagRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

// GitHubOutput renders d as $GITHUB_OUTPUT lines. It rejects a tag or commit
// that is not a plain tag name or 40 lowercase hex digits, so an API value
// cannot add or override output lines.
func (d Decision) GitHubOutput() (string, error) {
	if !tagRE.MatchString(d.Tag) {
		return "", fmt.Errorf("release tag %q is not a plain tag name", d.Tag)
	}
	if !commitRE.MatchString(d.Commit) {
		return "", fmt.Errorf("release commit %q is not 40 lowercase hex digits", d.Commit)
	}
	return fmt.Sprintf("blocking=%t\nnic-tag=%s\nnic-commit=%s\n", d.Blocking, d.Tag, d.Commit), nil
}

// Decide asks api for the latest release and whether it contains required,
// retrying a failing call up to attempts times, sleeping backoff times the
// attempt number between tries. It never guesses: persistent errors are
// returned.
func Decide(ctx context.Context, api ReleaseAPI, required string, attempts int,
	backoff time.Duration) (Decision, error) {
	var d Decision
	err := retry(ctx, attempts, backoff, func() error {
		var err error
		d.Tag, d.Commit, err = api.LatestRelease(ctx)
		return err
	})
	if err != nil {
		return Decision{}, fmt.Errorf("latest release: %w", err)
	}
	err = retry(ctx, attempts, backoff, func() error {
		var err error
		d.Blocking, err = api.Contains(ctx, d.Tag, required)
		return err
	})
	if err != nil {
		return Decision{}, fmt.Errorf("compare %s...%s: %w", required, d.Tag, err)
	}
	return d, nil
}

func retry(ctx context.Context, attempts int, backoff time.Duration, f func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 1; i <= attempts; i++ {
		if err = f(); err == nil {
			return nil
		}
		if i == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(i) * backoff):
		}
	}
	return err
}

// GitHubAPI implements ReleaseAPI over the GitHub REST API.
type GitHubAPI struct {
	c       *http.Client
	baseURL string
	repo    string
	token   string
}

// NewGitHubAPI returns a client for repo ("owner/name") at baseURL. The token
// is sent as a bearer token and never logged.
func NewGitHubAPI(c *http.Client, baseURL, repo, token string) *GitHubAPI {
	return &GitHubAPI{c: c, baseURL: strings.TrimRight(baseURL, "/"), repo: repo, token: token}
}

// LatestRelease implements ReleaseAPI.
func (g *GitHubAPI) LatestRelease(ctx context.Context) (string, string, error) {
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := g.get(ctx, "/repos/"+g.repo+"/releases/latest", &rel); err != nil {
		return "", "", err
	}
	if rel.TagName == "" {
		return "", "", fmt.Errorf("latest release has no tag_name")
	}
	var c struct {
		SHA string `json:"sha"`
	}
	if err := g.get(ctx, "/repos/"+g.repo+"/commits/"+url.PathEscape(rel.TagName), &c); err != nil {
		return "", "", err
	}
	if c.SHA == "" {
		return "", "", fmt.Errorf("commit for tag %s has no sha", rel.TagName)
	}
	return rel.TagName, c.SHA, nil
}

// Contains implements ReleaseAPI: compare commit...tag reports the tag as
// ahead of (or identical to) the commit when it contains it.
func (g *GitHubAPI) Contains(ctx context.Context, tag, commit string) (bool, error) {
	var cmp struct {
		Status string `json:"status"`
	}
	path := "/repos/" + g.repo + "/compare/" + url.PathEscape(commit) + "..." + url.PathEscape(tag) + "?per_page=1"
	if err := g.get(ctx, path, &cmp); err != nil {
		return false, err
	}
	switch cmp.Status {
	case "ahead", "identical":
		return true, nil
	case "behind", "diverged":
		return false, nil
	}
	return false, fmt.Errorf("unexpected compare status %q", cmp.Status)
}

func (g *GitHubAPI) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
