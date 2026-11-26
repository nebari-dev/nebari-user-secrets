// Command nicgate decides whether Tier 3 blocks merges: it blocks only once
// the latest NIC release contains NIC_REQUIRED_COMMIT (the commit that added
// the cluster CA). It writes blocking, nic-tag and nic-commit to
// $GITHUB_OUTPUT (stdout when unset) and exits 1 when it cannot decide.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/test/journeys/gate"
)

const (
	baseURL = "https://api.github.com"
	repo    = "nebari-dev/nebari-infrastructure-core"
	// About two minutes of retries (5+10+15+20+25 s of backoff): a gate
	// failure fails tier3 in every mode, so ride out short API outages.
	attempts = 6
	backoff  = 5 * time.Second
)

func main() {
	if err := run(context.Background(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "nicgate:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, stdout io.Writer) error {
	required := os.Getenv("NIC_REQUIRED_COMMIT")
	if required == "" {
		return fmt.Errorf("NIC_REQUIRED_COMMIT is not set")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	api := gate.NewGitHubAPI(client, baseURL, repo, os.Getenv("GITHUB_TOKEN"))
	d, err := gate.Decide(ctx, api, required, attempts, backoff)
	if err != nil {
		return err
	}

	text, err := d.GitHubOutput()
	if err != nil {
		return err
	}

	out := stdout
	if p := os.Getenv("GITHUB_OUTPUT"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	_, err = io.WriteString(out, text)
	return err
}
