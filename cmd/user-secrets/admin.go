package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nebari-dev/nebari-user-secrets/internal/admin"
	"github.com/nebari-dev/nebari-user-secrets/internal/audit"
	"github.com/nebari-dev/nebari-user-secrets/internal/crypto"
	"github.com/nebari-dev/nebari-user-secrets/internal/store"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	cmdRotateKEK = "rotate-kek"
	cmdRetireKEK = "retire-kek"
	cmdRotateDEK = "rotate-dek"
)

// actorAuditor stamps the admin's name on key events that carry none, so
// every key_event line from an admin command names its actor.
type actorAuditor struct {
	inner crypto.KeyAuditor
	actor string
}

func (a actorAuditor) KeyEvent(ctx context.Context, event, ownerSub, actor, detail string) {
	if actor == "" {
		actor = a.actor
	}
	a.inner.KeyEvent(ctx, event, ownerSub, actor, detail)
}

// restConfig uses KUBECONFIG when set, else the in-cluster config.
func restConfig() (*rest.Config, error) {
	if os.Getenv("KUBECONFIG") != "" {
		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	}
	return rest.InClusterConfig()
}

func runAdmin(args []string) int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := execAdmin(args, logger, os.Stderr); err != nil {
		logger.Error("admin command failed", "error", err.Error())
		return 1
	}
	return 0
}

func execAdmin(args []string, logger *slog.Logger, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd, flagArgs := args[0], args[1:]
	fs := flag.NewFlagSet("admin "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	namespace := fs.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace of the service (default $POD_NAMESPACE)")
	actor := fs.String("actor", "", "name recorded in key_event audit lines (required)")
	owner := fs.String("owner", "", "rotate-dek: owner sub (default all owners)")

	// The retire-kek id is positional and may come before or after the flags.
	var id string
	if cmd == cmdRetireKEK && len(flagArgs) > 0 && flagArgs[0] != "" && flagArgs[0][0] != '-' {
		id, flagArgs = flagArgs[0], flagArgs[1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if cmd == cmdRetireKEK && id == "" && fs.NArg() == 1 {
		id = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	switch cmd {
	case cmdRotateKEK, cmdRotateDEK, cmdRetireKEK:
	default:
		return fmt.Errorf("unknown admin command %q\n%s", cmd, usage)
	}
	if cmd == cmdRetireKEK && id == "" {
		return errors.New("retire-kek requires a key id")
	}
	if cmd != cmdRotateDEK && *owner != "" {
		return errors.New("--owner applies to rotate-dek only")
	}
	if *actor == "" {
		return errors.New("--actor is required")
	}
	if *namespace == "" {
		return errors.New("--namespace is required (or set POD_NAMESPACE)")
	}

	cfg, err := restConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st := store.NewKubernetesSecretStore(cs, *namespace, time.Now)
	aud := actorAuditor{inner: audit.NewSlogAuditSink(logger), actor: *actor}
	kek := crypto.NewKubernetesKEK(cs, *namespace, st, aud)
	// Load never creates a key, so a missing or invalid master key stops the
	// command here.
	if err := kek.Load(ctx); err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	sealer := crypto.NewSealer(kek, rand.Reader)

	switch cmd {
	case cmdRotateKEK:
		rep, err := admin.RotateKEK(ctx, st, kek, sealer, aud, *actor)
		if err != nil {
			return err
		}
		logger.Info("rotate-kek done", "rewrapped", rep.Rewrapped, "records_by_kek", rep.ByKEK)
	case cmdRetireKEK:
		if err := admin.RetireKEK(ctx, st, kek, id); err != nil {
			return err
		}
		logger.Info("retire-kek done", "kek_id", id)
	case cmdRotateDEK:
		rep, err := admin.RotateDEK(ctx, st, sealer, aud, *actor, *owner)
		if err != nil {
			return err
		}
		logger.Info("rotate-dek done", "rotated", rep.Rewrapped, "records_by_kek", rep.ByKEK)
	}
	return nil
}
