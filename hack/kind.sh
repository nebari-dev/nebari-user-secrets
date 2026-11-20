#!/usr/bin/env bash
# Manage the local kind cluster used by integration tests.
set -euo pipefail

CLUSTER=us-dev
IMAGE=kindest/node:v1.34.3
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBECONFIG_PATH="$ROOT/.kube/kind"

case "${1:-}" in
  up)
    mkdir -p "$ROOT/.kube"
    if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
      kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG_PATH"
    else
      kind create cluster --name "$CLUSTER" --image "$IMAGE" --kubeconfig "$KUBECONFIG_PATH"
    fi
    ;;
  down)
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG_PATH" || true
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
