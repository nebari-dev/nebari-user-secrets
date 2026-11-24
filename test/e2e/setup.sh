#!/usr/bin/env bash
# End-to-end cluster for the installable service: kind us-e2e with Calico (so
# NetworkPolicy is enforced), cert-manager and trust-manager with NIC's values,
# NIC's cluster CA and trust bundle (rendered from the vendored templates for
# certificate.type: letsencrypt), a static HTTPS JWKS server and the chart.
#
# Usage: setup.sh up|down. Uses $IMG (already in the local docker store; see
# make image-load). Kubeconfig: .kube/e2e. Test key: test/e2e/.tmp/.
set -euo pipefail

CLUSTER=us-e2e
NODE_IMAGE=kindest/node:v1.34.3
# Calico v3.32.3, manifest from the release tag:
CALICO_VERSION=v3.32.3
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
# NIC's cert-manager values set config.enableGatewayAPI, and cert-manager
# refuses to start without the Gateway API CRDs. NIC gets them from Envoy
# Gateway v1.9.1 (pkg/argocd/templates/apps/envoy-gateway.yaml), which builds
# against sigs.k8s.io/gateway-api v1.6.1; install that release's standard CRDs.
GATEWAY_API_VERSION=v1.6.1
GATEWAY_API_MANIFEST="https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
# Chart versions pinned by NIC at de81b11 (pkg/argocd/templates/apps/*.yaml).
JETSTACK_REPO=https://charts.jetstack.io
CERT_MANAGER_VERSION=v1.17.2
TRUST_MANAGER_VERSION=v0.22.1

SERVICE_NS=us-system
LANDING_NS=nebari-system
KID=e2e-1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/test/e2e"
TMP="$E2E/.tmp"
FIXTURES="$E2E/fixtures"
export KUBECONFIG="$ROOT/.kube/e2e"
IMG="${IMG:-ghcr.io/nebari-dev/nebari-user-secrets:dev}"

log() { echo "==> $*" >&2; }

# wait_for <description> <timeout seconds> <command...>: polls every 2 s.
wait_for() {
  local what=$1 timeout=$2
  shift 2
  local deadline=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      echo "timed out after ${timeout}s waiting for $what" >&2
      return 1
    fi
    sleep 2
  done
}

create_cluster() {
  mkdir -p "$ROOT/.kube"
  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    log "cluster $CLUSTER exists, exporting kubeconfig"
    kind export kubeconfig --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
    return
  fi
  log "creating kind cluster $CLUSTER ($NODE_IMAGE, no default CNI)"
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --kubeconfig "$KUBECONFIG" --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
}

install_calico() {
  log "installing Calico $CALICO_VERSION"
  kubectl apply --server-side -f "$CALICO_MANIFEST" >/dev/null
  kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
  kubectl -n kube-system rollout status deployment/calico-kube-controllers --timeout=300s
  kubectl wait --for=condition=Ready nodes --all --timeout=300s
  kubectl -n kube-system rollout status deployment/coredns --timeout=300s
}

install_cert_manager() {
  log "installing Gateway API $GATEWAY_API_VERSION CRDs"
  kubectl apply --server-side -f "$GATEWAY_API_MANIFEST" >/dev/null
  log "installing cert-manager $CERT_MANAGER_VERSION and trust-manager $TRUST_MANAGER_VERSION with NIC's values"
  helm upgrade --install cert-manager cert-manager --repo "$JETSTACK_REPO" --version "$CERT_MANAGER_VERSION" \
    --namespace cert-manager --create-namespace \
    -f "$FIXTURES/nic/values/cert-manager/base.yaml" --wait --timeout 5m
  helm upgrade --install trust-manager trust-manager --repo "$JETSTACK_REPO" --version "$TRUST_MANAGER_VERSION" \
    --namespace cert-manager \
    -f "$FIXTURES/nic/values/trust-manager/base.yaml" --wait --timeout 5m
}

install_nic_ca() {
  log "applying NIC's cluster CA and trust bundle (letsencrypt rendering)"
  (cd "$ROOT" && go run -tags e2e ./test/e2e/nicrender -dir "$FIXTURES/nic") | kubectl apply -f -
  kubectl -n cert-manager wait --for=condition=Ready certificate/nebari-root-ca --timeout=180s
  kubectl create namespace "$LANDING_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  wait_for "nebari-trust-bundle in $LANDING_NS" 180 kubectl -n "$LANDING_NS" get configmap nebari-trust-bundle
}

# gen_key writes the signing key (kept across runs) and its public JWKS.
gen_key() {
  mkdir -p "$TMP"
  if [[ ! -f "$TMP/signing-key.pem" ]]; then
    log "generating the test signing key in $TMP"
    (umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/signing-key.pem" 2>/dev/null)
  fi
  local n
  n=$(openssl rsa -in "$TMP/signing-key.pem" -noout -modulus | cut -d= -f2 | xxd -r -p | basenc --base64url -w0 | tr -d '=')
  jq -n --arg kid "$KID" --arg n "$n" \
    '{keys: [{kty: "RSA", use: "sig", alg: "RS256", kid: $kid, n: $n, e: "AQAB"}]}' >"$TMP/jwks.json"
}

install_jwks() {
  log "deploying the HTTPS JWKS server"
  gen_key
  kubectl apply -f "$FIXTURES/jwks.yaml"
  kubectl -n e2e-keycloak create configmap jwks-keys --from-file=jwks.json="$TMP/jwks.json" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n e2e-keycloak wait --for=condition=Ready certificate/jwks-tls --timeout=180s
  kubectl -n e2e-keycloak rollout status deployment/jwks --timeout=180s
}

install_chart() {
  log "loading $IMG into $CLUSTER and installing the chart"
  kind load docker-image "$IMG" --name "$CLUSTER"
  kubectl create namespace "$SERVICE_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  helm upgrade --install user-secrets "$ROOT/chart" --namespace "$SERVICE_NS" \
    -f "$FIXTURES/values.yaml" --set-string image="$IMG" --wait --timeout 5m
}

# restart_service moves the pods onto the image just loaded: the tag does not
# change between builds, so helm leaves running pods on the previous one. It
# runs after apply_bundle, so the guard starts with the bundle in place.
restart_service() {
  kubectl -n "$SERVICE_NS" rollout restart deployment/user-secrets
  kubectl -n "$SERVICE_NS" rollout status deployment/user-secrets --timeout=300s
}

# apply_bundle applies cluster/ (policies, bindings, cluster RBAC) after the
# chart, which creates the user-secrets-creators ConfigMap binding B reads. For
# another SERVICE_NS it renders a temporary copy with install-config.yaml
# rewritten; repo files are never edited.
apply_bundle() {
  log "applying the cluster bundle for namespace $SERVICE_NS"
  if [[ "$SERVICE_NS" == us-system ]]; then
    kubectl apply -k "$ROOT/cluster"
    return
  fi
  (
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    cp -r "$ROOT/cluster/." "$dir/"
    sed -i "s/^  namespace: us-system\$/  namespace: $SERVICE_NS/" "$dir/install-config.yaml"
    grep -qx "  namespace: $SERVICE_NS" "$dir/install-config.yaml"
    kubectl apply -k "$dir"
  )
}

install_clients() {
  log "starting the landing proxy and the workload client"
  kubectl apply -f "$FIXTURES/clients.yaml"
  kubectl -n "$LANDING_NS" wait --for=condition=Ready pod/landing-proxy --timeout=180s
  kubectl -n e2e-workload wait --for=condition=Ready pod/workload-client --timeout=180s
}

case "${1:-}" in
  up)
    create_cluster
    install_calico
    install_cert_manager
    install_nic_ca
    install_jwks
    install_chart
    apply_bundle
    restart_service
    install_clients
    log "ready: KUBECONFIG=$KUBECONFIG"
    ;;
  down)
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
