#!/usr/bin/env bash
# End-to-end cluster for the installable service: kind us-e2e with Calico (so
# NetworkPolicy is enforced), cert-manager and trust-manager with NIC's values,
# NIC's cluster CA and trust bundle (rendered from the vendored templates for
# certificate.type: letsencrypt), Keycloak with the test realm and the chart.
#
# Usage: setup.sh up|down. Uses $IMG (already in the local docker store; see
# make image-load). Kubeconfig: .kube/e2e. Rendered manifests: test/e2e/.tmp/.
set -euo pipefail

CLUSTER=us-e2e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Versions (KIND_NODE_IMAGE, CALICO_VERSION, GATEWAY_API_VERSION,
# CERT_MANAGER_VERSION, TRUST_MANAGER_VERSION, KEYCLOAK_IMAGE, CURL_IMAGE) come
# from ci/pins.env.
source "$ROOT/ci/load-pins.sh"
NODE_IMAGE=$KIND_NODE_IMAGE
# Calico manifest from the release tag:
CALICO_MANIFEST="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
# NIC's cert-manager values set config.enableGatewayAPI, and cert-manager
# refuses to start without the Gateway API CRDs. NIC gets them from Envoy
# Gateway v1.9.1 (pkg/argocd/templates/apps/envoy-gateway.yaml), which builds
# against sigs.k8s.io/gateway-api GATEWAY_API_VERSION; install that release's
# standard CRDs.
GATEWAY_API_MANIFEST="https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
# cert-manager and trust-manager chart versions are the ones NIC pins.
JETSTACK_REPO=https://charts.jetstack.io

SERVICE_NS=us-system
LANDING_NS=nebari-system
KEYCLOAK_NS=e2e-keycloak
# The realm's discovery document, as the service and the tests see it.
KEYCLOAK_ISSUER=https://keycloak.$KEYCLOAK_NS.svc:8443/realms/nebari

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
  mkdir -p "$TMP"
  (cd "$ROOT" && go run -tags e2e ./test/e2e/nicrender -dir "$FIXTURES/nic") >"$TMP/nic-ca.yaml"
  # trust-manager's webhook can refuse connections for a few seconds after
  # helm reports it ready (its Service is not yet routable), so retry.
  wait_for "trust-manager webhook to admit NIC's CA and bundle" 120 kubectl apply -f "$TMP/nic-ca.yaml"
  kubectl -n cert-manager wait --for=condition=Ready certificate/nebari-root-ca --timeout=180s
  kubectl create namespace "$LANDING_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  wait_for "nebari-trust-bundle in $LANDING_NS" 180 kubectl -n "$LANDING_NS" get configmap nebari-trust-bundle
}

# install_keycloak deploys Keycloak (start-dev, realm imported from
# fixtures/keycloak/realm.json, whose test passwords are fixture values, not
# secrets) with a certificate from NIC's CA issuer, and the kc-client pod the
# tests request tokens from. It returns once the realm's discovery document
# answers from inside the cluster with the in-cluster issuer.
install_keycloak() {
  log "deploying Keycloak ($KEYCLOAK_IMAGE) with the nebari test realm"
  mkdir -p "$TMP"
  # Images come from ci/pins.env only; render them into the manifest.
  sed -e "s|\${KEYCLOAK_IMAGE}|$KEYCLOAK_IMAGE|g" -e "s|\${CURL_IMAGE}|$CURL_IMAGE|g" \
    "$FIXTURES/keycloak/keycloak.yaml" >"$TMP/keycloak.yaml"
  # cert-manager's webhook can refuse the Certificate for a few seconds after
  # install, as trust-manager's does in install_nic_ca, so retry.
  wait_for "cert-manager webhook to admit the Keycloak manifests" 120 kubectl apply -f "$TMP/keycloak.yaml"
  kubectl -n "$KEYCLOAK_NS" create configmap keycloak-realm --from-file=nebari.json="$FIXTURES/keycloak/realm.json" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "$KEYCLOAK_NS" wait --for=condition=Ready certificate/keycloak-tls --timeout=180s
  kubectl -n "$KEYCLOAK_NS" rollout status deployment/keycloak --timeout=300s
  kubectl -n "$KEYCLOAK_NS" wait --for=condition=Ready pod/kc-client --timeout=180s
  log "waiting for the realm's discovery document from kc-client"
  local wk=$KEYCLOAK_ISSUER/.well-known/openid-configuration
  wait_for "$wk from kc-client" 180 kubectl -n "$KEYCLOAK_NS" exec kc-client -- \
    curl -sSf --max-time 10 --cacert /etc/nebari/trust/ca-certificates.crt "$wk"
  kubectl -n "$KEYCLOAK_NS" exec kc-client -- \
    curl -sSf --max-time 10 --cacert /etc/nebari/trust/ca-certificates.crt "$wk" |
    jq -e --arg iss "$KEYCLOAK_ISSUER" '.issuer == $iss' >/dev/null
}

# install_consumer creates the registered workload namespaces (e2e-workload,
# whose pods come from clients.yaml later, and test-consumer with its
# ServiceAccounts) before the chart, which renders a pod-reader Role into every
# registered workload namespace.
install_consumer() {
  log "creating the e2e-workload and test-consumer namespaces, workload and creator ServiceAccounts"
  kubectl create namespace e2e-workload --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f "$FIXTURES/consumer.yaml"
}

install_chart() {
  log "loading $IMG into $CLUSTER and installing the chart"
  kind load docker-image "$IMG" --name "$CLUSTER"
  kubectl create namespace "$SERVICE_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  helm upgrade --install user-secrets "$ROOT/chart" --namespace "$SERVICE_NS" \
    -f "$FIXTURES/values.yaml" -f "$FIXTURES/values-consumer.yaml" \
    --set-string image="$IMG" --wait --timeout 5m
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
    install_keycloak
    install_consumer
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
