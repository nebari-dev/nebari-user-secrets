#!/usr/bin/env bash
# Create a throwaway kind cluster per Kubernetes version, run the matrix, save the transcript, delete the cluster.
# Requires kind, kubectl and a container runtime. Uses its own kubeconfig in this directory;
# it never touches ~/.kube/config. Transcripts land in results/.
# Versions: POLICY_K8S_VERSIONS from ci/pins.env, or K8S_VERSION to run one.
# Exits 1 if any version failed (cluster create or a failed expect); every version still runs.
cd "$(dirname "$0")"
source ../../ci/load-pins.sh || exit 1
: "${POLICY_K8S_VERSIONS:?missing from ci/pins.env}"
export KUBECONFIG=$PWD/kubeconfig
set -o pipefail
failed=()
for v in ${K8S_VERSION:-$POLICY_K8S_VERSIONS}; do
  out=results/$v.txt
  echo "### $v" | tee "$out"
  kind delete cluster --name us-vap-spike >/dev/null 2>&1
  if ! kind create cluster --name us-vap-spike --image kindest/node:$v --wait 180s >>"$out" 2>&1; then
    echo "CLUSTER CREATE FAILED for $v" | tee -a "$out"
    failed+=("$v")
    kind delete cluster --name us-vap-spike >/dev/null 2>&1
    continue
  fi
  kubectl version 2>/dev/null | grep -i server | tee -a "$out"
  if ! SVC_NS=secrets-svc bash ./run.sh 2>&1 | tee -a "$out" | grep -E "^(PASS|FAIL|RESULT)" | tail -3; then
    failed+=("$v")
  fi
  kind delete cluster --name us-vap-spike >/dev/null 2>&1
done
echo "### done"
if (( ${#failed[@]} > 0 )); then
  echo "FAILED: ${failed[*]}"
  exit 1
fi
