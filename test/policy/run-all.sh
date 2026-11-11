#!/usr/bin/env bash
# Create a throwaway kind cluster per Kubernetes version, run the matrix, save the transcript, delete the cluster.
# Requires kind, kubectl and a container runtime. Uses its own kubeconfig in this directory;
# it never touches ~/.kube/config. Transcripts land in results/.
cd "$(dirname "$0")"
export KUBECONFIG=$PWD/kubeconfig
for v in v1.30.13 v1.32.11 v1.34.3; do
  out=results/$v.txt
  echo "### $v" | tee "$out"
  kind delete cluster --name us-vap-spike >/dev/null 2>&1
  if ! kind create cluster --name us-vap-spike --image kindest/node:$v --wait 180s >>"$out" 2>&1; then
    echo "CLUSTER CREATE FAILED for $v" | tee -a "$out"
    continue
  fi
  kubectl version 2>/dev/null | grep -i server | tee -a "$out"
  SVC_NS=secrets-svc bash ./run.sh 2>&1 | tee -a "$out" | grep -E "^(PASS|FAIL|RESULT)" | tail -3
  kind delete cluster --name us-vap-spike >/dev/null 2>&1
done
echo "### done"
