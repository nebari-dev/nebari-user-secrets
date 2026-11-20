#!/usr/bin/env bash
# Spike: exercise the user-secrets admission policies on a throwaway kind cluster.
set -u
cd "$(dirname "$0")"
export KUBECONFIG=$PWD/kubeconfig
SVC=${SVC_NS:-secrets-svc}
K="kubectl"
PAUSE=registry.k8s.io/pause:3.10
PASS=0; FAIL=0

expect() { # expect allow|deny <name> <msg-substring-or-empty> -- cmd...
  local want=$1 name=$2 sub=$3; shift 4
  local out rc
  out=$("$@" 2>&1); rc=$?
  local got=allow; [ $rc -ne 0 ] && got=deny
  if [ "$got" = "$want" ] && { [ -z "$sub" ] || grep -qF -- "$sub" <<<"$out"; }; then
    PASS=$((PASS+1)); echo "PASS  $name"
  else
    FAIL=$((FAIL+1)); echo "FAIL  $name (want $want, got $got)"; echo "      $(head -c 400 <<<"$out")"
  fi
}

pod() { # pod <name> <labelled:yes|no> <sub> <app> [sa] [extra-spec-yaml]
  local name=$1 lab=$2 sub=$3 app=$4 sa=${5:-default}
  echo "apiVersion: v1
kind: Pod
metadata:
  name: $name"
  if [ "$lab" = yes ]; then echo "  labels:
    nebari.dev/user-secrets: \"true\""; fi
  if [ -n "$sub$app" ]; then echo "  annotations:"
    [ -n "$sub" ] && echo "    nebari.dev/user-secrets-sub: \"$sub\""
    [ -n "$app" ] && echo "    nebari.dev/user-secrets-app: \"$app\""
  fi
  echo "spec:
  serviceAccountName: $sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: c
      image: $PAUSE
      imagePullPolicy: IfNotPresent
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
${6:-}"
}
as() { echo "--as=system:serviceaccount:$1"; }

echo "== setup"
for ns in $SVC hub-ns dask-ns other; do $K create ns $ns >/dev/null 2>&1; done
$K label ns $SVC pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
$K -n $SVC create sa user-secrets >/dev/null 2>&1
$K -n hub-ns create sa hub >/dev/null 2>&1
$K -n hub-ns create sa notebook-wl >/dev/null 2>&1
$K -n dask-ns create sa dask-ctrl >/dev/null 2>&1
$K -n other create sa mallory >/dev/null 2>&1
$K -n $SVC create rolebinding svc-pods --clusterrole=edit --serviceaccount=$SVC:user-secrets >/dev/null 2>&1
$K -n hub-ns create rolebinding hub-edit --clusterrole=edit --serviceaccount=hub-ns:hub >/dev/null 2>&1
$K -n dask-ns create rolebinding dask-edit --clusterrole=edit --serviceaccount=dask-ns:dask-ctrl >/dev/null 2>&1
$K -n hub-ns create rolebinding dask-in-hub --clusterrole=edit --serviceaccount=dask-ns:dask-ctrl >/dev/null 2>&1
$K -n hub-ns create rolebinding mallory-edit --clusterrole=edit --serviceaccount=other:mallory >/dev/null 2>&1
$K -n other create rolebinding mallory-edit --clusterrole=edit --serviceaccount=other:mallory >/dev/null 2>&1
$K -n kube-system create rolebinding mallory-edit --clusterrole=edit --serviceaccount=other:mallory >/dev/null 2>&1
CM_YAML='apiVersion: v1
kind: ConfigMap
metadata: {name: user-secrets-creators, namespace: '"$SVC"'}
data:
  hub-ns.hub: "namespaces=hub-ns;apps=notebook,jhub-apps"
  dask-ns.dask-ctrl: "namespaces=dask-ns;apps=dask"'
echo "$CM_YAML" | $K apply -f - >/dev/null
BUNDLE=$(mktemp -d); cp ../../cluster/* "$BUNDLE"/
sed -i "s/^  namespace: .*/  namespace: $SVC/" "$BUNDLE"/install-config.yaml
$K kustomize "$BUNDLE" | $K apply -f - >/dev/null
echo "== waiting for policies to take effect"
for i in $(seq 1 60); do
  if ! pod probe-unlabelled no A notebook | $K -n hub-ns create --dry-run=server -f - >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "== policy B: creator allowlist"
expect allow "hub creates labelled notebook pod in its namespace" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod nb-a yes sub-A notebook notebook-wl | $K -n hub-ns create $(as hub-ns:hub) -f -"
expect deny "non-creator (mallory) creates labelled pod with A's sub" "not a registered creator" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod evil-1 yes sub-A notebook | $K -n hub-ns create $(as other:mallory) -f -"
expect deny "hub creates labelled pod with an app it is not allowed (dask)" "not a registered creator" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod nb-x yes sub-A dask | $K -n hub-ns create $(as hub-ns:hub) -f -"
expect deny "dask controller creates labelled pod outside its namespace (hub-ns, app notebook)" "not a registered creator" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod evil-2 yes sub-A notebook | $K -n hub-ns create $(as dask-ns:dask-ctrl) -f -"
expect allow "dask controller creates labelled dask pod in dask-ns" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod dw-a yes sub-A dask | $K -n dask-ns create $(as dask-ns:dask-ctrl) -f -"

echo "== policy A: shape and immutability"
expect deny "annotated pod without the label" "must carry the label" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod evil-3 no sub-A notebook | $K -n hub-ns create $(as other:mallory) -f -"
expect deny "labelled pod missing the sub annotation (by hub, app allowed, so only policy A can deny)" "both user-secrets annotations" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod nb-y yes '' notebook | $K -n hub-ns create $(as hub-ns:hub) -f -"
expect allow "unannotated, unlabelled pod by anyone" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod plain-1 no '' '' | $K -n hub-ns create $(as other:mallory) -f -"
expect deny "change sub annotation on labelled pod (admin)" "immutable" -- \
  $K -n hub-ns annotate pod nb-a nebari.dev/user-secrets-sub=sub-B --overwrite
expect deny "remove label from labelled pod (admin)" "immutable" -- \
  $K -n hub-ns label pod nb-a nebari.dev/user-secrets-
expect deny "add label and annotations to existing plain pod (admin)" "immutable" -- \
  $K -n hub-ns patch pod plain-1 --type=merge -p '{"metadata":{"labels":{"nebari.dev/user-secrets":"true"},"annotations":{"nebari.dev/user-secrets-sub":"sub-A","nebari.dev/user-secrets-app":"notebook"}}}'
expect deny "change sub via pods/status (admin)" "immutable" -- \
  $K -n hub-ns patch pod nb-a --subresource=status --type=merge -p '{"metadata":{"annotations":{"nebari.dev/user-secrets-sub":"sub-B"}}}'
expect allow "unrelated annotation change on labelled pod (admin)" "" -- \
  $K -n hub-ns annotate pod nb-a example.com/other=1 --overwrite
expect deny "image patch on labelled pod (admin)" "spec of a labelled pod is immutable" -- \
  $K -n hub-ns set image pod/nb-a c=registry.k8s.io/pause:3.9
expect allow "image patch on unlabelled pod (admin, control)" "" -- \
  $K -n hub-ns set image pod/plain-1 c=registry.k8s.io/pause:3.9
expect deny "ephemeral container on labelled pod (admin)" "ephemeral containers" -- \
  $K -n hub-ns debug nb-a --image=$PAUSE --attach=false -q

echo "== pods/binding"
pod nb-unsched yes sub-A notebook notebook-wl "  schedulerName: no-such-scheduler" | $K -n hub-ns create $(as hub-ns:hub) -f - >/dev/null
NODE=$($K get nodes -o jsonpath='{.items[0].metadata.name}')
expect deny "binding carrying user-secrets annotations" "bindings may not carry" -- \
  bash -c "echo '{\"apiVersion\":\"v1\",\"kind\":\"Binding\",\"metadata\":{\"name\":\"nb-unsched\",\"annotations\":{\"nebari.dev/user-secrets-sub\":\"sub-B\"}},\"target\":{\"apiVersion\":\"v1\",\"kind\":\"Node\",\"name\":\"$NODE\"}}' | $K create --raw /api/v1/namespaces/hub-ns/pods/nb-unsched/binding -f -"
expect allow "plain binding" "" -- \
  bash -c "echo '{\"apiVersion\":\"v1\",\"kind\":\"Binding\",\"metadata\":{\"name\":\"nb-unsched\"},\"target\":{\"apiVersion\":\"v1\",\"kind\":\"Node\",\"name\":\"$NODE\"}}' | $K create --raw /api/v1/namespaces/hub-ns/pods/nb-unsched/binding -f -"

echo "== token minting"
expect deny "mallory mints a user-secrets token" "only kubelets" -- \
  $K -n other create token mallory --audience user-secrets $(as other:mallory)
expect deny "admin mints a user-secrets token for the hub SA" "only kubelets" -- \
  $K -n hub-ns create token notebook-wl --audience user-secrets
expect allow "admin mints a token for another audience" "" -- \
  $K -n hub-ns create token notebook-wl --audience spike

echo "== kubelet-minted projected token (pod must start)"
pod nb-proj yes sub-A notebook notebook-wl "  volumes:
    - name: us-token
      projected:
        sources:
          - serviceAccountToken: {audience: user-secrets, expirationSeconds: 600, path: token}" \
  | sed 's/^    - name: c$/    - name: c\n      volumeMounts: [{name: us-token, mountPath: \/var\/run\/us}]/' \
  | $K -n hub-ns create $(as hub-ns:hub) -f - >/dev/null
expect allow "pod with user-secrets projected token becomes Ready" "" -- \
  $K -n hub-ns wait pod/nb-proj --for=condition=Ready --timeout=90s

echo "== TokenReview extras for a pod-bound token (open question 5)"
UID_=$($K -n hub-ns get pod nb-a -o jsonpath='{.metadata.uid}')
TOK=$($K -n hub-ns create token notebook-wl --audience spike --bound-object-kind Pod --bound-object-name nb-a --bound-object-uid "$UID_")
TR=$(echo "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"$TOK\",\"audiences\":[\"spike\"]}}" | $K create -f - -o json)
echo "$TR" | python3 -c 'import json,sys; s=json.load(sys.stdin)["status"]; print("      authenticated:", s.get("authenticated"), "| user:", s["user"]["username"]); print("      extra:", json.dumps(s["user"].get("extra",{})))'
expect allow "TokenReview extra carries pod-name and pod-uid" "" -- \
  bash -c "echo '$TR' | grep -q 'authentication.kubernetes.io/pod-name' && echo '$TR' | grep -q '$UID_'"

echo "== service account: dry-run only, and the probe"
expect deny "service SA creates a real pod" "only create pods as dry-run" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod real-1 no '' '' | $K -n $SVC create $(as $SVC:user-secrets) -f -"
expect deny "probe: compliant labelled dry-run pod denied by the creators policy" "not a registered creator" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod probe yes probe-sub notebook | $K -n $SVC create --dry-run=server $(as $SVC:user-secrets) -f -"
expect deny "probe: unlabelled annotated dry-run pod denied by the guard policy" "must carry the label" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod probe2 no probe-sub notebook | $K -n $SVC create --dry-run=server $(as $SVC:user-secrets) -f -"
expect deny "probe: non-compliant pod is stopped by Pod Security first (N3)" "violates PodSecurity" -- \
  bash -c "printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: probe3, labels: {nebari.dev/user-secrets: \"true\"}, annotations: {nebari.dev/user-secrets-sub: s, nebari.dev/user-secrets-app: notebook}}\nspec: {containers: [{name: c, image: $PAUSE, securityContext: {privileged: true}}]}\n' | $K -n $SVC create --dry-run=server $(as $SVC:user-secrets) -f -"

expect allow "probe: canary (plain compliant dry-run pod by the service SA) is admitted" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod canary no '' '' | $K -n $SVC create --dry-run=server $(as $SVC:user-secrets) -f -"

echo "== label changes through subresources"
expect deny "remove label via pods/status (admin)" "immutable" -- \
  $K -n hub-ns patch pod nb-a --subresource=status --type=json -p '[{"op":"remove","path":"/metadata/labels/nebari.dev~1user-secrets"}]'
expect deny "add label via pods/status to a plain pod (admin)" "immutable" -- \
  $K -n hub-ns patch pod plain-1 --subresource=status --type=merge -p '{"metadata":{"labels":{"nebari.dev/user-secrets":"true"}}}'
pod plain-unsched no '' '' default "  schedulerName: no-such-scheduler" | $K -n hub-ns create -f - >/dev/null
expect deny "binding carrying the user-secrets label" "bindings may not carry" -- \
  bash -c "echo '{\"apiVersion\":\"v1\",\"kind\":\"Binding\",\"metadata\":{\"name\":\"plain-unsched\",\"labels\":{\"nebari.dev/user-secrets\":\"true\"}},\"target\":{\"apiVersion\":\"v1\",\"kind\":\"Node\",\"name\":\"$NODE\"}}' | $K create --raw /api/v1/namespaces/hub-ns/pods/plain-unsched/binding -f -"

echo "== missing ConfigMap (P1)"
$K -n $SVC delete configmap user-secrets-creators >/dev/null
for i in $(seq 1 60); do
  if ! pod probe-cm yes s notebook notebook-wl | $K -n hub-ns create --dry-run=server $(as hub-ns:hub) -f - >/dev/null 2>&1; then break; fi
  sleep 1
done
expect deny "labelled pod by a real creator is denied while params are missing" "no params found" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod nb-b yes sub-A notebook notebook-wl | $K -n hub-ns create $(as hub-ns:hub) -f -"
expect deny "labelled pod by mallory is denied while params are missing" "no params found" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod evil-4 yes sub-A notebook | $K -n hub-ns create $(as other:mallory) -f -"
expect allow "unannotated pod in kube-system still created" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod plain-ks no '' '' | $K -n kube-system create -f -"
expect allow "pods/status update on an unlabelled pod still allowed" "" -- \
  $K -n hub-ns patch pod plain-1 --subresource=status --type=merge -p '{"metadata":{"annotations":{"example.com/x":"1"}}}'
expect allow "token for another audience still minted" "" -- \
  $K -n hub-ns create token notebook-wl --audience spike
expect deny "guard rules still active: annotation change on labelled pod" "immutable" -- \
  $K -n hub-ns annotate pod nb-a nebari.dev/user-secrets-sub=sub-B --overwrite
expect deny "guard rules still active: user-secrets token by mallory" "only kubelets" -- \
  $K -n other create token mallory --audience user-secrets $(as other:mallory)
NBB_ERR=$(pod nb-b2 yes sub-A notebook notebook-wl | $K -n hub-ns create --dry-run=server $(as hub-ns:hub) -f - 2>&1)
echo "      denial text while params missing: $(head -c 300 <<<"$NBB_ERR")"

echo "== ConfigMap restored"
echo "$CM_YAML" | $K apply -f - >/dev/null
for i in $(seq 1 60); do
  if pod probe-cm2 yes s notebook notebook-wl | $K -n hub-ns create --dry-run=server $(as hub-ns:hub) -f - >/dev/null 2>&1; then break; fi
  sleep 1
done
expect allow "hub creates labelled pod again after restore" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod nb-c yes sub-A notebook notebook-wl | $K -n hub-ns create $(as hub-ns:hub) -f -"

echo "== Warn-only binding stops enforcement (guard must treat as bad), and the change is detectable"
RV0=$($K get validatingadmissionpolicybinding user-secrets-creators -o jsonpath='{.metadata.resourceVersion} {.metadata.generation} {.metadata.uid}')
$K patch validatingadmissionpolicybinding user-secrets-creators --type=merge -p '{"spec":{"validationActions":["Warn"]}}' >/dev/null
for i in $(seq 1 60); do
  if pod probe-w yes s notebook | $K -n hub-ns create --dry-run=server $(as other:mallory) -f - >/dev/null 2>&1; then break; fi
  sleep 1
done
expect allow "with [Warn], mallory's labelled pod is admitted (real create)" "" -- \
  bash -c "$(declare -f pod); PAUSE=$PAUSE; pod evil-5 yes sub-A notebook | $K -n hub-ns create $(as other:mallory) -f -"
$K patch validatingadmissionpolicybinding user-secrets-creators --type=merge -p '{"spec":{"validationActions":["Deny"]}}' >/dev/null
RV1=$($K get validatingadmissionpolicybinding user-secrets-creators -o jsonpath='{.metadata.resourceVersion} {.metadata.generation} {.metadata.uid}')
MF=$($K get validatingadmissionpolicybinding user-secrets-creators -o json | python3 -c 'import json,sys; o=json.load(sys.stdin)["metadata"]; print(max([o["creationTimestamp"]]+[m["time"] for m in o.get("managedFields",[]) if "time" in m]))')
POD_T=$($K -n hub-ns get pod evil-5 -o jsonpath='{.metadata.creationTimestamp}')
echo "      binding before: rv/gen/uid $RV0; after Warn and back to Deny: $RV1"
echo "      pod admitted under Warn created $POD_T; newest managedFields time on the binding $MF (not used: it does not advance on a value change)"
expect allow "Warn-and-restore is detectable: resourceVersion changed and generation advanced by 2, uid unchanged" "" -- \
  python3 -c "
a='$RV0'.split(); b='$RV1'.split()
import sys; sys.exit(0 if a[0]!=b[0] and int(b[1])==int(a[1])+2 and a[2]==b[2] else 1)"
$K delete validatingadmissionpolicybinding user-secrets-creators >/dev/null
$K kustomize "$BUNDLE" | $K apply -f - >/dev/null
RV2=$($K get validatingadmissionpolicybinding user-secrets-creators -o jsonpath='{.metadata.resourceVersion} {.metadata.generation} {.metadata.uid}')
echo "      after delete and re-create: $RV2"
expect allow "delete-and-recreate is detectable: uid changed" "" -- \
  python3 -c "import sys; sys.exit(0 if '$RV1'.split()[2] != '$RV2'.split()[2] else 1)"

rm -rf "$BUNDLE"
echo
echo "RESULT: $PASS passed, $FAIL failed"
