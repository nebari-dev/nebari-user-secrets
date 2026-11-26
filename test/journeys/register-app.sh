#!/usr/bin/env bash
# Registers an app with NIC's root App-of-Apps for Tier 3:
#
#   register-app.sh <app-name> <chart-source-dir> <application.yaml>
#
# Copies <chart-source-dir> into $GITOPS_DIR/<app-name>/, renders
# <application.yaml> with envsubst into $GITOPS_DIR/apps/<app-name>.yaml,
# commits, asks Argo CD to refresh Application/nebari-root, and waits (bounded)
# for Application/<app-name> to exist. Health is left to the caller.
#
# $GITOPS_DIR is NIC's local GitOps repository (~/.nic/gitops/<project_name>
# for the local repository provider), which the root Application nebari-root
# reads non-recursively for apps/*.yaml. Every ${VAR} the Application names
# must be set and non-empty: an unset variable would render as empty text.
# Env: GITOPS_DIR, KUBECONFIG; REGISTER_WAIT_SECONDS (default 300).
set -euo pipefail

die() {
  echo "::error::register-app: $*" >&2
  exit 1
}

[[ $# -eq 3 ]] || die "usage: register-app.sh <app-name> <chart-source-dir> <application.yaml>"
APP=$1 SRC=$2 MANIFEST=$3
: "${GITOPS_DIR:?GITOPS_DIR is required}"
WAIT_SECONDS=${REGISTER_WAIT_SECONDS:-300}

[[ "$APP" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || die "app name must be a DNS label: $APP"
case "$APP" in
  apps | manifests) die "app name $APP collides with the GitOps layout" ;;
esac
[[ -d "$GITOPS_DIR/apps" ]] || die "$GITOPS_DIR/apps does not exist"
[[ -d "$SRC" ]] || die "chart source is not a directory: $SRC"
[[ -f "$MANIFEST" ]] || die "application manifest is not a file: $MANIFEST"

export GITOPS_DIR
# Only these variables are substituted, so nothing else in the job's
# environment (the journey user's password, for one) can reach a committed
# manifest.
# shellcheck disable=SC2016 # literal variable names for envsubst, not expansions
ALLOWED='${GITOPS_DIR} ${KEYCLOAK_ISSUER} ${USER_SECRETS_IMAGE}'
while read -r var; do
  [[ -n "$var" ]] || continue
  [[ " $ALLOWED " == *" \${$var} "* ]] || die "$MANIFEST names \${$var}, which is not in the allowed list"
  [[ -n "${!var:-}" ]] || die "$MANIFEST names \${$var}, which is not set"
done < <(envsubst --variables "$(cat "$MANIFEST")" | sort -u)

dest="$GITOPS_DIR/$APP"
rm -rf "$dest"
mkdir -p "$dest"
cp -r "$SRC/." "$dest/"
envsubst "$ALLOWED" <"$MANIFEST" >"$GITOPS_DIR/apps/$APP.yaml"

git -C "$GITOPS_DIR" add -A -- "$APP" "apps/$APP.yaml"
# Nothing to commit when the same content is registered again.
if ! git -C "$GITOPS_DIR" diff --cached --quiet; then
  git -C "$GITOPS_DIR" -c user.email=tier3@nebari-user-secrets -c user.name=tier3 \
    commit -q -m "add $APP"
fi
# Argo CD's repo-server reads the repository from the kind node's read-only
# mount as another user: keep what this commit added group and world readable,
# whatever the runner's umask.
chmod -R go+rX "$dest" "$GITOPS_DIR/apps/$APP.yaml" "$GITOPS_DIR/.git"
echo "register-app: committed $APP to $GITOPS_DIR"

# Ask for a refresh now rather than at the next polling interval.
kubectl -n argocd annotate application/nebari-root argocd.argoproj.io/refresh=normal --overwrite >/dev/null

deadline=$((SECONDS + WAIT_SECONDS))
until kubectl -n argocd get "application/$APP" >/dev/null 2>&1; do
  ((SECONDS < deadline)) || die "Application/$APP not created by nebari-root within ${WAIT_SECONDS}s"
  sleep 3
done
echo "register-app: Application/$APP exists"
