#!/usr/bin/env bash
# Seeds the Tier 3 Nebari's Keycloak for the journeys: the public client
# user-secrets-journeys (direct access grants, the chart's keycloak.clientID)
# in the nebari realm, and one user with a password generated here. Writes
# JOURNEY_USER and JOURNEY_PASSWORD to $GITHUB_ENV (stdout when unset).
#
# Talks to Keycloak's in-cluster Service through kubectl port-forward and
# authenticates as the master realm admin: the nebari realm's own admin user
# holds only a plain realm role named admin (NIC realm-setup-job.yaml), which
# the admin REST API does not honour. NIC's own journey suite does the same.
#
# Env: KUBECONFIG; KEYCLOAK_ADMIN_PASSWORD (deploy-nebari-action's
# keycloak-admin-password output; when empty, read from the
# keycloak-admin-credentials Secret). Every credential is masked with
# ::add-mask:: before anything else is printed, and passed to curl on stdin,
# never as an argument.
set -euo pipefail

NS=keycloak
SVC=svc/keycloak-keycloakx-http
SVC_PORT=8080
REALM=nebari
CLIENT_ID=user-secrets-journeys
USERNAME=journey-user
WAIT_SECONDS=${SEED_WAIT_SECONDS:-300}

log() { echo "seed-keycloak: $*" >&2; }
die() {
  echo "::error::seed-keycloak: $*" >&2
  exit 1
}

# mask registers a value with the runner's log masking. Outside Actions the
# command is a harmless line on stdout.
mask() { [[ -z "$1" ]] || echo "::add-mask::$1"; }

PASSWORD=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
[[ ${#PASSWORD} -eq 32 ]] || die "could not generate a password"
mask "$PASSWORD"

ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD:-}
if [[ -z "$ADMIN_PASSWORD" ]]; then
  log "keycloak-admin-password output is empty; reading $NS/keycloak-admin-credentials"
  ADMIN_PASSWORD=$(kubectl -n "$NS" get secret keycloak-admin-credentials \
    -o jsonpath='{.data.admin-password}' | base64 -d)
fi
mask "$ADMIN_PASSWORD"
[[ -n "$ADMIN_PASSWORD" ]] || die "no master realm admin password"

TMP=$(mktemp -d)
PF_PID=
cleanup() {
  [[ -z "$PF_PID" ]] || kill "$PF_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

log "port-forwarding $NS/$SVC:$SVC_PORT"
kubectl -n "$NS" port-forward "$SVC" ":$SVC_PORT" >"$TMP/pf.log" 2>&1 &
PF_PID=$!
PORT=
for _ in $(seq 1 30); do
  PORT=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$TMP/pf.log" | head -n 1)
  [[ -n "$PORT" ]] && break
  kill -0 "$PF_PID" 2>/dev/null || die "port-forward exited: $(cat "$TMP/pf.log")"
  sleep 1
done
[[ -n "$PORT" ]] || die "port-forward did not start: $(cat "$TMP/pf.log")"
BASE="http://127.0.0.1:$PORT"

# admin_token prints a master realm admin access token (admin-cli, password
# grant); the password goes to curl on stdin.
admin_token() {
  local body
  body=$(printf '%s' "$ADMIN_PASSWORD" | curl -sS --max-time 20 \
    --data-urlencode grant_type=password --data-urlencode client_id=admin-cli \
    --data-urlencode username=admin --data-urlencode password@- \
    "$BASE/realms/master/protocol/openid-connect/token") || return 1
  jq -er '.access_token' <<<"$body"
}

# admin_status METHOD PATH [BODY_FILE] prints the HTTP status of an admin REST
# call. The token is passed in a header file, not as an argument.
admin_status() {
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --max-time 20 -o "$TMP/resp" -w '%{http_code}' -X "$method" -H "@$TMP/auth")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  fi
  curl "${args[@]}" "$BASE/admin/realms$path"
}

# The realm comes from NIC's PostSync hook, which can still be running.
log "waiting up to ${WAIT_SECONDS}s for Keycloak and the $REALM realm"
deadline=$((SECONDS + WAIT_SECONDS))
while :; do
  if TOKEN=$(admin_token 2>/dev/null); then
    mask "$TOKEN"
    printf 'Authorization: Bearer %s\n' "$TOKEN" >"$TMP/auth"
    [[ "$(admin_status GET "/$REALM" || true)" == 200 ]] && break
  fi
  ((SECONDS < deadline)) || die "Keycloak or the $REALM realm not ready after ${WAIT_SECONDS}s"
  sleep 5
done

# create PATH WHAT BODY_FILE IF_EXISTS posts BODY_FILE. 201 is created; 409
# (already there) is accepted when IF_EXISTS is ok, and fails otherwise.
create() {
  local status
  status=$(admin_status POST "$1" "$3") || die "create $2: request failed"
  case "$status" in
    201) log "created $2" ;;
    409) [[ "$4" == ok ]] || die "$2 already exists"
      log "$2 already exists" ;;
    *) die "create $2: HTTP $status: $(cat "$TMP/resp")" ;;
  esac
}

jq -n --arg id "$CLIENT_ID" '{
  clientId: $id, enabled: true, protocol: "openid-connect", publicClient: true,
  directAccessGrantsEnabled: true, standardFlowEnabled: false
}' >"$TMP/client.json"
create "/$REALM/clients" "client $CLIENT_ID" "$TMP/client.json" ok

# Keycloak's default user profile wants email, first and last name before a
# password grant succeeds. The password reaches jq through its environment,
# not its arguments. A user left from an earlier run has a password this run
# cannot know, so it fails.
JOURNEY_PW=$PASSWORD jq -n --arg u "$USERNAME" '{
  username: $u, enabled: true, emailVerified: true, requiredActions: [],
  email: ($u + "@nebari.local"), firstName: "Journey", lastName: "User",
  credentials: [{type: "password", value: env.JOURNEY_PW, temporary: false}]
}' >"$TMP/user.json"
create "/$REALM/users" "user $USERNAME" "$TMP/user.json" fail

out=${GITHUB_ENV:-/dev/stdout}
{
  echo "JOURNEY_USER=$USERNAME"
  echo "JOURNEY_PASSWORD=$PASSWORD"
} >>"$out"
log "wrote JOURNEY_USER and JOURNEY_PASSWORD"
