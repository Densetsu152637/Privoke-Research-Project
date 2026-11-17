#!/usr/bin/env bash
# Deploy a tested commit of the Rust stack to this VM, in a fixed, fail-closed order (stage 8a of
# docs/plans/rust-server-rewrite.md; stage 8b removed the reverse proxy, so there is no proxy to fall back to).
#
#   deploy.sh <commit-sha> <artifact-registry-prefix>   stage, smoke on loopback, switch to the public ports
#   deploy.sh confirm <commit-sha>                       the external smoke passed: make the release current
#   deploy.sh rollback [reason]                          the external smoke failed or timed out: undo the switch
#
# The order a deployment follows, and why:
#   1. Verify and stage. Fetch the certificates, keys and trust anchors from Secret Manager into a new release directory,
#      check that every certificate chains to its CA, matches its key and carries the right identity, and install a valid
#      CRL and registry. Nothing is started if any check fails.
#   2. Stage the containers with both public ports published on 127.0.0.1 only. Nothing is reachable from the network.
#   3. Smoke test on loopback (tests/smoke.py): mutual TLS required, private RPCs denied, the V3 package fetched and
#      pinned, telemetry accepted with the reporter credential, and every image refusing to start without its CA or CRL.
#   4. Switch: republish the public ports on 0.0.0.0:443 and 0.0.0.0:8443. Port 8443 stays closed in the firewall; the
#      caller opens it only now (the firewall rule is created disabled, see the deployment guide), then runs the external
#      smoke test against the public endpoints. The release is "pending" until it is confirmed.
#   5. Roll back until the external smoke passes. Any failure above, an explicit rollback, or the watchdog timer (set in
#      step 4 and cancelled by confirm) tears the new release down and restarts the previous one, if there is one. With
#      no previous release the stack is simply stopped: nothing is left exposed. The caller closes 8443 again.
#
# It also installs the 6-hourly CRL and registry refresh (privoke-pki-sync.timer); without a current CRL every server
# refuses every handshake after 7 days.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }

root=/opt/privoke
here=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)
tree=$(cd -- "$here/../.." && pwd)
pki_group=10010
service_names=(probe param-update fuzzer analysis)
model_publish_public=0.0.0.0:443
telemetry_publish_public=0.0.0.0:8443
model_publish_staging=127.0.0.1:50443
telemetry_publish_staging=127.0.0.1:58443

mode=deploy
case ${1:-} in
  confirm) mode=confirm; release_tag=${2:?Commit SHA required} ;;
  rollback) mode=rollback; reason=${2:-requested} ;;
  *) release_tag=${1:?Commit SHA required}; image_prefix=${2:?Artifact Registry prefix required} ;;
esac
if [[ $mode != rollback ]]; then
  [[ $release_tag =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid commit SHA.' >&2; exit 1; }
fi
if [[ $mode = deploy ]]; then
  [[ $image_prefix =~ ^[a-z0-9-]+-docker.pkg.dev/[a-z0-9-]+/[a-z0-9_-]+$ ]] || { echo 'Invalid image prefix.' >&2; exit 1; }
fi

mkdir -p "$root/releases"
exec 9>"$root/deploy.lock"
flock -n 9 || { echo 'Another deployment is active.' >&2; exit 1; }

compose_for() { # release directory, then docker compose arguments
  local dir=$1
  shift
  docker compose --project-name privoke --env-file "$dir/release.env" -f "$dir/compose.yml" "$@"
}

stop_watchdog() {
  systemctl stop privoke-pending-rollback.timer privoke-pending-rollback.service >/dev/null 2>&1 || true
  systemctl reset-failed privoke-pending-rollback.timer privoke-pending-rollback.service >/dev/null 2>&1 || true
}

# Tear down the candidate release and bring the previous one back. Safe to call more than once.
rollback_release() { # candidate release dir, previous release dir (may be empty)
  local candidate=$1 previous=$2
  trap - ERR
  stop_watchdog
  echo "Rolling back $(basename -- "$candidate")." >&2
  if [[ -f $candidate/release.env ]]; then
    compose_for "$candidate" ps >&2 || true
    compose_for "$candidate" down --remove-orphans --timeout 30 || echo 'Could not stop the candidate release; stop it by hand.' >&2
  fi
  rm -f -- "$root/pending"
  if [[ -n $previous && -f $previous/release.env && $previous != "$candidate" ]]; then
    compose_for "$previous" up -d --no-build --wait --wait-timeout 240 || echo 'The previous release did not restart.' >&2
  else
    echo 'No previous release: the stack is stopped and nothing is published.' >&2
  fi
}

case $mode in
  confirm)
    pending=$(readlink -f -- "$root/pending" 2>/dev/null || true)
    [[ -n $pending && -d $pending ]] || { echo 'No release is awaiting confirmation.' >&2; exit 1; }
    [[ $(basename -- "$pending") == "$release_tag".* ]] || { echo "The pending release is $(basename -- "$pending"), not $release_tag." >&2; exit 1; }
    ln -sfn "$pending" "$root/current"
    rm -f -- "$root/pending"
    stop_watchdog
    printf 'Confirmed %s\n' "$release_tag"
    exit 0
    ;;
  rollback)
    candidate=$(readlink -f -- "$root/pending" 2>/dev/null || true)
    if [[ -z $candidate || ! -d $candidate ]]; then
      echo 'Nothing is pending; nothing to roll back.'
      exit 0
    fi
    previous=$(readlink -f -- "$root/current" 2>/dev/null || true)
    echo "Rollback reason: $reason" >&2
    rollback_release "$candidate" "$previous"
    exit 0
    ;;
  *) ;;
esac

# ---- deploy --------------------------------------------------------------------------------------------------------
[[ ! -e $root/pending ]] || { echo 'A previous deployment is awaiting confirmation; run deploy.sh confirm or deploy.sh rollback first.' >&2; exit 1; }

# Only root/admins can write this operator-owned configuration.
# shellcheck source=/dev/null
source "$root/.env"
: "${GCP_PROJECT_ID:?}" "${TLS_CERT_SECRET:?}" "${TLS_KEY_SECRET:?}" "${CLIENT_CA_SECRET:?}" "${SERVER_CA_SECRET:?}"
: "${CRL_SECRET:?}" "${REGISTRY_SECRET:?}" "${SERVICE_SECRET_PREFIX:?}" "${SMOKE_SECRET_PREFIX:?}" "${STACK_HOST:?}"
: "${MODEL_RELEASE_DIR:?Stage verified V3 packages first}"
[[ $MODEL_RELEASE_DIR = /* && -d $MODEL_RELEASE_DIR ]] || { echo 'MODEL_RELEASE_DIR must be an existing absolute directory.' >&2; exit 1; }
[[ $STACK_HOST =~ ^[A-Za-z0-9.-]+$ ]] || { echo 'STACK_HOST must be a DNS name.' >&2; exit 1; }
smoke_python=$root/smoke-venv/bin/python
[[ -x $smoke_python ]] || { echo "Missing $smoke_python; run bootstrap.sh." >&2; exit 1; }
live=$root/pki-live
model_id=${MODEL_LATEST_ID:-privoke-v3-balanced}
# Copies of the operator values: they are unset before Compose runs, and the release file is written twice.
model_release_dir=$MODEL_RELEASE_DIR
compose_profiles=${COMPOSE_PROFILES:-}
fuzzer_prompt_count=${FUZZER_PROMPT_COUNT:-32}
fuzzer_interval=${FUZZER_REQUEST_INTERVAL_SECONDS:-3600}
fuzzer_seed=${FUZZER_REQUEST_SEED:-1337}
previous=$(readlink -f -- "$root/current" 2>/dev/null || true)
release_dir=$(mktemp -d "$root/releases/${release_tag}.XXXXXX")
touched=0

on_error() {
  local line=$1
  trap - ERR
  echo "Deployment failed at line $line." >&2
  if (( touched )); then
    rollback_release "$release_dir" "$previous"
  fi
  rm -rf -- "$release_dir"
  exit 1
}
trap 'on_error $LINENO' ERR

fetch() { gcloud secrets versions access latest --project="$GCP_PROJECT_ID" --secret="$1" > "$2"; }

key_matches() { # certificate, private key
  [[ $(openssl x509 -in "$1" -noout -pubkey | sha256sum) == "$(openssl pkey -in "$2" -pubout | sha256sum)" ]]
}

# 1. Verify and stage -------------------------------------------------------------------------------------------------
# The release directory carries everything it needs to be rolled back to, including these scripts.
(cd -- "$tree" && cp --parents -t "$release_dir" \
  deploy/gce/compose.yml deploy/gce/deploy.sh deploy/gce/pki-sync.sh deploy/gce/tests/smoke.py \
  deploy/gce/systemd/privoke-pki-sync.service deploy/gce/systemd/privoke-pki-sync.timer \
  shared/proto/privoke/v1/parameters.proto shared/proto/privoke/v1/telemetry.proto \
  shared/python/privoke_model/standard_v3.py extension/client-runtime/src/telemetry/privacy.py)
mkdir "$release_dir/src"
mv "$release_dir/deploy" "$release_dir/shared" "$release_dir/extension" "$release_dir/src/"
install -m 0600 "$release_dir/src/deploy/gce/compose.yml" "$release_dir/compose.yml"
ln -s src/deploy/gce/deploy.sh "$release_dir/deploy.sh"

install -m 0750 "$here/pki-sync.sh" /usr/local/sbin/privoke-pki-sync
install -m 0644 "$here/systemd/privoke-pki-sync.service" "$here/systemd/privoke-pki-sync.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now privoke-pki-sync.timer

pki=$release_dir/pki
install -d -m 0750 "$pki" "$pki/server" "$pki/svc"
fetch "$TLS_CERT_SECRET" "$pki/server/server.crt"
fetch "$TLS_KEY_SECRET" "$pki/server/server.key"
fetch "$CLIENT_CA_SECRET" "$pki/client-ca.pem"
fetch "$SERVER_CA_SECRET" "$pki/server-ca.pem"
for name in "${service_names[@]}"; do
  fetch "$SERVICE_SECRET_PREFIX-$name-cert" "$pki/svc/$name.crt"
  fetch "$SERVICE_SECRET_PREFIX-$name-key" "$pki/svc/$name.key"
done

# The server certificate must chain to the server CA, match its key, be valid for two more weeks and name every host the
# stack is reached by: the public name and the internal service names (loopback staging overrides the name to STACK_HOST).
openssl verify -CAfile "$pki/server-ca.pem" -purpose sslserver "$pki/server/server.crt" >/dev/null
key_matches "$pki/server/server.crt" "$pki/server/server.key"
openssl x509 -in "$pki/server/server.crt" -noout -checkend $((14 * 86400)) >/dev/null
for host in "$STACK_HOST" model-streaming-service telemetry-service param-update-service privoke-fuzzer analysis-service analysis-model-streaming; do
  openssl x509 -in "$pki/server/server.crt" -noout -checkhost "$host" | grep -q 'does match' \
    || { echo "The server certificate does not name $host." >&2; exit 1; }
done
# Each service identity must chain to the client CA, match its key and carry exactly its own service URN.
for name in "${service_names[@]}"; do
  openssl verify -CAfile "$pki/client-ca.pem" -purpose sslclient "$pki/svc/$name.crt" >/dev/null
  key_matches "$pki/svc/$name.crt" "$pki/svc/$name.key"
  openssl x509 -in "$pki/svc/$name.crt" -noout -ext subjectAltName | grep -q "URI:urn:privoke:service:$name\$" \
    || { echo "The $name certificate does not carry urn:privoke:service:$name." >&2; exit 1; }
  openssl x509 -in "$pki/svc/$name.crt" -noout -checkend $((7 * 86400)) >/dev/null
done

# Shared hot-reloaded files, then the first sync. Servers refuse everything without a valid CRL, so stop here without one.
install -d -m 0750 "$live"
install -m 0640 "$pki/client-ca.pem" "$live/client-ca.pem"
chgrp -R "$pki_group" "$pki" "$live"
find "$pki" "$live" -type d -exec chmod 0750 {} +
find "$pki" "$live" -type f -exec chmod 0640 {} +
sync_status=0
/usr/local/sbin/privoke-pki-sync || sync_status=$?
(( sync_status == 0 || sync_status == 2 )) || { echo 'No valid CRL and registry could be installed.' >&2; exit 1; }
[[ -s $live/crl.pem && -s $live/registry.toml ]] || { echo 'crl.pem and registry.toml are required.' >&2; exit 1; }

# Credentials for the smoke test (an installation registered for smoke tests and the shared reporter credential), kept
# only for this run. The unregistered and foreign-CA certificates are optional extra negative checks.
smoke_creds=$release_dir/smoke-creds
install -d -m 0700 "$smoke_creds"
cp "$pki/server-ca.pem" "$smoke_creds/server-ca.pem"
fetch "$SMOKE_SECRET_PREFIX-installation-cert" "$smoke_creds/installation.crt"
fetch "$SMOKE_SECRET_PREFIX-installation-key" "$smoke_creds/installation.key"
fetch "$SMOKE_SECRET_PREFIX-reporter-cert" "$smoke_creds/reporter.crt"
fetch "$SMOKE_SECRET_PREFIX-reporter-key" "$smoke_creds/reporter.key"
for optional in unregistered foreign; do
  if fetch "$SMOKE_SECRET_PREFIX-$optional-cert" "$smoke_creds/$optional.crt" 2>/dev/null \
     && fetch "$SMOKE_SECRET_PREFIX-$optional-key" "$smoke_creds/$optional.key" 2>/dev/null; then
    :
  else
    rm -f -- "$smoke_creds/$optional.crt" "$smoke_creds/$optional.key"
  fi
done

write_release_env() { # model publish address, telemetry publish address
  printf 'IMAGE_PREFIX=%s\nIMAGE_TAG=%s\nPRIVOKE_PKI_DIR=%s\nPRIVOKE_PKI_LIVE_DIR=%s\nMODEL_RELEASE_DIR=%s\nMODEL_LATEST_ID=%s\nMODEL_PUBLISH=%s\nTELEMETRY_PUBLISH=%s\nCOMPOSE_PROFILES=%s\nFUZZER_PROMPT_COUNT=%s\nFUZZER_REQUEST_INTERVAL_SECONDS=%s\nFUZZER_REQUEST_SEED=%s\n' \
    "$image_prefix" "$release_tag" "$pki" "$live" "$model_release_dir" "$model_id" "$1" "$2" \
    "$compose_profiles" "$fuzzer_prompt_count" "$fuzzer_interval" "$fuzzer_seed" \
    > "$release_dir/release.env"
}
write_release_env "$model_publish_staging" "$telemetry_publish_staging"
# Compose must use the saved release values, including during rollback.
unset IMAGE_PREFIX IMAGE_TAG PRIVOKE_PKI_DIR PRIVOKE_PKI_LIVE_DIR MODEL_RELEASE_DIR MODEL_LATEST_ID MODEL_PUBLISH TELEMETRY_PUBLISH \
  COMPOSE_PROFILES FUZZER_PROMPT_COUNT FUZZER_REQUEST_INTERVAL_SECONDS FUZZER_REQUEST_SEED

export DOCKER_CONFIG
DOCKER_CONFIG=$(mktemp -d)
trap 'rm -rf -- "$DOCKER_CONFIG"' EXIT
trap 'on_error $LINENO' ERR
gcloud auth print-access-token | docker login --username oauth2accesstoken --password-stdin "${image_prefix%%/*}"
compose=(compose_for "$release_dir")
"${compose[@]}" config --quiet
"${compose[@]}" pull

# 2. Stage on loopback ------------------------------------------------------------------------------------------------
touched=1
"${compose[@]}" up -d --no-build --wait --wait-timeout 300

# 3. Smoke test on loopback -------------------------------------------------------------------------------------------
"$smoke_python" -I "$release_dir/src/deploy/gce/tests/smoke.py" \
  --creds "$smoke_creds" --server-name "$STACK_HOST" --model-id "$model_id" \
  --model-target "$model_publish_staging" --telemetry-target "$telemetry_publish_staging" \
  --images "$image_prefix:$release_tag" --pki-dir "$pki" --live-dir "$live"
rm -rf -- "$smoke_creds"

# 4. Switch to the public ports ---------------------------------------------------------------------------------------
# From here the release is pending: not current, and rolled back by the watchdog unless it is confirmed in time.
ln -sfn "$release_dir" "$root/pending"
stop_watchdog
systemd-run --quiet --unit privoke-pending-rollback --on-active="${PENDING_TIMEOUT_MINUTES:-30}m" \
  --property=Type=oneshot /bin/bash "$release_dir/src/deploy/gce/deploy.sh" rollback timeout
write_release_env "$model_publish_public" "$telemetry_publish_public"
"${compose[@]}" up -d --no-build --wait --wait-timeout 300

trap - ERR
printf 'SWITCHED %s model=%s telemetry=%s\n' "$release_tag" "$model_publish_public" "$telemetry_publish_public"
printf 'Pending: open the firewall for tcp:8443, run the external smoke test, then run deploy.sh confirm %s (or deploy.sh rollback).\n' "$release_tag"
