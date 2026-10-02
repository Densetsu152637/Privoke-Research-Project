#!/usr/bin/env bash
# Input: a tested commit SHA and its Artifact Registry image prefix.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
release_tag=${1:?Commit SHA required}
image_prefix=${2:?Artifact Registry prefix required}
[[ $release_tag =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid commit SHA.' >&2; exit 1; }
[[ $image_prefix =~ ^[a-z0-9-]+-docker.pkg.dev/[a-z0-9-]+/[a-z0-9_-]+$ ]] || { echo 'Invalid image prefix.' >&2; exit 1; }
root=/opt/privoke
exec 9>"$root/deploy.lock"
flock -n 9 || { echo 'Another deployment is active.' >&2; exit 1; }
# Only root/admins can write this operator-owned configuration.
# shellcheck source=/dev/null
source "$root/.env"
: "${GCP_PROJECT_ID:?}" "${TLS_CERT_SECRET:?}" "${TLS_KEY_SECRET:?}" "${CLIENT_CA_SECRET:?}"
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
release_dir=$(mktemp -d "$root/releases/${release_tag}.XXXXXX")
install -m 0600 "$source_dir/compose.yml" "$source_dir/nginx.conf" "$release_dir/"
install -m 0700 "$source_dir/deploy.sh" "$release_dir/deploy.sh"
install -d -m 0700 "$release_dir/secrets"
gcloud secrets versions access latest --project="$GCP_PROJECT_ID" --secret="$TLS_CERT_SECRET" > "$release_dir/secrets/server.crt"
gcloud secrets versions access latest --project="$GCP_PROJECT_ID" --secret="$TLS_KEY_SECRET" > "$release_dir/secrets/server.key"
gcloud secrets versions access latest --project="$GCP_PROJECT_ID" --secret="$CLIENT_CA_SECRET" > "$release_dir/secrets/client-ca.crt"
printf 'IMAGE_PREFIX=%s\nIMAGE_TAG=%s\nSECRETS_DIR=%s\nFUZZER_PROMPT_COUNT=%s\n' \
  "$image_prefix" "$release_tag" "$release_dir/secrets" "${FUZZER_PROMPT_COUNT:-0}" > "$release_dir/release.env"
# Compose must use the saved release values, including during rollback.
unset IMAGE_PREFIX IMAGE_TAG SECRETS_DIR FUZZER_PROMPT_COUNT
export DOCKER_CONFIG
DOCKER_CONFIG=$(mktemp -d)
trap 'rm -rf -- "$DOCKER_CONFIG"' EXIT
gcloud auth print-access-token | docker login --username oauth2accesstoken --password-stdin "${image_prefix%%/*}"
compose=(docker compose --project-name privoke --env-file "$release_dir/release.env" -f "$release_dir/compose.yml")
"${compose[@]}" config --quiet
"${compose[@]}" pull
"${compose[@]}" run --rm --no-deps ingress nginx -t
previous=$(readlink -f "$root/current" || true)
if ! "${compose[@]}" up -d --no-build --wait --wait-timeout 240; then
  echo 'Deployment failed; attempting to restore the previous release.' >&2
  "${compose[@]}" ps
  if [[ -n $previous && -f $previous/release.env ]]; then
    docker compose --project-name privoke --env-file "$previous/release.env" -f "$previous/compose.yml" up -d --no-build --wait --wait-timeout 240
  fi
  exit 1
fi
ln -sfn "$release_dir" "$root/current"
printf 'Deployed %s\n' "$release_tag"
