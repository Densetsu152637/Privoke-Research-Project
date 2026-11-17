#!/usr/bin/env bash
# Refresh the two hot-reloaded trust files of the running stack from Secret Manager: the certificate revocation list
# (crl.pem) and the registry (registry.toml). Installed by deploy.sh as /usr/local/sbin/privoke-pki-sync and run by
# privoke-pki-sync.timer every six hours.
#
# Why this exists: every server refuses all handshakes once the CRL's nextUpdate has passed (a CRL lasts 7 days by
# default). The CA key is offline, so the operator publishes each new CRL to Secret Manager (docs/deployment/google-cloud.md,
# "Publish the CRL"); this job brings it to the VM. The servers reload the files in place, so no restart is needed.
#
# Fail-closed rules: a CRL that is not signed by the client CA, or has less than an hour left, is never installed and the
# previous file stays; the exit status is non-zero when the installed CRL has under 72 hours left (2) or has lapsed (3), so
# the unit shows as failed and `journalctl -u privoke-pki-sync` says why.
set -Eeuo pipefail
umask 027
root=${PRIVOKE_ROOT:-/opt/privoke}
# shellcheck source=/dev/null
source "$root/.env"
: "${GCP_PROJECT_ID:?}" "${CRL_SECRET:?}" "${REGISTRY_SECRET:?}"
live=${PRIVOKE_PKI_LIVE_DIR:-$root/pki-live}
group=10010
warn_seconds=$((72 * 3600))
[[ -d $live && -s $live/client-ca.pem ]] || { echo "No trust anchor in $live; run deploy.sh first." >&2; exit 1; }

now=$(date +%s)
next_update_epoch() {
  local text
  text=$(openssl crl -in "$1" -noout -nextupdate) || return 1
  date -d "${text#nextUpdate=}" +%s
}

stage=$(mktemp -d "$live/.sync.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
status=0

install_if_changed() { # name
  local name=$1
  if [[ -f $live/$name ]] && cmp -s "$stage/$name" "$live/$name"; then return 0; fi
  chgrp "$group" "$stage/$name"
  chmod 0640 "$stage/$name"
  mv -f -- "$stage/$name" "$live/$name"
  echo "Installed a new $name."
}

if gcloud secrets versions access latest --project="$GCP_PROJECT_ID" --secret="$CRL_SECRET" > "$stage/crl.pem"; then
  if openssl crl -in "$stage/crl.pem" -CAfile "$live/client-ca.pem" -verify -noout >/dev/null 2>&1 \
     && candidate=$(next_update_epoch "$stage/crl.pem") && (( candidate > now + 3600 )); then
    install_if_changed crl.pem
  else
    echo "Refusing the CRL in Secret Manager: not signed by the client CA, unreadable, or about to lapse." >&2
    status=1
  fi
else
  echo "Could not read secret $CRL_SECRET." >&2
  status=1
fi

if gcloud secrets versions access latest --project="$GCP_PROJECT_ID" --secret="$REGISTRY_SECRET" > "$stage/registry.toml"; then
  # Servers validate the whole file and keep the previous one on any error; this only stops an obviously wrong upload.
  if grep -Eq '^[[:space:]]*version[[:space:]]*=[[:space:]]*1' "$stage/registry.toml"; then
    install_if_changed registry.toml
  else
    echo "Refusing the registry in Secret Manager: no 'version = 1'." >&2
    status=1
  fi
else
  echo "Could not read secret $REGISTRY_SECRET." >&2
  status=1
fi

# Report the CRL that is actually installed.
if [[ -s $live/crl.pem ]] && installed=$(next_update_epoch "$live/crl.pem"); then
  remaining=$((installed - now))
  if (( remaining <= 0 )); then
    echo "The installed CRL has lapsed; every handshake is being refused. Publish a new CRL now." >&2
    exit 3
  elif (( remaining < warn_seconds )); then
    echo "The installed CRL lapses in $((remaining / 3600)) hours. Publish a new CRL." >&2
    (( status )) || status=2
  else
    echo "The installed CRL is valid for another $((remaining / 3600)) hours."
  fi
else
  echo "No readable CRL is installed." >&2
  exit 3
fi
exit "$status"
