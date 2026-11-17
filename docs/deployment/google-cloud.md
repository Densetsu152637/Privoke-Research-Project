# Deploy PriVoke to Google Cloud Compute Engine

## Architecture and prerequisites

The deployment runs the Rust services of the [server rewrite](../plans/rust-server-rewrite.md) on one Debian 12 Compute Engine VM, with no reverse proxy. Each public service terminates mutual TLS itself, requires a client certificate from the private client CA, checks the revocation list and a registry on every connection and request, and refuses to start without them:

| Service | Image | Public listener | Internal listener | Who may connect |
| --- | --- | --- | --- | --- |
| `model-streaming-service` | Rust (`rust/services/model-streaming`) | `443` (container `50443`) | `50051`, not published | public: registered installations (`consumer`); internal: registered services |
| `telemetry-service` | Rust (`rust/services/telemetry`) | `8443` (container `58443`) | `50055`, not published | public: the shared reporter credential only; internal: registered services |
| `param-update-service`, `param-update-bootstrap` | Rust (`rust/services/param-update`) | none | `50052`, not published | registered `publisher` and `trainer` services (profile `legacy-training`) |
| `privoke-fuzzer` | Python (`services/privoke-fuzzer`) | none | `50053`, not published | the update service and the fuzzer itself, on an allow list (profile `legacy-training`) |
| `analysis-service`, `analysis-model-streaming` | Rust on the Python runtime image (`rust/services/analysis`) | none | `50054`, no route out | only the fuzzer (profile `legacy-training`) |

Only ports `443` and `8443` are public. IAP carries administrative SSH traffic to port `22`; the internal ports are never published. Docker volumes retain telemetry, update history, fuzzer output, the quarantined service's model cache and the mutable model artifacts. Each workstation authenticates with its own client certificate, downloads models and, separately, reports telemetry with the shared reporter credential. Prompt analysis stays on the workstation. `model-streaming-service` and `telemetry-service` always run; the other services start only with the opt-in `legacy-training` Compose profile (see the training note below). The server no longer runs a `client-runtime` container: the fuzzer reaches inference only through the quarantined `analysis-service` (two `internal: true` networks, a read-only root, no capabilities, resource limits), which emits no telemetry.

This is the supported cloud shape in this repository: a single VM running `deploy/gce/compose.yml`. It is not a managed Kubernetes, Cloud Run, or multi-VM deployment, and nothing may sit in front of the two public ports: the telemetry service's per-source rate limit and daily cap read the connecting address. The browser extension, its native-messaging host and the client detector run on each user's workstation. The VM does not receive browser prompts for the extension's local detector.

The workflow in [deploy-gce.yml](../../.github/workflows/deploy-gce.yml) runs on pushes to `main` and can be dispatched manually on `main`, but it is **inert until you switch it on**: with the repository variable `GCP_DEPLOY_ENABLED` unset or not `true` every job is skipped and a notice says why. When enabled it calls the service CI, builds and publishes five commit-tagged images, then runs the cutover order below on the VM. Deployments are serialized.

### The deployment order (fail closed)

`deploy/gce/deploy.sh` enforces this order for every deployment, and the workflow drives the steps outside the VM:

1. **Verify and stage.** Fetch the server certificate, keys, trust anchors and service identities from Secret Manager into a new release directory; check that each certificate chains to its CA, matches its key and carries the right identity; install a valid CRL and registry. Any failure stops here with nothing started.
2. **Stage the containers on loopback.** Both public ports are published on `127.0.0.1` only (`50443` and `58443`); the firewall is untouched.
3. **Smoke test on loopback** with `deploy/gce/tests/smoke.py`: mutual TLS required, private RPCs denied (R9), the default V3 package fetched and its pin verified (G8), a telemetry report accepted with the reporter credential, and every image refusing to start without its CA, CRL or client CA.
4. **Switch.** Republish the ports on `0.0.0.0:443` and `0.0.0.0:8443`. The release is now *pending*, with a watchdog that rolls it back after `PENDING_TIMEOUT_MINUTES` (default 30). Only then does the workflow enable the firewall rule for `8443` (it is created disabled; `443` is already open).
5. **External smoke test** from the GitHub runner against `$STACK_HOST:443` and `:8443`.
6. **Confirm or roll back.** `deploy.sh confirm` makes the release current. Any failure, cancellation or timeout closes the `8443` rule, tears the new release down and restarts the previous one if there is one. With no previous release the stack is stopped and nothing stays exposed.

Staging replaces the previous release's containers in place (the Compose project is the same), so a redeployment has a maintenance interruption until the switch. The 7-day certificate revocation list is refreshed by a systemd timer that `deploy.sh` installs (see [Publish the CRL](#publish-the-crl)).

The Google guidance behind the commands below is [IAP TCP forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding) (including the `35.235.240.0/20` source range), [Artifact Registry Docker authentication](https://cloud.google.com/artifact-registry/docs/docker/authentication), and [Secret Manager per-secret access](https://cloud.google.com/secret-manager/docs/manage-access-to-secrets). This workflow authenticates with a service account JSON key stored in a GitHub Actions secret; keep that long-lived credential restricted and rotate it under your organization's policy.

You need a Google Cloud project with billing, permission to configure IAM/networking/VMs, a GitHub repository you administer, a DNS name pointing to the VM, and `gcloud`, OpenSSL and Bash for the commands below. Run local commands from this repository's root in Bash, WSL or Cloud Shell. Resource names below are examples: choose values first. A CPU VM such as `e2-standard-4` with a 100 GB persistent boot disk is an initial research configuration; measure your model memory and experiment load before selecting production capacity. This deployment has a maintenance interruption during container replacement and a single VM failure domain.

## 1. Create the project resources and identities

```bash
export PROJECT_ID=your-project-id
export REGION=australia-southeast1
export ZONE=australia-southeast1-b
export REPOSITORY=privoke
export INSTANCE=privoke-stack
export GITHUB_REPOSITORY=your-org/your-repo
# Numeric IDs from GitHub's repository API (not names that could be reused).
export GITHUB_REPOSITORY_ID=123456789
export GITHUB_OWNER_ID=1234567
export STACK_HOST=stack.example.com

gcloud auth login
gcloud config set project "$PROJECT_ID"
gcloud services enable compute.googleapis.com artifactregistry.googleapis.com \
  iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  secretmanager.googleapis.com iap.googleapis.com oslogin.googleapis.com
export PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')

gcloud artifacts repositories create "$REPOSITORY" --location="$REGION" \
  --repository-format=docker --description='PriVoke release images'
gcloud iam service-accounts create github-deployer
gcloud iam service-accounts create privoke-vm
export DEPLOY_SA="github-deployer@$PROJECT_ID.iam.gserviceaccount.com"
export VM_SA="privoke-vm@$PROJECT_ID.iam.gserviceaccount.com"

gcloud artifacts repositories add-iam-policy-binding "$REPOSITORY" --location="$REGION" \
  --member="serviceAccount:$DEPLOY_SA" --role=roles/artifactregistry.writer
gcloud artifacts repositories add-iam-policy-binding "$REPOSITORY" --location="$REGION" \
  --member="serviceAccount:$VM_SA" --role=roles/artifactregistry.reader
```

Use separate deployer and VM accounts. The deployer publishes images and administers this VM; the VM only pulls images and reads its TLS secrets. OS Login needs permission to act as the VM's attached service account as well as the OS Login role. The deployment needs sudo to manage Docker and its root-owned release directory. These project-level Compute/IAP roles are suitable for a dedicated PriVoke project; scope to the instance with IAM conditions in a shared project. See [Google's OS Login setup](https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin).

```bash
for role in roles/compute.osAdminLogin roles/compute.viewer roles/iap.tunnelResourceAccessor; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$DEPLOY_SA" --role="$role"
done
gcloud iam service-accounts add-iam-policy-binding "$VM_SA" \
  --member="serviceAccount:$DEPLOY_SA" --role=roles/iam.serviceAccountUser

# The workflow opens and closes one firewall rule (telemetry, tcp:8443). Grant only that, not a security admin role.
gcloud iam roles create privokeFirewallToggle --project="$PROJECT_ID" \
  --title='PriVoke telemetry firewall toggle' --permissions=compute.firewalls.get,compute.firewalls.update
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$DEPLOY_SA" --role="projects/$PROJECT_ID/roles/privokeFirewallToggle"
```

## 2. Prepare GitHub's Google Cloud identity

The deployment workflow reads the complete JSON key for a Google Cloud service account from the `GCP_SA_KEY` GitHub Actions secret. Use a dedicated service account with only the rights needed by the workflow: push to the selected Artifact Registry repository, connect to the named VM through IAP, use OS Login, and act as the VM's attached service account. The workflow does not need access to TLS secrets; the VM reads those directly. Confirm the selected account has these roles before adding its key. The actual principal is determined by the JSON key, so do not assume it matches a particular account name.

In GitHub **Settings → Environments → production → Secrets**, add `GCP_SA_KEY` with the full JSON key contents. Treat it like a password, restrict who can edit the production environment, and rotate or revoke the key if it is exposed. Do not commit the JSON key or paste it into workflow logs. Google recommends Workload Identity Federation over long-lived keys; this repository currently uses the key-based authentication requested for this setup. See the [Google authentication action's service account key guidance](https://github.com/google-github-actions/auth#inputs-service-account-key-json).

## 3. Create networking and the VM

```bash
gcloud compute networks create privoke --subnet-mode=custom
gcloud compute networks subnets create privoke --network=privoke \
  --region="$REGION" --range=10.40.0.0/24
gcloud compute addresses create privoke-stack --region="$REGION"
export STACK_IP=$(gcloud compute addresses describe privoke-stack --region="$REGION" --format='value(address)')
gcloud compute firewall-rules create privoke-https --network=privoke \
  --allow=tcp:443 --source-ranges=0.0.0.0/0 --target-tags=privoke-stack
# Telemetry port: created DISABLED. The deployment enables it only after the switch, and disables it on rollback.
gcloud compute firewall-rules create privoke-telemetry --network=privoke \
  --allow=tcp:8443 --source-ranges=0.0.0.0/0 --target-tags=privoke-stack --disabled
gcloud compute firewall-rules create privoke-iap-ssh --network=privoke \
  --allow=tcp:22 --source-ranges=35.235.240.0/20 --target-tags=privoke-stack
gcloud compute instances create "$INSTANCE" --zone="$ZONE" \
  --machine-type=e2-standard-4 --image-family=debian-12 --image-project=debian-cloud \
  --boot-disk-size=100GB --boot-disk-type=pd-balanced --no-boot-disk-auto-delete \
  --subnet=privoke --address="$STACK_IP" --tags=privoke-stack \
  --service-account="$VM_SA" --scopes=cloud-platform \
  --metadata=enable-oslogin=TRUE,block-project-ssh-keys=TRUE

gcloud compute scp deploy/gce/bootstrap.sh "$INSTANCE:~/privoke-bootstrap.sh" \
  --zone="$ZONE" --tunnel-through-iap
gcloud compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo bash ~/privoke-bootstrap.sh'
```

Point an A record for `$STACK_HOST` at `$STACK_IP`. Do not add public rules for `50051`–`50057`, `8080`, or general SSH. Only `443` and `8443` are public. Your operator identity also needs OS Login/IAP/service-account-user access for these interactive commands. IAP's documented forwarding range and IAM requirements are in [Use IAP for TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding).

The bootstrap installs Docker Engine, the Compose plugin, the Google Cloud CLI and OpenSSL, enables Docker at boot, creates `/opt/privoke`, and creates the Python environment (`/opt/privoke/smoke-venv`) that runs the smoke test. Existing containers restart with Docker after a VM reboot. The boot disk is retained on VM deletion, but volume data still requires backups.

## 4. Provision TLS and installation credentials

Every server authenticates its callers itself, with mutual TLS and a registry. There is no reverse proxy.

### Who holds what

| Principal | Certificate identity (URI SAN) | Role | Issued by |
| --- | --- | --- | --- |
| Installation | `urn:privoke:installation:<uuid>` | `consumer` | the operator, on a CSR the installation made |
| Service (param-update, fuzzer, runtime) | `urn:privoke:service:<name>` | `publisher`, `trainer` or `runtime`, set in the registry | the operator |
| Telemetry reporter | `urn:privoke:reporter` | `reporter`; one credential shared by every installation | the operator, delivered with each enrolment |

Every client certificate is a leaf with the `clientAuth` extended key usage only and exactly one `urn:privoke:` URI SAN. Installation and reporter certificates last 180 days, service and server certificates 90 days. The servers refuse anything else at the handshake (`privoke-transport`), then consult the registry on every RPC.

### Secret files

Every file in this table is either a secret or says it is public.

| File | Where it lives | Secret |
| --- | --- | --- |
| `ca/client/ca.key` | operator, offline | yes: signs every installation |
| `ca/server/ca.key` | operator, offline | yes |
| `ca/client/reporter/reporter.key` | operator, offline; copied to every installation | yes, but shared by design, so treat it as extractable |
| `ca/client/ledger.toml` | operator | no secrets, but it is the revocation record: back it up |
| `server.key` | the VM, from Secret Manager (a root-owned, group-readable file in the release directory) | yes |
| `svc/<name>.key` for `probe`, `param-update`, `fuzzer`, `analysis` | the VM, from Secret Manager | yes |
| smoke identity keys (`<prefix>-installation-key`, `<prefix>-reporter-key`) | the VM and the `production` GitHub environment | yes, but they are a dedicated test installation and the shared reporter credential |
| `client.key`, `client.next.key`, `client.prev.key`, `reporter.key` | the installation's credential directory, owner-only | yes |
| `*.crt`, `*.csr`, `server-ca.pem`, `crl.pem`, `registry.toml`, `installation.id` | various | no |

`privoke-pki` creates every key file with mode 0600 on Linux and macOS and restricts it to the current user with `icacls` on Windows.

### Operator setup (once)

Run on an operator workstation. Build the tool with `cargo build --release -p privoke-pki --manifest-path rust/Cargo.toml`.

```bash
privoke-pki init-ca --dir ca/client --name "PriVoke Client CA"
privoke-pki init-ca --dir ca/server --name "PriVoke Server CA"
# One server certificate for every listener. The public name must be first; the others are the names the services use to
# reach each other, and deploy.sh refuses a certificate that lacks any of them.
privoke-pki issue-server --ca-dir ca/server --out-dir out/server --dns "$STACK_HOST" \
  --dns model-streaming-service --dns telemetry-service --dns param-update-service \
  --dns privoke-fuzzer --dns analysis-service --dns analysis-model-streaming
privoke-pki issue-reporter --ca-dir ca/client
# Service identities and their registry roles. `probe` is the health-check identity of the model and telemetry containers.
privoke-pki sign-service --ca-dir ca/client --name probe --role runtime --out-dir out/services --registry out/registry.toml
privoke-pki sign-service --ca-dir ca/client --name param-update --role publisher --out-dir out/services --registry out/registry.toml
privoke-pki sign-service --ca-dir ca/client --name fuzzer --role publisher --out-dir out/services --registry out/registry.toml
privoke-pki sign-service --ca-dir ca/client --name analysis --role runtime --out-dir out/services --registry out/registry.toml
privoke-pki crl --ca-dir ca/client --out out/crl.pem --days 7
```

Enable the registry's reporter (`reporter = true`) and register the smoke installation (below) in `out/registry.toml` before uploading it. Service certificates and the server certificate last 90 days; `deploy.sh` refuses a server certificate with under 14 days left and a service certificate with under 7, so re-issue and redeploy before then.

Upload everything to Secret Manager (one PEM per secret; use `gcloud secrets versions add NAME --data-file=FILE` to update an existing one):

```bash
put() { gcloud secrets create "$1" --replication-policy=automatic --data-file="$2"; }
put privoke-server-cert out/server/server.crt
put privoke-server-key out/server/server.key
put privoke-client-ca ca/client/ca.crt
put privoke-server-ca ca/server/ca.crt
put privoke-crl out/crl.pem
put privoke-registry out/registry.toml
for name in probe param-update fuzzer analysis; do
  put "privoke-svc-$name-cert" "out/services/$name.crt"
  put "privoke-svc-$name-key" "out/services/$name.key"
done
# Smoke identities: a dedicated installation (enrol and sign it as below, register it) and the shared reporter credential.
put privoke-smoke-installation-cert out/smoke/client.crt
put privoke-smoke-installation-key smoke-credentials/client.key
put privoke-smoke-reporter-cert ca/client/reporter/reporter.crt
put privoke-smoke-reporter-key ca/client/reporter/reporter.key
for secret in $(gcloud secrets list --project="$PROJECT_ID" --filter='name~privoke-' --format='value(name)'); do
  gcloud secrets add-iam-policy-binding "$secret" --member="serviceAccount:$VM_SA" --role=roles/secretmanager.secretAccessor
done
```

Optional extra negative checks: add `privoke-smoke-unregistered-{cert,key}` (an installation signed by the client CA but absent from the registry) and `privoke-smoke-foreign-{cert,key}` (signed by another CA). CA private keys never go to the VM, GitHub or clients. The deployer needs no Secret Manager access: the VM reads the secrets directly. A rollback restores the previous release's certificate snapshot, so confirm it is still valid.

Each server starts with `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`; without any one of them it exits before binding. The Python fuzzer refuses to serve without its server credentials and an allow list.

#### Publish the CRL

The CA key is offline, so the CRL is signed by the operator and published as a new Secret Manager version. Every server refuses every handshake once the CRL's `nextUpdate` has passed (7 days by default), so **publish a new CRL at least every 5 days**. A scheduled task on the operator workstation (cron, Task Scheduler) is enough:

```bash
privoke-pki crl --ca-dir ca/client --out out/crl.pem --days 7
gcloud secrets versions add privoke-crl --data-file=out/crl.pem
gcloud secrets versions add privoke-registry --data-file=out/registry.toml   # after any registry change
```

On the VM, `deploy.sh` installs `privoke-pki-sync.timer`, which every six hours reads both secrets, installs a CRL only if it is signed by the client CA and valid for another hour, and swaps `crl.pem` and `registry.toml` atomically in `/opt/privoke/pki-live`; the servers reload them in place with no restart. The `privoke-pki-sync` unit fails (visible in `systemctl status` and `journalctl -u privoke-pki-sync`) when the installed CRL has under 72 hours left or has lapsed, so alert on it. Run `sudo /usr/local/sbin/privoke-pki-sync` to refresh by hand.

### Enrolment

Enrolment is operator-mediated. The CA key stays offline and there is no online issuing endpoint.

1. **User:** `privoke-supervisor enrol` (the same operation as `privoke-pki enrol --dir <credential dir>`) generates the installation UUID, a private key that never leaves the machine, and `client.csr`. It prints the CSR fingerprint.
2. **User to operator:** send `client.csr`, which is public, by any channel.
3. **Operator:** confirm the fingerprint and the user's identity out of band (in person or a known contact), then run:

   ```bash
   privoke-pki sign --ca-dir ca/client --csr client.csr --installation <uuid> --days 180 \
     --server-ca ca/server/ca.crt --registry out/registry.toml --out-dir out/<uuid> --label "<who>"
   ```

   This signs the CSR only if its single SAN is the UUID the operator named, records the certificate in the ledger, adds the installation to the registry with the certificate's expiry, and writes the bundle: `client.crt`, `server-ca.pem`, `reporter.crt` and `reporter.key`. Publish the updated `registry.toml`; servers pick it up within a minute.
4. **Operator to user:** return the bundle.
5. **User:** `privoke-supervisor install-cert` (or `privoke-pki install-cert --dir <dir> --cert client.crt --server-ca server-ca.pem --reporter-cert reporter.crt --reporter-key reporter.key`) checks that the certificate carries this installation's identity and `clientAuth`, is within its validity and matches the local key, then stores it. Configure the [client `.env`](../runtime/client-configuration.md) to point at the credential files.

### Renewal

`status` warns from 30 days before expiry. `renew` creates a new key and CSR under the same UUID (`client.next.key`, `client.next.csr`) and leaves the active certificate in force. The operator runs `sign` again with the same `--installation`, and the user runs `install-cert`, which recognises the renewal key, makes it active and keeps the old pair as `client.prev.*`. Both certificates are valid until the old one expires. Renewal needs a human at both ends, so this process suits a small cohort; automatic renewal would need an online issuer and is out of scope.

### Offline expiry

An installation that stays offline past `notAfter` loses only cloud model refresh and telemetry delivery. Local inspection keeps using the cached, pin-verified package in `MODEL_PACKAGE_CACHE_DIR`. The next contact fails closed at the handshake until the user renews, and `status` says so.

### Revocation

```bash
privoke-pki revoke --ca-dir ca/client --installation <uuid> --registry out/registry.toml --reason "device lost"
privoke-pki crl --ca-dir ca/client --out out/crl.pem --days 7
```

The registry deny entry applies to open connections as soon as servers reload the file. The CRL applies to new handshakes as soon as servers reload it, and a maximum connection age of ten minutes bounds how long an open stream can survive. Revoking the reporter (`revoke --reporter`) revokes every installation's telemetry credential at once; recovery is to issue a new reporter credential and deliver it at each installation's next renewal.

### Registry file

`registry.toml` (version 1) lists `[[installation]]` entries (`id`, optional `label`, optional `expires`), `[[service]]` entries (`name`, `role`, optional `expires`), `reporter = true|false` and `[[deny]]` entries (`urn`, `reason`). An invalid file is refused whole and the server keeps the registry it had; the first load must succeed or the server does not start. `privoke-pki` validates the whole file on every edit.

## 5. Configure VM and GitHub environments

Copy [deploy/gce/.env.example](../../deploy/gce/.env.example) to `deploy/gce/.env`, edit its project ID and Secret Manager names, then transfer it:

```bash
gcloud compute scp deploy/gce/.env "$INSTANCE:~/privoke.env" --zone="$ZONE" --tunnel-through-iap
gcloud compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo install -o root -g root -m 0600 ~/privoke.env /opt/privoke/.env && rm ~/privoke.env'
```

GitHub **Settings → Environments → production** must contain these secrets, also listed in the root [.env.example](../../.env.example), and the repository needs the variables below the table:

| Secret name | Value |
| --- | --- |
| `GCP_PROJECT_ID` | `$PROJECT_ID` |
| `GCP_REGION` | Artifact Registry region (`$REGION`) |
| `GCP_ARTIFACT_REPOSITORY` | Registry repository (`$REPOSITORY`) |
| `GCP_INSTANCE` | VM name (`$INSTANCE`) |
| `GCP_ZONE` | VM zone (`$ZONE`) |
| `GCP_SA_KEY` | Complete JSON key for the service account authorized in step 2 |
| `GCP_STACK_HOST` | `$STACK_HOST`, the DNS name in the server certificate |
| `SMOKE_SERVER_CA` | contents of `ca/server/ca.crt` |
| `SMOKE_INSTALLATION_CERT`, `SMOKE_INSTALLATION_KEY` | the smoke installation's certificate and key (used by the external smoke test) |
| `SMOKE_REPORTER_CERT`, `SMOKE_REPORTER_KEY` | the shared reporter credential |

| Repository variable | Value |
| --- | --- |
| `GCP_DEPLOY_ENABLED` | `true` to switch deployment on; anything else leaves the workflow inert |
| `GCP_TELEMETRY_FIREWALL_RULE` | optional; the disabled firewall rule for `8443` (default `privoke-telemetry`) |

These values are stored as GitHub secrets in the `production` environment. Restrict the environment to the `main` branch and protect `main` with required CI/review checks. Leave required environment reviewers unset for automatic deployment; enabling them intentionally introduces an approval gate. `.env` files are not uploaded to GitHub automatically.

Standard startup serves V3 balanced without training (the model and telemetry services only). Stage the locally prepared
`models/standard-releases` directory separately on the VM, retain its provenance,
and set `MODEL_RELEASE_DIR` to that existing absolute directory in the operator
`.env`. These weights are excluded from release images; deploy.sh does not fetch
them and refuses a missing staging directory. `MODEL_LATEST_ID` defaults to
`privoke-v3-balanced`; the path and alias are saved into release.env for rollback.
No deployment or V3 GPU support is implied by local validation.

Legacy V1 training requires the explicit `legacy-training` Compose profile: set `COMPOSE_PROFILES=legacy-training` in the VM `.env`, which `deploy.sh` saves into each release. It adds the update service, the fuzzer and the quarantined analysis service.
Within that opt-in profile, requests default to 32 prompts at startup and hourly.
`FUZZER_PROMPT_COUNT=0` in the VM `.env` disables it. Accepted model updates write
persistent state. Workstation OpenAI/LM Studio keys are unrelated to these
deployment identities and are never required for the streamed server stack.

### Training cycles and telemetry boundary

The fuzzer and parameter-update service request supervised Tiny training only in the explicit legacy profile. The fuzzer asks the quarantined analysis service for semantic-only inference and gradients over mutual TLS; the service rejects any other layer selection. Each automatic cycle performs head training followed by full encoder-and-head training on the same selected model ID. The maintained Compose file sets `FUZZER_TRAIN_UNDERLYING=true` (the one-shot `param-update-bootstrap` prepares the full-encoder release first); a reviewed Compose override setting it to `false` selects the head stage only (this value is not one of the release `.env` substitutions below). Each stage has an independent quality gate and atomic publication: if the second fails, an accepted first update remains. Both use explicit semantic-only runtime execution; regex and NER are not part of these training/guard phases.
Configure `FUZZER_PROMPT_COUNT`, `FUZZER_REQUEST_INTERVAL_SECONDS` and
`FUZZER_REQUEST_SEED` in the VM `.env`; defaults are `32`, `3600` and `1337`.
Count `0` disables training, while interval `0` requests one startup cycle.
New cycles advance the seed; retries retain the same identity and seed. Failed
cycles exhaust their bounded retries before waiting for the next interval.
All three values are saved into each release's `release.env`; changing the VM
`.env` affects a later deployment, not an already running release. The service
writes update history to `param-update-data` and the resulting model to
`model-data`. The durable `FUZZER_CYCLE_STATE_PATH=/data/training-cycles.sqlite3` journal resumes uncertain stages with the same IDs and seed, skips acknowledged stages and preserves completed one-shot status across restarts. Definite rejection records a partial/rejected cycle; the next periodic cycle uses a new seed. The second stage requires the first stage's committed base, so an intervening update is rejected rather than overwritten. The analysis image is built on the client-runtime image, which includes CPU Torch 2.11.0. The fuzzer uses the legacy random sampler (`FUZZ_CONTEXTUAL_SAMPLING_STRATEGY=legacy_random_v1`) because the deployment carries no pinned AU3 manifest; override it in the Compose file only after supplying one. Disable automatic training before a controlled research study. Source and local-test validation do not imply these changes have been deployed to a VM.

This stack does not train on browser-extension traffic. The server no longer runs a runtime that emits telemetry; reports come only from workstations that enable telemetry (disabled by default) and hold the reporter credential. Each report contains randomized action, risk bucket, primary category, fixed model release, and randomized four-hour time-of-day bucket. It excludes prompts, identifiers, target app names, exact timestamps, exact scores, text length, and layer timings. The event-level local-DP guarantee, daily installation-local budget, exact aggregate sample count, transport metadata limits, and legacy database handling are documented in [Telemetry service](../services/telemetry.md). This is not user-level or event-existence privacy: report presence, timing, IP address and operational logs remain outside the guarantee.

To run one deliberate cycle, first back up the model and update volumes, then
configure the explicit legacy training profile with a reviewed `.env` containing (for example) `FUZZER_PROMPT_COUNT=8`
and `FUZZER_REQUEST_INTERVAL_SECONDS=0`. Verify the fuzzer and parameter-update
logs, inspect the update artifact, and record the resulting model ID/fingerprint.
Stop the legacy profile services to disable training afterward; setting count to
`0` disables its request scheduler. The standard V3 serving path is inference-only. Do not delete `model-data` to force an
update; that removes the persistent model and causes the one-time seed copy to
run again.

## 6. Deploy and verify

Set the repository variable `GCP_DEPLOY_ENABLED=true`, then push the prepared repository changes to `main` or run **Actions → Deploy Compute Engine → Run workflow** on `main`. The workflow verifies the stack, builds and publishes the five images, authenticates with the `GCP_SA_KEY` secret, transfers the deployment files through IAP and runs the [deployment order](#the-deployment-order-fail-closed): `deploy.sh` stages and smoke-tests on loopback and switches to the public ports, the workflow opens the `8443` rule and runs the external smoke test, and `deploy.sh confirm` completes the release. The successful release lives at `/opt/privoke/current`; Compose always uses the project name `privoke` so volume identities are stable. It does not automatically delete old releases or data.

Model seeds are copied from the model service image into the `model-data` volume only when the volume is empty (`model-seed`, relying on Docker's copy-up of an image directory into a new named volume); learned weights are never overwritten. Normal startup does not migrate learned weights. In the `legacy-training` profile the one-shot `param-update-bootstrap` prepares the Tiny capability model idempotently before the update service starts; it preserves legacy learned coordinates and writes recovery receipts under its writer lock. It cannot update the pinned read-only V3 packages or change the configured V3 alias.

On the VM:

```bash
sudo docker compose --project-name privoke \
  --env-file /opt/privoke/current/release.env -f /opt/privoke/current/compose.yml ps
sudo docker compose --project-name privoke \
  --env-file /opt/privoke/current/release.env -f /opt/privoke/current/compose.yml \
  logs --tail=100 model-streaming-service telemetry-service
systemctl list-timers privoke-pki-sync.timer
sudo journalctl -u privoke-pki-sync -n 20
```

From a configured workstation, rebuild/reload the extension, enable its streamed LLM layer, and run a semantic prompt analysis: a successful health check and analysis confirm that DNS, server trust, client identity, model download and local inference work together. The smoke test checks the same path from any host with the smoke identity:

```bash
python deploy/gce/tests/smoke.py --creds smoke-credentials \
  --model-target "$STACK_HOST:443" --telemetry-target "$STACK_HOST:8443"
```

`--creds` holds `server-ca.pem`, `installation.{crt,key}` and `reporter.{crt,key}` (and, optionally, `unregistered.*` and `foreign.*`). The same command with `--model-target 127.0.0.1:50443 --telemetry-target 127.0.0.1:58443 --server-name "$STACK_HOST"` checks a staged release on loopback, and `--images PREFIX:TAG --pki-dir DIR --live-dir DIR` adds the checks that each image refuses to start without its CA or CRL. It needs `grpcio`, `grpcio-tools` and `protobuf` (pinned in `deploy/gce/bootstrap.sh`).

### Continuous integration and automatic deployment

Two workflows own this. Nothing here needs a Google Cloud resource until you switch deployment on.

**`service-stack-ci.yml`** runs on pushes to `main`, `feat/dev-testing`, `feat/rust-rewrite` and `wt/**`, on pull requests to `main`, and as the `verify` job of the deploy workflow. Its jobs relevant here:

| Job | What it proves |
| --- | --- |
| `deployment-config` | Every Compose file renders, the three deployment scripts pass `bash -n` and `shellcheck`, `smoke.py` compiles, and no reverse proxy remains in a deployment path. |
| `container-smoke` | Builds `privoke-pki` with cargo and generates a throwaway test PKI (`deploy/gce/tests/make_test_pki.py`, a new one per run, never committed), builds the base runtime image and every Compose image, brings `docker-compose.prod.yml --profile legacy-training` up on loopback with `--wait`, and runs `deploy/gce/tests/smoke.py --images` against it (mutual TLS, role gating, R9, telemetry, and each image refusing to start without its CA or CRL). It then runs `update_security.py --target rust --rust-service all` (the stage 9 negative rows, including live CRL reload) against the same images and uploads the JSON as the `update-security-rust-<run>` artifact. The job dumps the Compose logs and tears the stack down on every outcome. |
| `extension-tests` | `npm test` and both extension builds. |

In CI the stack serves the tracked legacy catalogue model (`MODEL_LATEST_ID=privoke-balanced`) because the standard V3 packages are ignored by Git and are not on the runner. `smoke.py --no-v3-package` and `update_security.py --no-v3` replace the V3 fetch with a legacy stream and record the V3 rows as `not_run`; the V3 package fetch with its pin (G8) is therefore verified only by the first deployment, whose smoke test runs without the flag, or by a local run with `models/standard-releases` present.

**`deploy-gce.yml`** is inert unless the repository variable `GCP_DEPLOY_ENABLED` is exactly `true`: the `gate` job prints a notice and every other job is skipped. It also only ever acts on `main`. When enabled, a push to `main` (or a manual run on `main`) runs `verify`, which calls `service-stack-ci.yml`, so a failing container smoke test or any other job there stops the release before anything is published. It then builds and pushes the five commit-tagged images to Artifact Registry (`publish`) and rolls them out in the [deployment order](#the-deployment-order-fail-closed) (`deploy`), rolling back and closing the `8443` rule if the external smoke test fails. A missing or malformed secret fails the run before anything changes. To switch it on later:

1. Create the Google Cloud resources and identities (sections 1 to 4) and upload the Secret Manager secrets.
2. Add the `production` environment secrets listed in [section 5](#5-configure-vm-and-github-environments): `GCP_PROJECT_ID`, `GCP_REGION`, `GCP_ARTIFACT_REPOSITORY`, `GCP_INSTANCE`, `GCP_ZONE`, `GCP_SA_KEY`, `GCP_STACK_HOST`, `SMOKE_SERVER_CA`, `SMOKE_INSTALLATION_CERT`, `SMOKE_INSTALLATION_KEY`, `SMOKE_REPORTER_CERT`, `SMOKE_REPORTER_KEY`.
3. Add the repository variables `GCP_DEPLOY_ENABLED=true` and, optionally, `GCP_TELEMETRY_FIREWALL_RULE` (default `privoke-telemetry`).
4. Protect `main` with the `service-stack-ci` jobs as required checks, and restrict the `production` environment to `main`.

## Rollback, backups and maintenance

Any failure before the release is confirmed tears the candidate down and restarts the previous release with its saved image tags and certificate files, then fails the workflow; a first deployment has no previous release, so the stack is left stopped and nothing is published. The same applies to a failed external smoke test and to a release not confirmed within `PENDING_TIMEOUT_MINUTES`. Inspect the failed containers and fix the configuration before retrying. VM failures, a terminated deploy process or incompatible persistent-data changes can require manual recovery.

Model updates and code releases are separate. A code rollback restores the previous image tag and release files but does not undo a parameter update already written to `model-data`. Before publishing a model update, copy the current artifact and record its model ID/fingerprint; to roll back the model, restore that known-good artifact during a maintenance window, preserve ownership/permissions, and restart the stack. Keep the matching old image in Artifact Registry as well as the model backup. Validate the restored model through the workstation smoke path before reopening access.

For an explicit rollback, connect through IAP, identify a retained release under `/opt/privoke/releases`, and run:

```bash
sudo bash /opt/privoke/releases/PREVIOUS_RELEASE_DIRECTORY/deploy.sh \
  PREVIOUS_40_CHARACTER_COMMIT_SHA \
  australia-southeast1-docker.pkg.dev/YOUR_PROJECT/privoke
# then, after checking the public endpoints from outside:
sudo bash /opt/privoke/releases/NEW_RELEASE_DIRECTORY/deploy.sh confirm PREVIOUS_40_CHARACTER_COMMIT_SHA   # or: ... rollback
```

This creates a new release using the old compose files and images, with the current Secret Manager certificate versions, and goes through the same loopback smoke test and pending state as any deployment (open the `8443` firewall rule yourself for the external check, and close it again if you roll back). Rolling back past the Rust cutover is not possible: earlier releases ran a reverse proxy that no longer exists in the repository, so redeploy only commits from the cutover onward. Retain Artifact Registry images for every release you might restore. Re-running the same SHA may republish its tag: the tags identify source commits but are not registry-enforced immutable digests. Protect registry write access. If strict reproducibility is required, pin base images and deploy application digests before enabling immutable tags.

Back up `privoke_model-data`, `privoke_param-update-data`, `privoke_telemetry-data`, `privoke_fuzzer-dumps` and `privoke_analysis-model-cache`, plus operator configuration, `/opt/privoke/pki-live` and release metadata. The Rust services run as user 65532 and the Python fuzzer as 10001, so a volume that an earlier (Python and Go) stack created is owned by 10001 and must be changed once with `chown -R 65532:65532` on the volume's `_data` directory before the Rust services can write it (`fuzzer-dumps` stays 10001). For consistent persistent-disk snapshots, stop the stack's writers during the snapshot or use an application-aware backup (SQLite's backup API for telemetry). Test restoring into a separate VM. Never use `docker compose down --volumes` on the production deployment. Code rollback does not undo parameter updates or database writes.

Monitor free disk, certificate expiry, VM health, container restarts and deployment failures. Container logs rotate at 10 MB with three files. Prune old images and root-only release/certificate snapshots according to a retention policy after verifying backups and preserving rollback candidates. Patch the VM and refresh base images regularly. The scripts do not provision alerting, scheduled backups, automatic certificate issuance or high availability.

### Persistence, cost control and teardown

The checked-in deployment stores its named Docker volumes on the VM's persistent boot disk: `model-data`, `param-update-data`, `telemetry-data`, `fuzzer-dumps`, and `analysis-model-cache`. The example VM uses a 100 GB `pd-balanced` boot disk and sets `--no-boot-disk-auto-delete`, so deleting the VM does not delete that disk. This is the repository's supported persistence arrangement; it is not a separate managed database or automatically replicated backup. If you attach a separate persistent disk, mount it before bootstrap and relocate Docker's data root using an operator-managed procedure; do not change volume paths casually because the deployment scripts assume stable Compose volume names.

Google Cloud bills the VM, boot disk, reserved static address, Artifact Registry storage, and Secret Manager storage while they exist. Before teardown, export and verify required backups, record the release/model metadata, and revoke client certificates or rotate the client CA. Then stop the stack and remove the VM resources when they are no longer needed:

```bash
gcloud compute instances delete "$INSTANCE" --zone="$ZONE"
gcloud compute addresses delete privoke-stack --region="$REGION"
gcloud compute firewall-rules delete privoke-https privoke-telemetry privoke-iap-ssh
gcloud compute networks subnets delete privoke --region="$REGION"
gcloud compute networks delete privoke
```

The retained boot disk is intentionally not deleted by the instance command; delete it separately only after verifying the backup and confirming that no rollback is required. Artifact Registry images and Secret Manager secrets are also retained until explicitly removed. For a disposable environment, list resources first with `gcloud compute disks list`, `gcloud artifacts docker images list \"$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY\"`, and `gcloud secrets list`, then delete only the named resources and any snapshots created for that environment. Deleting the project is a separate, irreversible administrative action and is outside this tutorial.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Google authentication or permission denied | Valid `GCP_SA_KEY` JSON and the service account's Artifact Registry, IAP, OS Login and VM service-account-user permissions |
| IAP SSH denied | IAP role, OS Admin Login role, VM service-account-user binding, OS Login metadata and IAP firewall rule |
| Registry pull denied | VM identity has repository reader; VM scope is `cloud-platform` |
| Secret access denied | VM identity has accessor on each named secret and an enabled version exists |
| A container exits at start | `docker compose logs`: it names the missing or invalid `--cert`, `--key`, `--client-ca`, `--crl` or `--registry`; check the release's `pki` directory and `/opt/privoke/pki-live` |
| Every handshake is refused | The CRL has lapsed: `journalctl -u privoke-pki-sync`, publish a new CRL (see [Publish the CRL](#publish-the-crl)) |
| One client is refused | Client certificate expiry, its registry entry and the deny list; the certificate must carry exactly one `urn:privoke:` SAN |
| Deployment stops at the loopback smoke test | The smoke output names the failing row; the release is rolled back and `8443` was never opened |
| Telemetry unreachable but models work | The `8443` firewall rule is disabled (it is enabled only during a deployment) or the client's network blocks 8443 |
| Cloud LLM health offline | DNS, server SAN/trust, client certificate expiry and private key, port 443 firewall |
| Local development works, cloud fails | Hidden toggle state and installation `.env`; local mode bypasses cloud TLS by design |
| Model release appears unchanged | V3 uses exact pinned packages in a separate read-only store. Legacy seeds are copied once; the opt-in bootstrap preserves learned coordinates. Inspect provenance/update receipts; never delete a volume to force migration |

## 9. Configure and operate a workstation installation

The cloud deployment is only half of the system. On each workstation, copy `extension/client-runtime/.env.example` to a private `.env` and set `PRIVOKE_CLOUD_MODEL_TARGET` to the model endpoint (for example `stack.example.com:443`) and `PRIVOKE_CLOUD_TELEMETRY_TARGET` to the telemetry endpoint (`stack.example.com:8443`), each with no URL scheme; an unset model target falls back to `PRIVOKE_CLOUD_TARGET`, and telemetry has no fallback (it stays off). Set `PRIVOKE_TLS_CERT_FILE` and `PRIVOKE_TLS_KEY_FILE` to that installation's client certificate and private key, `PRIVOKE_TELEMETRY_TLS_CERT_FILE` and `PRIVOKE_TELEMETRY_TLS_KEY_FILE` to the reporter credential delivered at enrolment, and `PRIVOKE_TLS_CA_FILE` to the server CA. Use a distinct client key/certificate per installation; never distribute a Google service-account key or a shared client private key.

Install the client-runtime and runtime-supervisor dependencies, generate the supervisor/runtime protobuf bindings, and install the native host using the commands in [Runtime supervisor](../runtime/supervisor.md). Under the controller architecture (stages 7 and W4) the extension reaches the controller over a native-messaging port and the workstation opens no listening ports; the extension never connects directly to the VM. The cloud target is the default. The hidden **Use local development servers** setting changes model and telemetry targets to `127.0.0.1`; turn it off for a cloud installation. `PRIVOKE_STACK_MODE=internal`, `MODEL_STREAMING_TARGET`, and `TELEMETRY_TARGET` belong to the server Compose container and must not be copied into a workstation `.env`.

For a workstation with streamed-transformer inference, install the normal client requirements and, when GPU inference is desired, install `extension/client-runtime/requirements-gpu.txt` into the same environment selected by the supervisor. `PRIVOKE_MODEL_DEVICE=auto` chooses CUDA or Apple MPS when available and otherwise uses CPU. The server's `docker-compose.gpu.yml` override affects only the quarantined analysis service; it does not accelerate the browser extension's child process.
