# Deploy PriVoke to Google Cloud Compute Engine

## Architecture and prerequisites

The deployment runs the five existing services and an nginx ingress on one Debian 12 Compute Engine VM. Docker volumes retain telemetry, update history, fuzzer output and mutable model artifacts. Only port `443` is public. IAP carries administrative SSH traffic to port `22`; the raw gRPC ports remain inside Docker. Each workstation authenticates with its own client certificate, downloads parameters and optionally submits metadata. Prompt analysis stays on the workstation.

CI also runs a disposable copy of the cloud Compose stack, tests client-certificate authentication and RPC access restrictions, and checks persisted data after container recreation. Run it locally after `docker compose build` with `python deploy/gce/tests/smoke.py` using an environment with `grpcio` and `grpcio-tools`. OpenSSL and a running Docker engine are required.

The workflow in [deploy-gce.yml](../.github/workflows/deploy-gce.yml) runs on pushes to `main`, and can be dispatched manually on `main`. It calls the existing service CI before publishing or deploying. Five images are tagged with the tested commit SHA, pushed to Artifact Registry, then pulled on the VM. Deployments are serialized and wait for container health. An unsuccessful rollout attempts to restore the previous release.

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
```

## 2. Trust GitHub without a service-account JSON key

```bash
gcloud iam workload-identity-pools create github --location=global \
  --display-name='GitHub deployment'
gcloud iam workload-identity-pools providers create-oidc github \
  --location=global --workload-identity-pool=github \
  --issuer-uri=https://token.actions.githubusercontent.com \
  --attribute-mapping='google.subject=assertion.sub,attribute.repository_id=assertion.repository_id' \
  --attribute-condition="assertion.repository_id == '$GITHUB_REPOSITORY_ID' && assertion.repository_owner_id == '$GITHUB_OWNER_ID' && assertion.ref == 'refs/heads/main' && assertion.workflow_ref == '$GITHUB_REPOSITORY/.github/workflows/deploy-gce.yml@refs/heads/main'"
gcloud iam service-accounts add-iam-policy-binding "$DEPLOY_SA" \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository_id/$GITHUB_REPOSITORY_ID"
gcloud iam workload-identity-pools providers describe github --location=global \
  --workload-identity-pool=github --format='value(name)'
```

Save the last output for `GCP_WORKLOAD_IDENTITY_PROVIDER`. The trust condition binds the numeric repository/owner IDs, branch and deployment workflow. GitHub generates a short-lived OIDC token; no `GCP_SA_KEY`, SSH private-key secret, PAT or manually configured `GITHUB_TOKEN` is required. Authentication occurs after lengthy image builds. See the [Google authentication action](https://github.com/google-github-actions/auth) and [Workload Identity Federation for deployment pipelines](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines).

## 3. Create networking and the VM

```bash
gcloud compute networks create privoke --subnet-mode=custom
gcloud compute networks subnets create privoke --network=privoke \
  --region="$REGION" --range=10.40.0.0/24
gcloud compute addresses create privoke-stack --region="$REGION"
export STACK_IP=$(gcloud compute addresses describe privoke-stack --region="$REGION" --format='value(address)')
gcloud compute firewall-rules create privoke-https --network=privoke \
  --allow=tcp:443 --source-ranges=0.0.0.0/0 --target-tags=privoke-stack
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

Point an A record for `$STACK_HOST` at `$STACK_IP`. Do not add public rules for `50051`–`50057`, `8080`, or general SSH. Your operator identity also needs OS Login/IAP/service-account-user access for these interactive commands. IAP's documented forwarding range and IAM requirements are in [Use IAP for TCP forwarding](https://docs.cloud.google.com/iap/docs/using-tcp-forwarding).

The bootstrap installs Docker Engine, the Compose plugin and the Google Cloud CLI, enables Docker at boot, and creates `/opt/privoke`. Existing containers restart with Docker after a VM reboot. The boot disk is retained on VM deletion, but volume data still requires backups.

## 4. Provision TLS and installation credentials

The ingress requires a server certificate with a SAN matching `$STACK_HOST`, its private key, and the public certificate of a CA trusted to issue client certificates. Use an organizational CA or managed certificate process. A publicly trusted server certificate lets clients leave `PRIVOKE_TLS_CA_FILE` empty. nginx terminates TLS and routes only the three permitted RPC methods; see the [nginx gRPC module](https://nginx.org/en/docs/http/ngx_http_grpc_module.html).

For a private research installation, this example produces a private server CA, a separate client CA, and one installation certificate. Run it on an operator workstation; keep the CA private keys offline. All output goes into an ignored `secrets/` directory. Adapt certificate validity and renewal to your operating process.

```bash
mkdir -p .tmp/gce-pki/secrets
cd .tmp/gce-pki/secrets
umask 077
cat > ca.cnf <<'EOF'
[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=PriVoke CA
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj '/CN=PriVoke Server CA' \
  -config ca.cnf \
  -keyout server-ca.key -out server-ca.crt
openssl req -newkey rsa:3072 -nodes -subj "/CN=$STACK_HOST" -keyout server.key -out server.csr
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$STACK_HOST" > server.ext
openssl x509 -req -in server.csr -CA server-ca.crt -CAkey server-ca.key -CAcreateserial \
  -days 90 -extfile server.ext -out server.crt
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj '/CN=PriVoke Client CA' \
  -config ca.cnf \
  -keyout client-ca.key -out client-ca.crt
openssl req -newkey rsa:3072 -nodes -subj '/CN=installation-001' -keyout client.key -out client.csr
printf 'extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n' > client.ext
openssl x509 -req -in client.csr -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -days 90 -extfile client.ext -out client.crt
cd ../../..

gcloud secrets create privoke-server-cert --replication-policy=automatic --data-file=.tmp/gce-pki/secrets/server.crt
gcloud secrets create privoke-server-key --replication-policy=automatic --data-file=.tmp/gce-pki/secrets/server.key
gcloud secrets create privoke-client-ca --replication-policy=automatic --data-file=.tmp/gce-pki/secrets/client-ca.crt
for secret in privoke-server-cert privoke-server-key privoke-client-ca; do
  gcloud secrets add-iam-policy-binding "$secret" \
    --member="serviceAccount:$VM_SA" --role=roles/secretmanager.secretAccessor
done
```

For existing secrets, use `gcloud secrets versions add NAME --data-file=FILE` instead of `create`. The deployer does not need direct Secret Manager access. The VM fetches the current versions into a root-only directory for each release. CA private keys never go to the VM, GitHub or clients. Distribute only `client.crt`, `client.key`, and (for this private server CA) `server-ca.crt` to the intended installation, then configure the [client `.env`](README.Client-configuration.md). Issue a new key and certificate for every other installation.

The example grants all currently valid certificates signed by the client CA the same limited download/telemetry access. It does not implement user accounts or enrollment. For individual revocation, maintain a CA-signed CRL, add it as a Secret Manager secret, fetch it alongside the other files in `deploy.sh`, and enable nginx `ssl_crl`; otherwise rely on short validity or rotate the client CA to revoke all clients. Renew server and client certificates before expiry. Publish the server secret versions and redeploy to reload nginx. A rollback restores the previous certificate snapshot as well as code, so confirm it is still valid.

## 5. Configure VM and GitHub environments

Copy [deploy/gce/.env.example](../deploy/gce/.env.example) to `deploy/gce/.env`, edit its project ID and Secret Manager names, then transfer it:

```bash
gcloud compute scp deploy/gce/.env "$INSTANCE:~/privoke.env" --zone="$ZONE" --tunnel-through-iap
gcloud compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo install -o root -g root -m 0600 ~/privoke.env /opt/privoke/.env && rm ~/privoke.env'
```

GitHub **Settings → Environments → production** must contain these secrets, also listed in the root [.env.example](../.env.example):

| Secret name | Value |
| --- | --- |
| `GCP_PROJECT_ID` | `$PROJECT_ID` |
| `GCP_REGION` | Artifact Registry region (`$REGION`) |
| `GCP_ARTIFACT_REPOSITORY` | Registry repository (`$REPOSITORY`) |
| `GCP_INSTANCE` | VM name (`$INSTANCE`) |
| `GCP_ZONE` | VM zone (`$ZONE`) |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Full provider resource from step 2, including project **number** |
| `GCP_DEPLOY_SERVICE_ACCOUNT` | `$DEPLOY_SA` email |

These are configuration identifiers, stored uniformly as GitHub secrets. No long-lived Google token is used. Restrict the environment to the `main` branch and protect `main` with required CI/review checks. Leave required environment reviewers unset for automatic deployment; enabling them intentionally introduces an approval gate. `.env` files are not uploaded to GitHub automatically.

`FUZZER_PROMPT_COUNT=0` in the VM `.env` disables automatic training on startup. Use a nonzero value only when intentional; model updates write persistent state. Workstation OpenAI/LM Studio keys are unrelated to these deployment identities and are never required for the streamed server stack.

## 6. Deploy and verify

Push the prepared repository changes to `main` or run **Actions → Deploy Compute Engine → Run workflow** on `main`. The workflow verifies the complete stack, builds all five images, authenticates with OIDC, publishes them, transfers just deployment files through IAP, then runs the VM deployment script.

The script validates inputs, locks deployment, fetches TLS secrets, pulls images, validates nginx, and runs `docker compose up --wait`. Model seeds are copied from the parameter-update image only when the model volume has never been initialized. Later deploys preserve trained artifacts. The successful release lives at `/opt/privoke/current`; Compose always uses the project name `privoke` so volume identities are stable. It does not automatically delete old releases or data.

On the VM:

```bash
sudo docker compose --project-name privoke \
  --env-file /opt/privoke/current/release.env -f /opt/privoke/current/compose.yml ps
sudo docker compose --project-name privoke \
  --env-file /opt/privoke/current/release.env -f /opt/privoke/current/compose.yml \
  logs --tail=100 ingress client-runtime
```

From a configured workstation, rebuild/reload the extension, leave the hidden local-development toggle off, and enable its streamed LLM layer. A successful health check and a semantic prompt analysis confirm that DNS, server trust, client identity, ingress, model download and local inference work together. To check the deployment with the existing internal integration harness:

```bash
sudo docker compose --project-name privoke \
  --env-file /opt/privoke/current/release.env -f /opt/privoke/current/compose.yml \
  exec -T client-runtime python test/stack_smoke.py --skip-training
```

This internal smoke test verifies service connectivity; the workstation check additionally verifies the public TLS path. Successful health checks alone do not prove external DNS or certificate provisioning.

## Rollback, backups and maintenance

A failed `up --wait` attempts to start the previous release with its saved image tags and certificate files, and still marks the workflow failed. A first deployment has no previous release; inspect the failed containers and fix the configuration before retrying. VM failures, a terminated deploy process or incompatible persistent-data changes can require manual recovery.

For an explicit rollback, connect through IAP, identify a retained release under `/opt/privoke/releases`, and run:

```bash
sudo bash /opt/privoke/releases/PREVIOUS_RELEASE_DIRECTORY/deploy.sh \
  PREVIOUS_40_CHARACTER_COMMIT_SHA \
  australia-southeast1-docker.pkg.dev/YOUR_PROJECT/privoke
```

This creates a new release using the old compose/nginx files and images, with the current Secret Manager certificate versions. Retain Artifact Registry images for every release you might restore. Re-running the same SHA may republish its tag: the tags identify source commits but are not registry-enforced immutable digests. Protect registry write access. If strict reproducibility is required, pin base images and deploy application digests before enabling immutable tags.

Back up `privoke_model-data`, `privoke_param-update-data`, `privoke_telemetry-data` and `privoke_fuzzer-dumps`, plus operator configuration and release metadata. For consistent persistent-disk snapshots, stop the stack's writers during the snapshot or use an application-aware backup (SQLite's backup API for telemetry). Test restoring into a separate VM. Never use `docker compose down --volumes` on the production deployment. Code rollback does not undo parameter updates or database writes.

Monitor free disk, certificate expiry, VM health, container restarts and deployment failures. Container logs rotate at 10 MB with three files. Prune old images and root-only release/certificate snapshots according to a retention policy after verifying backups and preserving rollback candidates. Patch the VM and refresh base images regularly. The scripts do not provision alerting, scheduled backups, automatic certificate issuance or high availability.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| OIDC exchange denied | Numeric repository/owner IDs, exact main-branch workflow path, provider and service-account binding |
| IAP SSH denied | IAP role, OS Admin Login role, VM service-account-user binding, OS Login metadata and IAP firewall rule |
| Registry pull denied | VM identity has repository reader; VM scope is `cloud-platform` |
| Secret access denied | VM identity has accessor on each named secret and an enabled version exists |
| nginx configuration fails | PEM files, matching server certificate/key, client CA and directory mount |
| Cloud LLM health offline | DNS, server SAN/trust, client certificate expiry and private key, port 443 firewall |
| Local development works, cloud fails | Hidden toggle state and installation `.env`; local mode bypasses cloud TLS by design |
| Model release appears unchanged | Persistent model volume is seeded once; publish/migrate models deliberately rather than deleting the volume |
