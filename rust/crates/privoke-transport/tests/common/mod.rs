//! In-process PKI and server harness. Every certificate and key is generated at test time and written to a
//! temporary directory; nothing sensitive is committed.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use privoke_proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_proto::v1::model_streaming_service_server::{ModelStreamingService, ModelStreamingServiceServer};
use privoke_proto::v1::{
    HealthRequest, HealthResponse, ModelAssetChunk, ModelAssetRequest, ModelPackageResponse, ModelParameterChunk, ModelParametersRequest,
    ModelParametersResponse,
};
use privoke_transport::client;
use privoke_transport::reload::WatcherGuard;
use privoke_transport::tls::{ClientTlsConfig, ServerTlsConfig};
use privoke_transport::{
    AuthLayer, LimiterKey, Limits, Policy, Registry, ReloadableTls, Role, SecureListener, SharedRegistry, secure_server,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType, SerialNumber,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::oneshot;
use tonic::{Request, Response, Status};

pub const ALICE: &str = "11111111-1111-4111-8111-111111111111";
pub const BOB: &str = "22222222-2222-4222-8222-222222222222";
pub const CAROL: &str = "33333333-3333-4333-8333-333333333333";

static SERIAL: AtomicU64 = AtomicU64::new(0x1000);

pub fn installation_urn(uuid: &str) -> String {
    format!("urn:privoke:installation:{uuid}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Eku {
    Client,
    Server,
    Absent,
}

pub struct LeafSpec {
    pub urn: Option<String>,
    pub eku: Eku,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl LeafSpec {
    pub fn installation(uuid: &str) -> Self {
        Self::urn(&installation_urn(uuid))
    }

    pub fn urn(urn: &str) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            urn: Some(urn.to_string()),
            eku: Eku::Client,
            not_before: now - TimeDuration::days(1),
            not_after: now + TimeDuration::days(30),
        }
    }
}

pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
    pub serial: u64,
}

pub struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Ca {
    pub fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::days(2);
        params.not_after = now + TimeDuration::days(365);
        Self { issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap() }
    }

    pub fn pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn server_leaf(&self) -> Leaf {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        self.sign(params)
    }

    pub fn leaf(&self, spec: LeafSpec) -> Leaf {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        if let Some(urn) = &spec.urn {
            params.subject_alt_names.push(SanType::URI(urn.clone().try_into().unwrap()));
        }
        params.extended_key_usages = match spec.eku {
            Eku::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
            Eku::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
            Eku::Absent => vec![],
        };
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = spec.not_before;
        params.not_after = spec.not_after;
        self.sign(params)
    }

    fn sign(&self, mut params: CertificateParams) -> Leaf {
        let serial = SERIAL.fetch_add(1, Ordering::SeqCst);
        params.serial_number = Some(SerialNumber::from(serial));
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        Leaf { cert_pem: certificate.pem(), key_pem: key.serialize_pem(), serial }
    }

    /// A CRL signed by this CA revoking the given serial numbers.
    pub fn crl(&self, revoked: &[u64], next_update_in: TimeDuration) -> String {
        let now = OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now - TimeDuration::hours(1),
            next_update: now + next_update_in,
            crl_number: SerialNumber::from(SERIAL.fetch_add(1, Ordering::SeqCst)),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: now - TimeDuration::minutes(30),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params.signed_by(&self.issuer).unwrap().pem().unwrap()
    }
}

/// Files on disk for one server: its certificate, the client CA bundle and the CRL.
pub struct Pki {
    pub dir: tempfile::TempDir,
    pub client_ca: Ca,
    pub server_ca: Ca,
    pub server: Leaf,
}

impl Pki {
    pub fn new() -> Self {
        let client_ca = Ca::new("Privoke Test Client CA");
        let server_ca = Ca::new("Privoke Test Server CA");
        let server = server_ca.server_leaf();
        let pki = Self { dir: tempfile::tempdir().unwrap(), client_ca, server_ca, server };
        pki.write("server.pem", &pki.server.cert_pem);
        pki.write("server.key", &pki.server.key_pem);
        pki.write("client-ca.pem", &pki.client_ca.pem());
        pki.write("server-ca.pem", &pki.server_ca.pem());
        pki.write_crl(&[]);
        pki
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Replace the CRL atomically (write beside, then rename), as an operator tool would.
    pub fn write_crl(&self, revoked: &[u64]) {
        self.replace_crl_text(&self.client_ca.crl(revoked, TimeDuration::days(7)));
    }

    pub fn replace_crl_text(&self, text: &str) {
        let temporary = self.path("crl.pem.tmp");
        std::fs::write(&temporary, text).unwrap();
        std::fs::rename(&temporary, self.path("crl.pem")).unwrap();
    }

    pub fn server_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new(self.path("server.pem"), self.path("server.key"), self.path("client-ca.pem"), self.path("crl.pem"))
    }

    /// Client configuration for `leaf`, written under `name`.
    pub fn client_config(&self, name: &str, leaf: Option<&Leaf>) -> ClientTlsConfig {
        let identity = leaf.map(|leaf| {
            let cert = self.write(&format!("{name}.pem"), &leaf.cert_pem);
            let key = self.write(&format!("{name}.key"), &leaf.key_pem);
            (cert, key)
        });
        ClientTlsConfig { server_ca: self.path("server-ca.pem"), identity, server_name: "localhost".to_string() }
    }
}

/// A test implementation of the model service that counts the calls that reach it.
pub struct Service {
    pub calls: Arc<AtomicUsize>,
}

type ChunkStream<T> = Pin<Box<dyn futures_util::Stream<Item = Result<T, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl ModelStreamingService for Service {
    async fn get_model_parameters(&self, request: Request<ModelParametersRequest>) -> Result<Response<ModelParametersResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.get_ref().model_id == "slow" {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Ok(Response::new(ModelParametersResponse::default()))
    }

    type StreamModelParametersStream = ChunkStream<ModelParameterChunk>;

    async fn stream_model_parameters(
        &self,
        _: Request<ModelParametersRequest>,
    ) -> Result<Response<Self::StreamModelParametersStream>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(Status::unimplemented("test service"))
    }

    async fn health(&self, _: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(HealthResponse { service: "test".into(), status: "SERVING".into() }))
    }

    async fn get_model_package(&self, request: Request<ModelParametersRequest>) -> Result<Response<ModelPackageResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let principal = request.extensions().get::<privoke_transport::Principal>().cloned();
        Ok(Response::new(ModelPackageResponse {
            model_id: principal.map(|principal| principal.identity.urn()).unwrap_or_default(),
            ..ModelPackageResponse::default()
        }))
    }

    type StreamModelAssetStream = ChunkStream<ModelAssetChunk>;

    async fn stream_model_asset(&self, _: Request<ModelAssetRequest>) -> Result<Response<Self::StreamModelAssetStream>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(Status::unimplemented("test service"))
    }
}

pub const HEALTH: &str = "/privoke.v1.ModelStreamingService/Health";
pub const GET_PARAMETERS: &str = "/privoke.v1.ModelStreamingService/GetModelParameters";
pub const GET_PACKAGE: &str = "/privoke.v1.ModelStreamingService/GetModelPackage";
pub const STREAM_PARAMETERS: &str = "/privoke.v1.ModelStreamingService/StreamModelParameters";

pub fn default_policy() -> Policy {
    Policy::new()
        .allow(HEALTH, &[Role::Consumer, Role::Publisher, Role::Reporter], LimiterKey::Identity)
        .allow(GET_PARAMETERS, &[Role::Consumer], LimiterKey::Identity)
        .allow(STREAM_PARAMETERS, &[Role::Consumer], LimiterKey::SourceIp)
        .allow(GET_PACKAGE, &[Role::Publisher], LimiterKey::Identity)
}

pub fn default_registry() -> Registry {
    Registry::new().with_installation(ALICE).with_installation(BOB).with_service("publisher", Role::Publisher).with_reporter()
}

pub struct TestServer {
    pub address: SocketAddr,
    pub tls: ReloadableTls,
    pub registry: SharedRegistry,
    pub calls: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    _reloader: WatcherGuard,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

pub struct Options {
    pub limits: Limits,
    pub registry: Registry,
    pub policy: Policy,
    pub poll: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self { limits: Limits::default(), registry: default_registry(), policy: default_policy(), poll: Duration::from_millis(100) }
    }
}

impl TestServer {
    pub async fn start(pki: &Pki) -> Self {
        Self::start_with(pki, Options::default()).await
    }

    pub async fn start_with(pki: &Pki, options: Options) -> Self {
        let tls = ReloadableTls::load(pki.server_config()).unwrap();
        let reloader = tls.spawn_watcher(options.poll);
        let registry = SharedRegistry::new(options.registry);
        let auth = AuthLayer::new(options.policy, registry.clone(), options.limits.rate);
        let listener = SecureListener::bind("127.0.0.1:0".parse().unwrap(), tls.clone(), options.limits.clone()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let service =
            ModelStreamingServiceServer::new(Service { calls: calls.clone() }).max_decoding_message_size(options.limits.max_message_bytes);
        let (shutdown, signal) = oneshot::channel::<()>();
        let server = secure_server(&options.limits, auth).add_service(service);
        tokio::spawn(async move {
            let _ = server
                .serve_with_incoming_shutdown(listener.incoming(), async {
                    let _ = signal.await;
                })
                .await;
        });
        Self { address, tls, registry, calls, shutdown: Some(shutdown), _reloader: reloader }
    }

    pub async fn connect(&self, client: &ClientTlsConfig) -> Result<ModelStreamingServiceClient<tonic::transport::Channel>, Status> {
        let channel = client::connect(&self.address.to_string(), client).await.map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(ModelStreamingServiceClient::new(channel))
    }

    /// Connect and call `Health`; every failure mode is an `Err`.
    pub async fn health(&self, client: &ClientTlsConfig) -> Result<(), Status> {
        let mut channel = self.connect(client).await?;
        channel.health(HealthRequest {}).await.map(|_| ())
    }

    pub fn handler_calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

pub async fn eventually<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn file_exists(path: &Path) -> bool {
    path.exists()
}
