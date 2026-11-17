//! Certificates generated at test time by the real `privoke-pki` library, and an in-process model-streaming server on
//! them. Nothing is committed: every key lives in a temporary directory that is removed with the test.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::releases::StandardReleases;
use privoke_model_streaming::server::{self, Listen, ServerHandle};
use privoke_model_streaming::service::ModelService;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::{client as enrolment, files::write_atomic, registry_edit};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{ClientTlsConfig, Limits};
use time::{Duration as TimeDuration, OffsetDateTime};

/// The prepared standard releases (ignored by Git): `V3_TEST_RELEASE_DIR`, this checkout, or the main checkout that
/// owns this linked worktree. Read only.
pub fn release_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("V3_TEST_RELEASE_DIR").filter(|value| !value.is_empty()) {
        return Some(path.into());
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let local = root.join("models/standard-releases");
    if local.is_dir() {
        return Some(local);
    }
    let pointer = std::fs::read_to_string(root.join(".git")).ok()?;
    let git_dir = PathBuf::from(pointer.trim().strip_prefix("gitdir:")?.trim());
    let main = git_dir.parent()?.parent()?.parent()?.join("models/standard-releases");
    main.is_dir().then_some(main)
}

/// An installation's credential directory, as `enrol` and `install-cert` leave it.
pub struct Installation {
    pub id: String,
    pub dir: PathBuf,
}

impl Installation {
    pub fn cert(&self) -> PathBuf {
        self.dir.join("client.crt")
    }
    pub fn key(&self) -> PathBuf {
        self.dir.join("client.key")
    }
}

pub struct TestPki {
    pub dir: tempfile::TempDir,
    pub client_ca: CaDir,
    pub foreign_ca: CaDir,
    pub models: tempfile::TempDir,
}

impl TestPki {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let validity = Validity::days(30);
        let client_ca = CaDir::init(&dir.path().join("client-ca"), "Test Client CA", validity).unwrap();
        let server_ca = CaDir::init(&dir.path().join("server-ca"), "Test Server CA", validity).unwrap();
        let foreign_ca = CaDir::init(&dir.path().join("foreign-ca"), "Foreign Client CA", validity).unwrap();
        let server = server_ca.issue_server(&["localhost".to_string(), "127.0.0.1".to_string()], validity).unwrap();
        write_atomic(&dir.path().join("server.crt"), server.cert_pem.as_bytes(), false).unwrap();
        write_atomic(&dir.path().join("server.key"), server.key_pem.as_bytes(), true).unwrap();
        let pki = Self { dir, client_ca, foreign_ca, models: tempfile::tempdir().unwrap() };
        // The catalog needs one legacy artifact to load; the tracked baseline is a read-only input.
        let baseline = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../models/privoke-baseline.json");
        std::fs::copy(baseline, pki.models.path().join("privoke-baseline.json")).unwrap();
        pki.refresh_crl();
        registry_edit::set_reporter(&pki.registry(), false).unwrap();
        pki
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn registry(&self) -> PathBuf {
        self.path("registry.toml")
    }

    pub fn server_ca(&self) -> PathBuf {
        self.path("server-ca/ca.crt")
    }

    pub fn refresh_crl(&self) {
        let pem = self.client_ca.crl_pem(OffsetDateTime::now_utc(), TimeDuration::days(7)).unwrap();
        write_atomic(&self.path("crl.pem"), pem.as_bytes(), false).unwrap();
    }

    fn tls_args(&self) -> CloudTlsArgs {
        CloudTlsArgs {
            cert: Some(self.path("server.crt")),
            key: Some(self.path("server.key")),
            client_ca: Some(self.path("client-ca/ca.crt")),
            crl: Some(self.path("crl.pem")),
            registry: Some(self.registry()),
        }
    }

    /// Enrol through `privoke_pki::client` (the code behind `privoke-supervisor enrol`), sign as the operator, and
    /// install: the credential directory is what the supervisor reads. `register` adds it to the server registry.
    pub fn installation(&self, name: &str, ca: &CaDir, register: bool) -> Installation {
        let dir = self.path(name);
        std::fs::create_dir_all(&dir).unwrap();
        let enrolled = enrolment::enrol(&dir).unwrap();
        let csr = std::fs::read_to_string(&enrolled.csr_path).unwrap();
        let signed = ca.sign_installation(&csr, &enrolled.installation, Validity::days(30)).unwrap();
        enrolment::install_cert(
            &dir,
            &signed.cert_pem,
            Some(&std::fs::read_to_string(self.server_ca()).unwrap()),
            None,
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        if register {
            registry_edit::add_installation(&self.registry(), &enrolled.installation, Some(name), signed.not_after).unwrap();
        }
        Installation { id: enrolled.installation, dir }
    }

    pub fn consumer(&self, name: &str) -> Installation {
        self.installation(name, &self.client_ca, true)
    }

    pub fn tls(&self, installation: &Installation) -> ClientTlsConfig {
        ClientTlsConfig {
            server_ca: self.server_ca(),
            identity: Some((installation.cert(), installation.key())),
            server_name: "localhost".to_string(),
        }
    }

    /// An in-process model-streaming server. With `releases`, it serves the real prepared standard V3 packages.
    pub async fn start_server(&self, releases: Option<&Path>) -> ServerHandle {
        let transport = self.tls_args().into_config().unwrap();
        let mut catalog =
            Catalog::load(self.models.path(), if releases.is_some() { "privoke-v3-balanced" } else { "privoke-baseline" }).unwrap();
        if let Some(directory) = releases {
            catalog.releases = Some(StandardReleases::open(directory).unwrap());
        }
        let any = "127.0.0.1:0".parse().unwrap();
        server::start(
            Listen { public: any, internal: any },
            ModelService::new(Arc::new(catalog)),
            transport,
            Limits::default(),
            Duration::from_millis(50),
        )
        .await
        .unwrap()
    }
}
