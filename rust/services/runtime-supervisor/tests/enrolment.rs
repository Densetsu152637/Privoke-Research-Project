//! `privoke-supervisor enrol`, `install-cert`, `renew` and `status` against an operator that signs with the real
//! `privoke-pki` library. Every CA, key and certificate is created in a temporary directory by the test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use privoke_pki::ca::{CaDir, Validity};
use privoke_supervisor::credentials;
use time::{Duration, OffsetDateTime};

const BINARY: &str = env!("CARGO_BIN_EXE_privoke-supervisor");

fn run(arguments: &[&str], extra_env: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(BINARY);
    command.args(arguments);
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

struct Operator {
    dir: tempfile::TempDir,
    client_ca: CaDir,
}

impl Operator {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let client_ca = CaDir::init(&dir.path().join("client-ca"), "Test Client CA", Validity::days(400)).unwrap();
        let server_ca = CaDir::init(&dir.path().join("server-ca"), "Test Server CA", Validity::days(400)).unwrap();
        std::fs::copy(server_ca_path(&server_ca, dir.path()), dir.path().join("server-ca.pem")).unwrap();
        client_ca.issue_reporter(Validity::days(400)).unwrap();
        Self { dir, client_ca }
    }

    /// What the operator does with a CSR: check it against the confirmed id and sign it.
    fn sign(&self, csr: &Path, id: &str, days: i64, name: &str) -> PathBuf {
        let signed = self.client_ca.sign_installation(&std::fs::read_to_string(csr).unwrap(), id, Validity::days(days)).unwrap();
        let path = self.dir.path().join(name);
        std::fs::write(&path, signed.cert_pem).unwrap();
        path
    }

    fn server_ca(&self) -> PathBuf {
        self.dir.path().join("server-ca.pem")
    }

    fn reporter_files(&self) -> (PathBuf, PathBuf) {
        let (cert, key) = self.client_ca.reporter().unwrap().unwrap();
        let (cert_path, key_path) = (self.dir.path().join("reporter.crt"), self.dir.path().join("reporter.key"));
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
        (cert_path, key_path)
    }
}

fn server_ca_path(_ca: &CaDir, base: &Path) -> PathBuf {
    base.join("server-ca").join("ca.crt")
}

fn installation_of(stdout: &str) -> String {
    stdout.lines().find_map(|line| line.strip_prefix("installation ")).unwrap().to_string()
}

fn csr_of(stdout: &str) -> PathBuf {
    PathBuf::from(stdout.lines().find_map(|line| line.strip_prefix("CSR: ")).unwrap())
}

#[test]
fn enrol_install_status_renew_and_install_again() {
    let operator = Operator::new();
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("credentials");
    let dir_arg = dir.to_str().unwrap();

    // Not enrolled yet: status says what to do, and exits successfully.
    let status = run(&["status", "--dir", dir_arg], &[]);
    assert!(status.status.success());
    assert!(text(&status.stdout).contains("Not enrolled"), "{}", text(&status.stdout));

    // enrol: an installation id, a key that stays in the directory, and a public CSR.
    let enrolled = run(&["enrol", "--dir", dir_arg], &[]);
    assert!(enrolled.status.success(), "{}", text(&enrolled.stderr));
    let output = text(&enrolled.stdout);
    let id = installation_of(&output);
    let csr = csr_of(&output);
    assert!(output.contains("CSR fingerprint"), "{output}");
    assert!(csr.is_file() && dir.join("client.key").is_file() && dir.join("installation.id").is_file());
    assert!(!output.contains("PRIVATE KEY") && !text(&enrolled.stderr).contains("PRIVATE KEY"), "the key is never printed");
    assert!(!std::fs::read_to_string(&csr).unwrap().contains("PRIVATE KEY"), "the CSR is public");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("client.key")).unwrap().permissions().mode() & 0o077, 0, "the key is owner-only");
    }
    let again = run(&["enrol", "--dir", dir_arg], &[]);
    assert!(!again.status.success(), "enrolling twice would orphan the first key");
    assert!(text(&again.stderr).contains("already enrolled"), "{}", text(&again.stderr));

    // Waiting for the certificate.
    let waiting = run(&["status", "--dir", dir_arg], &[]);
    assert!(text(&waiting.stdout).contains("waiting for the operator"), "{}", text(&waiting.stdout));

    // The operator signs; a certificate for another installation is refused.
    let other = run(&["enrol", "--dir", work.path().join("other").to_str().unwrap()], &[]);
    let other_id = installation_of(&text(&other.stdout));
    let wrong = operator.sign(&csr_of(&text(&other.stdout)), &other_id, 180, "wrong.crt");
    let refused = run(&["install-cert", "--dir", dir_arg, "--cert", wrong.to_str().unwrap()], &[]);
    assert!(!refused.status.success());
    assert!(!dir.join("client.crt").exists(), "a certificate for another installation is not stored");

    let (reporter_cert, reporter_key) = operator.reporter_files();
    let cert = operator.sign(&csr, &id, 180, "first.crt");
    let installed = run(
        &[
            "install-cert",
            "--dir",
            dir_arg,
            "--cert",
            cert.to_str().unwrap(),
            "--server-ca",
            operator.server_ca().to_str().unwrap(),
            "--reporter-cert",
            reporter_cert.to_str().unwrap(),
            "--reporter-key",
            reporter_key.to_str().unwrap(),
        ],
        &[],
    );
    assert!(installed.status.success(), "{}", text(&installed.stderr));
    assert_eq!(text(&installed.stdout).trim(), format!("installed for {id}"));
    for file in ["client.crt", "server-ca.pem", "reporter.crt", "reporter.key"] {
        assert!(dir.join(file).is_file(), "{file}");
    }

    let valid = run(&["status", "--dir", dir_arg], &[]);
    assert!(valid.status.success());
    assert!(!text(&valid.stderr).contains("action needed"), "{}", text(&valid.stderr));

    // renew: a new key and CSR under the same id; the active pair stays until the new certificate is installed.
    let active_key = std::fs::read(dir.join("client.key")).unwrap();
    let renewed = run(&["renew", "--dir", dir_arg], &[]);
    assert!(renewed.status.success(), "{}", text(&renewed.stderr));
    assert_eq!(installation_of(&text(&renewed.stdout)), id, "renewal keeps the installation id");
    assert_eq!(std::fs::read(dir.join("client.key")).unwrap(), active_key);
    let next_cert = operator.sign(&csr_of(&text(&renewed.stdout)), &id, 180, "second.crt");
    let promoted = run(&["install-cert", "--dir", dir_arg, "--cert", next_cert.to_str().unwrap()], &[]);
    assert!(promoted.status.success(), "{}", text(&promoted.stderr));
    assert!(text(&promoted.stdout).contains("renewal promoted"), "{}", text(&promoted.stdout));
    assert_ne!(std::fs::read(dir.join("client.key")).unwrap(), active_key);
    assert!(dir.join("client.prev.key").is_file(), "the previous pair is kept until the new one is confirmed");
}

#[test]
fn the_default_directory_comes_from_the_environment_and_status_needs_no_network() {
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("from-env");
    let enrolled = run(&["enrol"], &[("PRIVOKE_CREDENTIAL_DIR", &dir)]);
    assert!(enrolled.status.success(), "{}", text(&enrolled.stderr));
    assert!(dir.join("client.key").is_file());
    let status = run(&["status"], &[("PRIVOKE_CREDENTIAL_DIR", &dir)]);
    assert!(text(&status.stdout).contains("waiting for the operator"));
}

#[test]
fn status_warns_before_expiry_and_says_what_still_works_after() {
    let operator = Operator::new();
    let work = tempfile::tempdir().unwrap();
    let dir = work.path().join("credentials");
    let enrolled = text(&run(&["enrol", "--dir", dir.to_str().unwrap()], &[]).stdout);
    let id = installation_of(&enrolled);
    let cert = operator.sign(&csr_of(&enrolled), &id, 180, "c.crt");
    let installed = run(&["install-cert", "--dir", dir.to_str().unwrap(), "--cert", cert.to_str().unwrap()], &[]);
    assert!(installed.status.success(), "{}", text(&installed.stderr));

    let now = OffsetDateTime::now_utc();
    let fresh = credentials::status(&dir, now).unwrap();
    assert!(!credentials::needs_renewal(&fresh));
    let soon = credentials::status(&dir, now + Duration::days(160)).unwrap();
    assert!(credentials::needs_renewal(&soon), "{}", soon.message);
    let expired = credentials::status(&dir, now + Duration::days(200)).unwrap();
    assert!(credentials::needs_renewal(&expired));
    assert!(expired.message.contains("expired") && expired.message.contains("cached"), "{}", expired.message);
}
