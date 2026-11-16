//! `privoke-pki`: operator and installation commands. See the crate documentation and `docs/deployment/google-cloud.md`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use privoke_pki::ca::{CaDir, Validity};
use privoke_pki::client::{self, CredentialState};
use privoke_pki::files::{read_text, write_atomic};
use privoke_pki::{PkiError, registry_edit};
use privoke_transport::identity::Identity;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Parser)]
#[command(name = "privoke-pki", version, about = "PriVoke certificate authority and enrolment tool")]
enum Command {
    /// Operator: create a CA (run once for the client CA and once for the server CA). Keep the directory offline.
    InitCa {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 3650)]
        days: i64,
    },
    /// Operator: issue a server certificate from a server CA.
    IssueServer {
        #[arg(long)]
        ca_dir: PathBuf,
        /// DNS name or IP address; repeatable.
        #[arg(long = "dns", required = true)]
        names: Vec<String>,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value_t = 90)]
        days: i64,
    },
    /// Operator: issue the shared telemetry reporter credential, delivered with every enrolment.
    IssueReporter {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long, default_value_t = 180)]
        days: i64,
    },
    /// Operator: sign an installation CSR, register the installation and write the delivery bundle.
    Sign {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long)]
        csr: PathBuf,
        /// The installation UUID the operator verified out of band.
        #[arg(long)]
        installation: String,
        #[arg(long, default_value_t = client::CERTIFICATE_DAYS)]
        days: i64,
        #[arg(long)]
        out_dir: PathBuf,
        /// Server CA certificate to include in the bundle.
        #[arg(long)]
        server_ca: Option<PathBuf>,
        /// Registry file to update.
        #[arg(long)]
        registry: Option<PathBuf>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Operator: issue a certificate for a service principal and register its role.
    SignService {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long)]
        name: String,
        /// publisher, trainer or runtime.
        #[arg(long)]
        role: String,
        #[arg(long, default_value_t = 90)]
        days: i64,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Operator: revoke an identity. Marks it for the next CRL and puts it on the registry deny list.
    Revoke {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long, group = "who")]
        installation: Option<String>,
        #[arg(long, group = "who")]
        service: Option<String>,
        #[arg(long, group = "who")]
        reporter: bool,
        #[arg(long)]
        registry: Option<PathBuf>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Operator: write a CRL of everything revoked. Publish a new one before `--days` run out.
    Crl {
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 7)]
        days: i64,
    },
    /// Installation: create the installation id, key and CSR.
    Enrol {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Installation: create a renewal key and CSR under the same id.
    Renew {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Installation: store the certificate the operator returned.
    InstallCert {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        server_ca: Option<PathBuf>,
        #[arg(long, requires = "reporter_key")]
        reporter_cert: Option<PathBuf>,
        #[arg(long, requires = "reporter_cert")]
        reporter_key: Option<PathBuf>,
    },
    /// Installation: show when the certificate expires and what stops working then.
    Status {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn validity(days: i64) -> Result<Validity, PkiError> {
    if !(1..=3650).contains(&days) {
        return Err(PkiError::Refused("--days must be between 1 and 3650".into()));
    }
    Ok(Validity::days(days))
}

fn write_bundle_file(dir: &Path, name: &str, contents: &str, secret: bool) -> Result<(), PkiError> {
    write_atomic(&dir.join(name), contents.as_bytes(), secret)
}

fn run(command: Command) -> Result<(), PkiError> {
    let now = OffsetDateTime::now_utc();
    match command {
        Command::InitCa { dir, name, days } => {
            CaDir::init(&dir, &name, validity(days)?)?;
            println!("CA created in {}. ca.key is the secret: keep this directory offline.", dir.display());
        }
        Command::IssueServer { ca_dir, names, out_dir, days } => {
            let issued = CaDir::open(&ca_dir)?.issue_server(&names, validity(days)?)?;
            write_bundle_file(&out_dir, "server.crt", &issued.cert_pem, false)?;
            write_bundle_file(&out_dir, "server.key", &issued.key_pem, true)?;
            println!("server.crt and server.key written to {}", out_dir.display());
        }
        Command::IssueReporter { ca_dir, days } => {
            CaDir::open(&ca_dir)?.issue_reporter(validity(days)?)?;
            println!("reporter credential stored in {}/reporter and delivered with each sign", ca_dir.display());
        }
        Command::Sign { ca_dir, csr, installation, days, out_dir, server_ca, registry, label } => {
            let ca = CaDir::open(&ca_dir)?;
            let signed = ca.sign_installation(&read_text(&csr)?, &installation, validity(days)?)?;
            write_bundle_file(&out_dir, "client.crt", &signed.cert_pem, false)?;
            if let Some(path) = server_ca {
                write_bundle_file(&out_dir, "server-ca.pem", &read_text(&path)?, false)?;
            }
            match ca.reporter()? {
                Some((cert, key)) => {
                    write_bundle_file(&out_dir, "reporter.crt", &cert, false)?;
                    write_bundle_file(&out_dir, "reporter.key", &key, true)?;
                }
                None => eprintln!("warning: no reporter credential issued yet (issue-reporter); the bundle has none"),
            }
            if let Some(path) = registry {
                registry_edit::add_installation(&path, &installation, label.as_deref(), signed.not_after)?;
            }
            println!("signed installation {installation}; serial {}; bundle in {}", signed.serial, out_dir.display());
        }
        Command::SignService { ca_dir, name, role, days, out_dir, registry } => {
            let issued = CaDir::open(&ca_dir)?.issue_service(&name, validity(days)?)?;
            write_bundle_file(&out_dir, &format!("{name}.crt"), &issued.cert_pem, false)?;
            write_bundle_file(&out_dir, &format!("{name}.key"), &issued.key_pem, true)?;
            if let Some(path) = registry {
                registry_edit::add_service(&path, &name, &role, issued.not_after)?;
            }
            println!("service {name} ({role}) written to {}", out_dir.display());
        }
        Command::Revoke { ca_dir, installation, service, reporter, registry, reason } => {
            let identity = match (installation, service, reporter) {
                (Some(id), None, false) => Identity::Installation(id),
                (None, Some(name), false) => Identity::Service(name),
                (None, None, true) => Identity::Reporter,
                _ => return Err(PkiError::Refused("name exactly one of --installation, --service or --reporter".into())),
            };
            let changed = CaDir::open(&ca_dir)?.revoke(&identity, now)?;
            if let Some(path) = registry {
                registry_edit::deny(&path, &identity, reason.as_deref())?;
                if identity == Identity::Reporter {
                    registry_edit::set_reporter(&path, false)?;
                }
            }
            println!("{changed} certificate(s) for {identity} marked revoked; write a new CRL and publish it");
        }
        Command::Crl { ca_dir, out, days } => {
            let pem = CaDir::open(&ca_dir)?.crl_pem(now, Duration::days(days))?;
            write_atomic(&out, pem.as_bytes(), false)?;
            println!("CRL valid for {days} days written to {}", out.display());
        }
        Command::Enrol { dir } => {
            let enrolment = client::enrol(&dir)?;
            println!(
                "installation {}\nCSR: {}\nCSR fingerprint (confirm with the operator): {}",
                enrolment.installation,
                enrolment.csr_path.display(),
                enrolment.csr_fingerprint
            );
        }
        Command::Renew { dir } => {
            let enrolment = client::renew(&dir)?;
            println!(
                "installation {}\nCSR: {}\nCSR fingerprint (confirm with the operator): {}",
                enrolment.installation,
                enrolment.csr_path.display(),
                enrolment.csr_fingerprint
            );
        }
        Command::InstallCert { dir, cert, server_ca, reporter_cert, reporter_key } => {
            let server_ca = server_ca.map(|path| read_text(&path)).transpose()?;
            let reporter = match (reporter_cert, reporter_key) {
                (Some(cert), Some(key)) => Some((read_text(&cert)?, read_text(&key)?)),
                _ => None,
            };
            let installed = client::install_cert(
                &dir,
                &read_text(&cert)?,
                server_ca.as_deref(),
                reporter.as_ref().map(|(cert, key)| (cert.as_str(), key.as_str())),
                now,
            )?;
            println!("installed for {}{}", installed.installation, if installed.renewed { " (renewal promoted)" } else { "" });
        }
        Command::Status { dir } => {
            let status = client::status(&dir, now)?;
            println!("{}", status.message);
            if matches!(status.state, CredentialState::Expired | CredentialState::ExpiringSoon) {
                eprintln!("action needed: renew");
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Command::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
