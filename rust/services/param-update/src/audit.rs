//! Append-only parameter-update auditing and the health probes (`audit.py`).

use std::io::Write;
use std::path::Path;

use privoke_contracts::proto::v1::ParameterUpdateRequest;
use privoke_contracts::pyfloat;
use privoke_model_streaming::artifact::{MAX_ARTIFACT_BYTES, load_model_artifact_bytes, read_bounded};

use crate::pyfmt::json_string;

#[cfg(unix)]
fn open_storage(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    refuse_symlink(path)?;
    std::fs::OpenOptions::new().append(true).create(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_storage(path: &Path) -> std::io::Result<std::fs::File> {
    refuse_symlink(path)?;
    std::fs::OpenOptions::new().append(true).create(true).open(path)
}

fn refuse_symlink(path: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(std::io::Error::other("update audit file must not be a symbolic link"));
    }
    Ok(())
}

fn float_text(value: f32) -> String {
    pyfloat::repr(f64::from(value)).unwrap_or_else(|_| "null".to_string())
}

/// The audit line of an accepted update: `json.dumps(payload, separators=(",", ":"))` with the keys in the order the
/// Python service inserts them. Values are the float32 gradient values widened to doubles, as Python prints them.
pub fn audit_line(request: &ParameterUpdateRequest, applied_version: &str, artifact_checksum: &str) -> String {
    let mut line = String::from("{");
    for (name, value) in [
        ("source_id", &request.source_id),
        ("model_id", &request.model_id),
        ("base_version", &request.base_version),
        ("applied_version", &applied_version.to_string()),
        ("artifact_checksum", &artifact_checksum.to_string()),
    ] {
        line.push_str(&json_string(name));
        line.push(':');
        line.push_str(&json_string(value));
        line.push(',');
    }
    line.push_str("\"gradients\":[");
    for (index, gradient) in request.gradients.iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        line.push_str("{\"name\":");
        line.push_str(&json_string(&gradient.name));
        line.push_str(",\"shape\":[");
        line.push_str(&gradient.shape.iter().map(u32::to_string).collect::<Vec<_>>().join(","));
        line.push_str("],\"values\":[");
        line.push_str(&gradient.values.iter().map(|value| float_text(*value)).collect::<Vec<_>>().join(","));
        line.push_str("]}");
    }
    line.push_str("],\"metadata\":{");
    for (index, (key, value)) in request.metadata.iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        line.push_str(&json_string(key));
        line.push(':');
        line.push_str(&json_string(value));
    }
    line.push_str("}}");
    line
}

/// `persist_update_audit`: append one line to the audit file (mode 0600, symbolic links refused).
pub fn persist_update_audit(
    storage_path: &Path,
    request: &ParameterUpdateRequest,
    applied_version: &str,
    artifact_checksum: &str,
) -> std::io::Result<()> {
    let mut line = audit_line(request, applied_version, artifact_checksum);
    line.push('\n');
    let mut file = open_storage(storage_path)?;
    file.write_all(line.as_bytes())
}

/// `storage_is_writable`: the audit file can be opened for append.
pub fn storage_is_writable(storage_path: &Path) -> bool {
    open_storage(storage_path).is_ok()
}

/// `artifact_is_usable`: the model loads and validates, and its directory accepts a new file (the atomic write needs one).
pub fn artifact_is_usable(model_artifact_path: &Path) -> bool {
    let loaded = std::fs::symlink_metadata(model_artifact_path)
        .ok()
        .filter(|metadata| !metadata.file_type().is_symlink() && metadata.len() <= MAX_ARTIFACT_BYTES as u64)
        .and_then(|_| std::fs::File::open(model_artifact_path).ok())
        .and_then(|file| read_bounded(file).ok())
        .is_some_and(|raw| load_model_artifact_bytes(&raw, "").is_ok());
    loaded && directory_is_writable(model_artifact_path.parent().unwrap_or_else(|| Path::new(".")))
}

fn directory_is_writable(directory: &Path) -> bool {
    let probe = directory.join(format!(".privoke-health-{}", std::process::id()));
    let created = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).is_ok();
    if created {
        let _ = std::fs::remove_file(&probe);
    }
    created
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use privoke_contracts::proto::v1::Parameter;

    use super::*;

    #[test]
    fn audit_lines_use_the_python_key_order_and_float_text() {
        let request = ParameterUpdateRequest {
            source_id: "s".into(),
            model_id: "m".into(),
            base_version: "v1".into(),
            gradients: vec![Parameter { name: "g".into(), values: vec![0.5, -0.1], shape: vec![2] }],
            metadata: [("request_id".to_string(), "r".to_string())].into_iter().collect(),
        };
        assert_eq!(
            audit_line(&request, "v1+train.1", "abc"),
            r#"{"source_id":"s","model_id":"m","base_version":"v1","applied_version":"v1+train.1","artifact_checksum":"abc","gradients":[{"name":"g","shape":[2],"values":[0.5,-0.10000000149011612]}],"metadata":{"request_id":"r"}}"#
        );
    }

    #[test]
    fn storage_probe_creates_the_file_and_appends() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("updates.jsonl");
        assert!(storage_is_writable(&path));
        assert!(path.exists());
        assert!(directory_is_writable(directory.path()));
    }
}
