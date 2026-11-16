//! File helpers: atomic writes and owner-only permissions for private keys.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::PkiError;

/// Write `contents` to `path` through a temporary file and a rename, so a reader never sees half a file.
pub fn write_atomic(path: &Path, contents: &[u8], secret: bool) -> Result<(), PkiError> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|error| PkiError::io(parent, error))?;
    let name = path.file_name().map_or_else(|| "file".to_string(), |name| name.to_string_lossy().into_owned());
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| PkiError::io(&temporary, error))?;
        file.write_all(contents).map_err(|error| PkiError::io(&temporary, error))?;
        file.sync_all().map_err(|error| PkiError::io(&temporary, error))?;
    }
    #[cfg(windows)]
    if secret {
        restrict_to_current_user(&temporary);
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        PkiError::io(path, error)
    })
}

/// Windows has no mode bits; remove inherited access and grant only the current user. Failure is reported, not fatal,
/// because some volumes (FAT, network shares) have no ACLs.
#[cfg(windows)]
fn restrict_to_current_user(path: &Path) {
    let Ok(user) = std::env::var("USERNAME") else { return };
    let outcome = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{user}:F"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if !matches!(outcome, Ok(status) if status.success()) {
        eprintln!("warning: could not restrict {} to the current user", path.display());
    }
}

/// Read a UTF-8 text file.
pub fn read_text(path: &Path) -> Result<String, PkiError> {
    fs::read_to_string(path).map_err(|error| PkiError::io(path, error))
}
