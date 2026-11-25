//! `privoke-spacy-worker`: embeds CPython 3.11 through PyO3, loads `en_core_web_sm` once and serves spaCy over the
//! framed protocol of `privoke_spacy::protocol`.
//!
//! Layout: the worker sits in the bundle directory next to `python311.dll`, `python311._pth`, `Lib/site-packages` and
//! `bundle.lock.txt`. The `_pth` file makes CPython ignore the user's environment, so the host Python is never used.
//!
//! Descriptors: requests arrive on stdin. Frames leave on a duplicate of the original stdout, taken before Python
//! starts. Python then points its own fd 1 and `sys.stdout` at stderr, so nothing but this program writes frames.
//! Rust code never prints to stdout.
//!
//! Exit codes: 0 when the client closed stdin, 78 when the bundle was refused (a `fatal` frame is sent first), 1 on any
//! other failure.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use privoke_spacy_worker::{Handler, serve, write_frame};
use pyo3::prelude::*;
use pyo3::types::PyModule;

const IMPL: &str = include_str!("../python/privoke_spacy_impl.py");
const EXIT_BUNDLE_REFUSED: u8 = 78;

struct SpacyHandler {
    module: Py<PyModule>,
    nlp: Py<PyAny>,
}

fn message(err: &PyErr) -> String {
    err.to_string()
}

impl Handler for SpacyHandler {
    fn analyze(&mut self, selection: &str, text: &str) -> Result<String, String> {
        Python::attach(|py| {
            let call = self.module.bind(py).call_method1("analyze_body", (self.nlp.bind(py), text, selection));
            call.and_then(|body| body.extract::<String>()).map_err(|e| message(&e))
        })
    }

    fn lemma_index(&mut self) -> Result<String, String> {
        Python::attach(|py| {
            let call = self.module.bind(py).call_method1("lemma_index_body", (self.nlp.bind(py),));
            call.and_then(|body| body.extract::<String>()).map_err(|e| message(&e))
        })
    }

    #[cfg(feature = "test-hooks")]
    fn test_print(&mut self) -> Result<String, String> {
        Python::attach(|py| {
            let call = self.module.bind(py).call_method0("test_print");
            call.and_then(|body| body.extract::<String>()).map_err(|e| message(&e))
        })
    }
}

/// A duplicate of the original stdout. Its handle is independent of fd 1, which Python later repoints at stderr.
fn frame_output() -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(File::from(io::stdout().as_handle().try_clone_to_owned()?))
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(io::stdout().as_fd().try_clone_to_owned()?))
    }
}

fn bundle_dir() -> io::Result<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--bundle" {
            return args.next().map(PathBuf::from).ok_or_else(|| io::Error::other("--bundle needs a directory"));
        }
    }
    let exe = std::env::current_exe()?;
    exe.parent().map(PathBuf::from).ok_or_else(|| io::Error::other("the executable has no directory"))
}

/// Test hook: a lock file other than the bundle's own, to prove that a differing environment is refused.
#[cfg(feature = "test-hooks")]
fn lock_override() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--lock" {
            return args.next();
        }
    }
    None
}

#[cfg(not(feature = "test-hooks"))]
fn lock_override() -> Option<String> {
    None
}

fn model_name() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--model"
            && let Some(name) = args.next()
        {
            return name;
        }
    }
    "en_core_web_sm".to_string()
}

fn run() -> io::Result<ExitCode> {
    let mut frames = frame_output()?;
    let bundle = bundle_dir()?.canonicalize()?;
    // Strip the verbatim prefix: Python's path handling does not want `\\?\`.
    let bundle_str = bundle.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    let model = model_name();

    let started = Python::attach(|py| -> PyResult<(Py<PyModule>, Py<PyAny>, String)> {
        let module = PyModule::from_code(py, &std::ffi::CString::new(IMPL)?, c"privoke_spacy_impl.py", c"privoke_spacy_impl")?;
        module.call_method0("redirect_stdout")?;
        let outcome = module.call_method1("startup", (&bundle_str, &model, lock_override()))?;
        let (nlp, info): (Bound<'_, PyAny>, String) = outcome.extract()?;
        Ok((module.unbind(), nlp.unbind(), info))
    });
    let (module, nlp, info) = match started {
        Ok(started) => started,
        Err(err) => {
            let refused = Python::attach(|py| err.get_type(py).name().is_ok_and(|n| n == "BundleError"));
            let reason = err.to_string();
            eprintln!("privoke-spacy-worker: cannot start: {reason}");
            if !refused {
                // Not a bundle problem (for example a failed spacy.load): exit so that the pool retries with backoff.
                return Ok(ExitCode::FAILURE);
            }
            let fatal = serde_json::json!({"type": "fatal", "reason": reason}).to_string();
            write_frame(&mut frames, fatal.as_bytes())?;
            return Ok(ExitCode::from(EXIT_BUNDLE_REFUSED));
        }
    };
    write_frame(&mut frames, info.as_bytes())?;
    let mut handler = SpacyHandler { module, nlp };
    let mut input = BufReader::new(io::stdin().lock());
    serve(&mut input, &mut frames, &mut handler)?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("privoke-spacy-worker: {err}");
            ExitCode::FAILURE
        }
    }
}
