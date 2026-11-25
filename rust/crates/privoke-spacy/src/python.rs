//! The PyO3 engine of the in-process backend (feature `in-process`): CPython 3.11 embedded in the host process, the
//! hash-locked bundle checked, and `en_core_web_sm` loaded once, all on the interpreter thread.
//!
//! The Python side is the file the stage 11 worker embeds and the reference environment imports (`analyze_body`,
//! `startup`, `redirect_stdout`), included from the worker's source tree, so the result bytes come from one function in
//! every place and the lock check is the same code. `redirect_stdout` points fd 1 and `sys.stdout` at stderr before
//! anything else runs: a stray print or C-library message can never reach a protocol stream that the host owns.

use std::path::Path;

use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::inprocess::{Engine, StartFailure, Started};
use crate::protocol::{Selection, WorkerInfo};

const IMPL: &str = include_str!("../../../services/spacy-worker/python/privoke_spacy_impl.py");

struct PythonEngine {
    module: Py<PyModule>,
    nlp: Py<PyAny>,
}

fn message(err: &PyErr) -> String {
    err.to_string()
}

impl PythonEngine {
    fn body(
        &self,
        call: impl for<'py> FnOnce(Python<'py>, &Bound<'py, PyModule>, &Bound<'py, PyAny>) -> PyResult<String>,
    ) -> Result<String, String> {
        Python::attach(|py| call(py, self.module.bind(py), self.nlp.bind(py))).map_err(|e| message(&e))
    }
}

impl Engine for PythonEngine {
    fn analyze(&mut self, selection: Selection, text: &str) -> Result<String, String> {
        self.body(|_, module, nlp| module.call_method1("analyze_body", (nlp, text, selection.as_str()))?.extract::<String>())
    }

    fn lemma_index(&mut self) -> Result<String, String> {
        self.body(|_, module, nlp| module.call_method1("lemma_index_body", (nlp,))?.extract::<String>())
    }

    #[cfg(feature = "test-hooks")]
    fn crash(&mut self) -> Result<String, String> {
        // A real interpreter crash: abort() from inside CPython takes the whole process down, as a segfault in a C
        // extension would.
        let _ = self.body(|py, _, _| {
            PyModule::from_code(py, c"import os\nos.abort()\n", c"privoke_crash.py", c"privoke_crash")?;
            Ok(String::new())
        });
        std::process::abort()
    }

    #[cfg(feature = "test-hooks")]
    fn test_print(&mut self) -> Result<String, String> {
        self.body(|_, module, _| module.call_method0("test_print")?.extract::<String>())
    }
}

/// Checks the bundle and loads the model. Runs on the interpreter thread. A `BundleError` from the Python side is a
/// refusal (final); any other failure is not.
pub(crate) fn load(bundle: &Path, model: &str) -> Started {
    let bundle = bundle.canonicalize().map_err(|e| StartFailure::Failed(format!("bundle directory {}: {e}", bundle.display())))?;
    // Strip the verbatim prefix: Python's path handling does not want `\\?\`.
    let bundle_str = bundle.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    let started = Python::attach(|py| -> PyResult<(Py<PyModule>, Py<PyAny>, String)> {
        let module = PyModule::from_code(py, &std::ffi::CString::new(IMPL)?, c"privoke_spacy_impl.py", c"privoke_spacy_impl")?;
        module.call_method0("redirect_stdout")?;
        let outcome = module.call_method1("startup", (&bundle_str, model, None::<String>))?;
        let (nlp, info): (Bound<'_, PyAny>, String) = outcome.extract()?;
        Ok((module.unbind(), nlp.unbind(), info))
    });
    match started {
        Ok((module, nlp, info)) => {
            let info: WorkerInfo =
                serde_json::from_str(&info).map_err(|e| StartFailure::Failed(format!("malformed ready announcement: {e}")))?;
            Ok((Box::new(PythonEngine { module, nlp }) as Box<dyn Engine>, info))
        }
        Err(err) => {
            let refused = Python::attach(|py| err.get_type(py).name().is_ok_and(|n| n == "BundleError"));
            let reason = err.to_string();
            Err(if refused { StartFailure::Refused(reason) } else { StartFailure::Failed(reason) })
        }
    }
}
