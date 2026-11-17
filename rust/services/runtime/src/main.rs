//! `privoke-runtime-worker`: the Rust analysis runtime as a W1 worker for the W2 pool.
//!
//! ```text
//! privoke-runtime-worker [--bundle DIR] [--model NAME] [--max-text-chars N] [--warm-layers regex,ner]
//!     [--model-root DIR]... [--latest-model-id ID] [--warm-semantic-model ID]... [--spacy fake]
//! ```
//!
//! The pool starts it with the stage 11 bundle directory as its working location (the executable sits in the bundle,
//! because CPython finds its `_pth` file next to its library); `--bundle` names another directory. `PRIVOKE_NER_MODEL`,
//! `PRIVOKE_WAIT_FOR_REGEX`, the regex and NER switches and the robustness flags are read as the Python runtime reads
//! them. `PRIVOKE_WORKER_SANDBOX=1` runs the sandbox self-check before anything loads. `--spacy fake` (only in a build
//! with the `fake-spacy` feature) starts the Python-free stand-in engine for the process tests.
//!
//! The worker never opens a socket (the self-check opens and closes loopback sockets to test that it cannot), reads
//! only the bundle, and has no telemetry.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

use privoke_ner_layer::EntityNerDetector;
use privoke_rules::{Detector, RuleSetOptions};
use privoke_runtime::frames::{self, code};
use privoke_runtime::request::{DEFAULT_MAX_TEXT_CHARS, Layer};
use privoke_runtime::semantic::SemanticLayer;
use privoke_runtime::worker::{self, exit};
use privoke_runtime::{Pipeline, PipelineOptions, Service, ServiceOptions};
use privoke_spacy::{InProcess, InProcessConfig, Spacy};
use privoke_worker_pool::{worker_side, write_frame_sync};

struct Arguments {
    bundle: Option<String>,
    model: Option<String>,
    max_text_chars: usize,
    warm_layers: Vec<Layer>,
    fake_spacy: bool,
    model_roots: Vec<String>,
    latest_model_id: Option<String>,
    warm_models: Vec<String>,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = Arguments {
        bundle: None,
        model: None,
        max_text_chars: DEFAULT_MAX_TEXT_CHARS,
        warm_layers: vec![Layer::Regex, Layer::Ner],
        fake_spacy: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(name) = args.next() {
        let mut value = |what: &str| args.next().ok_or_else(|| format!("{what} needs a value"));
        match name.as_str() {
            "--bundle" => arguments.bundle = Some(value("--bundle")?),
            "--model" => arguments.model = Some(value("--model")?),
            "--max-text-chars" => {
                arguments.max_text_chars =
                    value("--max-text-chars")?.parse().map_err(|_| "--max-text-chars must be a positive integer".to_string())?;
                if arguments.max_text_chars == 0 {
                    return Err("--max-text-chars must be a positive integer".to_string());
                }
            }
            "--warm-layers" => {
                arguments.warm_layers = value("--warm-layers")?
                    .split(',')
                    .filter(|layer| !layer.is_empty())
                    .map(|layer| match layer {
                        "regex" => Ok(Layer::Regex),
                        "ner" => Ok(Layer::Ner),
                        other => {
                            Err(format!("--warm-layers: the Rust worker warms regex and ner, not {other:?} (use --warm-semantic-model)"))
                        }
                    })
                    .collect::<Result<_, _>>()?;
            }
            "--model-root" => arguments.model_roots.push(value("--model-root")?),
            "--latest-model-id" => arguments.latest_model_id = Some(value("--latest-model-id")?),
            "--warm-semantic-model" => arguments.warm_models.push(value("--warm-semantic-model")?),
            "--spacy" => match value("--spacy")?.as_str() {
                "fake" => arguments.fake_spacy = true,
                "real" => arguments.fake_spacy = false,
                other => return Err(format!("--spacy must be real or fake, not {other:?}")),
            },
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(arguments)
}

#[cfg(feature = "fake-spacy")]
fn start_fake(config: &InProcessConfig) -> Result<InProcess, String> {
    use privoke_spacy::fake::{FakeEngine, fake_info};
    InProcess::start_with(config, || Ok((Box::new(FakeEngine) as Box<dyn privoke_spacy::Engine>, fake_info())))
        .map_err(|error| error.to_string())
}

#[cfg(not(feature = "fake-spacy"))]
fn start_fake(_config: &InProcessConfig) -> Result<InProcess, String> {
    Err("this build has no fake spaCy engine (feature `fake-spacy`)".to_string())
}

fn start_spacy(arguments: &Arguments) -> Result<Spacy, String> {
    let mut config = InProcessConfig { max_text_chars: arguments.max_text_chars, ..InProcessConfig::default() };
    if let Some(bundle) = &arguments.bundle {
        config.bundle = bundle.into();
    }
    if let Some(model) = &arguments.model {
        config.model.clone_from(model);
    }
    let backend = if arguments.fake_spacy { start_fake(&config)? } else { InProcess::start(&config).map_err(|error| error.to_string())? };
    Ok(Spacy::InProcess(backend))
}

fn fail(frames_out: &mut impl Write, kind: &str, message: &str, exit_code: i32) -> i32 {
    eprintln!("worker: {message}");
    let truncated: String = message.chars().take(512).collect();
    let _ = write_frame_sync(frames_out, &frames::encode_error(0, kind, &truncated));
    exit_code
}

fn run() -> io::Result<i32> {
    // Frames leave on a duplicate of the original stdout; stdout itself now points at stderr.
    let mut frames_out = worker_side::claim_frame_output()?;
    let arguments = match parse_arguments() {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("worker: {message}");
            return Ok(exit::USAGE);
        }
    };

    let sandboxed = std::env::var("PRIVOKE_WORKER_SANDBOX").is_ok_and(|value| value == "1");
    if sandboxed {
        let findings = worker::sandbox_self_check();
        if !findings.is_empty() {
            let message = format!("Sandbox self-check failed: this process can open {} sockets.", findings.join(", "));
            return Ok(fail(&mut frames_out, code::SANDBOX_VIOLATION, &message, exit::SANDBOX));
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let spacy = match start_spacy(&arguments) {
        Ok(spacy) => spacy,
        Err(message) => {
            return Ok(fail(&mut frames_out, code::STARTUP_FAILED, &format!("Worker startup failed: {message}"), exit::STARTUP));
        }
    };
    let model_name =
        std::env::var("PRIVOKE_NER_MODEL").ok().filter(|name| !name.trim().is_empty()).unwrap_or_else(|| "en_core_web_sm".to_string());
    let started: Result<Service<Spacy>, String> = runtime.block_on(async {
        spacy.wait_ready(Duration::from_secs(300)).await.map_err(|error| error.to_string())?;
        let regex = Detector::new(RuleSetOptions::from_env()).map_err(|error| error.to_string())?;
        let ner = EntityNerDetector::new(spacy, &model_name).await.map_err(|error| error.to_string())?;
        let mut pipeline = Pipeline::new(regex, ner, PipelineOptions::from_env());
        if !arguments.model_roots.is_empty() {
            let roots = arguments.model_roots.iter().map(std::path::PathBuf::from).collect();
            pipeline = pipeline.with_semantic(SemanticLayer::new(roots, arguments.latest_model_id.clone())?);
        }
        Ok(Service::new(pipeline, ServiceOptions { max_text_chars: arguments.max_text_chars, clear_elapsed: false }))
    });
    let service = match started {
        Ok(service) => service,
        Err(message) => {
            return Ok(fail(&mut frames_out, code::STARTUP_FAILED, &format!("Worker startup failed: {message}"), exit::STARTUP));
        }
    };
    let loaded = match runtime.block_on(worker::warm_up(&service, &arguments.warm_layers, &arguments.warm_models)) {
        Ok(loaded) => loaded,
        Err(message) => {
            return Ok(fail(&mut frames_out, code::STARTUP_FAILED, &format!("Worker startup failed: {message}"), exit::STARTUP));
        }
    };

    write_frame_sync(&mut frames_out, &worker::ready_frame(&loaded, if sandboxed { "passed" } else { "not_requested" }))?;
    let mut input = io::BufReader::new(io::stdin().lock());
    Ok(worker::serve(&service, &runtime, &mut input, &mut frames_out))
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("privoke-runtime-worker: {error}");
            ExitCode::FAILURE
        }
    }
}
