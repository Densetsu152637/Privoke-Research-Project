# PriVoke worker pipe protocol

Stage W1 of the [Rust server rewrite plan](../plans/rust-server-rewrite.md#stage-w1-worker-pipe-protocol-and-python-worker-entrypoint). It defines how a controller runs the existing client-runtime analysis pipeline as a child process, with no listening socket and no network.

- Worker entrypoint: `extension/client-runtime/src/worker_main.py`
- Reference codec (standard library only): `extension/client-runtime/src/worker_protocol.py`
- Conformance capture: `tests/conformance/worker-frames/`
- Oracle: `extension/client-runtime/src/grpc_main.py` and `hosting/grpc_server.py`, unchanged

The worker is the same pipeline the gRPC server runs. Its handlers are the `PrivokeRuntimeService` methods, called with the decoded protobuf request, so the pipe protocol adds a framing layer and nothing else to the analysis messages.

## Process model

```text
controller ── request pipe  (controller writes, worker reads)  ──> worker
controller <─ response pipe (worker writes, controller reads) ──── worker
                       stdout and fd 1 redirected to stderr
```

- The controller creates two anonymous pipes and passes only those ends to the child, as `--request-fd N` and `--response-fd M`. Neither may be 0, 1 or 2, and they must differ (exit code 2 otherwise).
  - POSIX: `N` and `M` are inherited file descriptors.
  - Windows: `N` and `M` are inheritable `HANDLE` values (pass them in the `STARTUPINFO` handle list). The worker converts them with `msvcrt.open_osfhandle`.
- The worker never opens a socket and needs no network. Its stdin is the null device.
- **stdout.** Immediately after opening the pipes the worker duplicates stderr onto file descriptor 1 and sets `sys.stdout` to stderr. A stray `print`, a C library warning or a raw write to fd 1 therefore appears on stderr and can never interleave with frames, which travel only on the dedicated pipe. The controller should capture stderr as the worker log.
- **Telemetry.** The worker builds its servicer with no `TelemetryReporter` and forces `TELEMETRY_ENABLED=false`. The client controller owns the reporter.
- **End of life.** The worker exits 0 when the controller closes the request pipe at a frame boundary. Closing the pipe is the clean shutdown request.

### Command line and environment

| Option | Meaning |
| --- | --- |
| `--request-fd`, `--response-fd` | Pipe ends, see above. Required. |
| `--model-root DIR` | Read-only directory of model artifacts and packages. Repeatable; the first root that has the model wins. |
| `--latest-model-id ID` | What the alias `latest` resolves to. Without it `latest` is refused. |
| `--warm-layers LIST` | Layers exercised before READY. Default `regex,ner`; empty disables. |
| `--warm-semantic-model ID` | Semantic model loaded before READY. Repeatable. |
| `PRIVOKE_WORKER_SANDBOX=1` | Run the [sandbox self-check](#sandbox-self-check) before anything else. |

The worker also sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` when unset, replaces `ModelParameterStreamer.fetch` with the read-only path provider, and makes the gRPC channel helpers raise, so no code path can reach model-streaming or telemetry.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The request pipe closed cleanly. |
| 2 | Usage: bad pipe descriptors. |
| 3 | The sandbox self-check found network capability. |
| 4 | Start-up failed (dependency check, model load or warm-up). |
| 5 | The stream broke: a truncated frame or an unrecoverable length. |
| 6 | The response pipe closed while writing. |

Before exiting with 3, 4 or 5 the worker makes a best effort to write one `ERROR` frame (request id 0 for start-up failures, the offending id when known).

## Models

The front end (the client controller, or the quarantined service) fetches models over mutual TLS, checks the pins, writes them to its cache, and passes the worker read-only paths. The worker never writes to a model root.

| Layout under a `--model-root` | Served as |
| --- | --- |
| `<model_id>.json` | A legacy Tiny or sparse-presence artifact. The worker builds the same snapshot the Go model-streaming service streams: tensors sorted by name, values rounded to float32, the original `config` text as `model_config`, plus `architecture`, `artifact_checksum`, `artifact_file_checksum` (SHA-256 of the file), `trainable_parameters` and the artifact's own metadata. |
| `<model_id>/manifest.json` and the four V3 assets | A pinned standard V3 package. The manifest must match the compiled pin and every asset hash; the package is verified once per process. |

`model_id` must match `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}`; separators and `..` never reach the file system. Scratch-presence and pretrained-context artifacts are not served in W1 (the stage 0 corpus records the same gap). A parity test checks that the snapshot of all four tracked legacy models equals the Go service's recorded `GetModelParameters` response (metadata, versions, shapes and float32 tensor digests).

## Frames

All integers are big-endian. Every frame has a fixed 20-byte header followed by `payload_len` bytes.

| Offset | Size | Field | Notes |
| ---: | ---: | --- | --- |
| 0 | 4 | `payload_len` | Bytes after the header. |
| 4 | 1 | `version` | `1`. |
| 5 | 1 | `kind` | 1 request, 2 response, 3 error, 4 ready. |
| 6 | 1 | `method` | Method tag, 0 when not applicable. |
| 7 | 1 | `flags` | Bit 0 `METADATA`. All other bits must be 0. |
| 8 | 8 | `request_id` | Chosen by the controller, echoed by the worker. |
| 16 | 4 | `deadline_ms` | Requests: 0 for the method default. Responses: 0. |

### Methods

The payload of a request or response is the serialized protobuf message of the matching `PrivokeRuntimeService` method (`shared/proto/privoke/v1/runtime.proto`), serialized with deterministic map order.

| Tag | Method | Request message | Response message |
| ---: | --- | --- | --- |
| 1 | `AnalyzePrompt` | `AnalyzePromptRequest` | `AnalyzePromptResponse` |
| 2 | `DetectAnnotationPresence` | `DetectAnnotationPresenceRequest` | `DetectAnnotationPresenceResponse` |
| 3 | `Health` | `RuntimeHealthRequest` | `RuntimeHealthResponse` |
| 4 | `ComputeSemanticGradients` | `ComputeSemanticGradientsRequest` | `ComputeSemanticGradientsResponse` |
| 5 | `ComputeUnderlyingModelGradients` (full encoder) | `ComputeSemanticGradientsRequest` | `ComputeSemanticGradientsResponse` |
| 6 | `ComputePresenceGradients` | `ComputePresenceGradientsRequest` | `ComputePresenceGradientsResponse` |

Tags `0x10` to `0x1f` are reserved for the stage 11 spaCy worker and `0x20` to `0x3f` for later stages; the header, kinds, flags, error frames and limits rules here apply to them unchanged. A worker answers each request with exactly one `RESPONSE` or `ERROR` frame carrying the same `request_id`. Requests are served one at a time in arrival order.

Failures the gRPC server reports inside the response message (`error` fields, such as empty text, an unknown model or wrong training layers) are returned as ordinary `RESPONSE` frames with the same bytes. `ERROR` frames are for protocol faults and worker faults only.

### Metadata

With `flags` bit 0 set on a gradient method, the payload starts with a metadata block, then the protobuf message. It carries the values a gRPC call sends as invocation metadata (the training admission header `x-privoke-training-admission-v1`, and nothing else is read).

```text
u16 count (at most 16), then per entry: u16 key_len (1..64), key (UTF-8), u32 value_len (at most 16 KiB), value (UTF-8)
```

### Kinds

- **READY** (kind 4, method 0, request id 0): the first frame, sent only after the dependency check, the warm-up layers and every `--warm-semantic-model` have loaded, and the sandbox self-check (when requested) has passed. The payload is JSON with `protocol_version`, `implementation`, `pid`, `sandbox_self_check` (`passed` or `not_requested`), `telemetry` (`disabled`), `loaded` and the `limits` table. A controller sends nothing before READY and treats a start-up `ERROR` frame or an early exit as a failed start.
- **ERROR** (kind 3): payload is JSON `{"code": ..., "message": ...}` (sorted keys, ASCII). `request_id` is the offending request's id, or 0 when none could be read.

### Error codes

| Code | Cause | Stream afterwards |
| --- | --- | --- |
| `UNSUPPORTED_VERSION`, `INVALID_KIND`, `UNKNOWN_METHOD`, `INVALID_FLAGS` | Header field not accepted. | Payload skipped, worker continues. |
| `FRAME_TOO_LARGE` | `payload_len` above the method's request limit. | Payload skipped, worker continues. |
| `INVALID_METADATA` | Malformed metadata block. | Worker continues. |
| `INVALID_PAYLOAD` | Payload is not a valid request message. | Worker continues. |
| `INVALID_LAYERS` | Empty layer list, or `DETECTION_LAYER_RUNTIME` on `AnalyzePrompt`. | Worker continues. |
| `DEADLINE_EXCEEDED` | The handler finished after its deadline; the late result is discarded. | Worker continues. |
| `RESPONSE_TOO_LARGE` | Serialized response above the method's response limit. | Worker continues. |
| `INTERNAL` | An unexpected exception in a handler (the traceback goes to stderr). | Worker continues. |
| `STREAM_TRUNCATED`, `UNRECOVERABLE_FRAME` | Stream ended inside a frame, or `payload_len` above 64 MiB (it cannot be skipped). | Worker exits with code 5. |
| `SANDBOX_VIOLATION`, `STARTUP_FAILED` | Before READY. | Worker exits with code 3 or 4. |

A frame the worker rejects is consumed in full before the error is sent, so the next frame starts at a frame boundary and a controller can pipeline requests.

## Explicit layer selection

An empty layer list means the complete detector pipeline in the gRPC server. The worker never runs an implicit pipeline: every layer-bearing request (`AnalyzePrompt`, `DetectAnnotationPresence` and both gradient families) with an empty `layers` list is rejected with `INVALID_LAYERS`, and so is `DETECTION_LAYER_RUNTIME` on `AnalyzePrompt`. Other invalid selections reach the servicer and are answered exactly as the gRPC path answers them (for example, training requires exactly the semantic layer). The LLM layer is exercised with `layers = [DETECTION_LAYER_SEMANTIC]` and the response's executed layers are asserted to be exactly that. Selections that include regex or NER belong to the product pipeline or to a detector ablation and are labelled apart in the capture.

## Limits and deadlines

Frame and payload ceilings (the protocol hard maximum is 64 MiB, 67,108,864 bytes, for any single frame payload):

| Method | Max request payload | Max response payload | Default deadline | Max deadline |
| --- | ---: | ---: | ---: | ---: |
| `AnalyzePrompt` | 262,144 | 1,048,576 | 25 s | 25 s |
| `DetectAnnotationPresence` | 262,144 | 1,048,576 | 25 s | 25 s |
| `Health` | 1,024 | 4,096 | 5 s | 5 s |
| `ComputeSemanticGradients` | 4,194,304 | 67,108,864 | 120 s | 900 s |
| `ComputeUnderlyingModelGradients` | 4,194,304 | 67,108,864 | 300 s | 900 s |
| `ComputePresenceGradients` | 4,194,304 | 67,108,864 | 120 s | 900 s |

- The small-method request limit equals the gRPC server's default receive limit (262,144) and the response limit its default send limit (1 MiB).
- A gradient request carries up to 1,024 examples and 200,000 characters of text (at most four UTF-8 bytes each) plus metadata, which fits 4 MiB.
- **Largest gradient payload.** The measured full-encoder response for the tracked `privoke-balanced` Tiny model (36,756 parameters) is 150,889 bytes; the largest tracked model, `privoke-quality` (54,292 parameters), is about 0.22 MiB. The 64 MiB response limit also covers a full-encoder update of the 9.6 million parameter pretrained-V3 encoder (about 38.4 MB of float32 values), so a later V3 gradient RPC needs no protocol change.
- **Deadlines.** `deadline_ms` in a request is clamped to the method maximum; 0 selects the default. Analysis deadlines stay below the supervisor bridge's 30 s deadline. The worker enforces the deadline cooperatively: the context given to the handler reports inactive once it passes (the full-encoder trainer checks it when an optimizer admission is supplied), and a result that arrives late is replaced by `DEADLINE_EXCEEDED`. A handler stuck in native code is the controller's to kill: it should wait the deadline plus a short grace period, then kill and restart the worker (stage W2) and must not retry that request on another worker.

## Sandbox self-check

With `PRIVOKE_WORKER_SANDBOX=1` the worker tries to create a TCP/IPv4, UDP/IPv4 and TCP/IPv6 socket before it loads anything. If any creation succeeds it logs the capability to stderr, sends `SANDBOX_VIOLATION` and exits with code 3, so READY is never announced. A process whose operating-system layer denies socket creation passes and reports `sandbox_self_check: "passed"`. This is a self-check only: enforcement is the OS layer's job (stage W2), and on Windows no network denial is claimed beyond this check and the absence of network code in the worker.

## Conformance and evidence

`tests/conformance/worker-frames/` holds the W1 capture (`capture_worker_frames.py` regenerates it, and two consecutive captures were byte-identical):

- `prompts.json`: 20 synthetic prompts (the stage 0 corpus has no `PrivokeRuntimeService` prompt bodies);
- `analysis.json`, `training.json`, `protocol.json`: request frames in hex with the response kind, a SHA-256 and length of the normalised response payload and a flag saying whether the gRPC path produced the same bytes; malformed-frame cases with the expected error code;
- `manifest.json`: counts by scope, environment (Python, torch, one thread) and the limits table.

**Parity method.** The gRPC oracle is `create_grpc_server` in the test process on an ephemeral loopback port, serving models through the same read-only provider; the worker is a separate child over dedicated pipes. Both responses are compared as serialized protobuf bytes with deterministic map order. The only normalisation is clearing `elapsed_ms` and its copy in the response metadata map (wall-clock values). Both processes use one CPU thread.

**Result.** All 201 captured cases were byte-identical (53 LLM-only, 60 detector ablation, 88 product pipeline), and the semantic, underlying (full encoder) and presence gradient responses were byte-identical, so no float tolerance is declared for any RPC. Caveats: the model transport differs by design (read-only files in the worker, gRPC streaming in the server), which the model-corpus test above bounds; gradient parity is established for the Tiny models and the sparse presence model, since the gradient RPCs do not serve V3 packages; and digests recorded in the capture hold for the torch build named in its manifest (the replay tests skip on a different build).

LLM-only evidence is the `semantic` selection and the semantic-only RPCs. The regex and NER selections in the capture are detector-ablation or product-pipeline rows and must not be cited as LLM-only results.
