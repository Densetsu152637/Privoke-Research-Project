# Documentation index

Commands in these guides retain their original working-directory assumptions. Start from the repository root and follow each explicit `cd` command.

## Project and contracts

| Guide | Contents |
| --- | --- |
| [Project](project/overview.md) | Architecture, classification contract and development workflow |
| [Shared contracts](project/shared-contracts.md) | Protobuf and shared Python packages |
| [Shared workflow guidance](project/shared-guidance.md) | Reusable coding, Git, container, environment and validation policy |

## Runtime and browser extension

| Guide | Contents |
| --- | --- |
| [Client configuration](runtime/client-configuration.md) | Installation secrets, cloud connections and hidden local-development switch |
| [Browser extension](runtime/browser-extension.md) | Build, native messaging and browser integration |
| [Client runtime](runtime/client-runtime.md) | Detectors, HTTP harness, configuration and verification |
| [Runtime supervisor](runtime/supervisor.md) | Workstation process lifecycle and gRPC-Web bridge |
| [Runtime hosting](runtime/hosting.md) | HTTP API and response contract |

## Detector layers

| Guide | Contents |
| --- | --- |
| [Detection preprocessing](detectors/preprocessing.md) | Text normalization |
| [Semantic classifiers](detectors/semantic-classifiers.md) | Streamed, local and OpenAI backends |
| [NER detector](detectors/ner.md) | Entity classification |
| [Regex detector](detectors/regex.md) | Rules and visibility heuristics |

## Server services and model artifacts

| Guide | Contents |
| --- | --- |
| [Services](services/overview.md) | Server topology and responsibilities |
| [Model streaming](services/model-streaming.md) | Model artifacts and download RPCs |
| [Parameter updates](services/parameter-updates.md) | Updates and fuzzer orchestration |
| [Fuzzer](services/fuzzer.md) | Experiments and training |
| [Telemetry](services/telemetry.md) | Metadata ingestion and storage |
| [Model artifacts](services/model-artifacts.md) | Model storage and formats |

## Evaluation

| Guide | Contents |
| --- | --- |
| [Evaluation](evaluation/overview.md) | Datasets, experiments and metrics |
| [Regex evaluation results](evaluation/regex-results.md) | Existing evaluation report |
| [Host Python evaluation and tests](../evaluation/README.md) | Localhost test invocation, controlled update experiments and raw run manifests |

## Deployment

| Guide | Contents |
| --- | --- |
| [Google Cloud deployment](deployment/google-cloud.md) | Compute Engine, IAM, GitHub Actions, certificates, backups and recovery |

## Research plans and results

Research documents, dataset reviews and evidence retain their existing locations. Historical full-pipeline measurements retain their original scope; they are not LLM-only evidence.

| Guide | Contents |
| --- | --- |
| [In-house model training status](in-house-model-training.md) | Current randomly initialized/head-only training and the separately accepted end-to-end training direction |
| [Sparse presence profile results](presence-model-improvements.md) | Validation-selected binary annotation-presence profiles and matched runtime measurements |
| [PII dataset analysis](PII-dataset-analysis.md) | Pinned source preparation, offline fit and verified RPC comparison; final remains unscored |
| [Prospective clean-data augmentation](../paper/research/clean-augmentation-protocol.md) | AdvPIIBench structural scan of 104,728 rows and protected-key scan complete; blinded whole-prompt review, quota-feasible partitions, fitting, and scoring remain pending |
| [Contextual cascade results](contextual-cascade-results.md) | Development cascade and provisional contextual-fixture comparison; final remains unscored |
| [Synthetic prompt generation](synthetic-prompt-generation-research-20261009.md) | Generation methods, continual fuzzer integration, label quality, retention and prospective evaluation |
| [Continual synthetic fuzzer results](continual-fuzzer-results-20261009.md) | Three-profile, 60-attempt Docker study; matched before/after metrics, replay coverage and observed recall/specificity tradeoffs |
| [Six-hour synthetic fuzzer results](long-fuzzer-results-20261009.md) | Three sequential two-hour profile windows; aggregate endpoint trajectories, paired intervals and limitations |
| [Curriculum improvement process and results](fuzzer-curriculum-improvement-process-20261009.md) | Audited semantic-only 63-cell comparison of curriculum, sampler, replay and offline representation; all seed outcomes, tradeoffs and amendment history |
| [Accelerated normal-batch fuzzer study](accelerated-fuzzer-study-20261010.md) | Audited twelve-trajectory semantic-only schedule; measurable tradeoffs, quality plateau, fixed iteration criteria and safe reproducible aggregates |
| [Research completion plan](Research-completion-plan.md) | Research questions, experiments, milestones and publication readiness |
| [Research paper writing guide](Research-paper-writing-guide.md) | Methodology improvements, wording, evidence reporting and venue requirements |
| [Current research evidence](../paper/research/claims.md) | Provisional claims, measured development results, protocol and professor review requests |
