# Documentation index

Commands in these guides retain their original working-directory assumptions. Start from the repository root and follow each explicit `cd` command.

| Guide | Contents |
| --- | --- |
| [Google Cloud deployment](README.Google-cloud-deployment.md) | Compute Engine, IAM, GitHub Actions, certificates, backups and recovery |
| [Client configuration](README.Client-configuration.md) | Installation secrets, cloud connections and hidden local-development switch |
| [Project](README.Project.md) | Architecture, classification contract and development workflow |
| [Browser extension](README.Browser-extension.md) | Build, native messaging and browser integration |
| [Client runtime](README.Client-runtime.md) | Detectors, HTTP harness, configuration and verification |
| [Runtime supervisor](README.Runtime-supervisor.md) | Workstation process lifecycle and gRPC-Web bridge |
| [Runtime hosting](README.Runtime-hosting.md) | HTTP API and response contract |
| [Detection preprocessing](README.Detection-preprocessing.md) | Text normalization |
| [Semantic classifiers](README.Semantic-classifiers.md) | Streamed, local and OpenAI backends |
| [NER detector](README.NER-detector.md) | Entity classification |
| [Regex detector](README.Regex-detector.md) | Rules and visibility heuristics |
| [Services](README.Services.md) | Server topology and responsibilities |
| [Model streaming](README.Model-streaming-service.md) | Model artifacts and download RPCs |
| [Parameter updates](README.Parameter-update-service.md) | Updates and fuzzer orchestration |
| [Fuzzer](README.Fuzzer-service.md) | Experiments and training |
| [Telemetry](README.Telemetry-service.md) | Metadata ingestion and storage |
| [Shared contracts](README.Shared-contracts.md) | Protobuf and shared Python packages |
| [Model artifacts](README.Model-artifacts.md) | Model storage and formats |
| [In-house model training status](in-house-model-training.md) | Current randomly initialized/head-only training and the separately accepted end-to-end training direction |
| [Sparse presence profile results](presence-model-improvements.md) | Validation-selected binary annotation-presence profiles and matched runtime measurements |
| [PII dataset analysis](PII-dataset-analysis.md) | Pinned source preparation, offline fit and verified RPC comparison; final remains unscored |
| [Prospective clean-data augmentation](../paper/research/clean-augmentation-protocol.md) | AdvPIIBench structural scan of 104,728 rows and protected-key scan complete; blinded whole-prompt review, quota-feasible partitions, fitting, and scoring remain pending |
| [Contextual cascade results](contextual-cascade-results.md) | Development cascade and provisional contextual-fixture comparison; final remains unscored |
| [Evaluation](README.Evaluation.md) | Datasets, experiments and metrics |
| [Regex evaluation results](README.Regex-evaluation-results.md) | Existing evaluation report |
| [Host Python evaluation and tests](../evaluation/README.md) | Localhost test invocation, controlled update experiments and raw run manifests |
| [Research completion plan](Research-completion-plan.md) | Research questions, experiments, milestones and publication readiness |
| [Research paper writing guide](Research-paper-writing-guide.md) | Methodology improvements, wording, evidence reporting and venue requirements |
| [Current research evidence](../paper/research/claims.md) | Provisional claims, measured development results, protocol and professor review requests |
