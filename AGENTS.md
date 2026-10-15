# Custom workflow

Read [AGENT-INSTRUCTIONS](C:/Users/Nicholas/.codex/custom-workflow/AGENTS.md) and assume its configuration.

Resolve companion links relative to the instruction file that contains them.

# LLM layer testing

LLM-layer training, evaluation and testing must isolate the semantic layer. Send an explicit semantic-only layer selection and assert the actual returned layer execution. Never send an empty protobuf layer list: the runtime interprets it as the complete detector pipeline.

Run regex, NER or the full pipeline only for an explicitly requested product end-to-end task or detector ablation. Keep that purpose and its results separate from LLM-only results. Historical combined-detector scores remain historical full-pipeline measurements and must not be presented as LLM-only evidence.

Legacy combined-protocol study commands refuse execution unless `--allow-product-pipeline` explicitly selects that separately authorized product/detector-analysis scope. Do not use this flag for LLM-only testing or reinterpret their historical pipeline selection rules as semantic-only results.

# Host Python test workflow

Run raw Python tests, evaluation clients, dataset loops, and study scoring in the
host Python environment. Docker Compose may host model streaming, runtime, fuzzer,
and updater servers on loopback ports; do not use `docker compose run` or a test
driver container to execute Python test cases. Use `evaluation/setup-host.py` to
generate host protobuf clients with the maintained host environment, then invoke
the relevant host test script. The TW01 synthetic mechanics command is
`evaluation/.venv/Scripts/python.exe -m unittest discover -s evaluation/tests -p test_task_query_window_study.py`.
TW01 component-reference preparation and post-fit evidence audit also require
NumPy on the host. This checkout has `evaluation/.venv-fuzzer-study` with Python
3.11 and NumPy for those phases; use the same compatible host environment for
the TW01 fit controller. The broader NumPy/Torch suites require their own
supported Python 3.11/3.12 dependencies; report them unavailable if missing.

Retain reusable temporary model weights and their provenance metadata under
`models/experiments/<run>/`. Keep per-cell initial catalogs, effective artifacts,
and independently pinned ORIGINAL weights there. Remove only disposable temporary
copies after byte hashes and references are verified; preserve immutable evidence
and failed-attempt records. Generated experiment weights are local and ignored by
Git and Docker build context.
