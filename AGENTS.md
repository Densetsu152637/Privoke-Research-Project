# Custom workflow

Read [AGENT-INSTRUCTIONS](C:/Users/Nicholas/.codex/custom-workflow/AGENTS.md) and assume its configuration.

Resolve companion links relative to the instruction file that contains them.

# LLM layer testing

LLM-layer training, evaluation and testing must isolate the semantic layer. Send an explicit semantic-only layer selection and assert the actual returned layer execution. Never send an empty protobuf layer list: the runtime interprets it as the complete detector pipeline.

Run regex, NER or the full pipeline only for an explicitly requested product end-to-end task or detector ablation. Keep that purpose and its results separate from LLM-only results. Historical combined-detector scores remain historical full-pipeline measurements and must not be presented as LLM-only evidence.

Legacy combined-protocol study commands refuse execution unless `--allow-product-pipeline` explicitly selects that separately authorized product/detector-analysis scope. Do not use this flag for LLM-only testing or reinterpret their historical pipeline selection rules as semantic-only results.
