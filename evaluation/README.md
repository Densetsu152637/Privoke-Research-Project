# PriVoke Evaluation

This folder evaluates whether PriVoke detects privacy-sensitive information. It sends every selected dataset prompt to the existing client-runtime `/analyze` API, so the tested system is the complete regex/rules + NER + selected LLM pipeline.

The evaluator does not import runtime modules, train another classifier, use SMOTE, or use the fuzzer.

```text
dataset prompt
  -> POST http://127.0.0.1:8765/analyze
  -> regex/rules + NER + selected LLM backend
  -> privacy classification and ALLOW/WARN/BLOCK action
  -> score the privacy classification only
```

## What counts as detected?

```text
PriVoke returns S1, S2, or S3, or any privacy category -> detected sensitive
PriVoke returns S0 with no privacy categories           -> not detected
```

This matches the client runtime's `Classification.is_sensitive()` rule. `ALLOW`, `WARN`, and `BLOCK` are saved for diagnosis but do not decide the detection score.

For binary ground truth:

```text
Valid PII annotation -> actually sensitive
No PII annotation    -> actually non-sensitive
```

This is prompt-level detection. It does not measure exact span extraction, category-name agreement, masking quality, or action quality.

### Ground-truth limitation

The datasets label PII spans. They do not reliably state whether every date, city, organization, or name is harmful in its particular context. The evaluator does not remove categories that PriVoke misses, because changing ground truth to agree with the detector would unfairly increase its score.

Use `prompt_detection_recall_by_source_category` in the JSON report to see which source labels occur in prompts PriVoke catches or misses. This is still prompt-level: if a prompt contains several labels and PriVoke detects the prompt, every source label on that prompt is counted as caught.

### Runtime API limitation

`/analyze` returns the classification selected by the client-runtime pipeline, not every raw result separately produced by regex, NER, and the LLM. An internal result that remains at `ALLOW` level may not be exposed. The evaluator measures the strongest action-independent detection signal available from the existing API, without changing the runtime.

## Setup after the root README

First complete the Docker setup in the project root `README.md`. Keep the root stack running so the model-streaming service remains available on port `50051`.

### Terminal 1: start the existing client runtime

From the repository root:

```bash
source evaluation/.venv/bin/activate
cd extension/client-runtime

MODEL_STREAMING_TARGET=localhost:50051 \
python src/main.py \
  --host 127.0.0.1 \
  --port 8765 \
  --llm-choice streamed
```

Keep this terminal running.

### Terminal 2: check and run evaluation

From the repository root:

```bash
curl http://127.0.0.1:8765/health
```

Continue when the response contains `"status": "SERVING"`.

Then:

```bash
source evaluation/.venv/bin/activate
cd evaluation

python evaluate.py \
  --dataset piimb \
  --samples 500 \
  --sampling balanced \
  --english-only \
  --seed 42 \
  --bootstrap-iterations 2000 \
  --run-name english_balanced_seed42 \
  --backend streamed
```

This is the recommended English-only main experiment.

### One-time Python setup

Only run this if `evaluation/.venv` does not exist or packages are missing:

```bash
python3 -m venv evaluation/.venv
source evaluation/.venv/bin/activate
pip install -r evaluation/requirements.txt
pip install -r extension/client-runtime/requirements.txt
```

The runtime dependencies are needed to run `extension/client-runtime/src/main.py`. The evaluator still communicates with it only through HTTP.

## English-only evaluation

Add `--english-only` to filter before duplicate removal, class counting, balancing, and random sampling.

```bash
python evaluate.py \
  --dataset piimb \
  --samples 500 \
  --sampling balanced \
  --english-only \
  --seed 42 \
  --backend streamed
```

Dataset behavior:

| Dataset | English-only behavior |
|---|---|
| PIIMB | Keeps rows whose language is `en`. |
| AI4Privacy | Keeps rows labelled `English`. |
| Gretel Finance | Keeps rows labelled `English`. |
| Nemotron-PII | Keeps the dataset because its official dataset definition is English-only; it has locale rather than per-row language. |
| Meddies PII | Already uses the published `english` configuration. |
| `local-jsonl` | Keeps rows whose metadata contains `"language": "en"` or `"English"`; rows without a language are excluded. |

The report records `metadata.language_filter` and `metadata.sampling.exclusions.non_english_language_rows`. State clearly in the paper that these results apply to English prompts only.

Without `--english-only`, all available languages are eligible.

The pinned live-data check found 107,488 eligible English PIIMB rows, 7,037 eligible English AI4Privacy positive rows, and 2,760 eligible English Gretel positive rows after validation, duplicate handling, and the positive-only rules. Nemotron and the selected Meddies configuration are already English.

## Recommended experiments

### Connection test

```bash
python evaluate.py --dataset piimb --samples 20 --sampling sequential --english-only --backend streamed
```

Use this only to check the setup. It is too small for a paper result.

### Main binary experiment

```bash
python evaluate.py --dataset piimb --samples 500 --sampling balanced --english-only --seed 42 --bootstrap-iterations 2000 --run-name english_balanced_seed42 --backend streamed
```

This selects 250 sensitive and 250 non-sensitive English prompts when enough rows exist. It does not duplicate, modify, or synthesize prompts.

### Supporting positive-only experiments

```bash
python evaluate.py --dataset ai4privacy --samples 500 --sampling random --english-only --seed 42 --bootstrap-iterations 2000 --run-name english_recall_seed42 --backend streamed
python evaluate.py --dataset nemotron-pii --samples 500 --sampling random --english-only --seed 42 --bootstrap-iterations 2000 --run-name english_recall_seed42 --backend streamed
python evaluate.py --dataset gretel-finance --samples 500 --sampling random --english-only --seed 42 --bootstrap-iterations 2000 --run-name english_recall_seed42 --backend streamed
python evaluate.py --dataset meddies-pii --samples 500 --sampling random --english-only --seed 42 --bootstrap-iterations 2000 --run-name english_recall_seed42 --backend streamed
```

### Why these four datasets are positive-only

AI4Privacy, Nemotron, Gretel, and Meddies were mainly created for finding or masking PII inside text. Their labels work like this:

```text
At least one PII label -> we know the prompt contains PII
No PII label          -> we do not know for certain that the whole prompt is clean
```

A missing label can mean the row is genuinely clean, but it can also mean that the dataset did not label every privacy concern PriVoke understands. If we automatically called every empty row clean, a correct PriVoke detection could be counted as a false positive.

The evaluator therefore uses the reliable part of the ground truth:

- rows with explicit PII labels are included as sensitive prompts;
- rows without verified PII labels are excluded and counted in the report;
- recall shows how many labelled-sensitive prompts PriVoke detected;
- miss rate shows how many labelled-sensitive prompts PriVoke missed;
- clean-prompt metrics are `null` because these datasets have no trusted clean comparison class.

This does not mean the excluded rows are sensitive. It means their negative label is not strong enough for a fair binary score. These four datasets are supporting recall tests. PIIMB is the main dataset for testing both sensitive and non-sensitive detection.

Do not average different datasets into one score. Some share source material, and each tests different text and PII distributions.

## Command options

| Option | Simple meaning |
|---|---|
| `--dataset piimb` | Choose the dataset. Replace `piimb` with another listed dataset name. |
| `--samples 500` | Test 500 prompts. |
| `--samples all` | Test every usable prompt. This can take a long time. |
| `--sampling balanced` | Choose the same number of sensitive and non-sensitive prompts. Use for PIIMB. |
| `--sampling random` | Randomly choose prompts. Use for the four positive-only datasets. |
| `--sampling stratified` | Choose a smaller sample while keeping the original sensitive/clean ratio. |
| `--sampling sequential` | Use the first prompts found. Use only for a quick setup check. |
| `--english-only` | Remove non-English prompts before selecting the sample. |
| `--seed 42` | Make random selection repeatable. The same command and seed choose the same prompts. |
| `--bootstrap-iterations 2000` | Estimate score uncertainty. Keep `2000` for paper results; use `0` only for quick testing. |
| `--run-name my_run` | Add `my_run` to the result filename so runs do not overwrite each other. |
| `--backend streamed` | Use PriVoke's model-streaming backend. |
| `--backend openai` | Use PriVoke's OpenAI backend. This may cost money. |

For example:

```bash
python evaluate.py --dataset piimb --samples 500 --sampling balanced --english-only --seed 42 --backend streamed
```

means: test 500 English PIIMB prompts, choose equal sensitive and clean counts, make the selection repeatable with seed 42, and send the prompts through the streamed PriVoke pipeline.

## Retained datasets

| Dataset | Supported use |
|---|---|
| [`piimb`](https://huggingface.co/datasets/piimb/pii-masking-benchmark) | Main binary sensitive/non-sensitive sentence benchmark. |
| [`ai4privacy`](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) | Supporting positive-only general PII recall. |
| [`nemotron-pii`](https://huggingface.co/datasets/nvidia/Nemotron-PII) | Supporting positive-only English PII/PHI recall. |
| [`gretel-finance`](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) | Supporting positive-only financial PII recall. |
| [`meddies-pii`](https://huggingface.co/datasets/Meddies/meddies-pii) | Supporting positive-only English healthcare PII recall. It uses an English training split, which must be reported as a limitation. |
| `local-jsonl` | Optional binary benchmark with explicit user-provided labels. |

Public datasets are pinned to fixed Hugging Face commits. Each result records `metadata.dataset_revision` and Python/library versions so a paper run can be reproduced.

## Metrics

For PIIMB, look first at balanced accuracy, sensitive recall, and non-sensitive specificity. F1 and F2 are supporting summaries.

For positive-only datasets, only sensitive recall and miss rate are supported.

| Metric or field | Meaning |
|---|---|
| Balanced accuracy | Average of recall and specificity. It gives sensitive and non-sensitive prompts equal importance and is the main binary score. |
| Sensitive recall | Percentage of sensitive prompts PriVoke detected. Higher is better. |
| Miss rate / false-negative rate | Percentage of sensitive prompts PriVoke missed. It equals `1 - recall`. Lower is better. |
| Non-sensitive specificity | Percentage of non-sensitive prompts PriVoke correctly did not detect. Higher is better. |
| False-positive rate | Percentage of non-sensitive prompts incorrectly detected as sensitive. It equals `1 - specificity`. Lower is better. |
| Precision | Of all prompts detected as sensitive, the percentage actually labelled sensitive. |
| Negative predictive value | Of all prompts not detected, the percentage actually labelled non-sensitive. It depends on class balance. |
| F1 | Combines precision and recall with equal weight. |
| F2 | Combines precision and recall while giving recall more weight. This is useful when missed PII matters more than extra detections. |
| Accuracy | Percentage of all predictions that were correct. It is saved but is not the main score because imbalance can make it misleading. |
| Ground-truth sensitive rate | Percentage of evaluated prompts labelled sensitive. This shows the evaluated class balance. |
| Predicted sensitive rate | Percentage of evaluated prompts PriVoke classified as sensitive. A large difference from the ground-truth rate can reveal over- or under-detection. |
| Prompt detection recall by source category | Prompt-level recall grouped by dataset source labels. It does not prove exact category or span detection. |
| Successful-analysis coverage | Percentage of selected prompts that received a valid runtime response. A paper run should have 100% coverage. |
| Runtime error rate | Percentage of requests that failed. A run with errors is marked unsuitable for paper reporting. |
| 95% confidence interval | Uncertainty range around a sample score. It is not another performance score. Narrower is more precise. |

### TP, TN, FP, and FN

| Count | Meaning |
|---|---|
| True positive (`TP`) | Sensitive prompt detected correctly. |
| False negative (`FN`) | Sensitive prompt not detected. |
| True negative (`TN`) | Non-sensitive prompt correctly not detected. |
| False positive (`FP`) | Non-sensitive prompt incorrectly detected as sensitive. |

Example:

```text
TP = 36, FN = 14 -> recall = 36/50 = 72%
TN = 40, FP = 10 -> specificity = 40/50 = 80%
Balanced accuracy = (72% + 80%) / 2 = 76%
```

`76% (95% CI 67%-84%)` means the measured score is 76%, with an estimated uncertainty range of 67% to 84%. Keep the default 2,000 bootstrap iterations for reported experiments. The evaluator uses Wilson intervals for simple rates such as recall and specificity, so even an observed 100% score retains honest uncertainty. It uses source-document bootstrap groups for related PIIMB sentences and bootstrap intervals for composite scores such as balanced accuracy and F-scores.

`evaluated_samples` counts valid predictions. Runtime failures are recorded separately as `runtime_errors`, `sensitive_runtime_errors`, and `non_sensitive_runtime_errors`. `paper_result_valid` is true only when runtime errors are zero.

`metadata.prediction_diagnostics` records returned sensitivity, category, and action counts. These are debugging distributions rather than additional performance scores. They help explain results such as 100% recall by showing what PriVoke actually returned across successful prompts.

## Handling class imbalance

Class imbalance means one class has many more prompts than the other. For example:

```text
950 sensitive prompts
 50 clean prompts
```

A detector that always says “sensitive” would have 95% ordinary accuracy on that dataset, even though it never identifies a clean prompt correctly.

We handle this without changing or retraining PriVoke:

1. The main PIIMB command uses `--sampling balanced`, selecting equal sensitive and non-sensitive counts.
2. Balanced accuracy gives sensitive recall and clean specificity equal importance.
3. Recall and specificity are also shown separately, so good performance on one class cannot hide poor performance on the other.
4. The report saves both the original and selected class counts, making the sampling visible.
5. A full-dataset run can be reported separately to show performance under the original class distribution.

Balanced sampling does not create, duplicate, or rewrite prompts. It only selects the same number from each class.

## OpenAI backend

The OpenAI key belongs to the running client runtime, not the evaluator.

```bash
curl http://127.0.0.1:8765/config/llm
```

If OpenAI does not show `"api_key_configured": true`:

```bash
export OPENAI_API_KEY='PASTE_YOUR_KEY_HERE'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H 'Content-Type: application/json' \
  -d "{\"choice\":\"openai\",\"openai\":{\"api_key\":\"$OPENAI_API_KEY\",\"model\":\"gpt-4o-mini\"}}"

unset OPENAI_API_KEY
```

Test with a small run first:

```bash
python evaluate.py --dataset piimb --samples 20 --sampling sequential --english-only --backend openai
```

Use identical dataset, sample count, sampling, language filter, and seed when comparing streamed and OpenAI.

## Automatic data checks

The evaluator:

- validates labels, PII span types, category names, and character offsets;
- excludes malformed public-source rows and records their counts;
- excludes unverified empty annotations from positive-only datasets;
- filters language before duplicate removal and sampling;
- normalizes outer whitespace exactly as `/analyze` does;
- removes duplicate effective prompts;
- excludes public prompts with conflicting duplicate labels;
- pins public dataset revisions;
- records selected IDs, source-document groups, exclusions, class counts, seed, and a selection digest;
- validates runtime classification values before scoring;
- reports errors rather than treating them as predictions;
- records software versions and category-grouped prompt recall.

These checks prevent known loading and scoring loopholes. They cannot prove that every published annotation is contextually perfect.

## Results and tests

Results are saved as:

```text
results/<dataset>_pipeline_<backend>_<run-name>_results.json
```

Run tests from the repository root:

```bash
PYTHONPATH=evaluation evaluation/.venv/bin/python -m unittest discover -s evaluation/tests -v
```

Keep the `tests/` folder in the repository. It is not loaded during an evaluation run, but it verifies dataset schemas, language filtering, sampling, duplicate handling, metric calculations, runtime-response validation, and report generation. This is important evidence that changes to the evaluator have not silently changed the research results.

The `results/` folder contains generated experiment output rather than source code. Keep results needed for the paper locally or archive them with the paper artifacts; new JSON reports are ignored by Git to prevent accidental commits.
