# PriVoke Regex Layer Execution-Time Summary

> Source area: `evaluation/results`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This summary focuses on regex-layer execution time across two benchmark datasets.

Both benchmarks were run through the Docker `client-runtime` gRPC service. The runtime value comes from PriVoke's server-side `elapsed_ms`, so it measures the time spent inside the runtime analysis call for each prompt.

## How to read the timing values

All runtime values are in milliseconds.

`Average runtime across repeats` is still a per-prompt runtime. For each repeat, PriVoke evaluates 500 prompts and records the average `elapsed_ms` per prompt. The report then averages those three per-run averages.

For example, if one configuration has repeat averages of 1 ms, 2 ms, and 3 ms, the average runtime across repeats is 2 ms per prompt.

`Median run average` is the middle value of the three repeat averages. It is useful because Docker or gRPC can sometimes have one unusually slow run, and the median is less affected by that spike.

## What was compared

Four regex-layer configurations were tested:

1. Custom regex only
   - Rules loaded: 46

2. Custom regex + Presidio
   - Rules loaded: 89

3. Custom regex + Gitleaks
   - Rules loaded: 254

4. Custom regex + Presidio + Gitleaks
   - Rules loaded: 297

## Dataset 1: Personalized synthetic dataset

Dataset file:

```text
evaluation/datasets/privoke_personalized_synthetic.jsonl
```

Dataset description:

- Controlled synthetic PriVoke dataset
- 2000 total rows
- 1000 sensitive rows
- 1000 clean rows
- Includes structured fake PII such as names, emails, phone numbers, addresses, SSNs, student IDs, employee IDs, medical information, insurance IDs, account details, API keys, and password-style secrets

Example clean prompt:

```text
Can you help me draft a message to a landlord in a formal tone about asking about the benefits enrollment deadline after a missed update?
```

Example sensitive prompt:

```text
Make this tenant message clearer: I am Riley Singh at 4323 Maple Street, Boston, MA 02108, and you can call me at 771-555-1969.
```

Timing setup:

- 3 repeated runs per configuration
- 500 prompts per repeat
- 1500 prompt checks per configuration

### Execution-time results

Custom regex only:

- Average runtime across repeats: 1.745 ms
- Median run average: 0.625 ms

Custom regex + Presidio:

- Average runtime across repeats: 27.101 ms
- Median run average: 26.566 ms

Custom regex + Gitleaks:

- Average runtime across repeats: 21.504 ms
- Median run average: 22.73 ms

Custom regex + Presidio + Gitleaks:

- Average runtime across repeats: 41.784 ms
- Median run average: 40.965 ms

### Timing takeaway

On the controlled synthetic dataset, custom regex only was the fastest configuration.

Adding Gitleaks or Presidio increased execution time, and enabling both together produced the slowest runtime.

The controlled synthetic dataset is useful because the labels are reliable and balanced. It shows that the existing custom regex layer is already efficient on clean, structured PriVoke-style prompts.

## Dataset 2: Open-source Rotten Tomatoes text with fake PII injection

Dataset file:

```text
evaluation/datasets/privoke_open_source_injected_mixed.jsonl
```

Dataset description:

- Open-source Rotten Tomatoes review text
- Fake PII injected into half of the prompts
- 500 total rows
- 250 sensitive rows
- 250 clean rows
- Injected fake PII includes names, emails, phone numbers, addresses, dates of birth, employee IDs, passwords, API keys, and GitHub tokens
- This dataset is messier than the personalized synthetic dataset because the base text comes from natural movie-review language

Example clean prompt:

```text
rewrite this for me, keep the meaning: " the kid stays in the picture " is a great story , terrifically told by the man who wrote it but this cliff notes edition is a cheat .
```

Example sensitive prompt:

```text
can u clean this up pls: in his u . s . debut , mr . schnitzler proves himself a deft pace master and stylist . and include this detail: Sam Morgan lives at 1439 Sunset Boulevard, Seattle, WA 98101
```

Timing setup:

- 3 repeated runs per configuration
- 500 prompts per repeat
- 1500 prompt checks per configuration

### Execution-time results

Custom regex only:

- Average runtime across repeats: 2.113 ms
- Median run average: 0.835 ms

Custom regex + Presidio:

- Average runtime across repeats: 25.065 ms
- Median run average: 24.549 ms

Custom regex + Gitleaks:

- Average runtime across repeats: 18.628 ms
- Median run average: 18.34 ms

Custom regex + Presidio + Gitleaks:

- Average runtime across repeats: 46.525 ms
- Median run average: 46.117 ms

### Timing takeaway

On the messier open-source injected dataset, the same runtime pattern appeared.

Custom regex only remained the fastest. Gitleaks and Presidio added runtime overhead, and the combined configuration was the slowest.

This dataset is useful because it is closer to real user input. The review text is less template-like, and the fake PII is inserted into more natural, noisy prompts. This helps test execution time under more realistic prompt shapes.

## Overall timing conclusion

Across both datasets, the execution-time pattern was consistent:

1. Custom regex only was fastest.
2. Custom regex + Gitleaks was slower.
3. Custom regex + Presidio was slower.
4. Custom regex + Presidio + Gitleaks was slowest.

The timing results suggest that adding more external regex sources increases execution cost.

For execution-time efficiency, custom regex only is the best-performing configuration in these benchmarks.

## Short detection context

Detection quality was similar across configurations in both datasets, so the main observed difference was runtime.

This means the timing comparison is especially important: if larger rule sets do not improve the final detection result on these datasets, their additional runtime cost needs to be justified by targeted coverage benefits, such as detecting secrets or credentials.

The open-source injected dataset also exposed more false positives than the controlled synthetic dataset. On the 500-prompt injected benchmark, all configurations had recall of 1.0 and false-positive rate of 0.136. This means the regex layer detected all injected sensitive prompts, but incorrectly flagged 13.6% of clean Rotten Tomatoes based prompts.

This suggests that future regex-layer improvements should focus on reducing over-detection in natural language, not only adding more rules.

## Recommendation on rule sets

Based on these timing-focused benchmarks, custom regex only is the strongest default candidate for general PII detection because it was the fastest while producing the same detection quality as the larger configurations.

Presidio may still be useful for broader standard PII coverage, but these benchmarks did not show a detection improvement from enabling it. Since Presidio adds runtime overhead, its use should be justified by cases where it catches PII that the custom rules miss.

Gitleaks should be treated separately. It is mainly designed for secrets and credentials such as API keys, access tokens, cloud credentials, private keys, and database URLs. These benchmarks do not prove that Gitleaks is unnecessary; they show that Gitleaks did not improve the final result on the two tested datasets while adding runtime cost. To decide whether to keep Gitleaks enabled by default, it should be tested on a targeted secrets dataset.

## Final research interpretation

For these regex-layer benchmarks, the custom rule set provides the best runtime efficiency.

Presidio and Gitleaks may still be useful for broader coverage, but their value should be evaluated against targeted datasets where those external rules are expected to detect cases that custom regex does not already catch.

The main conclusion is not that external rules are bad. The conclusion is that more regex rules should only be added when they provide measurable coverage gains that justify their execution-time cost.
