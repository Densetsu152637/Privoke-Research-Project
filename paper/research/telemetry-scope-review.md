# Telemetry privacy scope review

Reviewed 4 October 2026 against source `d1e7e3ca77eaef9101907e9082fee3bc0dcbf766`. This is a provisional implementation and mathematical review for claim C7, pending professor review. It changes no runtime, model, calibration, protocol or manuscript source. No deployment, collector, ledger, prompt corpus or final partition was accessed.

The defensible claim is that the **nominal five-field local randomizer** satisfies pure event-tuple epsilon-LDP under the assumptions below. This does not establish epsilon-LDP for the entire observable reporting transcript, anonymity, user-level privacy, useful monitoring accuracy, or private model training. The existing manuscript already excludes report presence and transport metadata; its wording should also name the fixed-report/public-configuration and finite-precision boundaries.

## Implemented mechanism and mathematical argument

`privacy.py:15–29` fixes the dimensions and domains. Before randomization, `event_emitter.py:35–60,161–205` derives a deterministic tuple from an analysis: action; a risk bucket derived from action/sensitivity rather than a calibrated model score; one primary category selected by fixed precedence; a model release stripped at `+train.` and mapped to `OTHER` if unknown; and the current UTC four-hour bin without date. The category precedence is a reporting convention, not a contextual severity ranking.

| Dimension | Public domain | K | Nominal p at event epsilon=1 | Nominal q for each alternative |
| --- | --- | ---: | ---: | ---: |
| action | ALLOW, WARN, BLOCK | 3 | 0.379152453 | 0.310423773 |
| risk_bucket | four fixed numeric intervals | 4 | 0.289335756 | 0.236888081 |
| primary_category | NONE and ten categories | 11 | 0.108845818 | 0.089115418 |
| model_version | v0.3.0, OTHER | 2 | 0.549833997 | 0.450166003 |
| time_bucket | six UTC four-hour bins | 6 | 0.196322727 | 0.160735455 |

Let the event tuple be x in the product of the five domains, and let public event epsilon be E. Each coordinate i receives epsilon_i=E/5. The nominal GRR kernel is

\[
P_i(y\mid x_i)=\begin{cases}p_i=e^{E/5}/(e^{E/5}+K_i-1),&y=x_i,\\q_i=1/(e^{E/5}+K_i-1),&y\ne x_i.\end{cases}
\]

For every two coordinate inputs a,b and output y, the likelihood ratio is one of 1, p_i/q_i or q_i/p_i, and is at most exp(E/5). All probabilities are positive. With independent random draws, for any tuples x,x' and output tuple y,

\[
\frac{P(M(x)=y)}{P(M(x')=y)}=\prod_{i=1}^5\frac{P_i(y_i\mid x_i)}{P_i(y_i\mid x'_i)}\le e^{\sum_i E/5}=e^E.
\]

Summing over any output event yields the same bound, with delta=0. Correlated true fields do not invalidate this argument: independence is required of the randomization draws, not of the input coordinates. The argument applies to any fixed deterministic mapping from an analyzed prompt to the five-field tuple, but does not assert confidentiality for prompt transmission to other services. Basic composition and post-processing are established in [Dwork and Roth, *The Algorithmic Foundations of Differential Privacy* (2014), Corollary 3.15, Proposition 2.1 and Definition 12.1](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf). The displayed GRR proof is derived here for the actual domain sizes.

The scope assumptions are: public fixed domains and a common public E for compared inputs; a trusted unmodified emitter; fresh independent draws with the nominal GRR law; and comparison of tuple values at an externally fixed reporting opportunity. A fixed common report schedule and public epsilon sequence permit composition over reports. Merely conditioning an arbitrary data-dependent observable transcript on “a report was sent” does not prove this kernel bound. If output-dependent selection, delivery or loss changes the distribution among delivered packets, that distribution needs its own argument.

## Daily accounting and transcript boundary

`privacy.py:15–20,32–46` defaults E to 1, supports 0.5 through 2, and defaults the daily budget B to 8 with E<=B<=8. `DailyPrivacyBudget.reserve`, lines 131–194, checks integrity, starts `BEGIN IMMEDIATE`, retains one UTC-day/spend row, rejects backward calendar dates and reserves before returning. `event_emitter.py:99–116` reserves before building/randomizing and enqueueing, with no refund for failed build, queue overflow or failed submission. Consequently a retained, correctly configured ledger bounds the nominal sum of reserved epsilon by B (subject to the implementation's arithmetic tolerance), conservatively including unsent reports. With E=1,B=8 there are at most eight reservations; E=0.5 permits sixteen and E=2 permits four. For variable approved E_j the bound is the sum of E_j, not a universal eight-packet cap.

This is an installation-local calendar-day accounting bound, not an identity-based user guarantee or a rolling 24-hour bound. Several installations, devices or days compose separately. Two adjacent UTC days can each spend B. Ledger deletion/replacement, reinstall without state retention, forward clock jumps, independently configured ledgers and hostile client changes are excluded. Backward-date rejection does not establish secure time; the trusted system clock and persistent ledger remain assumptions. The epsilon-configuration precision checks and spend comparisons use floating arithmetic and tolerances; they are not exact-arithmetic formal verification.

`grpc_server.py:60–92` reports after a successfully constructed analysis response when a reporter exists; request errors can produce a response without that report. Reporting enablement, workload, budget exhaustion, local processing failure, queue pressure and delivery failure determine which reports appear. Selection can depend on workload or analysis conditions. No report-presence randomizer or cover-traffic schedule is implemented. The emitter's background sender avoids waiting for network delivery, but synchronous budget reservation still runs before the RPC returns; this review does not certify zero telemetry overhead.

Declared packet fields exclude raw prompts, direct user/event/request identifiers, app names, exact scores, exact timestamps and per-layer results (`telemetry.proto:12–21`). The packet includes the unrandomized mechanism marker and epsilon, so their configuration must be public and input-independent for the stated comparison. This schema claim concerns the official emitter; it is not a claim that an arbitrary malicious client's protobuf or network traffic cannot contain other information. Report existence, count, length, arrival time, source IP and transport identifiers remain outside the guarantee. In particular, comparing a no-event history with an event history can yield an observable report with probability zero versus nonzero, so finite pure-LDP protection of presence does not follow.

## Collector and estimator scope

`validation.py:25–41` checks marker, supported finite epsilon and fixed-domain membership. It cannot infer whether values were randomized, whether a local ledger exists, or whether a client exceeded its budget. It neither attests the official binary nor implements a per-person bound. A syntactically valid deterministic or adversarial packet can pass validation; this is a trust assumption, not proof of compliant clients.

`storage.py:12–28,63–85` stores epsilon-stratified marginal counts rather than rows containing individual report tuples. This reduces retained linkage but the receiver necessarily sees packets during ingestion; transport and operational logs are separate surfaces. `server.py:36–49` validates and stores without a randomization verifier. `telemetry.proto:43–47` explicitly returns the exact accepted report count. Counts and noisy marginals can change between summary queries; the API does not hide arrival/presence.

For value v in a fixed stratum of n independent compliant reports, let t_v denote the true count and O_v the noisy count. Then

\[
\mathbb E[O_v]=nq+(p-q)t_v,\quad \widehat t_v=(O_v-nq)/(p-q),\quad
\operatorname{Var}(\widehat t_v)=\frac{t_vp(1-p)+(n-t_v)q(1-q)}{(p-q)^2}.
\]

The untruncated estimator is unbiased under those assumptions. These expectations target the contributing reports, not all prompts/users: report selection, per-installation caps, failures and hostile clients can induce additional sampling bias. `storage.py:105–134` corrects each epsilon stratum, sums estimates and clips each value to [0,n_total]. Clipping is post-processing of reports but generally biases estimates; independently clipped category counts need not sum to n_total. Public stratum metadata and a fixed schedule are part of the privacy argument. Exact sample count does not become private through post-processing.

At E=1 the category gap p-q is about 0.019730399, so inversion amplifies noisy-count errors by about 50.68. This is an algebraic sensitivity observation, not a measured deployment error, sample-size recommendation, confidence interval or utility result. No user-scale accuracy, longitudinal monitoring, attack/re-identification experiment, hostile-client resistance, real reporting-loss study, finite-sampler audit or multi-device accounting measurement was performed here. Telemetry is not connected to fuzzer examples, parameter gradients or federated learning; no training-privacy claim follows.

## Numerical implementation and existing evidence

`privacy.py:62–106` computes probabilities using binary floating-point `math.exp`; `SystemRandom.random()` and `choice()` implement finite randomness. The ideal formula proves the nominal kernel. The actual finite-precision acceptance probability and alternative-selection distribution require a separate implementation-level analysis to certify an exact E,delta=0 bound. Positivity over small domains alone is insufficient to establish that the maximum actual ratio is exactly exp(E). The existing float tests allow tolerance and do not certify random-bit generation, independence or exact deployed likelihood ratios. This is a qualification of the mathematical claim, not a discovered catastrophic privacy breach or authorization to change the frozen runtime.

The reviewed client tests cover probability formulas/all coordinate input-output pairs, one joint composition enumeration, sampler threshold branches, malformed configurations, stable ledger location, reopening/UTC rollover, clock rollback, corruption/unavailable paths, concurrent reservations, packet fields/mapping, budget suppression and no refund after failed build (`test_telemetry_privacy.py:49–338`). Collector tests cover aggregate schema, stratum-specific inverse correction/clipping, synthetic loopback gRPC, domain/epsilon validation and legacy rejection (`test_security_validation.py:40–190`). These are bounded mechanism/regression tests; their existence is not a new passing deployment run. C7 already records utility as unmeasured. This assignment did not rerun these component suites because generated protobuf/grpc dependencies are unavailable on the host and no Docker was authorized.

The standalone [nominal math check](../../evaluation/analysis/verify-telemetry-privacy-math.py) reads only source-domain constants via AST, without importing runtime modules, opening ledgers or calling services. A host run using Python 3.13 passed 70-digit Decimal checks at E=0.5,1,2, normalized all fields, enumerated all ordered coordinate input/output triples and verified the product maximum log ratio equals E within 1e-65. This is numerical corroboration of the symbolic proof, not exact transcendental arithmetic or a sampler/utility certificate. Command: `python evaluation/analysis/verify-telemetry-privacy-math.py`.

## Proposed manuscript wording

For `main.tex:167`, replace the unconditional mechanism sentence with:

> The official client applies generalized randomized response independently to five fixed-domain categorical fields, using a public event budget epsilon=1 by default (configurable 0.5–2), divided equally across fields. For a fixed reporting opportunity, the nominal mechanism has pure epsilon-local differential privacy (delta=0) for the released tuple. This mathematical guarantee assumes compliant client execution and ideal random sampling; the implementation uses floating-point probabilities and finite randomness, whose exact privacy loss has not been certified.

Follow with:

> A retained installation-local ledger reserves budget before packet construction and caps the nominal cumulative expenditure at epsilon=8 per UTC day by default. This accounting bound assumes retained state and a trusted clock. It does not identify a user across installations. Neither the guarantee nor aggregate storage hides report presence, exact accepted counts, data-dependent selection or delivery, or network metadata. The collector validates declared fields and epsilon but cannot verify client randomization. Inverse-response marginal estimates are clipped, which can introduce bias; monitoring utility and reporting-selection effects remain unmeasured.

For the abstract/contribution (`main.tex:45,72`), use “locally randomized categorical telemetry for aggregate monitoring, with a conditional event-tuple privacy guarantee.” Avoid suggesting absence of direct identifiers implies anonymity. For C7 (`claims.md:22`), retain the qualified claim and add the fixed-report/public-configuration and nominal-sampler qualifications. This document proposes wording only; manuscript/claim edits remain with the integration owner. Professor review and a finite-randomness audit remain outstanding before a stronger guarantee.

## Stable source evidence ledger

Line locators refer to the reviewed Git revision. SHA256 values below hash UTF-8 source bytes with CRLF normalized to LF, without other changes; this permits reproducible Windows/Linux source comparison. They are source hashes, not deployment image or test-result hashes.

| Path | Canonical-LF SHA256 |
| --- | --- |
| extension/client-runtime/src/telemetry/privacy.py | fa3aea9bf534a3041acecdedba78eae3ad8df55acf684c3ef35dbf6f433d53d4 |
| extension/client-runtime/src/telemetry/event_emitter.py | 328be76b6a4787caeff513f8e06e2420c37d6a3dfe7a8e33b3a7bc66d6ea0e5e |
| shared/proto/privoke/v1/telemetry.proto | d3815e6a8993ec769c864c8e2c81f9c7a30ae33dcf7695a35afa607af444585c |
| services/telemetry-service/app/validation.py | e10baa292462bdab4a07a0439d720bd46d7a54ebda18a438394057d8f16c10da |
| services/telemetry-service/app/storage.py | 441d3bddba3fddc5f2ad732869143964972b3ee675ca29a317d23bf8570a2f0a |
| services/telemetry-service/app/server.py | c89a48eb39a02517ef4df2e0825fd87db4ec7bfe9cacbcf61995db8f75a89e89 |
| extension/client-runtime/test/test_telemetry_privacy.py | d8396bd2c0590c2e5f0b5528db9ff030c93e1fa72716f2e58e842401e796aa00 |
| services/telemetry-service/tests/test_security_validation.py | 4502e7e8bb0e1e6a8f37d7e24d5a10bf76ca88e306904ffe6601a4e398eb5c8c |
| extension/client-runtime/src/hosting/grpc_server.py | 7b977d53cf564ee0ab4783f09fe93c5b927b345c106900bf51823132414e9220 |
| paper/main.tex | a388016a11cd401d84d062727d412a61cb28ec793eec87ad46f16467ed42cc0f |
| paper/research/claims.md | 88f841f380a1143bc4552004baba5b24abdf4732bb6151f4ddd9bde464691314 |
