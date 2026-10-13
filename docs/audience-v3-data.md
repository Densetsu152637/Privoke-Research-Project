# Audience coverage data and automatic training

Normal automatic contextual requests now use the pinned `audience_coverage_v1`
release shipped in `services/privoke-fuzzer/data`. The updater still requests its
existing head stage followed by its full Tiny stage. With no custom legacy
dataset/curriculum or explicit strategy, `FuzzerConfig.from_env` selects AU3;
both stages resolve and fingerprint that source before replay or reservation.
The fuzzer Dockerfile already copies the service data directory. No held-out
authoring catalog is copied into that image.

Each supported cycle requests a multiple of 32 originals. Each 32-row block has
24 new audience contrasts (four per audience, including actual, clean and mild
cases) and eight unchanged PH3 TRAIN rehearsal rows. Its 12 actual category
slots cover all ten primary categories. Selection is seeded and distinct within
the cycle; a new seed does not guarantee novel cases. One maintained invariant
transformation gives 64 exposures per block, which may include repeated text.
Actual selected IDs, audience/expression counts, source pins and transformed
exposure counts accompany training evidence. The separate fixed 16-row guard
is an exact subset of the new validation release, with eight sensitive and eight
clean labels. It is a regression guard, not an independent test.
Full IDs and source provenance stay in durable `execution_evidence.audience_audit`;
publication metadata carries their digest and compact counts under the unchanged
updater limits. A ten-file sampler/renderer/transform/service implementation
closure is bound before receipt lookup, so changing code cannot replay a cycle
reserved under different generation semantics.

`FUZZ_CONTEXTUAL_SAMPLING_STRATEGY=legacy_random_v1` explicitly restores the
legacy random route. An explicit `FUZZ_PROMPT_DATASET_PATH` or
`FUZZ_CURRICULUM_MANIFEST_PATH`, without an explicit strategy, retains that
legacy source. Existing named taxonomy/benign/rehearsal/window requests retain
their own fixed contracts. Custom AU3 releases require both
`FUZZ_AUDIENCE_MANIFEST_PATH` and `FUZZ_AUDIENCE_MANIFEST_SHA256`; unavailable,
changed or partial pins fail instead of falling back. These are fuzzer-process
environment variables; Compose overrides must put them in the fuzzer service's
`environment`, rather than assuming a shell variable is forwarded automatically.

The experimental v3 study keeps its frozen BC01 source by default. The separate
`evaluation/compose.pretrained-v3-audience.yml` override selects
`V3_SAMPLING_STRATEGY=audience_common_frozen_stream_v1`. The same pinned TRAIN
sampler supplies its batches; runtime and checkpoint admission reconstruct the
exact source wires, provenance sidecars, transformations and guards. Its image
copies only the runtime data directory. Custom v3 releases require the matching
`V3_AUDIENCE_MANIFEST_PATH`/`V3_AUDIENCE_MANIFEST_SHA256` in every admitting
process, with the same read-only release mount. Old BC01 evidence and defaults
remain separate.

The AU3 study data builder is `evaluation/prepare-audience-v3.py`; its host API is
`privoke_eval.audience_v3_data`. TRAIN contains byte-identical PH3 rehearsal
6,240 rows and 3,120 additions, all at unit weight. New validation and fresh
evaluation each contain 1,560 rows. The new catalogs provide eight TRAIN and
four validation/fresh audience expressions per class. Categories, S0–S3 and
multilabel assertions remain supervised. P4 explicitly means self-only and
unshared, P3 means an actual closed group, and PU means audience information is
absent or unknown. Quoted clean controls explicitly use fabricated statements
with no actual referent; quotation alone never makes real disclosure clean.
Actual multi-fact variants retain all asserted domains. Their clean counterparts
remove actuality, and may quote only the primary synthetic fact; they are not
all exact fact-for-fact contrast pairs.

All three native v3 configurations have a 512-token positional capacity.
Tokenizer-only admission checks actual configured caps without truncation.
The admitted R3 source gives maximum WordPiece lengths 62/73/73 for
TRAIN/validation/fresh in every tier. The normal Tiny training stream reaches
56 tokens before augmentation and 61 with the review prefix; its fixed guard
reaches 52, within the checked 64-token limit. Fresh data are v3-only: three
fresh originals exceed Tiny64, with a maximum of 67. No Tiny fresh comparison
is implied.

Authoring and review use no model predictions. R1/R2 failed candidates and
predicate repairs remain retained. Labels are assistant-provisional, with
independent assistant review rather than human annotation. Historical checks
cover declared IDs, normalized/transformed text, skeletons, assertion
components and mechanism identifiers, plus opaque protected-final commitments.
Bounded semantic review addresses concrete historical near-clones; hashes and
unique IDs do not prove universal semantic novelty. TRAIN intentionally revisits
some historical domain concepts with new audience contrasts. Scenario families
and audience expressions create crossed dependence among rows.

Fitting may read only TRAIN and new validation. Fresh loader authorization is
checked before file access, and its payload must remain unused by models until
all three fits, selected/terminal exports, native audits and the six-model seal
are fixed. Existing PH3/EN3 source closures, weights and records are retained;
changed live fuzzer sources require a new AU3 closure. The automatic network
pilot, full fits and fresh comparison are separate acceptance steps; unit tests
and data preparation do not establish those outcomes.
