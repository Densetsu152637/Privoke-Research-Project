"""Prepare audited positive training sources without opening locked partitions."""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import random
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))
from privoke_model.training_data import training_text_key

PINS = {"nemotron-pii": ("nvidia/Nemotron-PII", "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed", "default", 100000),
        "meddies-pii": ("Meddies/meddies-pii", "6a5c8f5441e3b421d983c9741770262365acdd77", "english", 47744)}
PIIMB_PIN = "4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133"
LOADER_REVISION = "9998e8986c7924223ea4598cb1ba683e32ade0ba"
LOADER_SHA256 = "016a25a56b6fa3a9b8c16fcf9fde8a350c205101b26000cedd1095f097e15733"
REFERENCE = {"train": (3832, "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"),
             "validation": (968, "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1")}
CAPS = {"nemotron-pii": 13168, "meddies-pii": 3000}
HELDOUT_CAP = 1000


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value=None, *, raw=None):
    with Path(path).open("xb") as stream:
        stream.write(raw if raw is not None else (canonical(value) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def opaque(kind, value):
    return digest("privoke-external-exclusion-v1\0" + kind + "\0" + value)


def canonical_group(value, source=None):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing source grouping identity.")
    value = value.strip()
    match = re.fullmatch(r"(?:piimb:)?nemotron-pii:([0-9a-fA-F]{32})(?:_s\d+)?", value)
    if match:
        return "nemotron-pii:" + match[1].lower()
    if source == "nemotron-pii" and re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "nemotron-pii:" + value.lower()
    return value


def identity_aliases(identifier, group):
    aliases = {identifier}
    if re.fullmatch(r"(?:piimb:)?nemotron-pii:[0-9a-fA-F]{32}(?:_s\d+)?", identifier):
        aliases.add(canonical_group(identifier))
    aliases.add(canonical_group(group))
    return aliases


def row_keys(identifier, group, text):
    return {"ids": {opaque("id", x) for x in identity_aliases(identifier, group)},
            "groups": {opaque("group", canonical_group(group))},
            "texts": {opaque("text_key", training_text_key(text))}}


def merge_keys(target, incoming):
    for kind in target:
        target[kind].update(incoming[kind])


def empty_keys():
    return {"ids": set(), "groups": set(), "texts": set()}


def protected_index(spec, loaded):
    if (spec.revision != PIIMB_PIN or loaded.population_scan_complete is not True
            or loaded.rows_seen != 150022 or loaded.eligible_rows != 107488
            or loaded.duplicate_rows != 15354
            or loaded.population_label_counts != {"pii": 60418, "clean": 47070}
            or loaded.exclusions.get("conflicting_duplicate_label_rows") != 598
            or loaded.exclusions.get("non_english_language_rows") != 27180
            or loaded.selected_label_counts != {"pii": 500, "clean": 500}
            or loaded.sampling_seed != 3102026 or loaded.sampling_strategy != "balanced"
            or len(loaded.examples) != 1000):
        raise ValueError("Original protected PIIMB selection aggregates/order contract differ.")
    keys, records, identifiers = empty_keys(), [], set()
    for example in loaded.examples:
        identifier, group = example.metadata.get("example_id"), example.metadata.get("group_id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers or not isinstance(group, str) or not group:
            raise ValueError("Protected selection lacks unique stable IDs/groups.")
        identifiers.add(identifier)
        incoming = row_keys(identifier, group, example.text)
        merge_keys(keys, incoming)
        records.append({"id_sha256": opaque("id", identifier),
                        "canonical_group_sha256": opaque("group", canonical_group(group)),
                        "normalized_text_sha256": opaque("text_key", training_text_key(example.text)),
                        "text_sha256": digest(example.text)})
    records.sort(key=canonical)
    if len(keys["groups"]) != 929 or len(keys["texts"]) != 1000:
        raise ValueError("Protected selection group/text aggregate mismatch.")
    result = {"schema_version": 1, "records": records,
              "key_sets": {k: sorted(v) for k, v in keys.items()},
              "algorithm": "pinned PIIMB balanced full-scan reservoir and sampler order",
              "loader_revision": LOADER_REVISION, "loader_canonical_lf_sha256": LOADER_SHA256,
              "dataset_revision": PIIMB_PIN, "seed": 3102026,
              "aggregate": {"selected": 1000, "rows_seen": 150022, "eligible_rows": 107488,
                            "selected_label_counts": {"pii": 500, "clean": 500},
                            "duplicate_rows": loaded.duplicate_rows, "population_label_counts": loaded.population_label_counts,
                            "exclusions": loaded.exclusions},
              "sorted_records_sha256": digest(canonical(records))}
    return result, keys


def reproduce_protection():
    loader_source = ROOT / "evaluation/privoke_eval/datasets.py"
    canonical_lf = loader_source.read_bytes().decode("utf-8").replace("\r\n", "\n").encode("utf-8")
    if hashlib.sha256(canonical_lf).hexdigest() != LOADER_SHA256:
        raise ValueError("PIIMB loader code differs from the pinned original implementation.")
    from privoke_eval.datasets import load_examples
    first, keys = protected_index(*load_examples("piimb", 1000, seed=3102026, strategy="balanced", english_only=True))
    second, _ = protected_index(*load_examples("piimb", 1000, seed=3102026, strategy="balanced", english_only=True))
    if first != second:
        raise ValueError("Protected source selection failed deterministic reproduction.")
    first["reproduced_twice"] = True
    return first, keys


def read_references(path):
    result, raw = {}, {}
    for name, (count, expected_sha) in REFERENCE.items():
        file = Path(path) / f"{name}.jsonl"
        raw[name] = file.read_bytes()
        if hashlib.sha256(raw[name]).hexdigest() != expected_sha:
            raise ValueError("Original train/validation reference digest mismatch.")
        rows = [json.loads(line) for line in raw[name].decode("utf-8").splitlines() if line]
        if len(rows) != count or len({r.get("id") for r in rows}) != count:
            raise ValueError("Original reference row count/identity mismatch.")
        for row in rows:
            if (not isinstance(row.get("id"), str) or not row["id"] or not isinstance(row.get("group_id"), str)
                    or not row["group_id"] or not isinstance(row.get("text"), str) or not row["text"]
                    or type(row.get("expected_has_pii")) is not bool
                    or row.get("text_key") != training_text_key(row["text"])):
                raise ValueError("Malformed original reference truth/provenance.")
        result[name] = rows
    return result, raw


def bootstrap_texts(path):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "training_samples")
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    samples = namespace["training_samples"]()
    if len(samples) != 43 or any(not isinstance(x[0], str) or not x[0] for x in samples):
        raise ValueError("Bootstrap exclusion must contain exactly 43 authored texts.")
    return [x[0] for x in samples]


class ExcludeRow(ValueError):
    """Count-only rejection reason, never includes source PII."""


def english(value):
    return isinstance(value, str) and (value.strip().lower().replace("_", "-") in ("en", "eng", "english")
                                      or value.strip().lower().replace("_", "-").startswith("en-"))


def decode_labels(value, expected_type):
    if value in (None, ""):
        return expected_type()
    try:
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = ast.literal_eval(value)
        else:
            parsed = value
    except (ValueError, TypeError, SyntaxError):
        raise ExcludeRow("malformed_annotation_encoding") from None
    if not isinstance(parsed, expected_type):
        raise ExcludeRow("malformed_annotation_type")
    return parsed


def nemotron_annotations(row):
    text = row["text"]
    spans = decode_labels(row.get("spans"), list)
    categories = set()
    for span in spans:
        if not isinstance(span, dict):
            raise ExcludeRow("malformed_span")
        start, end = span.get("start"), span.get("end")
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
            raise ExcludeRow("malformed_span_bounds")
        labels = [span[k] for k in ("label", "category", "entity_type", "entity", "type", "tag") if k in span]
        if not labels or any(not isinstance(x, str) or not x.strip() for x in labels) or len(set(labels)) != 1:
            raise ExcludeRow("unknown_span_label")
        for key in ("text", "value", "entity_text"):
            if key in span and (not isinstance(span[key], str) or span[key] != text[start:end]):
                raise ExcludeRow("annotation_text_mismatch")
        categories.add(labels[0])
    return spans, sorted(categories)


def meddies_annotations(row):
    labels = decode_labels(row.get("label"), dict)
    categories = set()
    for name, values in labels.items():
        if not isinstance(name, str) or not name.strip():
            raise ExcludeRow("unknown_entity_label")
        if values is None or values == [] or values == "":
            continue
        values = [values] if isinstance(values, str) else values
        if not isinstance(values, list) or any(not isinstance(x, str) or not x.strip() for x in values):
            raise ExcludeRow("malformed_entity_values")
        if any(value not in row["raw"] for value in values):
            raise ExcludeRow("annotation_text_mismatch")
        categories.add(name)
    return labels, sorted(categories)


def source_identity(source, row, ordinal):
    text = row.get("text" if source == "nemotron-pii" else "raw")
    if not isinstance(text, str) or not text.strip():
        raise ExcludeRow("missing_text")
    if source == "nemotron-pii":
        uid = row.get("uid")
        if not isinstance(uid, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", uid):
            raise ExcludeRow("missing_or_invalid_native_uid")
        group = canonical_group(uid, source)
        # UID identifies a parent with reviewed us/intl document variants.
        # Variant IDs remain deterministic; parent aliases/groups protect both.
        identifier = group + ":variant:" + digest(canonical([row.get("locale"), training_text_key(text)]))
        # The exact-pin Nemotron card declares English. `locale` is geographic
        # (for example us/intl), and does not encode a language code.
        language = "en"
    else:
        names = ("document_type", "document_label", "text_format", "edge_case")
        values = []
        for name in names:
            actual = "type" if name == "document_type" and "type" in row else name
            if actual not in row:
                raise ExcludeRow("missing_template_group_field")
            values.append(row[actual])
        group = "meddies-pii:template:" + digest(canonical(values))
        native = row.get("id")
        identifier = "meddies-pii:" + str(native) if native not in (None, "") else "meddies-pii:generated:" + digest(
            PINS[source][1] + "\0" + str(ordinal) + "\0" + training_text_key(text))
        language = row.get("language")
    return identifier, group, text, language


def serialize_candidate(source, row, ordinal, identity):
    identifier, group, text, language = identity
    if not english(language):
        raise ExcludeRow("non_english_or_unknown_language")
    annotations, categories = nemotron_annotations(row) if source == "nemotron-pii" else meddies_annotations(row)
    if not categories:
        raise ExcludeRow("unknown_empty_annotation")
    return {"id": identifier, "group_id": group, "text": text, "text_key": training_text_key(text),
            "expected_has_pii": True, "expected_categories": categories, "source": PINS[source][0],
            "source_family": source, "source_revision": PINS[source][1], "original_split": "train",
            "source_absolute_ordinal": ordinal, "id_provenance": "native_parent_uid_locale_and_text_hash" if source == "nemotron-pii" else "native_id" if row.get("id") not in (None, "") else "pinned_fullscan_ordinal_and_text_hash",
            "group_provenance": "native_parent_uid" if source == "nemotron-pii" else "conservative_template_tuple_not_verified_document_lineage",
            "annotations": annotations, "domain": row.get("domain"), "document_type": row.get("document_type", row.get("type")),
            "document_label": row.get("document_label"), "document_format": row.get("document_format", row.get("text_format")),
            "language": language, "locale": row.get("locale") if source == "nemotron-pii" else None,
            "language_provenance": "pinned_source_card_english" if source == "nemotron-pii" else "source_language_field",
            "edge_case": row.get("edge_case"),
            "document_description": row.get("document_description"), "document_length": row.get("document_length"),
            "text_tags": row.get("text_tags", row.get("text_tagged"))}


def validate_audit(receipt):
    """Bind the exact metadata-audit contract; row semantics are checked separately."""
    if receipt.get("schema_version") != 1 or receipt.get("status") != "audited":
        raise ValueError("Source audit is not a completed version-one receipt.")
    entries = receipt.get("sources")
    if not isinstance(entries, list) or len(entries) != 2:
        raise ValueError("Audit must contain exactly the two pinned source views.")
    bound = {}
    for source, (repo, revision, config, count) in PINS.items():
        matches = [x for x in entries if isinstance(x, dict) and x.get("repo_id") == repo]
        if len(matches) != 1:
            raise ValueError("Audit source identity is missing or duplicated.")
        entry = matches[0]
        path = ("data" if source == "nemotron-pii" else "english") + "/train-00000-of-00001.parquet"
        license_name = "cc-by-4.0" if source == "nemotron-pii" else "cc-by-nc-4.0"
        file = entry.get("file", {})
        fields = file.get("schema_fields", [])
        required = {"uid", "text", "spans", "locale"} if source == "nemotron-pii" else {
            "language", "document_type", "document_label", "text_format", "edge_case", "raw", "label"}
        if (entry.get("revision") != revision or entry.get("config") != config
                or entry.get("split") != "train" or entry.get("license") != license_name
                or file.get("path") != path or file.get("row_count") != count
                or file.get("parquet_url") != f"https://huggingface.co/datasets/{repo}/resolve/{revision}/{path}"
                or type(file.get("parquet_size_bytes")) is not int or file["parquet_size_bytes"] <= 0
                or not isinstance(fields, list) or not required.issubset(fields)
                or source == "meddies-pii" and "id" in fields):
            raise ValueError("Audited pin/split/file/schema/license differs from the frozen source contract.")
        for value in [receipt.get("audit_script_sha256"), file.get("lfs_sha256"),
                      entry.get("card_sha256"), entry.get("license_source_sha256"),
                      entry.get("revision_metadata_sha256"), entry.get("file_tree_metadata_sha256")]:
            if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
                raise ValueError("Audit provenance digest is missing or malformed.")
        if entry["card_sha256"] != entry["license_source_sha256"]:
            raise ValueError("Pinned card/license evidence binding differs.")
        bound[source] = entry
    return bound


def source_rows(entry):
    """Fetch only the reviewed immutable file and verify its complete bytes."""
    from huggingface_hub import hf_hub_download
    from datasets import load_dataset
    file = entry["file"]
    local = Path(hf_hub_download(repo_id=entry["repo_id"], repo_type="dataset",
                               revision=entry["revision"], filename=file["path"]))
    hasher = hashlib.sha256()
    with local.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    if local.stat().st_size != file["parquet_size_bytes"] or hasher.hexdigest() != file["lfs_sha256"]:
        raise ValueError("Downloaded exact-pin source bytes differ from audited LFS identity.")
    return load_dataset("parquet", data_files=str(local), split="train", streaming=True)


class CandidatePool:
    """Private full-scan staging; no source text is emitted to logs or receipts."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE rows (n INTEGER PRIMARY KEY, source TEXT, identifier TEXT, grouping TEXT, textkey TEXT, state TEXT, labels TEXT, payload TEXT, eligible INTEGER DEFAULT 0, partition TEXT)")
        self.db.execute("CREATE INDEX rows_source_group ON rows(source,grouping)")
        self.db.execute("CREATE INDEX rows_identifier ON rows(identifier)")
        self.db.execute("CREATE INDEX rows_textkey ON rows(textkey)")
        self.counts = defaultdict(Counter)

    def close(self):
        self.db.close()

    def scan(self, source, rows, excluded, *, expected_count, schema_fields=None):
        seen = 0
        for ordinal, row in enumerate(rows):
            seen += 1
            if not isinstance(row, dict) or schema_fields is not None and set(row) != set(schema_fields) - {"schema"}:
                raise ValueError("Source row schema differs from the audited pinned file.")
            self.counts[source]["rows_seen"] += 1
            try:
                identity = source_identity(source, row, ordinal)
            except ExcludeRow as exc:
                self.counts[source][str(exc)] += 1
                continue
            identifier, group, text, _ = identity
            incoming = row_keys(identifier, group, text)
            is_protected = any(incoming[k] & excluded[k] for k in incoming)
            state, labels, payload = "invalid", None, None
            try:
                candidate = serialize_candidate(source, row, ordinal, identity)
                state, labels, payload = "positive", canonical(candidate["expected_categories"]), canonical(candidate)
                self.counts[source]["annotation_valid_positive"] += 1
            except ExcludeRow as exc:
                state = "unknown" if str(exc) == "unknown_empty_annotation" else "invalid"
                self.counts[source][str(exc)] += 1
            if is_protected:
                self.counts[source]["protected_overlap"] += 1
            self.db.execute("INSERT INTO rows(source,identifier,grouping,textkey,state,labels,payload,eligible) VALUES(?,?,?,?,?,?,?,?)",
                            (source, identifier, group, opaque("text_key", training_text_key(text)), state, labels,
                             payload, int(state == "positive" and not is_protected)))
        self.db.commit()
        if seen != expected_count:
            raise ValueError("Actual full-scan source row count differs from audited footer.")

    def eliminate_conflicts(self):
        # Inspect all rows, including invalid/unknown/protected variants, before caps.
        # The audited Nemotron train file has exactly two geographic variants per
        # UID. Text differences alone do not make this recognized parent ambiguous.
        parents = [x[0] for x in self.db.execute("SELECT DISTINCT grouping FROM rows WHERE source='nemotron-pii' ORDER BY grouping")]
        fields = ("domain", "document_type", "document_format", "document_description")
        for parent in parents:
            variants = list(self.db.execute("SELECT state,payload FROM rows WHERE source='nemotron-pii' AND grouping=? ORDER BY n", (parent,)))
            verified = len(variants) == 2 and all(state == "positive" and payload is not None for state, payload in variants)
            if verified:
                first, second = (json.loads(payload) for _, payload in variants)
                verified = (first.get("locale") in ("us", "intl") and second.get("locale") in ("us", "intl")
                            and first["locale"] != second["locale"]
                            and all(first.get(field) == second.get(field) for field in fields)
                            and all(isinstance(first.get(field), str) and first[field].strip() for field in fields))
            if verified:
                self.counts["nemotron-pii"]["verified_variant_parents"] += 1
            else:
                self.counts["nemotron-pii"]["excluded_variant_parents"] += 1
                count = self.db.execute("SELECT COUNT(*) FROM rows WHERE source='nemotron-pii' AND grouping=? AND eligible=1", (parent,)).fetchone()[0]
                self.counts["nemotron-pii"]["unverified_native_variant_parent_rows"] += count
                self.db.execute("UPDATE rows SET eligible=0 WHERE source='nemotron-pii' AND grouping=?", (parent,))
        ambiguous = {x[0] for x in self.db.execute("SELECT identifier FROM rows GROUP BY identifier HAVING COUNT(DISTINCT textkey)>1")}
        conflicting = {x[0] for x in self.db.execute("SELECT textkey FROM rows GROUP BY textkey HAVING COUNT(DISTINCT state)>1")}
        conflicting.update(x[0] for x in self.db.execute("SELECT textkey FROM rows WHERE state='positive' GROUP BY source,textkey HAVING COUNT(DISTINCT labels)>1"))
        for reason, column, values in [("ambiguous_native_identity", "identifier", ambiguous),
                                       ("conflicting_annotation_variants", "textkey", conflicting)]:
            for value in sorted(values):
                for source, count in self.db.execute(f"SELECT source,COUNT(*) FROM rows WHERE {column}=? AND eligible=1 GROUP BY source", (value,)):
                    self.counts[source][reason] += count
                self.db.execute(f"UPDATE rows SET eligible=0 WHERE {column}=?", (value,))
        self.db.commit()

    def assign_groups(self, heldout_cap=HELDOUT_CAP):
        assigned = {}
        for source in PINS:
            groups = list(self.db.execute("SELECT grouping,COUNT(*) FROM rows WHERE source=? AND eligible=1 GROUP BY grouping ORDER BY grouping", (source,)))
            random.Random(9102026).shuffle(groups)
            total, heldout = 0, set()
            for group, count in groups:
                if count <= heldout_cap - total:
                    heldout.add(group)
                    total += count
            for group, _ in groups:
                part = source + "_heldout" if group in heldout else "train"
                self.db.execute("UPDATE rows SET partition=? WHERE source=? AND grouping=?", (part, source, group))
            assigned[source] = {"eligible_groups": len(groups), "heldout_assigned_groups": len(heldout),
                                "heldout_assigned_rows_before_dedup": total}
        self.db.commit()
        return assigned

    def dedupe_and_sample(self, caps=None, heldout_cap=HELDOUT_CAP):
        caps = CAPS if caps is None else caps
        # Assignment precedes global dedup; removed rows never move to another partition.
        seen = set()
        for n, source, textkey in list(self.db.execute("SELECT n,source,textkey FROM rows WHERE eligible=1 ORDER BY source,grouping,identifier,n")):
            if textkey in seen:
                self.counts[source]["global_normalized_text_duplicate"] += 1
                self.db.execute("UPDATE rows SET eligible=0 WHERE n=?", (n,))
            else:
                seen.add(textkey)
        result = {"train": [], "nemotron-pii_heldout": [], "meddies-pii_heldout": []}
        for source in PINS:
            for partition, cap in [("train", caps[source]), (source + "_heldout", heldout_cap)]:
                groups = list(self.db.execute("SELECT grouping,COUNT(*) FROM rows WHERE source=? AND partition=? AND eligible=1 GROUP BY grouping ORDER BY grouping", (source, partition)))
                random.Random(8102026 if partition == "train" else 9102026).shuffle(groups)
                count = 0
                for group, size in groups:
                    if size > cap - count:
                        self.counts[source][partition + "_row_cap_excluded"] += size
                        continue
                    for (payload,) in self.db.execute("SELECT payload FROM rows WHERE source=? AND grouping=? AND eligible=1 ORDER BY identifier,n", (source, group)):
                        result[partition].append(json.loads(payload))
                    count += size
                self.counts[source][partition + "_selected"] = count
        self.db.commit()
        return result


def recheck_partitions(partitions, excluded):
    seen_ids, seen_texts, group_partitions = set(), set(), {}
    for partition, rows in partitions.items():
        for row in rows:
            keys = row_keys(row["id"], row["group_id"], row["text"])
            if any(keys[k] & excluded[k] for k in keys):
                raise ValueError("Final candidate partition overlaps an exclusion key.")
            if row["id"] in seen_ids or row["text_key"] in seen_texts:
                raise ValueError("Candidate partitions repeat an identity or normalized text.")
            previous = group_partitions.setdefault(row["group_id"], partition)
            if previous != partition:
                raise ValueError("Source group crosses candidate partitions.")
            if row["expected_has_pii"] is not True or not row["expected_categories"]:
                raise ValueError("Candidate lacks verified positive annotation truth.")
            seen_ids.add(row["id"])
            seen_texts.add(row["text_key"])
    return {"protected_id_overlap": 0, "protected_group_overlap": 0, "protected_text_overlap": 0,
            "candidate_duplicate_ids": 0, "candidate_duplicate_texts": 0, "cross_partition_groups": 0}


def coverage(rows):
    result = {field: dict(sorted(Counter(str(row.get(field)) for row in rows).items()))
              for field in ("source", "domain", "document_format", "language")}
    result["categories"] = dict(sorted(Counter(category for row in rows for category in row["expected_categories"]).items()))
    result["groups"] = len({row["group_id"] for row in rows})
    return result


def validate_inputs(args):
    if args.output.exists():
        raise ValueError("Refusing an existing preparation output directory.")
    if not re.fullmatch("[0-9a-f]{40}", args.source_revision):
        raise ValueError("Execution source revision must be a full Git SHA.")
    if not re.fullmatch("[0-9a-f]{64}", args.protocol_sha256) or sha(args.protocol_file) != args.protocol_sha256:
        raise ValueError("Prospective protocol digest mismatch.")
    if not args.output.resolve().is_relative_to((ROOT / "evaluation/results").resolve()):
        raise ValueError("Private preparation output must be under evaluation/results.")
    receipt = json.loads(args.source_audit.read_text(encoding="utf-8"))
    return receipt, validate_audit(receipt)


def prepare(args):
    receipt, audited = validate_inputs(args)
    references, reference_bytes = read_references(args.prepared_reference)
    anchors = bootstrap_texts(args.bootstrap_source)
    index, excluded = reproduce_protection()
    for rows in references.values():
        for row in rows:
            merge_keys(excluded, row_keys(row["id"], row["group_id"], row["text"]))
    excluded["texts"].update(opaque("text_key", training_text_key(text)) for text in anchors)
    index["all_exclusion_key_sets"] = {k: sorted(v) for k, v in excluded.items()}
    index["all_exclusion_key_sets_sha256"] = digest(canonical(index["all_exclusion_key_sets"]))
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / "source-audit.json", raw=args.source_audit.read_bytes())
    write(args.output / "protocol.md", raw=args.protocol_file.read_bytes())
    write(args.output / "exclusion-index.json", index)
    write(args.output / "preparation-start.json", {"status": "preparing", "source_revision": args.source_revision,
          "protocol_sha256": args.protocol_sha256, "source_audit_sha256": sha(args.source_audit),
          "pins": audited, "row_semantics": "strict positive full documents only; empty labels unknown",
          "seeds": {"sample": 8102026, "heldout_groups": 9102026}, "caps": CAPS, "heldout_target_per_source": HELDOUT_CAP})
    pool = CandidatePool(args.output / "private-candidates.sqlite3")
    try:
        for source, entry in audited.items():
            pool.scan(source, source_rows(entry), excluded, expected_count=PINS[source][3],
                      schema_fields=entry["file"]["schema_fields"])
        pool.eliminate_conflicts()
        assignments = pool.assign_groups(heldout_cap=HELDOUT_CAP)
        added = pool.dedupe_and_sample(caps=CAPS, heldout_cap=HELDOUT_CAP)
        overlaps = recheck_partitions(added, excluded)
        missing = [source for source in PINS if not added[source + "_heldout"]]
        if missing:
            write(args.output / "manifest.json", {"schema_version": 1, "status": "blocked",
                  "reason": "zero diagnostic coverage after conservative whole-group cap",
                  "zero_coverage_sources": missing, "counts": {k: dict(v) for k, v in pool.counts.items()},
                  "group_assignments": assignments})
            raise ValueError("Zero source diagnostic coverage: preparation blocked before fitting.")
        files = {"train": "train.jsonl", "validation": "validation.jsonl",
                 "nemotron_heldout": "nemotron-heldout.jsonl", "meddies_heldout": "meddies-heldout.jsonl"}
        rows = {"train": references["train"] + added["train"], "validation": references["validation"],
                "nemotron_heldout": added["nemotron-pii_heldout"], "meddies_heldout": added["meddies-pii_heldout"]}
        for name, file in files.items():
            if name == "validation":
                data = reference_bytes["validation"]
            elif name == "train":
                prefix = reference_bytes["train"]
                if not prefix.endswith(b"\n"):
                    raise ValueError("Original training reference lacks a complete newline boundary.")
                data = prefix + b"".join((canonical(row) + "\n").encode("utf-8") for row in added["train"])
            else:
                data = b"".join((canonical(row) + "\n").encode("utf-8") for row in rows[name])
            write(args.output / file, raw=data)
        # Verify the untouched reference files again; no development/final path is constructed.
        read_references(args.prepared_reference)
        if (args.output / files["validation"]).read_bytes() != reference_bytes["validation"]:
            raise ValueError("Validation bytes changed during preparation.")
        manifest = {"schema_version": 1, "status": "prepared", "partition_files": files,
                    "partition_sha256": {k: sha(args.output / v) for k, v in files.items()},
                    "rows": {k: len(v) for k, v in rows.items()}, "source_revision": args.source_revision,
                    "protocol_sha256": args.protocol_sha256, "source_audit_sha256": sha(args.source_audit),
                    "prepared_reference": {k + "_sha256": sha(args.prepared_reference / (k + ".jsonl")) for k in REFERENCE},
                    "exclusion_index_file": "exclusion-index.json", "exclusion_index_sha256": sha(args.output / "exclusion-index.json"),
                    "bootstrap_source_sha256": sha(args.bootstrap_source), "protected_selection": index["aggregate"],
                    "protected_selection_sha256": index["sorted_records_sha256"], "preparation_script_sha256": sha(Path(__file__)),
                    "training_text_key_source_sha256": sha(ROOT / "shared/python/privoke_model/training_data.py"),
                    "sources": audited, "original_train_preserved_as_exact_prefix": True,
                    "seeds": {"sample": 8102026, "heldout_groups": 9102026}, "caps": CAPS,
                    "group_assignments": assignments, "counts": {k: dict(v) for k, v in pool.counts.items()},
                    "coverage": {k: coverage(v) for k, v in added.items()}, "integrity": overlaps,
                    "shortfalls": {source: {"train": CAPS[source] - sum(r["source_family"] == source for r in added["train"]),
                                            "heldout": HELDOUT_CAP - len(added[source + "_heldout"])} for source in PINS},
                    "limitations": ["Added corpora are positive-only; diagnostic specificity is not estimable.",
                                    "Meddies metadata family grouping is not verified document/template independence.",
                                    "Existing train/validation are exploratory within-corpus controls, not an independent PIIMB benchmark."]}
        manifest["prepared_reference"]["train_bytes"] = len(reference_bytes["train"])
        write(args.output / "manifest.json", manifest)
        return manifest
    except Exception as exc:
        if not (args.output / "manifest.json").exists():
            write(args.output / "manifest.json", {"schema_version": 1, "status": "failed",
                  "error_type": type(exc).__name__, "source_revision": args.source_revision,
                  "protocol_sha256": args.protocol_sha256, "counts": {k: dict(v) for k, v in pool.counts.items()}})
        raise
    finally:
        pool.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("source-audit", "prepared-reference", "output", "protocol-file"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--bootstrap-source", type=Path, default=ROOT / "models/generate_baseline.py")
    parser.add_argument("--protocol-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    try:
        manifest = prepare(args)
    except Exception as exc:
        # No source values or opaque individual identifiers are printed on failure.
        print(canonical({"status": "failed", "error_type": type(exc).__name__}), file=sys.stderr)
        return 1
    print(canonical({"status": manifest["status"], "rows": manifest["rows"], "manifest_sha256": sha(args.output / "manifest.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
