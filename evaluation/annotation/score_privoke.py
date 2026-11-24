#!/usr/bin/env python
"""Score PriVoke against the frozen, human-adjudicated Stage 13a labels (run with the pipeline interpreter).

Usage (host Python, PYPIPE; takes the host lock; needs the frozen labels):
  python score_privoke.py --freeze-dir docs/research/s13a --sheet <packet/sheets/main_A.csv> \
      --key <packet/key/sampling_key.jsonl> --out <results/s13a/scores> \
      --release-dir <models/standard-releases> --generated <extension/client-runtime/generated>

The scorer refuses to run unless the freeze record (iaa.json) exists, every label file it lists matches its
sha256 and is committed without local changes. It scores two separately labelled arms (decision D6):
  product        layers [2, 3, 4] (regex, NER, semantic), V3 balanced, shipped defaults;
                 scope 'product pipeline (in-process)'
  semantic_only  layers [4] (semantic); scope 'LLM-only (semantic)'
Every request names its layers explicitly, an empty layer list is refused before anything is sent, and the
executed layers of every response are asserted; a mismatch aborts the run.

The positive class is sensitive = yes. PriVoke's prediction is positive when its action is WARN or BLOCK.
Under-enforcement is an action less strict than the reference action label; over-enforcement is stricter.
Text comes only from the blank sheet in the packet directory (outside Git); outputs hold ids and actions only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402

MAIN_CHECKOUT = Path("D:/Git Repositories/Privoke-Research-Project")
LAYER_NAMES = {2: "regex", 3: "ner", 4: "semantic"}
RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
SEED = 20261124
JUSTIFICATION = ("The supervisor request relayed by the user on 19 Nov 2026 asks explicitly for PriVoke's "
                 "accuracy (ASIACCS plan, Stage 13 'Source').")
ARMS = {
    "product": {"layers": [2, 3, 4], "scope_label": "product pipeline (in-process)", "justification": JUSTIFICATION},
    "semantic_only": {"layers": [4], "scope_label": "LLM-only (semantic)",
                      "justification": "Isolates the semantic layer, as the LLM-layer testing rule requires (D6)."},
}
STAGE = "13a-5"


class FreezeError(RuntimeError):
    """The labels are not frozen: the freeze record, a hash or the Git state does not hold."""


class LayerAssertionError(AssertionError):
    pass


def require_layers(layers):
    """Refuse an empty or unknown layer list before any request is sent (an empty list means the full pipeline)."""
    if not layers:
        raise ValueError("an explicit, non-empty layer list is required; an empty list selects the full pipeline")
    unknown = [layer for layer in layers if layer not in LAYER_NAMES]
    if unknown:
        raise ValueError(f"unknown layers {unknown}")
    return list(layers)


def assert_layers(executed, requested, expected_checksum=None, metadata=None):
    """Assert the response lists exactly the requested layers, in order; the regex-first skip applies only
    when regex was requested. ``executed`` is a list of {layer, status}. Returns {layer: status}."""
    names = [LAYER_NAMES[v] for v in requested]
    got = [item["layer"] for item in executed]
    if got != names:
        raise LayerAssertionError(f"executed layers {got} differ from the requested {names}")
    statuses = {item["layer"]: item["status"] for item in executed}
    for name, status in statuses.items():
        if status not in ("ok", "skipped", "error"):
            raise LayerAssertionError(f"layer {name} has status {status!r}")
    if "regex" in names:
        if statuses["regex"] != "ok":
            raise LayerAssertionError("regex layer did not run")
        later = [statuses[n] for n in names if n != "regex"]
        if "skipped" in later and any(s != "skipped" for s in later):
            raise LayerAssertionError("regex-first skip must skip both later layers")
    elif "skipped" in statuses.values():
        raise LayerAssertionError("a layer was skipped although regex was not requested")
    if statuses.get("semantic") == "ok" and expected_checksum is not None:
        if (metadata or {}).get("privoke.semantic.artifact_checksum") != expected_checksum:
            raise LayerAssertionError("semantic layer executed with an unexpected model identity")
    return statuses


# ---------------------------------------------------------------- freeze gate
def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def verify_freeze(freeze_dir):
    """Return the freeze record when the label files are listed, hash-correct and committed unchanged."""
    freeze_dir = Path(freeze_dir)
    record_path = freeze_dir / "iaa.json"
    if not record_path.is_file():
        raise FreezeError(f"freeze record {record_path} does not exist; commit the labels first")
    record = json.loads(record_path.read_text(encoding="utf8"))
    files = record.get("files")
    if not isinstance(files, dict) or "labels/adjudicated.csv" not in files:
        raise FreezeError("freeze record does not list labels/adjudicated.csv")
    top = git(freeze_dir, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise FreezeError("the freeze directory is not in a Git repository")
    repo = Path(top.stdout.strip())
    for name, expected in sorted(files.items()):
        path = freeze_dir / name
        if not path.is_file():
            raise FreezeError(f"labelled file {name} is missing")
        if sha256_file(path) != expected:
            raise FreezeError(f"{name} does not match its frozen sha256")
        if git(repo, "ls-files", "--error-unmatch", str(path.resolve())).returncode != 0:
            raise FreezeError(f"{name} is not committed")
        if git(repo, "diff", "--quiet", "HEAD", "--", str(path.resolve())).returncode != 0:
            raise FreezeError(f"{name} has uncommitted changes")
    if git(repo, "ls-files", "--error-unmatch", str(record_path.resolve())).returncode != 0:
        raise FreezeError("the freeze record is not committed")
    return record


# ---------------------------------------------------------------- host lock
def lock_path():
    return Path(os.environ.get("S13_HOST_LOCK") or MAIN_CHECKOUT / "evaluation" / "results" / "s13-host.lock")


class HostLock:
    def __enter__(self):
        path = lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise SystemExit(f"host lock {path} is held; refusing to start")
        with os.fdopen(fd, "w") as handle:
            json.dump({"stage": STAGE, "pid": os.getpid()}, handle)
        self.path = path
        return self

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------- scoring
def score_items(items, arm, analyse, expected_checksum=None):
    """items: [{item_id, text}]; analyse(text, request_id, layers) -> {action, layers, metadata}."""
    layers = require_layers(ARMS[arm]["layers"])
    records = []
    for item in items:
        response = analyse(item["text"], f"s13a-{arm}-{item['item_id']}", layers)
        assert_layers(response["layers"], layers, expected_checksum, response.get("metadata"))
        if response["action"] not in RANK:
            raise LayerAssertionError(f"unexpected action {response['action']!r}")
        records.append({"item_id": item["item_id"], "action": response["action"]})
    return records


def metric(num, den, kind="wilson"):
    value = (num / den) if den else None
    ci = list(ag.wilson_interval(num, den)) if kind == "wilson" and den else [None, None]
    return {"value": value, "ci95": ci, "num": num, "den": den}


def counts_of(rows):
    tp = sum(r["ref_pos"] and r["pred_pos"] for r in rows)
    fp = sum((not r["ref_pos"]) and r["pred_pos"] for r in rows)
    fn = sum(r["ref_pos"] and not r["pred_pos"] for r in rows)
    tn = sum((not r["ref_pos"]) and not r["pred_pos"] for r in rows)
    under = sum(RANK[r["pred"]] < RANK[r["ref_action"]] for r in rows)
    over = sum(RANK[r["pred"]] > RANK[r["ref_action"]] for r in rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "under": under, "over": over, "n": len(rows)}


def f1_parts(c):
    return 2 * c["tp"], 2 * c["tp"] + c["fp"] + c["fn"]


def metrics_of(rows):
    c = counts_of(rows)
    f1n, f1d = f1_parts(c)
    return {
        "precision": metric(c["tp"], c["tp"] + c["fp"]),
        "recall": metric(c["tp"], c["tp"] + c["fn"]),
        "specificity": metric(c["tn"], c["tn"] + c["fp"]),
        "f1": {**metric(f1n, f1d, kind="none")},
        "under_enforcement": metric(c["under"], c["n"]),
        "over_enforcement": metric(c["over"], c["n"]),
    }


def joined_rows(predictions, reference):
    """Join predictions {item_id: action} to reference labels {item_id: record}; only reference items count."""
    missing = sorted(set(reference) - set(predictions))
    if missing:
        raise ValueError(f"{len(missing)} reference items have no prediction")
    rows = []
    for item_id in sorted(reference):
        ref, pred = reference[item_id], predictions[item_id]
        rows.append({"item_id": item_id, "ref_pos": ref["sensitive"] == "yes", "pred_pos": pred in ("WARN", "BLOCK"),
                     "pred": pred, "ref_action": ref["action"], "categories": ref["categories"], "audience": ref["audience"]})
    return rows


def bootstrap_metrics(rows, clusters, n_boot, seed):
    """Cluster-bootstrap 95% intervals for every aggregate metric, resampling quota cells."""
    by_id = {r["item_id"]: r for r in rows}
    out = {}
    for name in ("precision", "recall", "specificity", "f1", "under_enforcement", "over_enforcement"):
        def statistic(ids, name=name):
            m = metrics_of([by_id[i] for i in ids])[name]
            return m["value"]
        lo, hi, used = ag.cluster_bootstrap(sorted(by_id), clusters, statistic, n_boot, seed)
        out[name] = {"ci95": [lo, hi], "replicates_used": used}
    return out


def arm_report(arm, predictions, reference, clusters, n_boot=1000, seed=SEED):
    rows = joined_rows(predictions, reference)
    metrics = metrics_of(rows)
    boot = bootstrap_metrics(rows, clusters, n_boot, seed)
    for name, m in metrics.items():
        m["ci95_cluster_bootstrap"] = boot[name]["ci95"]
        if name == "f1":
            m["ci95"] = boot[name]["ci95"]
    per_category = {}
    for category in schema.CATEGORIES:
        members = [r for r in rows if category in r["categories"] and r["ref_pos"]]
        per_category[category] = {"n": len(members), "recall": metric(sum(r["pred_pos"] for r in members), len(members))}
    per_audience = {}
    for audience in schema.AUDIENCES:
        members = [r for r in rows if r["audience"] == audience]
        pos = [r for r in members if r["ref_pos"]]
        neg = [r for r in members if not r["ref_pos"]]
        per_audience[audience] = {"n": len(members),
                                  "recall": metric(sum(r["pred_pos"] for r in pos), len(pos)),
                                  "specificity": metric(sum(not r["pred_pos"] for r in neg), len(neg))}
    spec = ARMS[arm]
    return {"arm": arm, "scope_label": spec["scope_label"], "justification": spec["justification"],
            "layers_requested": spec["layers"], "layers_executed_ok": True, "n": len(rows),
            "bootstrap": {"unit": "quota_cell", "replicates": n_boot, "seed": seed},
            "metrics": metrics, "per_category": per_category, "per_audience": per_audience,
            "predictions": {r["item_id"]: r["pred"] for r in rows}}


# ---------------------------------------------------------------- real runtime (lazy; PYPIPE only)
def make_runtime(release_dir, generated):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import adversarial_evasion as ae

    class Runtime(ae.Runtime):
        def analyse_layers(self, text, request_id, layers):
            request = self.pb.AnalyzePromptRequest(
                request_id=request_id, text=text, layers=list(layers),
                regex_execution_order=self.pb.REGEX_EXECUTION_ORDER_FIRST, semantic_model_id=ae.SEMANTIC_MODEL_ID)
            response = self.service.AnalyzePrompt(request, None)
            return {"action": response.action, "metadata": dict(response.metadata), "error": response.error,
                    "layers": [{"layer": LAYER_NAMES[item.layer], "status": item.status, "error": item.error}
                               for item in response.layers]}

    runtime = Runtime(Path(release_dir), "defaults", Path(generated))
    return runtime, runtime.identity["artifact_checksum"]


def load_items(sheet, reference):
    rows = [r for r in schema.read_rows(sheet) if r["item_id"] in reference]
    return [{"item_id": r["item_id"], "text": r["text"]} for r in rows]


def load_clusters(key_path, item_ids):
    clusters = {}
    for line in Path(key_path).read_text(encoding="utf8").splitlines():
        if line.strip():
            row = json.loads(line)
            clusters[row["item_id"]] = row.get("quota_cell") or row["family_id"]
    return {i: clusters[i] for i in item_ids}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--freeze-dir", required=True, help="docs/research/s13a (holds iaa.json and labels/)")
    p.add_argument("--sheet", required=True, help="blank main sheet with the text (packet directory, outside Git)")
    p.add_argument("--key", required=True, help="sampling_key.jsonl, for the quota-cell bootstrap")
    p.add_argument("--out", required=True, help="directory for arm_<arm>.json (ids and actions only)")
    p.add_argument("--arm", choices=sorted(ARMS) + ["both"], default="both")
    p.add_argument("--release-dir", default=str(MAIN_CHECKOUT / "models" / "standard-releases"))
    p.add_argument("--generated", default=str(MAIN_CHECKOUT / "extension" / "client-runtime" / "generated"))
    p.add_argument("--n-boot", type=int, default=1000)
    args = p.parse_args(argv)

    verify_freeze(args.freeze_dir)  # refuses before anything else happens
    reference = schema.read_labels(Path(args.freeze_dir) / "labels" / "adjudicated.csv", version=2)
    items = load_items(args.sheet, reference)
    clusters = load_clusters(args.key, sorted(reference))
    arms = sorted(ARMS) if args.arm == "both" else [args.arm]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with HostLock():
        runtime, checksum = make_runtime(args.release_dir, args.generated)
        for arm in arms:
            records = score_items(items, arm, runtime.analyse_layers, checksum)
            report = arm_report(arm, {r["item_id"]: r["action"] for r in records}, reference, clusters, args.n_boot)
            report["semantic_identity"] = runtime.identity
            (out / f"arm_{arm}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf8")
            print(json.dumps({"arm": arm, "n": report["n"], "scope_label": report["scope_label"]}))


if __name__ == "__main__":
    main()
