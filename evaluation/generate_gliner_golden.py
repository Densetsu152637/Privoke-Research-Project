"""Golden output of the Python GLiNER detector for the Rust backend (stage 15).

``NER/gliner_detector.py`` is run over the C53 sets (the NER-model study's development, ``personalized`` and
``openai`` rows, reusing the stage 13 set loaders) at one label preset and threshold (default: the frozen
``core``, 0.5). One JSONL row per text records

* ``windows``: every ``GLiNER.predict_entities`` call (window text and the spans it returned), so the Rust test can
  replay the model without the weights;
* ``raw``: ``predict_raw`` (spans after the threshold and label filters);
* ``pf1`` / ``pf0``: the detector's results with the post-filter on and off, and ``decisions`` for ``pf1``;
* ``spacy``: the spaCy analyses the post-filter read (the ner-disabled parse as ``full``, the tagger re-tags as
  ``tagger``), in the stage 11 worker's field order, for replay without a worker.

Narrow host run, one process, read-only on the reference environment::

    evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_gliner_golden.py \
        --gliner-dir <checkpoint dir> --out <ignored dir> development openai

The GLiNER package, the checkpoint (``knowledgator/gliner-pii-small-v1.0`` at the study's pinned revision) and the
spaCy model must be installed; the environment of the study was ``evaluation/.venv-ner-models``. The output holds
dataset text: write it to an ignored directory (``evaluation/results/`` is ignored), never commit it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SETS = ["development", "personalized", "openai"]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Recorder:
    """The syntax pipeline, with each distinct analysis recorded for replay."""

    def __init__(self, nlp, doc_body) -> None:
        self._nlp = nlp
        self._doc_body = doc_body
        self._mode = "full"
        self.log: list[dict] = []
        self._seen: set = set()

    def __getattr__(self, name):
        return getattr(self._nlp, name)

    def __call__(self, text):
        doc = self._nlp(text)
        key = (self._mode, text)
        if key not in self._seen:
            self._seen.add(key)
            self.log.append({"sel": self._mode, "text": text, "body": self._doc_body(doc)})
        return doc

    def select_pipes(self, **kwargs):
        owner = self
        inner = self._nlp.select_pipes(**kwargs)
        # ``disable=["ner"]`` is the detector's parse (replayed as the full selection); ``enable=...`` is the
        # post-filter's tagger-only re-tag.
        mode = "tagger" if "enable" in kwargs else "full"

        class _Selection:
            def __enter__(self_inner):
                inner.__enter__()
                self_inner.previous = owner._mode
                owner._mode = mode
                return self_inner

            def __exit__(self_inner, *exc):
                owner._mode = self_inner.previous
                return inner.__exit__(*exc)

        return _Selection()

    def reset(self) -> None:
        self.log = []
        self._seen = set()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sets", nargs="+", choices=SETS)
    parser.add_argument("--gliner-dir", required=True, help="local checkpoint directory")
    parser.add_argument("--data-root", default=str(REPO), help="checkout that holds the ignored dataset files")
    parser.add_argument("--out", default=str(REPO / "evaluation" / "results" / "gliner-golden-20261117"))
    parser.add_argument("--preset", default="core", choices=["core", "pii"])
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args(argv)

    golden = load_module("generate_ner_golden", HERE / "generate_ner_golden.py")
    golden.bootstrap()
    from src.config import GLOBAL_CONFIG
    from src.NER import gliner_detector, ner_detector
    from src.NER.ner_postfilter import _english_lexicon

    detector = gliner_detector.GlinerEntityDetector(args.gliner_dir, threshold=args.threshold, label_preset=args.preset)
    detector._syntax()
    recorder = Recorder(detector._syntax_entry.nlp, golden.doc_body)
    detector._syntax_entry.nlp = recorder
    detector.nlp = recorder

    calls: list[dict] = []
    model = detector._gliner.model
    original = model.predict_entities

    def recording(window, labels, threshold=0.5, **kwargs):
        found = original(window, labels, threshold=threshold, **kwargs)
        calls.append({"window": window, "found": [
            {"start": f["start"], "end": f["end"], "label": f["label"], "score": f["score"]} for f in found]})
        return found

    model.predict_entities = recording

    decisions: list[list] = []
    original_filter = ner_detector.postfilter

    def recording_postfilter(doc, entities, **kwargs):
        decided = original_filter(doc, entities, **kwargs)
        decisions.append([golden.decision_record(d) for d in decided])
        return decided

    ner_detector.postfilter = recording_postfilter

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    texts_by_set = golden.load_sets(args.sets, Path(args.data_root))
    asked: set[str] = set()
    summary = {"preset": args.preset, "threshold": args.threshold, "model": args.gliner_dir, "sets": {}}
    for name in args.sets:
        texts = texts_by_set[name]
        rows = 0
        with (out / f"{name}.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
            for index, text in enumerate(texts):
                if args.limit and rows >= args.limit:
                    break
                if golden.has_surrogate(text):
                    continue
                recorder.reset()
                calls.clear()
                GLOBAL_CONFIG.ner_postfilter = True
                decisions.clear()
                row = {"id": index, "text": text}
                try:
                    row["pf1"] = [golden.result_record(r) for r in detector.extract_entities(text)]
                    row["decisions"] = decisions[0] if decisions else []
                    row["windows"] = list(calls)
                    row["raw"] = [
                        {"start": s.start_char, "end": s.end_char, "label": s.label_, "source": s.source_label,
                         "score": s.score, "text": s.text} for s in detector.predict_raw(text)]
                    row["spacy"] = list(recorder.log)
                    GLOBAL_CONFIG.ner_postfilter = False
                    row["pf0"] = [golden.result_record(r) for r in detector.extract_entities(text)]
                except Exception as exc:  # noqa: BLE001 - recorded, as the pipeline reports it
                    row = {"id": index, "text": text, "error": golden.error_message(exc)}
                for record in row.get("spacy", []):
                    if record["sel"] == "tagger":
                        for token in record["body"]["tokens"]:
                            asked.add(token[7].lower())
                            asked.add(token[4])
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                rows += 1
        summary["sets"][name] = {"rows": rows}
        print(name, summary["sets"][name], flush=True)
    lexicon = _english_lexicon(recorder)
    present = sorted(word for word in asked if word in lexicon)
    if not present and lexicon:
        present = [sorted(lexicon)[0]]
    (out / "lexicon.json").write_text(json.dumps(present), encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
