"""Golden output for the Rust analysis runtime, ``rust/services/runtime`` (RUST-S17).

The Rust worker serves the regex and NER layers of ``AnalyzePrompt``. This tool records what the unchanged Python
``PrivokeRuntimeService`` answers for the same requests, so that the Rust test can replay them and compare the
serialised ``AnalyzePromptResponse`` byte for byte.

* Every request names its layers explicitly (``regex``, ``ner`` or both); an empty layer list is never sent, because
  the servicer reads an empty list as the whole detector pipeline. The semantic layer is never requested, so these
  results are detector ablations or product-pipeline selections and are never LLM-only evidence.
* Responses are serialised with ``SerializeToString(deterministic=True)`` after clearing ``elapsed_ms`` and
  ``metadata["elapsed_ms"]`` (the only wall-clock fields), the normal form of the W1 conformance capture.
* The spaCy results the NER layer saw are recorded (the full and the tagger-only runs, as in the NER golden) so that
  the Rust crate can replay them without a Python interpreter, and the lexicon words the post-filter asked about.
* Requests come from three sources: the 20 synthetic prompts of the W1 capture in layer and order variants, the
  ``detector_ablation`` requests of the W1 capture itself (whose recorded response digests are re-checked here), and
  validation and policy cases (visibility hints, whitespace, limits, bad selections).

Usage (host Python with the client runtime requirements; the protobuf clients must exist)::

    python evaluation/generate_runtime_golden.py write --out rust/services/runtime/tests/fixtures/runtime_golden.json

The committed fixture is synthetic: the prompts are the capture's own synthetic prompts and generic sentences defined
here. Nothing from a recorded dataset is read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import struct
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FRAMES = REPO / "tests" / "conformance" / "worker-frames"
DEFAULT_OUT = REPO / "rust" / "services" / "runtime" / "tests" / "fixtures" / "runtime_golden.json"
HEADER = struct.Struct(">IBBBBQI")
LAYER_VALUES = {"regex": 2, "ner": 3}

EXTRA_TEXTS = {
    "name-and-email": "Please forward the notes to Maria Gonzalez at maria.gonzalez@example.org before Friday.",
    "address-and-phone": "Send it to 14 Elm Road, Leeds, and call +44 20 7946 0958 if nobody answers.",
    "health-and-person": "Dr. Okafor said that Tunde Adeyemi has been treated for depression since March.",
    "lowercase-names": "met sarah johnson and tom baker in new york yesterday to talk about the mortgage",
    "ALL-CAPS": "CONTACT JOHN SMITH AT ACME CORPORATION IN CHICAGO ABOUT THE CONTRACT",
    "short": "Hi",
    "padding": "   Remind Priya Raman about the visit to Berlin.\n\n",
    "digits-words": "My number is four one five, five five five, zero one three two.",
    "mixed-script": "田中さん (Tanaka) lives in 東京 and works at Sony.",
}


def bootstrap() -> None:
    paths = [REPO / "extension" / "client-runtime", REPO / "shared" / "python"]
    generated = os.environ.get("PRIVOKE_GENERATED")
    paths.append(Path(generated) if generated else REPO / "extension" / "client-runtime" / "generated")
    for path in reversed(paths):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    evaluation = str(REPO / "evaluation")
    if evaluation not in sys.path:
        sys.path.insert(0, evaluation)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Harness:
    """The Python servicer with the NER layer's spaCy calls recorded."""

    def __init__(self) -> None:
        bootstrap()
        from privoke.v1 import runtime_pb2
        from src import pipeline
        from src.NER import build_ner_detector
        from src.hosting.grpc_server import PrivokeRuntimeService
        from src.regex.rule_detector import RuleDetector

        ner_golden = importlib.import_module("generate_ner_golden")
        self.pb = runtime_pb2
        self.servicer = PrivokeRuntimeService(telemetry_reporter=None)
        regex = RuleDetector()
        ner = build_ner_detector()
        self.nlp = ner_golden.RecordingNlp(ner.nlp)
        self.nlp.record = True
        ner.nlp = self.nlp
        self.records: dict[tuple[str, str], dict] = {}

        def detector_for(layer, semantic_model_id=None):
            if layer == pipeline.REGEX_LAYER:
                return regex.analyze
            if layer == pipeline.NER_LAYER:
                return ner.extract_entities
            raise AssertionError(f"layer {layer!r} requested by a regex or NER run")

        pipeline._detector_for = detector_for

    def normalise(self, payload: bytes) -> bytes:
        message = self.pb.AnalyzePromptResponse.FromString(payload)
        message.ClearField("elapsed_ms")
        if "elapsed_ms" in message.metadata:
            del message.metadata["elapsed_ms"]
        return message.SerializeToString(deterministic=True)

    def run(self, request) -> bytes:
        self.nlp.reset()
        response = self.servicer.AnalyzePrompt(request, None)
        for record in self.nlp.log:
            self.records.setdefault((record["sel"], record["text"]), record)
        return self.normalise(response.SerializeToString(deterministic=True))

    def lexicon(self) -> list[str]:
        from src.NER.ner_postfilter import _english_lexicon

        lexicon = _english_lexicon(self.nlp)
        asked = set()
        for (selection, _), record in self.records.items():
            if selection != "tagger":
                continue
            for token in record["body"]["tokens"]:
                asked.add(token[7].lower())
                asked.add(token[4])
        present = sorted(word for word in asked if word in lexicon)
        if not present and lexicon:
            present = [sorted(lexicon)[0]]
        return present


def request_for(pb, text: str, layers: list[str], **fields):
    message = pb.AnalyzePromptRequest(text=text, layers=[LAYER_VALUES[name] for name in layers], **fields)
    return message


def capture_requests(pb) -> list[tuple[str, object, str]]:
    """The ``detector_ablation`` requests of the W1 capture: (label, request, recorded response digest)."""
    cases = json.loads((FRAMES / "analysis.json").read_text(encoding="utf-8"))["cases"]
    out = []
    for case in cases:
        if case["scope"] != "detector_ablation" or case["method"] != "AnalyzePrompt":
            continue
        frame = bytes.fromhex(case["request_frame_hex"])
        length, version, kind, method, flags, request_id, deadline = HEADER.unpack(frame[:20])
        request = pb.AnalyzePromptRequest.FromString(frame[20:20 + length])
        if not request.layers or any(value not in LAYER_VALUES.values() for value in request.layers):
            continue
        out.append((case["label"], request, case["response_payload_sha256"]))
    return out


def build_cases(harness: Harness) -> list[dict]:
    pb = harness.pb
    prompts = json.loads((FRAMES / "prompts.json").read_text(encoding="utf-8"))["prompts"]
    texts = {item["id"]: item["text"] for item in prompts}
    texts.update(EXTRA_TEXTS)
    selections = [
        ("regex", ["regex"], {}),
        ("ner", ["ner"], {}),
        ("regex+ner", ["regex", "ner"], {}),
        ("regex+ner/parallel", ["ner", "regex"], {"regex_execution_order": pb.REGEX_EXECUTION_ORDER_PARALLEL}),
        ("regex+ner/first", ["regex", "ner"], {"regex_execution_order": pb.REGEX_EXECUTION_ORDER_FIRST}),
    ]
    cases: list[dict] = []

    def add(case_id: str, note: str, scope: str, request, capture=None) -> None:
        payload = request.SerializeToString(deterministic=True)
        expected = harness.run(request)
        record = {"id": case_id, "note": note, "scope": scope,
                  "request": base64.b64encode(payload).decode("ascii"),
                  "response": base64.b64encode(expected).decode("ascii")}
        if capture is not None:
            label, digest = capture
            record["capture_label"] = label
            record["capture_sha256"] = digest
            record["capture_match"] = sha256(expected) == digest
        cases.append(record)

    for text_id, text in texts.items():
        for name, layers, fields in selections:
            scope = "detector_ablation" if len(layers) == 1 else "product_pipeline"
            add(f"{text_id}/{name}", "explicit layer selection", scope,
                request_for(pb, text, layers, request_id=f"{text_id}/{name}", **fields))

    context = texts["person-organisation"]
    for hint in ("P0", "P1", "P2", "p3", "P4", "PU"):
        add(f"hint/{hint}", "visibility hint on a NER finding", "product_pipeline",
            request_for(pb, context, ["regex", "ner"], visibility_hint=hint, request_id=f"hint-{hint}"))
        add(f"hint-regex/{hint}", "visibility hint on a regex finding", "product_pipeline",
            request_for(pb, texts["email"], ["regex", "ner"], visibility_hint=hint, request_id=f"hint-regex-{hint}"))
    add("hint/benign", "visibility hint without a finding", "product_pipeline",
        request_for(pb, texts["benign-weather"], ["regex", "ner"], visibility_hint="P2", request_id="hint-benign"))
    add("context/fields", "context fields are stripped and echoed", "product_pipeline",
        request_for(pb, texts["phone"], ["regex", "ner"], source="  extension  ", target_app="chat.example",
                    request_id="  rid-7  ", metadata={"a": "b", "k": ""}))
    add("layers/duplicates", "duplicate layers collapse and run in pipeline order", "product_pipeline",
        pb.AnalyzePromptRequest(text=texts["card"], layers=[3, 2, 3, 2], request_id="dups"))
    add("layers/semantic-model-ignored", "semantic_model_id is ignored without the semantic layer", "detector_ablation",
        request_for(pb, texts["email"], ["regex"], semantic_model_id="privoke-balanced", request_id="ignored"))

    invalid = {
        "validation/empty": (request_for(pb, "", ["regex"], request_id="v-empty"), "empty text"),
        "validation/blank": (request_for(pb, "  \n\t ", ["regex"], request_id="v-blank"), "whitespace-only text"),
        "validation/too-long": (request_for(pb, "a" * 20001, ["regex"], request_id="v-long"), "over the length limit"),
        "validation/just-long-enough": (request_for(pb, "a" * 20000, ["regex"], request_id="v-edge"), "at the length limit"),
        "validation/hint": (request_for(pb, "hello there", ["regex"], visibility_hint="secret", request_id="v-hint"), "bad hint"),
        "validation/source-control": (request_for(pb, "hello there", ["regex"], source="a\u0007b", request_id="v-src"), "control character"),
        "validation/source-long": (request_for(pb, "hello there", ["regex"], source="x" * 257, request_id="v-src2"), "long source"),
        "validation/request-id-long": (request_for(pb, "hello there", ["regex"], request_id="r" * 300), "long request id"),
        "validation/metadata-count": (request_for(pb, "hello there", ["regex"], request_id="v-md",
                                                  metadata={f"k{i:03d}": "v" for i in range(65)}), "65 entries"),
        "validation/metadata-key": (request_for(pb, "hello there", ["regex"], request_id="v-mk", metadata={"": "v"}), "empty key"),
        "validation/metadata-value": (request_for(pb, "hello there", ["regex"], request_id="v-mv",
                                                  metadata={"k": "é" * 342}), "long value"),
        "validation/metadata-total": (request_for(pb, "hello there", ["regex"], request_id="v-mt",
                                                  metadata={f"key{i:03d}": "x" * 400 for i in range(45)}), "total size"),
        "validation/layer-value": (pb.AnalyzePromptRequest(text="hello there", layers=[0], request_id="v-layer"), "unspecified layer"),
        "validation/layer-unknown": (pb.AnalyzePromptRequest(text="hello there", layers=[2, 9], request_id="v-layer9"), "unknown layer"),
        "validation/regex-order": (request_for(pb, "hello there", ["regex"], regex_execution_order=7, request_id="v-order"), "bad order"),
        "validation/gate-model": (request_for(pb, "hello there", ["regex"], request_id="v-gate",
                                              semantic_presence_gate=pb.SemanticPresenceGate(model_id="nope")), "bad gate model"),
        "validation/gate-layer": (request_for(pb, "hello there", ["regex"], request_id="v-gate2",
                                              semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-presence-balanced")),
                                  "gate without the semantic layer"),
    }
    for case_id, (request, note) in invalid.items():
        add(case_id, note, "validation", request)

    for label, request, digest in capture_requests(pb):
        add(f"capture/{label}/{request.request_id or 'noid'}", "request of the W1 capture", "detector_ablation"
            if len(request.layers) == 1 else "product_pipeline", request, (label, digest))
    return cases


def write(out: Path) -> dict:
    harness = Harness()
    cases = build_cases(harness)
    document = {
        "schema": 1,
        "python": sys.version.split()[0],
        "unicode": unicodedata.unidata_version,
        "scope_note": "regex and NER selections only: detector ablations and product-pipeline rows, never LLM-only evidence",
        "lexicon": harness.lexicon(),
        "spacy": [record for _, record in sorted(harness.records.items(), key=lambda item: item[0])],
        "cases": cases,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return document


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    writer = sub.add_parser("write", help="write the golden fixture")
    writer.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    document = write(Path(args.out))
    cases = document["cases"]
    matched = [case for case in cases if "capture_match" in case]
    print(f"wrote {args.out}: {len(cases)} cases, {len(document['spacy'])} spaCy records, "
          f"{sum(case['capture_match'] for case in matched)} of {len(matched)} capture digests reproduced")


if __name__ == "__main__":
    main()
