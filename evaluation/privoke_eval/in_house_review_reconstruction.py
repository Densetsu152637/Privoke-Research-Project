"""Read-only complete-source reconstruction of frozen published review preparation.

Published output hashes must come from an external authority. The private map
is compared byte-for-byte after full source replay, never used to invent rows.
The original twelve input and eleven execution pins remain unchanged; this
adapter has its own external source commitment.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys
from types import MappingProxyType
from collections.abc import Mapping
import privoke_eval.in_house_advpii_review_io as io

_FILES = {"manifest.json": 4 * 1024 * 1024,
          "review-packages.jsonl": 64 * 1024 * 1024,
          "private-review-map.jsonl": 16 * 1024 * 1024}


@dataclass(frozen=True)
class PublishedPreparationTrust:
    """Externally committed publication and separate reconstruction source pin."""
    output_raw_sha256: Mapping[str, str]
    reconstruction_raw_sha256: str
    expected_counts: Mapping[str, int]

    def __post_init__(self):
        object.__setattr__(self, "output_raw_sha256", MappingProxyType(dict(self.output_raw_sha256)))
        object.__setattr__(self, "expected_counts", MappingProxyType(dict(self.expected_counts)))


def _fail():
    raise io.InHousePreparationError("reconstruction:validation_failed") from None


def _attest_adapter(source_root, expected):
    path = source_root / "evaluation/privoke_eval/in_house_review_reconstruction.py"
    if not io._valid_sha(expected):
        _fail()
    fd, before = io._open_read_nofollow(path)
    try:
        raw = b""
        while len(raw) <= io._CODE_LIMIT:
            chunk = os.read(fd, min(1024 * 1024, io._CODE_LIMIT + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if (len(raw) > io._CODE_LIMIT or io._identity(before) != io._identity(os.fstat(fd))
                or io._sha(raw) != expected):
            _fail()
    finally:
        os.close(fd)
    io._attest_module("reconstruction", raw, path, module_override=sys.modules[__name__])


class _HeldPublication:
    """Hold every ancestor and verify all named files on each execution edge."""
    def __init__(self, source_root, output, pins):
        self.source_root, self.output, self.pins = source_root, output, pins
        self.directories = []
        self.files = {}
        self.payloads = {}

    def __enter__(self):
        try:
            if (not io._platform_supported() or not self.source_root.is_absolute()
                    or self.source_root.resolve(strict=True) != self.source_root
                    or self.output.parent != self.source_root / "evaluation/results"
                    or set(self.pins) != set(_FILES)
                    or any(not io._valid_sha(x) for x in self.pins.values())):
                _fail()
            parent = None
            for path in (self.source_root, self.source_root / "evaluation",
                         self.output.parent, self.output):
                info = os.lstat(path) if parent is None else os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or io._is_reparse(info):
                    _fail()
                fd = os.open(path if parent is None else path.name,
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.directories.append((path, fd, io._identity(info)))
                if io._identity(os.fstat(fd)) != io._identity(info):
                    _fail()
                parent = fd
            for name, limit in _FILES.items():
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                self.files[name] = (fd, io._identity(os.fstat(fd)))
                self.payloads[name] = self._read(name, limit)
            self.verify()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def _read(self, name, limit):
        fd, identity = self.files[name]
        named = os.stat(name, dir_fd=self.directories[-1][1], follow_symlinks=False)
        before = os.fstat(fd)
        for info in (named, before):
            if (not stat.S_ISREG(info.st_mode) or io._identity(info) != identity
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_size > limit):
                _fail()
        os.lseek(fd, 0, os.SEEK_SET)
        raw = b""
        while len(raw) <= limit:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(fd)
        if (len(raw) > limit or len(raw) != before.st_size
                or io._identity(after) != identity or after.st_size != before.st_size
                or stat.S_IMODE(after.st_mode) != 0o600 or after.st_nlink != 1
                or after.st_uid != os.geteuid() or io._sha(raw) != self.pins[name]):
            _fail()
        # Authenticate the published pathname again after consuming the held
        # descriptor. A rename/replacement can preserve the old inode and hash.
        named_after = os.stat(name, dir_fd=self.directories[-1][1], follow_symlinks=False)
        if (not stat.S_ISREG(named_after.st_mode) or io._identity(named_after) != identity
                or stat.S_IMODE(named_after.st_mode) != 0o600
                or named_after.st_uid != os.geteuid() or named_after.st_nlink != 1
                or named_after.st_size != after.st_size):
            _fail()
        return raw

    def _verify_directory_closure(self):
        for index, (path, fd, identity) in enumerate(self.directories):
            named = os.lstat(path) if index == 0 else os.stat(
                path.name, dir_fd=self.directories[index - 1][1], follow_symlinks=False)
            info = os.fstat(fd)
            if (not stat.S_ISDIR(named.st_mode) or io._identity(named) != identity
                    or io._identity(info) != identity or io._identity(os.lstat(path)) != identity):
                _fail()
            if index == len(self.directories) - 1 and (
                    stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid()):
                _fail()
        if set(os.listdir(self.directories[-1][1])) != set(_FILES):
            _fail()
    def verify(self):
        self._verify_directory_closure()
        for name, limit in _FILES.items():
            if self._read(name, limit) != self.payloads[name]:
                _fail()
        # Reading the final file must not leave renamed ancestors or extra
        # named entries unchecked until some later execution edge.
        self._verify_directory_closure()
        for name, (fd, identity) in self.files.items():
            named = os.stat(name, dir_fd=self.directories[-1][1], follow_symlinks=False)
            info = os.fstat(fd)
            if (not stat.S_ISREG(named.st_mode) or io._identity(named) != identity
                    or io._identity(info) != identity
                    or stat.S_IMODE(named.st_mode) != 0o600 or named.st_uid != os.geteuid()
                    or named.st_nlink != 1 or named.st_size != len(self.payloads[name])):
                _fail()

    def __exit__(self, *args):
        for fd, _ in self.files.values():
            os.close(fd)
        for _, fd, _ in reversed(self.directories):
            os.close(fd)
        self.files.clear()
        self.directories.clear()


def _rebuild(paths, captures, trust, code_hashes, protection_binding, combined, edge):
    snapshots = io._paths_for_captured(paths, captures)
    stage = "validate_source_audit"
    edge()
    source_audit = io.validate_source_audit(snapshots.source_audit)
    edge()
    text_bindings = io.require_frozen_text_inputs(snapshots.protocol, snapshots.rubric)
    if source_audit["source_audit_sha256"] != captures["source_audit"].sha256:
        io._fail(stage, "captured_source_audit_mismatch")
    edge()
    if io.verify_parquet_bytes(snapshots.parquet) != captures["parquet"].sha256:
        io._fail("verify_parquet", "captured_hash_mismatch")
    edge()
    stage = "open_parquet"
    parquet = io.open_verified_parquet(snapshots.parquet)
    edge()
    io.validate_arrow_schema(parquet.schema_arrow)
    edge()
    if parquet.metadata.num_rows != io.PARQUET_ROWS:
        io._fail("validate_parquet", "row_count_mismatch")
    edge()
    parsed_rows = []
    spans_by_uid = {}
    stage = "scan_source"
    parser_snapshot = io._parser_contract_snapshot()
    for raw, parsed in io._iter_rows(parquet, edge_guard=edge, parser_snapshot=parser_snapshot):
        parsed_rows.append(parsed)
        if parsed.grouping_row.eligible:
            spans_by_uid[parsed.grouping_row.uid] = io._span_inputs(raw, parsed)
    if len(parsed_rows) != io.PARQUET_ROWS:
        io._fail("scan_source", "row_count_mismatch")
    edge()
    stage = "close_graph"
    _counts, graph = io.aggregate_scan(parsed_rows, combined, expected_rows=io.PARQUET_ROWS)
    edge()
    if (io.review.protected_keys_digest(combined) != protection_binding.internal_protected_keys_sha256
            or io.fixture.combined_protection_digest(combined) != protection_binding.combined_protection_sha256):
        io._fail("compare_protection_bindings", "key_digest_mismatch")
    legacy = io.ReviewBindings(
        source_revision=trust.source_revision, source_sha256=captures["parquet"].sha256,
        protocol_sha256=text_bindings["protocol_sha256"], rubric_sha256=text_bindings["rubric_sha256"],
        parser_sha256=code_hashes["parser"], grouping_sha256=code_hashes["grouping"],
        normalizer_sha256=code_hashes["normalizer"],
        protected_union_sha256=protection_binding.historical_union_content_sha256,
        protected_keys_sha256=protection_binding.internal_protected_keys_sha256,
    )
    bindings = io.InHouseReviewBindings(
        legacy=legacy, protection=protection_binding,
        preparation_pin_manifest_raw_sha256=captures["pin_manifest"].sha256,
        execution_code_raw_sha256=code_hashes,
    )
    stage = "build_pool"
    pool = io.in_house.build_in_house_review_pool(tuple(parsed_rows), graph, bindings, combined, spans_by_uid)
    edge()
    io.in_house.validate_in_house_review_pool(pool, trusted_bindings=bindings)
    edge()
    packages_payload = b"".join(io.canonical_json_bytes({
        "review_id": package.review_id, "text": package.text, "text_sha256": package.text_sha256,
        "rubric_sha256": package.rubric_sha256,
        "native_spans": [{"entity_type": span.entity_type, "start": span.start, "end": span.end}
                         for span in package.native_spans],
    }) + b"\n" for package in pool.core.packages)
    map_payload = b"".join(io.canonical_json_bytes({
        "review_id": member.review_id, "source_uid": member.uid, "component_id": member.component_id,
        "source_text_sha256": member.exact_text_sha256, "native_category": member.native_category,
        "structural_eligible": member.structural_eligible,
        "native_span_types": [span.entity_type for span in member.native_spans],
    }) + b"\n" for member in pool.core._members)
    edge()
    counts = {"source_rows": len(parsed_rows), "pool_size": pool.core.pool_size,
              "graph_components": graph.component_count, "assignable_rows": graph.assignable_row_count}
    return pool, packages_payload, map_payload, counts, source_audit, text_bindings


def _manifest(pool, packages, private_map, counts, audit, texts, captures, code_hashes, trust):
    return {
        "schema_version": 1, "kind": "privoke-in-house-blind-review-preparation-v1",
        "status": "complete", "scope": "review_preparation_only", "source_revision": trust.source_revision,
        "preparation_identity": pool.preparation_identity, "review_pool_sha256": pool.review_pool_sha256,
        "bindings": pool.bindings.to_dict(), "input_raw_sha256": {k: captures[k].sha256 for k in io._INPUT_ROLES},
        "input_consumed_sha256": {
            role: io._sha(io._canonical_lf(captures[role].data)
                          if role in {"protocol", "rubric", "fixture", "fixture_rubric"}
                          else captures[role].data) for role in io._INPUT_ROLES},
        "execution_code_raw_sha256": dict(code_hashes), "source_audit_sha256": audit["source_audit_sha256"],
        "parquet_sha256": captures["parquet"].sha256, "protocol_sha256": texts["protocol_sha256"],
        "rubric_sha256": texts["rubric_sha256"], "counts": counts,
        "review_status": "assistant_provisional_professor_pending", "no_allocation": True,
        "no_model_scoring": True, "not_authorized_for_fitting": True,
        "review_packages_file": "review-packages.jsonl", "review_packages_sha256": io._sha(packages),
        "private_review_map_file": "private-review-map.jsonl", "private_review_map_sha256": io._sha(private_map),
        "legacy_pool_sha256": pool.core.pool_sha256,
        "graph_membership_sha256": pool.core.graph_membership_sha256,
        "private_members_sha256": pool.core.private_members_sha256,
        "private_directory_mode": "0700", "private_file_mode": "0600", "platform": "posix",
    }


def reconstruct_in_house_review_pool(paths: io.InHouseReviewIOPaths, *,
                                     trust: io.InHousePreparationTrust,
                                     published_trust: PublishedPreparationTrust,
                                     source_root: Path):
    """Return a validated genuine pool only after complete captured-source replay.

    Rejects altered publication, input/code/protection drift, incomplete source,
    private-map inconsistencies and mismatched external counts.
    Only private temporary input snapshots are written; published files stay untouched.
    Requires POSIX no-follow descriptor support; Windows deliberately fails.
    """
    try:
        if type(published_trust) is not PublishedPreparationTrust:
            _fail()
        io._trusted_maps(trust)
        expected_counts = published_trust.expected_counts
        if (set(expected_counts) != {"source_rows", "pool_size", "graph_components", "assignable_rows"}
                or any(type(x) is not int or x < 0 for x in expected_counts.values())):
            _fail()
        _attest_adapter(source_root, published_trust.reconstruction_raw_sha256)
        with _HeldPublication(source_root, paths.output, published_trust.output_raw_sha256) as publication:
            code_hashes = io._attest_code(source_root, trust)
            with io._capture_all(paths, trust) as (_, captures, _snapshot_root):
                def edge():
                    publication.verify()
                    _attest_adapter(source_root, published_trust.reconstruction_raw_sha256)
                    io._verify_execution_edge(source_root, trust, code_hashes, captures)
                edge()
                actual, _, combined = io._protection_preflight(paths, captures, trust, code_hashes, source_root)
                if actual != io._expected_bindings(trust.expected_protection_bindings):
                    _fail()
                edge()
                pool, packages, private_map, counts, audit, texts = _rebuild(
                    paths, captures, trust, code_hashes, actual, combined, edge)
                manifest = _manifest(pool, packages, private_map, counts, audit, texts, captures, code_hashes, trust)
                expected = {"manifest.json": io.canonical_json_bytes(manifest) + b"\n",
                            "review-packages.jsonl": packages, "private-review-map.jsonl": private_map}
                if counts != dict(expected_counts) or expected != publication.payloads:
                    _fail()
                edge()
                # Source attestation/input rechecks may themselves take time.
                # Reauthenticate the publication immediately before returning.
                publication.verify()
                return pool
    except Exception:
        _fail()
