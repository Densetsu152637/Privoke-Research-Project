#!/usr/bin/env python3
"""Audit immutable Hugging Face source metadata and Parquet footers only.

No dataset rows are downloaded or parsed. The bounded HTTP Range requests read
the Parquet footer metadata to verify row counts and schema at the pinned commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCES = (
    {
        "repo_id": "nvidia/Nemotron-PII",
        "revision": "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
        "config": "default",
        "split": "train",
        "license": "cc-by-4.0",
        "parquet_path": "data/train-00000-of-00001.parquet",
        "required_schema": ["uid", "text", "spans"],
        "excluded_derivatives": [],
    },
    {
        "repo_id": "Meddies/meddies-pii",
        "revision": "6a5c8f5441e3b421d983c9741770262365acdd77",
        "config": "english",
        "split": "train",
        "license": "cc-by-nc-4.0",
        "parquet_path": "english/train-00000-of-00001.parquet",
        "required_schema": ["language", "document_type", "document_label", "document_length", "text_format", "edge_case", "raw", "label"],
        "excluded_derivatives": ["data", "eval", "pii-bioes", "grpo*"],
    },
)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_FOOTER_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 30


class AuditError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, *, range_header: str | None = None) -> tuple[bytes, dict[str, str], int]:
    headers = {"User-Agent": "PrivokeResearchSourceAudit/1.0"}
    if range_header:
        headers["Range"] = range_header
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            data = response.read(MAX_JSON_BYTES + 1)
            if len(data) > MAX_JSON_BYTES:
                raise AuditError(f"Response exceeded bounded size: {url}")
            return data, {k.lower(): v for k, v in response.headers.items()}, response.status
    except (urllib.error.URLError, TimeoutError) as exc:
        raise AuditError(f"Unable to retrieve pinned metadata from {url}: {exc}") from exc


def json_request(url: str) -> tuple[Any, bytes]:
    data, _, status = fetch(url)
    if status != 200:
        raise AuditError(f"Unexpected HTTP status {status}: {url}")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"Invalid JSON response: {url}") from exc
    return value, data


class CompactReader:
    """Small bounded Thrift compact-protocol reader for Parquet footer fields."""

    STOP, TRUE, FALSE, BYTE, I16, I32, I64, DOUBLE, BINARY, LIST, SET, MAP, STRUCT = range(13)

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise AuditError("Truncated Parquet footer metadata")
        result = self.data[self.pos]
        self.pos += 1
        return result

    def varint(self) -> int:
        result = shift = 0
        while shift < 70:
            item = self.byte()
            result |= (item & 0x7F) << shift
            if not item & 0x80:
                return result
            shift += 7
        raise AuditError("Malformed compact-protocol varint")

    def signed(self) -> int:
        value = self.varint()
        return (value >> 1) ^ -(value & 1)

    def binary(self) -> bytes:
        length = self.varint()
        if length < 0 or length > len(self.data) - self.pos:
            raise AuditError("Invalid compact-protocol binary length")
        out = self.data[self.pos:self.pos + length]
        self.pos += length
        return out

    def field_header(self, previous_id: int) -> tuple[int, int]:
        header = self.byte()
        typ = header & 0x0F
        if typ == self.STOP:
            return 0, self.STOP
        delta = header >> 4
        field_id = previous_id + delta if delta else self.signed()
        return field_id, typ

    def collection(self) -> tuple[int, int]:
        header = self.byte()
        size = header >> 4
        typ = header & 0x0F
        if size == 15:
            size = self.varint()
        if size > 1_000_000:
            raise AuditError("Unreasonable collection size in Parquet footer")
        return size, typ

    def skip(self, typ: int) -> None:
        if typ in (self.TRUE, self.FALSE):
            return
        if typ == self.BYTE:
            self.byte()
        elif typ in (self.I16, self.I32, self.I64):
            self.varint()
        elif typ == self.DOUBLE:
            self.pos += 8
        elif typ == self.BINARY:
            self.binary()
        elif typ == self.STRUCT:
            previous = 0
            while True:
                field_id, field_type = self.field_header(previous)
                if field_type == self.STOP:
                    return
                previous = field_id
                self.skip(field_type)
        elif typ in (self.LIST, self.SET):
            size, element_type = self.collection()
            for _ in range(size):
                self.skip(element_type)
        elif typ == self.MAP:
            size = self.varint()
            if size > 1_000_000:
                raise AuditError("Unreasonable map size in Parquet footer")
            if size:
                types = self.byte()
                key_type, value_type = types >> 4, types & 0x0F
                for _ in range(size):
                    self.skip(key_type)
                    self.skip(value_type)
        else:
            raise AuditError(f"Unsupported compact-protocol type {typ}")

    def schema_element_name(self) -> str | None:
        previous = 0
        name = None
        while True:
            field_id, typ = self.field_header(previous)
            if typ == self.STOP:
                return name
            previous = field_id
            if field_id == 4 and typ == self.BINARY:
                name = self.binary().decode("utf-8")
            else:
                self.skip(typ)

    def parquet_metadata(self) -> dict[str, Any]:
        previous = 0
        schema: list[str] | None = None
        row_count: int | None = None
        while True:
            field_id, typ = self.field_header(previous)
            if typ == self.STOP:
                break
            previous = field_id
            if field_id == 2 and typ == self.LIST:
                size, element_type = self.collection()
                if element_type != self.STRUCT:
                    raise AuditError("Parquet schema field is not a struct list")
                schema = []
                for _ in range(size):
                    name = self.schema_element_name()
                    if name:
                        schema.append(name)
            elif field_id == 3 and typ == self.I64:
                row_count = self.signed()
            elif field_id == 4:
                # Row groups may be large; row count and schema are already known.
                break
            else:
                self.skip(typ)
        if schema is None or row_count is None or row_count < 0:
            raise AuditError("Parquet footer did not contain schema and row count")
        return {"schema_fields": schema, "row_count": row_count}


def parquet_footer(repo: dict[str, Any], file_info: dict[str, Any]) -> dict[str, Any]:
    size = file_info.get("size")
    if not isinstance(size, int) or size < 8:
        raise AuditError(f"Missing/invalid parquet size for {repo['repo_id']}")
    resolve = f"https://huggingface.co/datasets/{repo['repo_id']}/resolve/{repo['revision']}/{repo['parquet_path']}"
    suffix, headers, status = fetch(resolve, range_header="bytes=-8")
    if status != 206 or len(suffix) != 8 or not suffix.endswith(b"PAR1"):
        raise AuditError("Pinned Parquet endpoint did not return a valid 8-byte ranged footer suffix")
    if headers.get("content-range") != f"bytes {size - 8}-{size - 1}/{size}":
        raise AuditError("Pinned Parquet suffix Content-Range does not match immutable file metadata")
    footer_len = int.from_bytes(suffix[:4], "little")
    if footer_len <= 0 or footer_len > MAX_FOOTER_BYTES or footer_len + 8 > size:
        raise AuditError(f"Parquet footer length outside audit bound: {footer_len}")
    start, end = size - footer_len - 8, size - 9
    footer, footer_headers, footer_status = fetch(resolve, range_header=f"bytes={start}-{end}")
    if footer_status != 206 or len(footer) != footer_len:
        raise AuditError("Pinned Parquet footer range response did not match requested length")
    content_range = footer_headers.get("content-range", "")
    if content_range != f"bytes {start}-{end}/{size}":
        raise AuditError(f"Unexpected Content-Range for pinned footer: {content_range}")
    metadata = CompactReader(footer).parquet_metadata()
    metadata.update({"footer_metadata_bytes": footer_len, "parquet_size_bytes": size, "parquet_url": resolve})
    return metadata


def audit_source(source: dict[str, Any]) -> dict[str, Any]:
    api = f"https://huggingface.co/api/datasets/{source['repo_id']}/revision/{source['revision']}"
    repo_data, repo_bytes = json_request(api)
    if not isinstance(repo_data, dict):
        raise AuditError(f"Expected repository metadata object: {api}")
    if repo_data.get("sha") != source["revision"]:
        raise AuditError(f"Resolved revision differs from requested pin for {source['repo_id']}")
    card_data = repo_data.get("cardData") or {}
    license_value = str(card_data.get("license", "")).lower()
    if license_value != source["license"]:
        raise AuditError(f"Pinned card license mismatch for {source['repo_id']}: {license_value!r}")

    tree_url = f"https://huggingface.co/api/datasets/{source['repo_id']}/tree/{source['revision']}?recursive=true&expand=true"
    tree, tree_bytes = json_request(tree_url)
    siblings = tree.get("siblings", []) if isinstance(tree, dict) else tree
    files = siblings
    if not isinstance(files, list):
        raise AuditError(f"Pinned file tree response has unexpected shape for {source['repo_id']}")
    file_info = next((item for item in files if item.get("path") == source["parquet_path"]), None)
    if not isinstance(file_info, dict):
        raise AuditError(f"Expected split file not found at exact pin: {source['parquet_path']}")
    lfs = file_info.get("lfs") or {}
    lfs_oid = str(lfs.get("oid", ""))
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", lfs_oid):
        raise AuditError(f"Expected LFS SHA-256 metadata missing for {source['repo_id']}")
    if lfs.get("size") != file_info.get("size"):
        raise AuditError(f"LFS and tree file sizes differ for {source['repo_id']}")

    readme_url = f"https://huggingface.co/datasets/{source['repo_id']}/resolve/{source['revision']}/README.md"
    readme, _, readme_status = fetch(readme_url)
    if readme_status != 200:
        raise AuditError(f"Pinned dataset card README unavailable for {source['repo_id']}")
    readme_text = readme.decode("utf-8")
    license_match = re.search(r"(?m)^license:\s*([a-z0-9.-]+)\s*$", readme_text)
    if not license_match or license_match.group(1).lower() != license_value:
        raise AuditError(f"Pinned README license frontmatter does not match metadata for {source['repo_id']}")
    footer = parquet_footer(source, file_info)
    missing = sorted(set(source["required_schema"]) - set(footer["schema_fields"]))
    if missing:
        raise AuditError(f"Required schema fields missing from {source['repo_id']}: {missing}")
    if source["repo_id"] == "Meddies/meddies-pii" and "id" in footer["schema_fields"]:
        raise AuditError("Expected source ID absence changed; re-evaluate grouping semantics")
    footer.update({"path": source["parquet_path"], "lfs_sha256": lfs_oid.removeprefix("sha256:")})

    card_split_claim = None
    if source["repo_id"] == "nvidia/Nemotron-PII":
        claim = re.search(r"(?i)(\d+)k\s+train\s*/\s*(\d+)k\s+test", readme_text)
        if claim:
            card_split_claim = {"train": int(claim.group(1)) * 1000, "test": int(claim.group(2)) * 1000}
    return {
        "repo_id": source["repo_id"],
        "revision": source["revision"],
        "config": source["config"],
        "split": source["split"],
        "license": license_value,
        "license_evidence": "cardData.license at immutable revision; exact pinned README bytes hashed",
        "license_source_sha256": sha256(readme),
        "card_sha256": sha256(readme),
        "revision_metadata_url": api,
        "revision_metadata_sha256": sha256(repo_bytes),
        "file_tree_metadata_url": tree_url,
        "file_tree_metadata_sha256": sha256(tree_bytes),
        "card_url": readme_url,
        "file": footer,
        "card_split_count_claim": card_split_claim,
        "card_count_consistent_with_footer": card_split_claim is None or card_split_claim["train"] == footer["row_count"],
        "excluded_derivatives": source["excluded_derivatives"],
        "adapter_fields": source["required_schema"],
        "positive_parsing": {
            "supported_by_adapter": source["repo_id"] == "nvidia/Nemotron-PII" and "spans" in footer["schema_fields"] or source["repo_id"] == "Meddies/meddies-pii" and "label" in footer["schema_fields"],
            "verification_scope": "schema plus repository parser/tests; no data rows were scanned",
        },
        "grouping": (
            {"field": "uid", "status": "schema exposes source UID; parser uses uid with row-index fallback"}
            if source["repo_id"] == "nvidia/Nemotron-PII"
            else {"field": None, "status": "no stable id field; adapter falls back to row index. Grouping by document_type, document_label, text_format, edge_case, document_length is only a conservative metadata family proxy, not document identity; assign stable groups before partitioning."}
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Fresh, ignored results directory; existing paths are rejected")
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error(f"output must be a fresh path: {args.output}")
    try:
        sources = [audit_source(item) for item in SOURCES]
    except AuditError as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    unresolved = [
        "Actual row-level annotation value encodings and malformed-row rates were not scanned; adapter parsing is supported by declared fields and local parser tests only.",
        "Meddies has no stable row ID in the Parquet schema; metadata-family grouping is not proof of document/template independence and must be assigned before splitting.",
        "Nemotron revision provides UID in the schema, but uniqueness/completeness of row-level UIDs was not checked.",
        "License terms and source cards should be reviewed for intended redistribution/training use; CC-BY-NC-4.0 restricts commercial use of Meddies-derived material.",
    ]
    for source in sources:
        if source["card_count_consistent_with_footer"] is False:
            unresolved.append(
                f"{source['repo_id']} pinned README states {source['card_split_count_claim']['train']} train rows, but pinned Parquet footer reports {source['file']['row_count']}; use the verified file footer count and investigate the stale/inconsistent card statement."
            )
    manifest = {
        "schema_version": 1,
        "status": "audited",
        "scope": "Pinned source metadata, split file identity, Parquet schema and footer row counts. No corpus rows downloaded or parsed.",
        "audit_script_sha256": sha256(Path(__file__).read_bytes()),
        "sources": sources,
        "unresolved_checks": unresolved,
    }
    args.output.mkdir(parents=True)
    target = args.output / "manifest.json"
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": manifest["status"], "manifest": str(target), "sources": [{"repo_id": x["repo_id"], "rows": x["file"]["row_count"], "schema_fields": x["file"]["schema_fields"]} for x in sources]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
