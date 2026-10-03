import tempfile
import unittest
from pathlib import Path
import importlib.util

SCRIPT = Path(__file__).resolve().parents[1] / "audit-external-pii-sources.py"
SPEC = importlib.util.spec_from_file_location("external_source_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
AuditError, CompactReader, SOURCES, main = AUDIT.AuditError, AUDIT.CompactReader, AUDIT.SOURCES, AUDIT.main


class ExternalSourceAuditTests(unittest.TestCase):
    def test_reads_parquet_schema_and_row_count_without_row_groups(self):
        # FileMetaData: version=1, one SchemaElement(name="text"), num_rows=42.
        encoded = bytes((0x15, 0x02, 0x19, 0x1C, 0x48, 0x04)) + b"text" + bytes((0x00, 0x16, 0x54, 0x00))
        result = CompactReader(encoded).parquet_metadata()
        self.assertEqual(result, {"schema_fields": ["text"], "row_count": 42})

    def test_rejects_truncated_compact_metadata(self):
        with self.assertRaises(AuditError):
            CompactReader(bytes((0x19, 0x1C))).parquet_metadata()

    def test_source_selection_is_pinned_to_train_views(self):
        self.assertEqual(
            [(item["repo_id"], item["config"], item["split"]) for item in SOURCES],
            [("nvidia/Nemotron-PII", "default", "train"), ("Meddies/meddies-pii", "english", "train")],
        )
        self.assertEqual(SOURCES[0]["revision"], "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed")
        self.assertEqual(SOURCES[1]["revision"], "6a5c8f5441e3b421d983c9741770262365acdd77")

    def test_cli_rejects_reusing_an_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit) as raised:
                main(["--output", str(Path(directory))])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
