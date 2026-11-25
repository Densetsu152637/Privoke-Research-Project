"""Tests of the Stage 13b declared templates and of the template freeze (synthetic rows only)."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import adversarial_evasion_transforms as stage3  # noqa: E402
import e2e_evasion as e2e  # noqa: E402
import e2e_evasion_transforms as tx  # noqa: E402

TEXT = "Hello, my name is Alice Smith and my social security number is 123-45-6789, email alice@example.org."


def span(value, label):
    start = TEXT.index(value)
    return {"start": start, "end": start + len(value), "label": label}


ROW = {"id": "r1", "group_id": "g1", "text": TEXT, "source_dataset": "synthetic/a", "expected_has_pii": True,
       "entities": [span("Alice Smith", "name"), span("123-45-6789", "ssn"), span("alice@example.org", "EMAIL")]}
ONE_ENTITY = dict(ROW, id="r2", entities=[span("Alice Smith", "name")])
NO_ENTITY = dict(ROW, id="r3", entities=[])
SHORT = dict(ROW, id="r4", entities=[{"start": 0, "end": 3, "label": "name"}])


class FragmentedIdentifierTests(unittest.TestCase):
    def test_it_is_deterministic_and_changes_the_text(self):
        first = tx.apply_e2e_variant("fragmented_identifier", ROW)
        self.assertEqual(first, tx.apply_e2e_variant("fragmented_identifier", ROW))
        self.assertNotEqual(first, TEXT)

    def test_no_identifier_stays_contiguous_but_each_is_recoverable_from_its_halves(self):
        out = tx.apply_e2e_variant("fragmented_identifier", ROW)
        for entity in ROW["entities"]:
            value = TEXT[entity["start"]:entity["end"]]
            half = len(value) // 2
            self.assertNotIn(value, out)
            self.assertTrue(any(t.format(a=value[:half], b=value[half:]) in out for t in tx.FRAGMENT_TEMPLATES), value)

    def test_context_outside_the_identifiers_is_kept(self):
        out = tx.apply_e2e_variant("fragmented_identifier", ROW)
        self.assertTrue(out.startswith("Hello, my name is "))
        self.assertIn(" and my social security number is ", out)

    def test_it_is_not_applicable_without_a_long_enough_identifier(self):
        self.assertIsNone(tx.apply_e2e_variant("fragmented_identifier", NO_ENTITY))
        self.assertIsNone(tx.apply_e2e_variant("fragmented_identifier", SHORT))

    def test_the_draw_depends_on_the_row_id(self):
        outs = {tx.apply_e2e_variant("fragmented_identifier", dict(ROW, id=f"r{i}")) for i in range(30)}
        self.assertGreater(len(outs), 1)


class MixedLanguageTests(unittest.TestCase):
    def test_it_is_deterministic_and_keeps_every_value(self):
        out = tx.apply_e2e_variant("mixed_language", ROW)
        self.assertEqual(out, tx.apply_e2e_variant("mixed_language", ROW))
        for value in ("Alice Smith", "123-45-6789", "alice@example.org"):
            self.assertIn(value, out)

    def test_it_mixes_languages_and_differs_from_every_single_language_variant(self):
        out = tx.apply_e2e_variant("mixed_language", ROW)
        singles = {stage3.apply_variant(f"multilingual_{lang}", ROW) for lang in stage3.MULTILINGUAL}
        self.assertNotIn(out, singles)
        sentences = [s for s in out.split(". ")]
        self.assertGreaterEqual(len(sentences), 2)
        matched = []
        for lang, table in stage3.MULTILINGUAL.items():
            for template in table.values():
                prefix = template.split("{v}")[0]
                matched.extend(lang for s in sentences if prefix and s.startswith(prefix.rstrip()))
        self.assertGreaterEqual(len(set(matched)), 2, "more than one language appears in one prompt")

    def test_a_single_identifier_is_not_a_mixture(self):
        self.assertIsNone(tx.apply_e2e_variant("mixed_language", ONE_ENTITY))
        self.assertIsNone(tx.apply_e2e_variant("mixed_language", NO_ENTITY))


class RegistryTests(unittest.TestCase):
    def test_the_variant_set_is_stage3_plus_two_with_unique_names(self):
        self.assertEqual(len(e2e.STAGE3_VARIANTS), 20)
        self.assertEqual(e2e.E2E_VARIANTS, ("fragmented_identifier", "mixed_language"))
        self.assertEqual(len(set(e2e.ALL_VARIANTS)), 22)
        for name in e2e.E2E_VARIANTS:
            family, removing = e2e.variant_meta(name)
            self.assertEqual((family, removing), (name, False))
        self.assertTrue(e2e.variant_meta("indirect_pointer")[1])

    def test_stage3_transforms_are_untouched(self):
        self.assertEqual(tx.lf_sha256(Path(stage3.__file__)), e2e.STAGE3_TRANSFORMS_SHA256)
        self.assertEqual(stage3.GENERATOR_REVISION, e2e.STAGE3_GENERATOR_REVISION)

    def test_the_templates_import_nothing_that_could_read_detector_output(self):
        imports = {line.split()[1].split(".")[0] for line in Path(tx.__file__).read_text(encoding="utf-8").splitlines()
                   if line.startswith(("import ", "from ")) and not line.startswith("from __future__")}
        self.assertEqual(imports, {"hashlib", "random", "pathlib", "typing", "adversarial_evasion_transforms"})


class TemplateFreezeTests(unittest.TestCase):
    def test_the_committed_pin_matches_the_templates(self):
        digest = tx.lf_sha256(tx.template_file())
        self.assertEqual(e2e.read_pin(), digest, "edit the templates only before any PriVoke output; otherwise this stage must be redone")
        result = e2e.verify_templates(digest)
        self.assertTrue(result["ok"], result)

    def test_verify_templates_exits_zero_only_for_the_frozen_hash(self):
        digest = tx.lf_sha256(tx.template_file())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(e2e.main(["verify-templates", "--expected-sha256", digest]), 0)
            self.assertEqual(e2e.main(["verify-templates", "--expected-sha256", "0" * 64]), 1)

    def test_an_edited_template_or_a_missing_pin_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = Path(tmp) / "templates.py"
            template.write_text("A = 1\n", encoding="utf-8", newline="\n")
            digest = tx.lf_sha256(template)
            allowlist = Path(tmp) / "allow.json"
            allowlist.write_text(json.dumps({e2e.TEMPLATE_PIN_KEY: digest}), encoding="utf-8")
            self.assertTrue(e2e.verify_templates(digest, template, allowlist=allowlist)["ok"])
            template.write_text("A = 2\n", encoding="utf-8", newline="\n")
            edited = e2e.verify_templates(digest, template, allowlist=allowlist)
            self.assertFalse(edited["ok"])
            self.assertFalse(edited["checks"]["template_matches_expected"])
            self.assertFalse(edited["checks"]["template_matches_pin"])
            nopin = Path(tmp) / "empty.json"
            nopin.write_text("{}", encoding="utf-8")
            self.assertFalse(e2e.verify_templates(tx.lf_sha256(template), template, allowlist=nopin)["checks"]["template_matches_pin"])

    def test_crlf_and_lf_checkouts_hash_the_same(self):
        with tempfile.TemporaryDirectory() as tmp:
            lf, crlf = Path(tmp) / "a.py", Path(tmp) / "b.py"
            lf.write_bytes(b"x = 1\ny = 2\n")
            crlf.write_bytes(b"x = 1\r\ny = 2\r\n")
            self.assertEqual(tx.lf_sha256(lf), tx.lf_sha256(crlf))

    def test_the_pin_file_pins_only_the_template_module_for_this_stage(self):
        pins = json.loads((ROOT / "evaluation" / "s13_allowlist.json").read_text(encoding="utf-8"))
        self.assertIn(e2e.TEMPLATE_PIN_KEY, pins)


if __name__ == "__main__":
    unittest.main()
