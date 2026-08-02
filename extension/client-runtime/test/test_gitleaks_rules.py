from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = PACKAGE_ROOT.parents[1] / "shared/python"
for path in (PACKAGE_ROOT, SHARED_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.regex.rules_gitleaks import GITLEAKS_CONFIG_PATH, gitleaks_rules


class GitleaksRuleImportTests(unittest.TestCase):
    def test_imports_official_gitleaks_catalog(self) -> None:
        rules = gitleaks_rules()

        self.assertGreater(len(rules), 100)
        self.assertTrue(all(rule.name.startswith("gitleaks_") for rule in rules))
        for rule in rules[:20]:
            rule.compile()

    def test_catalog_file_is_vendored_with_runtime(self) -> None:
        self.assertTrue(GITLEAKS_CONFIG_PATH.exists())

    def test_skips_regexes_python_cannot_compile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "gitleaks.toml"
            config_path.write_text(
                textwrap.dedent(
                    r"""
                    [[rules]]
                    id = "valid-secret"
                    regex = '''secret-[[:alnum:]]{8}'''

                    [[rules]]
                    id = "invalid-secret"
                    regex = '''(?P<broken'''
                    """
                ),
                encoding="utf-8",
            )

            rules = gitleaks_rules(config_path)

        self.assertEqual(["gitleaks_valid_secret"], [rule.name for rule in rules])
        rules[0].compile()

    def test_skips_rules_that_require_allowlist_logic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "gitleaks.toml"
            config_path.write_text(
                textwrap.dedent(
                    r"""
                    [[rules]]
                    id = "allowlisted-secret"
                    regex = '''secret-[A-Za-z0-9]{8}'''

                        [[rules.allowlists]]
                        regexes = ['''secret-EXAMPLE''']
                    """
                ),
                encoding="utf-8",
            )

            rules = gitleaks_rules(config_path)

        self.assertEqual([], rules)


if __name__ == "__main__":
    unittest.main()
