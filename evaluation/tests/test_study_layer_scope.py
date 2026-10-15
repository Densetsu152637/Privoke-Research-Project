"""Legacy product-scope refusal and sustained semantic-only output boundaries."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from study_scope import require_product_pipeline

EVALUATION = Path(__file__).resolve().parents[1]
FUZZER_STUDIES = (
    "contextual", "class-balanced", "mean-category", "role-quota", "local-sgd", "decision-margin",
)
CALLERS = {f"run-{name}-fuzzer-study.py": ["plan", "--output", "unused"] for name in FUZZER_STUDIES}
CALLERS.update({
    "run-independent-updates.py": ["--experiment-id", "unused"],
    "run-model-profile-study.py": [],
    "run-training-curve.py": ["--experiment-id", "unused"],
    "run-public-negative-study.py": [],
    "run-public-negative-curve.py": ["--experiment-id", "unused", "--study-manifest", "unused"],
})


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), EVALUATION / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {name: load(name) for name in CALLERS}

    def test_every_legacy_cli_refuses_before_data_or_subprocess(self):
        for name, arguments in CALLERS.items():
            with self.subTest(caller=name), patch.object(sys, "argv", [name, *arguments]), \
                 patch("pathlib.Path.open", side_effect=AssertionError("data accessed")), \
                 patch("pathlib.Path.mkdir", side_effect=AssertionError("output created")), \
                 patch("subprocess.run", side_effect=AssertionError("process started")), \
                 patch("subprocess.check_output", side_effect=AssertionError("process started")), \
                 contextlib.redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as stopped:
                    self.modules[name].main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn("not an LLM-only study", error.getvalue())
                self.assertIn("--allow-product-pipeline", error.getvalue())

    def test_help_is_available_without_execution(self):
        for name, module in self.modules.items():
            with self.subTest(caller=name), patch.object(sys, "argv", [name, "--help"]), \
                 patch("subprocess.run", side_effect=AssertionError("process started")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as stopped:
                    module.main()
                self.assertEqual(stopped.exception.code, 0)
                self.assertIn("--allow-product-pipeline", output.getvalue())

    def test_each_parser_accepts_explicit_product_selection(self):
        class ScopeSelected(Exception):
            pass

        def selected(args, parser):
            require_product_pipeline(args, parser)
            raise ScopeSelected

        for name, arguments in CALLERS.items():
            with self.subTest(caller=name), patch.object(sys, "argv", [name, *arguments, "--allow-product-pipeline"]), \
                 patch.object(self.modules[name], "require_product_pipeline", side_effect=selected):
                with self.assertRaises(ScopeSelected):
                    self.modules[name].main()

    def test_all_inherited_drivers_require_explicit_product_scope(self):
        state = {"prefix": "scope-test", "prepared": "unused", "runtime_target": "unused:1"}
        for name in FUZZER_STUDIES:
            driver = self.modules[f"run-{name}-fuzzer-study.py"].Driver
            with self.subTest(driver=name):
                with self.assertRaisesRegex(ValueError, "not an LLM-only study"):
                    driver(SimpleNamespace(), {})
                args = SimpleNamespace(allow_product_pipeline=True, project_name="unused")
                self.assertIsInstance(driver(args, state), driver)

    def test_truthy_values_do_not_substitute_for_explicit_flag(self):
        for value in (None, False, 1, "true"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_product_pipeline(SimpleNamespace(allow_product_pipeline=value))

    def test_scope_guard_is_bound_by_legacy_computation_inventory(self):
        module = self.modules["run-contextual-fuzzer-study.py"]
        self.assertIn(EVALUATION / "study_scope.py", module.computation_sources())

    def test_authorized_public_negative_parent_forwards_product_scope_to_children(self):
        module = self.modules["run-public-negative-study.py"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            curriculum = root / "evaluation/results/public-negative-curriculum"
            curriculum.mkdir(parents=True)
            data = b"synthetic test data\n"
            (curriculum / "prompts.jsonl").write_bytes(data)
            (curriculum / "manifest.json").write_text(json.dumps({
                "curriculum_sha256": hashlib.sha256(data).hexdigest()}), encoding="utf-8")
            model = root / "models/privoke-balanced.json"
            model.parent.mkdir()
            model.write_text("synthetic model bytes", encoding="utf-8")
            with patch.object(module, "ROOT", root), patch.object(module, "PRIOR", model), \
                 patch.object(sys, "argv", [module.__file__, "--allow-product-pipeline"]), \
                 patch.object(module, "call", return_value="0"), patch.object(module, "restore"), \
                 patch.object(module.subprocess, "check_output", return_value="test-source"), \
                 patch.object(module.subprocess, "run") as child, \
                 contextlib.redirect_stdout(io.StringIO()):
                module.main()
            self.assertEqual(child.call_count, 3)
            for invocation in child.call_args_list:
                command = invocation.args[0]
                self.assertEqual(command[1], "evaluation/run-independent-updates.py")
                self.assertEqual(command.count("--allow-product-pipeline"), 1)


class SustainedSemanticTests(unittest.TestCase):
    def test_semantic_summary_and_mixed_contract_rejection(self):
        wrapper = load("run-long-fuzzer-study.py")
        cell = {"semantic": {"metrics": {"recall": .8, "specificity": .7}}}
        summary = {"profiles": {"balanced": {"checkpoints": {"0": cell, "20": cell},
                   "final_cycle": 20, "timed_training_seconds": 7200, "attempts": 20,
                   "accepted_updates": 10}}}
        rendered = "\n".join(wrapper.semantic_results_lines(summary))
        self.assertIn("semantic", rendered)
        self.assertNotIn("pipeline", rendered)
        cell["pipeline"] = cell["semantic"]
        with self.assertRaisesRegex(ValueError, "exactly the semantic layer"):
            wrapper.semantic_results_lines(summary)


if __name__ == "__main__":
    unittest.main()
