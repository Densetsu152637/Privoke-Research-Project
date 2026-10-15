from __future__ import annotations

import itertools
import math
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
for path in (PACKAGE_ROOT, PACKAGE_ROOT / "generated", REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.telemetry import event_emitter
from src.telemetry.privacy import (
    DAILY_EPSILON_DEFAULT,
    DIMENSIONS,
    DOMAINS,
    DailyPrivacyBudget,
    default_ledger_path,
    generalized_randomized_response,
    grr_probabilities,
    randomize_report,
    validate_privacy_config,
)


class _FixedRng:
    def __init__(self, random_value: float, choice_value: str | None = None):
        self.random_value = random_value
        self.choice_value = choice_value

    def random(self) -> float:
        return self.random_value

    def choice(self, values):
        return self.choice_value if self.choice_value in values else values[0]


class TelemetryPrivacyTests(unittest.TestCase):
    def test_grr_probability_and_likelihood_bound_for_every_domain_pair(self) -> None:
        epsilon = 0.7
        for domain in DOMAINS.values():
            for true_value, alternate_value in itertools.permutations(domain, 2):
                probabilities = grr_probabilities(true_value, domain, epsilon)
                denominator = math.exp(epsilon) + len(domain) - 1
                p = math.exp(epsilon) / denominator
                q = 1 / denominator
                self.assertAlmostEqual(probabilities[true_value], p)
                self.assertAlmostEqual(sum(probabilities.values()), 1.0)
                self.assertTrue(all(
                    math.isclose(probability, q) for value, probability in probabilities.items()
                    if value != true_value
                ))

                alternate = grr_probabilities(alternate_value, domain, epsilon)
                for output in domain:
                    self.assertLessEqual(
                        probabilities[output] / alternate[output],
                        math.exp(epsilon) + 1e-12,
                    )

    def test_grr_sampler_uses_truthful_probability_boundary(self) -> None:
        domain = ("a", "b", "c")
        p = grr_probabilities("a", domain, 0.6)["a"]
        self.assertEqual(
            generalized_randomized_response("a", domain, 0.6, rng=_FixedRng(p - 1e-12)),
            "a",
        )
        self.assertEqual(
            generalized_randomized_response("a", domain, 0.6, rng=_FixedRng(p, "c")),
            "c",
        )

    def test_five_field_composition_respects_event_epsilon(self) -> None:
        epsilon = 1.0
        first = {dimension: domain[0] for dimension, domain in DOMAINS.items()}
        second = dict(first)
        for dimension, domain in DOMAINS.items():
            second[dimension] = domain[-1]

        per_field_epsilon = epsilon / len(DIMENSIONS)
        distributions = {}
        for dimension, domain in DOMAINS.items():
            distributions[(dimension, first[dimension])] = grr_probabilities(
                first[dimension], domain, per_field_epsilon
            )
            distributions[(dimension, second[dimension])] = grr_probabilities(
                second[dimension], domain, per_field_epsilon
            )

        max_joint_ratio = 1.0
        output_domains = [DOMAINS[dimension] for dimension in DIMENSIONS]
        for outputs in itertools.product(*output_domains):
            p_first = math.prod(
                distributions[(dimension, first[dimension])][output]
                for dimension, output in zip(DIMENSIONS, outputs)
            )
            p_second = math.prod(
                distributions[(dimension, second[dimension])][output]
                for dimension, output in zip(DIMENSIONS, outputs)
            )
            max_joint_ratio = max(max_joint_ratio, p_first / p_second)
        self.assertLessEqual(max_joint_ratio, math.exp(epsilon) + 1e-12)

        values = dict(first)
        # Deterministic RNG pins output to each truth value while checking shape.
        p_by_dimension = {
            dimension: grr_probabilities(value, DOMAINS[dimension], per_field_epsilon)[value]
            for dimension, value in values.items()
        }
        protected = randomize_report(
            values,
            epsilon,
            rng=_FixedRng(min(p_by_dimension.values()) - 1e-12),
        )
        self.assertEqual(set(protected), set(DIMENSIONS))
        for dimension, output in protected.items():
            self.assertIn(output, DOMAINS[dimension])

    def test_grr_and_report_reject_invalid_domains_and_values(self) -> None:
        for domain in ((), ("only",), ("same", "same")):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                grr_probabilities("x", domain, 1.0)
        with self.assertRaises(ValueError):
            grr_probabilities("missing", ("a", "b"), 1.0)
        with self.assertRaises(ValueError):
            randomize_report({"action": "ALLOW"}, 1.0)

    def test_privacy_config_finite_bounds_and_precision(self) -> None:
        for event_epsilon, daily_epsilon in ((0.5, 0.5), (1.0, 8.0), (2.0, 8.0)):
            validate_privacy_config(event_epsilon, daily_epsilon)
        for event_epsilon, daily_epsilon in (
            (0.49, 1.0), (2.01, 8.0), (math.nan, 8.0), (math.inf, 8.0),
            (1.0, 0.99), (1.0, 8.01), (1.0, math.nan), (1.0, math.inf),
            (0.5000001, 1.0), (1.0, 1.0000001),
        ):
            with self.subTest(event_epsilon=event_epsilon, daily_epsilon=daily_epsilon):
                with self.assertRaises(ValueError):
                    validate_privacy_config(event_epsilon, daily_epsilon)

    def test_native_ledger_default_is_stable_and_configurable(self) -> None:
        with patch.dict(os.environ, {
            "TELEMETRY_PRIVACY_LEDGER_PATH": "",
            "LOCALAPPDATA": r"C:\\StableState",
        }, clear=False):
            if os.name == "nt":
                self.assertEqual(
                    default_ledger_path(),
                    Path(r"C:\\StableState") / "PriVoke" / "telemetry-budget.sqlite3",
                )
        with patch.dict(os.environ, {"TELEMETRY_PRIVACY_LEDGER_PATH": "~/custom-ledger.sqlite3"}):
            self.assertEqual(default_ledger_path(), Path.home() / "custom-ledger.sqlite3")

    def test_daily_budget_cap_survives_reopen_and_resets_on_utc_day(self) -> None:
        day_one = datetime(2026, 1, 1, 23, 50, tzinfo=timezone.utc)
        day_two = day_one + timedelta(minutes=20)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.sqlite3"
            budget = DailyPrivacyBudget(path, DAILY_EPSILON_DEFAULT)
            self.assertTrue(all(budget.reserve(1.0, now=day_one) for _ in range(8)))
            self.assertFalse(budget.reserve(1.0, now=day_one))

            restarted = DailyPrivacyBudget(path, DAILY_EPSILON_DEFAULT)
            self.assertFalse(restarted.reserve(1.0, now=day_one))
            self.assertTrue(restarted.reserve(1.0, now=day_two))

    def test_ledger_uses_utc_day_and_rejects_clock_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            budget = DailyPrivacyBudget(Path(temporary) / "ledger.sqlite3", 1.0)
            later_utc = datetime(2026, 3, 1, 0, 15, tzinfo=timezone.utc)
            earlier_local = datetime(2026, 2, 28, 15, 30, tzinfo=timezone(timedelta(hours=14)))
            self.assertTrue(budget.reserve(1.0, now=later_utc))
            with self.assertRaisesRegex(RuntimeError, "budget unavailable"):
                budget.reserve(0.5, now=earlier_local)

    def test_corrupt_and_unavailable_ledgers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corrupt = Path(temporary) / "corrupt.sqlite3"
            corrupt.write_bytes(b"not a sqlite database")
            with self.assertRaisesRegex(RuntimeError, "budget unavailable"):
                DailyPrivacyBudget(corrupt, 1.0).reserve(1.0)

            parent_file = Path(temporary) / "parent-file"
            parent_file.write_text("x", encoding="utf-8")
            unavailable = DailyPrivacyBudget(parent_file / "ledger.sqlite3", 1.0)
            with self.assertRaisesRegex(RuntimeError, "budget unavailable"):
                unavailable.reserve(1.0)

    def test_concurrent_reservations_never_overspend_daily_budget(self) -> None:
        fixed_day = datetime(2026, 4, 2, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ledger.sqlite3"

            def reserve_one(_: int) -> bool:
                return DailyPrivacyBudget(path, 8.0).reserve(1.0, now=fixed_day)

            with ThreadPoolExecutor(max_workers=12) as executor:
                results = list(executor.map(reserve_one, range(24)))
            self.assertEqual(sum(results), 8)
            self.assertFalse(DailyPrivacyBudget(path, 8.0).reserve(1.0, now=fixed_day))

    def test_event_packet_contains_only_randomized_bounded_fields(self) -> None:
        category = SimpleNamespace(
            sensitivity=lambda: SimpleNamespace(name="S2"),
            categories=lambda: [SimpleNamespace(name="HEALTH"), SimpleNamespace(name="CHILD")],
        )
        analysis = SimpleNamespace(
            action=SimpleNamespace(name="WARN"),
            result=SimpleNamespace(
                classification=category,
                metadata={"model_version": "v0.3.0+train.17"},
            ),
        )
        observed_true_values = {}

        def identity_randomizer(values, epsilon):
            observed_true_values.update(values)
            return dict(values)

        with patch.object(event_emitter, "randomize_report", side_effect=identity_randomizer):
            packet = event_emitter.StructuredEventEmitter().build_packet(analysis)

        self.assertEqual(observed_true_values["primary_category"], "CHILD")
        self.assertEqual(observed_true_values["model_version"], "v0.3.0")
        packet_fields = {field.name for field, _ in packet.ListFields()}
        self.assertEqual(
            packet_fields,
            {"time_bucket", "action", "primary_category", "risk_bucket", "model_version",
             "privacy_mechanism", "privacy_epsilon"},
        )
        self.assertEqual(set(packet.DESCRIPTOR.fields_by_name), packet_fields)

    def test_unknown_category_and_model_release_map_to_fixed_other_values(self) -> None:
        classification = SimpleNamespace(
            sensitivity=lambda: SimpleNamespace(name="S1"),
            categories=lambda: [SimpleNamespace(name="PRIVATE_NEW_CATEGORY")],
        )
        analysis = SimpleNamespace(
            action=SimpleNamespace(name="ALLOW"),
            result=SimpleNamespace(
                classification=classification,
                metadata={"model_version": "v9.9.9+train.500000"},
            ),
        )
        observed = {}

        def identity_randomizer(values, epsilon):
            observed.update(values)
            return dict(values)

        with patch.object(event_emitter, "randomize_report", side_effect=identity_randomizer):
            event_emitter.StructuredEventEmitter().build_packet(analysis)
        self.assertEqual(observed["primary_category"], "NONE")
        self.assertEqual(observed["model_version"], "OTHER")

    def test_reporter_suppresses_outgoing_packet_after_budget_exhaustion(self) -> None:
        analysis = SimpleNamespace(
            action=SimpleNamespace(name="ALLOW"),
            result=SimpleNamespace(classification=None, metadata={"model_version": "v0.3.0"}),
        )
        sent_packets = []

        class Channel:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        class Stub:
            def RecordTelemetry(self, packet, timeout):
                sent_packets.append(packet)
                return SimpleNamespace(accepted=True)

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(event_emitter, "grpc_channel", return_value=Channel()), \
                patch.object(event_emitter.telemetry_pb2_grpc, "TelemetryServiceStub", return_value=Stub()):
            reporter = event_emitter.TelemetryReporter(
                target="unused:50055",
                event_epsilon=0.5,
                daily_epsilon=0.5,
                ledger_path=str(Path(temporary) / "ledger.sqlite3"),
            )
            try:
                reporter.report(analysis)
                reporter.report(analysis)
            finally:
                reporter.close()
        self.assertEqual(len(sent_packets), 1)
        self.assertEqual(sent_packets[0].privacy_epsilon, 0.5)

    def test_budget_is_reserved_before_packet_build_and_failed_build_is_not_refunded(self) -> None:
        analysis = SimpleNamespace(
            action=SimpleNamespace(name="ALLOW"),
            result=SimpleNamespace(classification=None, metadata={}),
        )

        class Channel:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        class Stub:
            def RecordTelemetry(self, packet, timeout):
                raise AssertionError("no packet should be sent after packet build fails")

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(event_emitter, "grpc_channel", return_value=Channel()), \
                patch.object(event_emitter.telemetry_pb2_grpc, "TelemetryServiceStub", return_value=Stub()):
            path = Path(temporary) / "ledger.sqlite3"
            reporter = event_emitter.TelemetryReporter(
                target="unused:50055", event_epsilon=0.5, daily_epsilon=0.5,
                ledger_path=str(path),
            )
            try:
                with patch.object(reporter.emitter, "build_packet", side_effect=ValueError("test")):
                    reporter.report(analysis)
                self.assertTrue(reporter._queue.empty())
                self.assertFalse(DailyPrivacyBudget(path, 0.5).reserve(0.5))
            finally:
                reporter.close()


if __name__ == "__main__":
    unittest.main()
