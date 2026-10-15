import argparse
import json
import sys
import time
import uuid
from pathlib import Path

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from prompt_testing import add_test_prompt_args, run_prompt_tests


def run_training_cycle(args) -> None:
    import grpc
    from privoke.v1 import parameters_pb2, parameters_pb2_grpc

    request_id = (
        args.request_id or f"privoke-cli-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    )
    metadata={"initiator":"privoke-fuzzer-cli"}
    if args.training_policy is not None:
        from privoke_model import window_training as window
        if not args.window_manifest_sha256 or not args.component_manifest_sha256:
            raise ValueError("Window policy requires both explicit prepared manifest pins.")
        metadata.update(contextual_sampling_strategy=window.SAMPLER,
            expected_contextual_training_optimizer=window.POLICY,expected_contextual_training_objective=window.OBJECTIVE,
            expected_contextual_candidate_eligibility=window.ELIGIBILITY,expected_contextual_training_scope="full_encoder")
        metadata.update({"expected_"+window.CONFIG_KEY:window.canonical(window.CONFIG),
            "expected_"+window.WINDOW_KEY:args.window_manifest_sha256,"expected_"+window.REFERENCE_KEY:args.component_manifest_sha256})
        window.expectations(metadata)
    elif args.window_manifest_sha256 or args.component_manifest_sha256:
        raise ValueError("Manifest pins require an explicit window training policy.")
    with grpc.insecure_channel(args.target) as channel:
        stub=parameters_pb2_grpc.FuzzerServiceStub(channel)
        method=stub.RunUnderlyingTrainingCycle if args.training_policy or args.underlying else stub.RunTrainingCycle
        response = method(
            parameters_pb2.FuzzerTrainingRequest(
                request_id=request_id,
                source_id=args.source_id,
                model_id=args.model_id,
                prompt_count=args.prompt_count if args.prompt_count is not None else (256 if args.training_policy else 8),
                seed=args.seed,
                metadata=metadata,
            ),
            timeout=args.timeout if args.timeout is not None else (1800. if args.training_policy else 60.),
        )
    print(
        json.dumps(
            {
                "accepted": response.accepted,
                "model_id": response.model_id,
                "base_version": response.base_version,
                "applied_version": response.applied_version,
                "prompts_generated": response.prompts_generated,
                "message": response.message,
                "metadata": dict(response.metadata),
            },
            indent=2,
            sort_keys=True,
        )
    )
    if not response.accepted:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="PriVoke fuzzer CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser(
        "train",
        help="Request a fuzzer training cycle and persist the resulting model version.",
    )
    train_parser.add_argument("--target", default="privoke-fuzzer:50053")
    train_parser.add_argument("--model-id", default="privoke-baseline")
    train_parser.add_argument("--source-id", default="privoke-fuzzer-cli")
    train_parser.add_argument("--request-id")
    train_parser.add_argument("--prompt-count", type=int, default=None)
    train_parser.add_argument("--training-policy",choices=("full_projected_adam64_window_checkpoint_v1",))
    train_parser.add_argument("--underlying",action="store_true",help="Use the FULL underlying-model endpoint.")
    train_parser.add_argument("--window-manifest-sha256")
    train_parser.add_argument("--component-manifest-sha256")
    train_parser.add_argument("--seed", type=int, default=1337)
    train_parser.add_argument("--timeout", type=float, default=None)
    train_parser.set_defaults(handler=run_training_cycle)

    test_parser = subparsers.add_parser(
        "test-prompts",
        help="Run prompt tests against selected detection layers.",
    )
    add_test_prompt_args(test_parser)
    test_parser.set_defaults(handler=run_prompt_tests)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
