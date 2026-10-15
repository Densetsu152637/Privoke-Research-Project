"""Host inference-only native three-detector PIPE3 server."""
import argparse
import os
from pathlib import Path


def main():
    from privoke_eval import pipeline_v1_v3 as core
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--name", choices=core.NAMES, required=True)
    parser.add_argument("--port", type=int, default=53771)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args()
    for key, value in core.PRODUCT_ENV.items():
        os.environ[key] = value
    core.configure(args.repository)
    from privoke_eval.pipeline_v1_v3_serving import serve
    serve(args.results, args.name, args.port, args.ready_file)


if __name__ == "__main__":
    main()
