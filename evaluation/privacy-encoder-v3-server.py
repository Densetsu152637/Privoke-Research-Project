"""Host loopback server for a sealed EN3 native CPU package."""
import argparse
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--tier", choices=("efficient", "balanced", "quality"), required=True)
    parser.add_argument("--port", type=int, default=50371)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args()
    for name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS"):
        os.environ[name] = "4"
    from privoke_eval import privacy_encoder_v3 as core
    core.ph.configure_repository(args.repository)
    from privoke_eval.privacy_encoder_v3_serving import serve
    serve(args.results, args.tier, args.port, args.ready_file)


if __name__ == "__main__":
    main()
