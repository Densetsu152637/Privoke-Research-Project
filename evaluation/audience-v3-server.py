"""Host loopback server for an AU3-sealed BEFORE or AFTER native CPU package."""
import argparse
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--name", choices=[p + "-" + t for p in ("before", "after") for t in ("efficient", "balanced", "quality")], required=True)
    parser.add_argument("--port", type=int, default=50381)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args()
    for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS"):
        os.environ[key] = "4"
    from privoke_eval import privacy_encoder_v3 as en
    en.ph.configure_repository(args.repository)
    from privoke_eval.audience_v3_serving import serve
    serve(args.results, args.name, args.port, args.ready_file)


if __name__ == "__main__":
    main()
