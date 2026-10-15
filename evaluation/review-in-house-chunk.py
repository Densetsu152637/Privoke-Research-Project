"""Read only /chunk; write explicit actor judgments only to /response."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python")]
from privoke_eval.in_house_review_transport import (  # noqa: E402
    MAX_REQUEST_BYTES, read_chunk_page, write_chunk_response,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    read = sub.add_parser("read")
    read.add_argument("--assignment-sha256", required=True)
    read.add_argument("--start", type=int, default=0)
    read.add_argument("--count", type=int, default=10)
    write = sub.add_parser("write")
    write.add_argument("--assignment-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "read":
            raw = read_chunk_page(Path("/chunk"), assignment_sha256=args.assignment_sha256, start=args.start, count=args.count)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
        else:
            raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
            result = write_chunk_response(Path("/chunk"), Path("/response"), raw,
                                          assignment_sha256=args.assignment_sha256)
            print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"failed","error_code":"assigned_review_transport_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
