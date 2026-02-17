"""
CLI entry point: gbe verify --offline

Usage:
    gbe verify --offline --bundle <path> --keyring <path> [--output <path>]

Exits 0 on PASS, 1 on FAIL.
"""

import argparse
import json
import sys

from .offline import OfflineVerifier


def main():
    parser = argparse.ArgumentParser(description="Offline bundle verification")
    parser.add_argument("--offline", action="store_true", required=True)
    parser.add_argument("--bundle", required=True, help="Path to bundle tar.gz")
    parser.add_argument("--keyring", required=True, help="Path to public keyring")
    parser.add_argument("--output", default=None, help="Write report to file")

    args = parser.parse_args()

    verifier = OfflineVerifier()
    report = verifier.verify(args.bundle, args.keyring)

    report_json = report.model_dump(mode="json")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report_json, f, indent=2)
    else:
        print(json.dumps(report_json, indent=2))

    sys.exit(0 if report.overall == "PASS" else 1)


if __name__ == "__main__":
    main()
