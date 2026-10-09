"""
Forensight - Robustness test.

Runs the ingestion and header forensics modules on every .eml file in a
folder and reports how many were processed successfully, how many failed,
whether every file's integrity was preserved, and a summary of the findings.
"""

import sys
import time
from collections import Counter
from pathlib import Path

from forensight.headers import analyze_headers
from forensight.ingest import load_email, verify_integrity


def run(folder: str) -> None:
    files = sorted(Path(folder).expanduser().glob("*.eml"))
    if not files:
        print(f"No .eml files found in {folder}")
        sys.exit(1)

    ok, failed, intact, with_ip = 0, [], 0, 0
    severities = Counter()
    start = time.time()

    for i, path in enumerate(files, start=1):
        try:
            evidence = load_email(path)
            report = analyze_headers(evidence)
            ok += 1
            if report.originating_ip:
                with_ip += 1
            severities.update(f.severity for f in report.findings)
            if verify_integrity(evidence):
                intact += 1
        except Exception as error:
            failed.append((path.name, repr(error)))
        if i % 1000 == 0:
            print(f"  ... {i}/{len(files)} emails processed")

    elapsed = time.time() - start
    print("=" * 60)
    print("FORENSIGHT - Robustness Test")
    print("=" * 60)
    print(f"Emails found          : {len(files)}")
    print(f"Processed successfully: {ok}")
    print(f"Failed                : {len(failed)}")
    print(f"Integrity verified    : {intact}/{ok}")
    print(f"Originating IP found  : {with_ip}/{ok}")
    print(f"Findings (high)       : {severities['high']}")
    print(f"Findings (medium)     : {severities['medium']}")
    print(f"Findings (low)        : {severities['low']}")
    print(f"Total time            : {elapsed:.1f} s ({elapsed / len(files) * 1000:.1f} ms per email)")
    print("=" * 60)
    for name, error in failed[:10]:
        print(f"FAILED: {name}: {error}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m forensight.robustness <folder-with-eml-files>")
        sys.exit(1)
    run(sys.argv[1])
