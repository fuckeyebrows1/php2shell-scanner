#!/usr/bin/env python3
"""Scan a real, patched PHP server and assert it is not reported vulnerable.

Usage: python3 tests/real_php_check.py URL [--body MARKER]

The README documents a false positive on patched PHP when a multipart probe
exceeds ``memory_limit``: it was reproduced on PHP 8.4.27 at 2M-32M, and on
8.3.36 at 128M with a raised ``max_multipart_body_parts``. This check pins a
patched 8.4.27 at the default 128M, where the scanner has to reach FIXED and
must not flag the target. A regression that starts treating a healthy patched
server as vulnerable fails here, which is the case the mock target cannot see.

Stdlib only.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SCANNER = Path(__file__).resolve().parent.parent / "scanner.py"
VERSION = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
PATCHED_RELEASES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
FAILURES = []


def check(label, ok, detail=None):
    line = "  %s %s" % ("ok  " if ok else "FAIL", label)
    if not ok and detail:
        line += "  [%s]" % detail
    print(line)
    if not ok:
        FAILURES.append(label)


def scan(url):
    """Run the scanner and return the process plus its parsed JSON output."""
    workdir = Path(tempfile.mkdtemp(prefix="real-php-"))
    output = workdir / "results.json"
    command = [
        sys.executable,
        str(SCANNER),
        "-u",
        url,
        "--all-results",
        "-o",
        str(output),
        "--no-color",
        "-q",
        "--timeout",
        "30",
    ]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=600)
    payload = json.loads(output.read_text()) if output.exists() else None
    return proc, payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL of the real PHP target")
    parser.add_argument(
        "--body",
        default="",
        help=(
            "marker the target must echo in the recorded response; only usable "
            "when that response is expected to have a body"
        ),
    )
    parser.add_argument(
        "--expect-signal",
        action="store_true",
        help=(
            "require that an ambiguous crash signal was produced and overridden "
            "by the patched release; used for the low memory_limit target"
        ),
    )
    args = parser.parse_args()

    if not SCANNER.exists():
        raise SystemExit("scanner.py not found at %s" % SCANNER)

    print("scanning real target: %s" % args.url)
    proc, payload = scan(args.url)
    if payload is None:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit("scanner wrote no JSON results")

    results = payload.get("results") or []
    check("one result was recorded", len(results) == 1, "got %d" % len(results))
    if not results:
        raise SystemExit(1)
    result = results[0]

    check("exit code is 0", proc.returncode == 0, "got %d" % proc.returncode)
    check(
        "target is not vulnerable",
        result["vulnerable"] is False,
        repr(result["vulnerable"]),
    )
    check("verdict is FIXED", result["verdict"] == "FIXED", result["verdict"])

    # result["status_code"] and result["response"] carry the last request sent,
    # which is the probe. On the low-memory target that response is the empty
    # 500 by design, so the control request is what proves the server is healthy.
    control = result.get("control") or {}
    check(
        "control request returned HTTP 200",
        control.get("status_code") == 200,
        repr(control.get("status_code")),
    )
    probes = result.get("probes") or []
    check(
        "a probe got a real response",
        bool(probes) and probes[0].get("status_code") is not None,
        "probes=%r" % (probes[:1],),
    )
    if args.body:
        check(
            "target echoed %r" % args.body,
            args.body in (result.get("response") or ""),
        )
    if args.expect_signal:
        reason = result.get("reason") or ""
        check(
            "an ambiguous crash signal was overridden",
            "produced" in reason
            and "but X-Powered-By reports a patched release" in reason,
            reason,
        )

    match = VERSION.search(result.get("powered_by") or "")
    if not match:
        check("server advertises its PHP release", False, repr(result.get("powered_by")))
    else:
        version = tuple(int(part) for part in match.groups())
        fixed = PATCHED_RELEASES.get(version[:2])
        check(
            "advertised release is patched",
            fixed is not None and version[2] >= fixed,
            "%d.%d.%d is below the fixed release; update the image pin"
            % version,
        )

    print("")
    print("reason: %s" % result.get("reason"))
    if FAILURES:
        print("FAILED: %d check(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("Patched target scanned clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
