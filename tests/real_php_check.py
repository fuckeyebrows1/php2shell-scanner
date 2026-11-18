#!/usr/bin/env python3
"""Scan a real, patched PHP server and assert it is not reported vulnerable.

Usage: python3 tests/real_php_check.py URL [--body MARKER]
       python3 tests/real_php_check.py URL --expect-vulnerable
       python3 tests/real_php_check.py URL --expect-worker-death

The README documents a false positive on patched PHP when a multipart probe
exceeds ``memory_limit``: it was reproduced on PHP 8.4.27 at 2M-32M, and on
8.3.36 at 128M with a raised ``max_multipart_body_parts``. This check pins a
patched 8.4.27 at the default 128M, where the scanner has to reach FIXED and
must not flag the target. A regression that starts treating a healthy patched
server as vulnerable fails here, which is the case the mock target cannot see.

``--expect-worker-death`` is the mirror image: it scans an unpatched
``php:8.4.26-fpm`` target that hides its release, so the version rule cannot
fire and only a worker dying mid-request can produce VULNERABLE.

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


def scan(url, sapi="auto"):
    """Run the scanner and return the process plus its parsed JSON output."""
    workdir = Path(tempfile.mkdtemp(prefix="real-php-"))
    output = workdir / "results.json"
    command = [
        sys.executable,
        str(SCANNER),
        "-u",
        url,
        "--sapi",
        sapi,
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


def check_unpatched(proc, result):
    """Assert a genuinely unpatched build is flagged by probe evidence.

    The advertised version alone already makes the scanner report VULNERABLE, so
    a verdict check on its own would pass without the parser ever being
    exercised. The crash-evidence check is what proves the probe rules still fire
    against a build that really has the bug rather than only against mocks.
    """
    check("exit code is 1", proc.returncode == 1, "got %d" % proc.returncode)
    check(
        "target is vulnerable",
        result["vulnerable"] is True,
        repr(result["vulnerable"]),
    )
    check("verdict is VULNERABLE", result["verdict"] == "VULNERABLE", result["verdict"])

    reason = result.get("reason") or ""
    check(
        "a probe crashed the request handler",
        "crashed the request handler" in reason or "killed the PHP worker" in reason,
        reason,
    )

    control = result.get("control") or {}
    check(
        "control request returned HTTP 200",
        control.get("status_code") == 200,
        repr(control.get("status_code")),
    )

    match = VERSION.search(result.get("powered_by") or "")
    if not match:
        check("server advertises its PHP release", False, repr(result.get("powered_by")))
    else:
        version = tuple(int(part) for part in match.groups())
        fixed = PATCHED_RELEASES.get(version[:2])
        check(
            "advertised release is unpatched",
            fixed is None or version[2] < fixed,
            "%d.%d.%d is at or above the fixed release; update the image pin"
            % version,
        )

    print("")
    print("reason: %s" % result.get("reason"))
    if FAILURES:
        print("FAILED: %d check(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("Unpatched target correctly reported vulnerable.")
    return 0


def check_worker_death(proc, result):
    """Assert VULNERABLE comes from a worker dying, not the advertised release.

    The target runs with expose_php off, so there is no X-Powered-By header for
    the version rule to read: memory-exhaustion evidence alone would make the
    scanner answer INCONCLUSIVE. Reaching VULNERABLE therefore requires the one
    rule that fires when a worker disappears mid-request, which until now only
    the mock target could imitate.
    """
    check("exit code is 1", proc.returncode == 1, "got %d" % proc.returncode)
    check(
        "target is vulnerable",
        result["vulnerable"] is True,
        repr(result["vulnerable"]),
    )
    check("verdict is VULNERABLE", result["verdict"] == "VULNERABLE", result["verdict"])
    check(
        "SAPI is reported as PHP-FPM",
        result.get("sapi") == "PHP-FPM",
        repr(result.get("sapi")),
    )

    reason = result.get("reason") or ""
    check("a probe killed the PHP worker", "killed the PHP worker" in reason, reason)
    check("the worker died mid-request", "worker died mid-request" in reason, reason)

    # The version rule must not be what reached VULNERABLE: the target advertises
    # nothing, and the reason must not claim a release settled the verdict.
    check(
        "target advertises no PHP release",
        not result.get("powered_by"),
        repr(result.get("powered_by")),
    )
    check(
        "the verdict did not come from the advertised release",
        "X-Powered-By" not in reason,
        reason,
    )

    control = result.get("control") or {}
    check(
        "control request returned HTTP 200",
        control.get("status_code") == 200,
        repr(control.get("status_code")),
    )

    probes = result.get("probes") or []
    last = probes[-1] if probes else {}
    status = last.get("status_code")
    check(
        "the last probe got a worker-death response",
        status in (502, 503, 504)
        or (status == 200 and last.get("response_bytes") == 0),
        "probes=%r" % (probes,),
    )

    print("")
    print("reason: %s" % result.get("reason"))
    if FAILURES:
        print("FAILED: %d check(s): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("Unpatched PHP-FPM target correctly reported vulnerable from worker death.")
    return 0


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
    parser.add_argument(
        "--expect-fatal",
        action="store_true",
        help=(
            "require that the in-band memory-exhaustion fatal was produced and "
            "overridden by the patched release; used for the low memory_limit "
            "target whose display_errors is on"
        ),
    )
    parser.add_argument(
        "--expect-vulnerable",
        action="store_true",
        help=(
            "require VULNERABLE from probe crash evidence on an unpatched "
            "release; used for the php:8.4.26-apache target"
        ),
    )
    parser.add_argument(
        "--expect-worker-death",
        action="store_true",
        help=(
            "require VULNERABLE from a PHP-FPM worker that died mid-request, "
            "with no advertised release to decide the verdict; used for the "
            "php:8.4.26-fpm target behind nginx"
        ),
    )
    args = parser.parse_args()

    if not SCANNER.exists():
        raise SystemExit("scanner.py not found at %s" % SCANNER)

    print("scanning real target: %s" % args.url)
    proc, payload = scan(args.url, "fpm" if args.expect_worker_death else "auto")
    if payload is None:
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit("scanner wrote no JSON results")

    results = payload.get("results") or []
    check("one result was recorded", len(results) == 1, "got %d" % len(results))
    if not results:
        raise SystemExit(1)
    result = results[0]

    if args.expect_vulnerable:
        return check_unpatched(proc, result)
    if args.expect_worker_death:
        return check_worker_death(proc, result)

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
    if args.expect_signal or args.expect_fatal:
        reason = result.get("reason") or ""
        check(
            "an ambiguous crash signal was overridden",
            "produced" in reason
            and "but X-Powered-By reports a patched release" in reason,
            reason,
        )
        if args.expect_fatal:
            check(
                "the overridden signal was the in-band memory-exhaustion fatal",
                "in-band PHP fatal error" in reason,
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
