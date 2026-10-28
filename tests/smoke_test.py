#!/usr/bin/env python3
"""Verdict smoke tests for scanner.py, run against a local mock PHP target.

Covers the detection and reporting paths CI must keep working:

  * in-band PHP fatal error            -> VULNERABLE
  * PHP-FPM worker death (HTTP 502)    -> VULNERABLE
  * --sapi mod_php ignores the FPM-only signal
  * clean target on a patched version  -> not vulnerable (FIXED)
  * clean target on a legacy branch    -> VULNERABLE by advertised version
  * duplicate host lines are scanned once
  * a custom --path is preserved
  * --all-results saves non-vulnerable targets

Stdlib only. Talks to loopback exclusively.
"""
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scanner.py"
MOCK = Path(__file__).resolve().parent / "mock_server.py"

FAILURES = []
_counter = 0


def check(name, condition, detail=""):
    if condition:
        print("  ok   " + name)
        return
    print("  FAIL " + name + ((": " + detail) if detail else ""))
    FAILURES.append(name)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class MockTarget:
    """Start tests/mock_server.py on a free loopback port."""

    def __init__(self, mode, php_version=None):
        self.mode = mode
        self.php_version = php_version
        self.port = None
        self.proc = None

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def __enter__(self):
        self.port = free_port()
        command = [sys.executable, str(MOCK), str(self.port), self.mode]
        if self.php_version:
            command.append(self.php_version)
        self.proc = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "mock server exited early: "
                    + self.proc.stderr.read().decode("utf-8", "replace")
                )
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("mock server did not start listening")

    def __exit__(self, *exc_info):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        return False


def run_scan(args, workdir):
    """Run the scanner, always writing results for every target."""
    global _counter
    _counter += 1
    output = Path(workdir) / ("results-%d.json" % _counter)
    command = [
        sys.executable,
        str(SCANNER),
        *args,
        "--all-results",
        "-o",
        str(output),
        "--no-color",
        "-q",
        "--timeout",
        "20",
    ]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=300)
    payload = None
    if output.exists():
        payload = json.loads(output.read_text(encoding="utf-8"))
    return proc, payload


def only_result(payload):
    if not payload or not payload.get("results"):
        raise AssertionError("scanner wrote no results: %r" % (payload,))
    return payload["results"][0]


def test_in_band_fatal(workdir):
    print("in-band PHP fatal error")
    with MockTarget("vuln") as mock:
        proc, payload = run_scan(["-u", mock.url], workdir)
    result = only_result(payload)
    check("exit code is 1", proc.returncode == 1, "got %d" % proc.returncode)
    check("verdict is VULNERABLE", result["verdict"] == "VULNERABLE", result["verdict"])
    check("vulnerable flag is true", result["vulnerable"] is True)
    check(
        "reason names the fatal error",
        "fatal error" in result["reason"].lower(),
        result["reason"],
    )
    check("SAPI is combined", result["sapi"] == "mod_php/PHP-FPM", result["sapi"])
    check(
        "response evidence is retained",
        "Allowed memory size" in (result["response"] or ""),
    )


def test_fpm_worker_death(workdir):
    print("PHP-FPM worker death")
    with MockTarget("fpm") as mock:
        proc, payload = run_scan(["-u", mock.url], workdir)
    result = only_result(payload)
    check("exit code is 1", proc.returncode == 1, "got %d" % proc.returncode)
    check("verdict is VULNERABLE", result["verdict"] == "VULNERABLE", result["verdict"])
    check("SAPI is PHP-FPM", result["sapi"] == "PHP-FPM", str(result["sapi"]))
    check("reason names HTTP 502", "502" in result["reason"], result["reason"])


def test_sapi_filter(workdir):
    print("--sapi mod_php ignores the FPM-only signal")
    with MockTarget("fpm") as mock:
        proc, payload = run_scan(["-u", mock.url, "--sapi", "mod_php"], workdir)
    result = only_result(payload)
    check("not flagged vulnerable", result["vulnerable"] is False, result["verdict"])
    check("exit code is 0", proc.returncode == 0, "got %d" % proc.returncode)


def test_patched_version(workdir):
    print("patched version, no crash")
    with MockTarget("clean", "8.4.27") as mock:
        proc, payload = run_scan(["-u", mock.url], workdir)
    result = only_result(payload)
    check("verdict is FIXED", result["verdict"] == "FIXED", result["verdict"])
    check("not flagged vulnerable", result["vulnerable"] is False)
    check("exit code is 0", proc.returncode == 0, "got %d" % proc.returncode)
    check("--all-results keeps the target", payload["total_results"] == 1)


def test_legacy_version(workdir):
    print("unfixed legacy branch advertised")
    with MockTarget("clean", "8.1.30") as mock:
        proc, payload = run_scan(["-u", mock.url], workdir)
    result = only_result(payload)
    check("verdict is VULNERABLE", result["verdict"] == "VULNERABLE", result["verdict"])
    check(
        "reason cites the advertised version",
        "8.1.30" in result["reason"],
        result["reason"],
    )
    check("exit code is 1", proc.returncode == 1, "got %d" % proc.returncode)


def test_deduplication(workdir):
    print("duplicate host lines scanned once")
    hosts = Path(workdir) / "hosts.txt"
    with MockTarget("vuln") as mock:
        hosts.write_text(
            "\n".join([mock.url, mock.url + "/index.php", mock.url]) + "\n",
            encoding="utf-8",
        )
        proc, payload = run_scan(["-l", str(hosts)], workdir)
    check("one result saved", payload and payload["total_results"] == 1,
          str(payload and payload.get("total_results")))
    check("exit code is 1", proc.returncode == 1, "got %d" % proc.returncode)


def test_custom_path(workdir):
    print("--path is preserved")
    with MockTarget("vuln") as mock:
        proc, payload = run_scan(["-u", mock.url, "--path", "/admin.php"], workdir)
    result = only_result(payload)
    request_line = (result["request"] or "").split("\r\n")[0]
    check("probe targets /admin.php", request_line == "POST /admin.php HTTP/1.1",
          request_line)


def main():
    if not SCANNER.exists():
        raise SystemExit("scanner.py not found at %s" % SCANNER)

    print("php2shell verdict smoke tests (%s)" % sys.version.split()[0])
    with tempfile.TemporaryDirectory() as workdir:
        try:
            test_in_band_fatal(workdir)
            test_fpm_worker_death(workdir)
            test_sapi_filter(workdir)
            test_patched_version(workdir)
            test_legacy_version(workdir)
            test_deduplication(workdir)
            test_custom_path(workdir)
        except Exception as exc:  # report harness failures as failures, not crashes
            print("  FAIL harness error: %r" % (exc,))
            FAILURES.append("harness")

    print()
    if FAILURES:
        print("FAILED: %d check(s) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All verdict smoke tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
