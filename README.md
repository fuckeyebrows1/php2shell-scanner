# php2shell-scanner

A command-line tool for detecting CVE-2026-109618 and CVE-2026-109619 in PHP applications.

## How It Works

The scanner sends a minimal multipart control request followed by up to three crafted multipart probes. The probes use PHP array keys nested 62 levels deep and increase from 1 MiB to 20 MiB, matching the detection logic used by Assetnote's internal scanner.

A probe response is classified by what it proves:

- A **PHP-FPM worker that dies mid-request** (an FPM 502, 503 or 504, or an empty HTTP 200) is crash evidence. An enforced `memory_limit` cannot explain it: that is a fatal error PHP reports and the worker survives it. The death therefore means the parser took the process down, by corrupting memory or, as the unpatched `php:8.4.26-fpm` target in CI shows, by allocating until the container's own memory cap killed it. That second cause can kill a patched build too: the `php:8.4.27-fpm` control in CI dies exactly like the unpatched target under the same cap. So the advertised release settles this signal as well: patched means `FIXED` and records the overridden death, while unpatched or undisclosed means `VULNERABLE`.
- A **memory-exhaustion response** — the in-band `Allowed memory size … exhausted … in Unknown` fatal, or a differential empty HTTP 500 — is ambiguous, because a patched build answers a probe past its `memory_limit` with exactly the same thing. The advertised release decides: patched means `FIXED`, unpatched means `VULNERABLE`, and no advertised release means `INCONCLUSIVE`.
- An **advertised release known to be unpatched** is reported vulnerable even when no probe crashed.

Initial 5xx responses, common request-rejection statuses, and nonempty HTTP 500 responses without the PHP fatal-error signature are not treated as crash signals.

The scanner tests `/index.php` by default. A path supplied in the URL is preserved, and `--path` or `--path-file` can test custom paths. phpMyAdmin targets are automatically retested at `/show_config_errors.php`. Redirects are not followed unless `--follow-redirects` is set.

### SAPI Modes

The default `--sapi auto` mode applies both mod_php and PHP-FPM verdict rules, matching the combined behavior of Assetnote's postmodules. Use `--sapi mod_php` or `--sapi fpm` to restrict detection to a known SAPI.

### Network Impact

Each tested path may receive a 42-byte control request and three probes totalling about 29 MiB. Probing stops as soon as the verdict is settled, and duplicate input URLs are scanned once.

## Requirements

- Python 3.9+
- h11
- tqdm

## Installation

```
pip install -r requirements.txt
```

### Docker

Build the image:

```
docker build -t php2shell-scanner .
```

Run it with the same options as `scanner.py`:

```
docker run --rm php2shell-scanner -u https://example.com
```

Mount the current directory to read host lists and write results:

```
docker run --rm -v "$PWD:/data" -w /data php2shell-scanner -l hosts.txt -o results.json
```

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Scan a custom path:

```
python3 scanner.py -u https://example.com --path /phpinfo.php
python3 scanner.py -u https://example.com --path /index.php --path /admin.php
python3 scanner.py -u https://example.com --path-file paths.txt
```

Use only PHP-FPM verdict rules:

```
python3 scanner.py -u https://example.com --sapi fpm
```

## Options

```
-u, --url         Single URL to check
-l, --list        File containing hosts (one per line)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 60)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable hosts
-k, --insecure    Disable TLS certificate verification
--follow-redirects Follow HTTP redirects (up to 10 hops)
-H, --header      Custom header (can be used multiple times)
-v, --verbose     Show verdict reasons and response snippets
-q, --quiet       Only output vulnerable hosts
--no-color        Disable colored output
--sapi            Verdict rules: auto, mod_php, or fpm (default: auto)
--path            Custom path to test (can be used multiple times)
--path-file       File containing paths to test (one per line)
```

## Credits

The first, original discovery of php2shell is attributed to the Calif team. You can read their write up here: [https://calif.io/php2shell/](https://calif.io/php2shell/).

The scanner was built by the Assetnote Security Research Team using logic built for [Searchlight's Exposure Platform](https://www.slcyber.io/exposure).

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file with the verdict reason and redacted HTTP request/response evidence.

## Limitations

On specific PHP configurations, a multipart probe that exceeds PHP's `memory_limit` makes a patched build answer with the same empty HTTP 500 a vulnerable one does. This was reproduced on patched PHP 8.4.27 with `memory_limit` values from **2M to 32M**, and on PHP 8.3.36 at **128M** when `max_multipart_body_parts` is set to **2785 or higher**. The exact threshold may vary between builds.

With `display_errors` on, the same patched build serves the in-band `Allowed memory size … exhausted … in Unknown` text instead of an empty body, so that signal is equally ambiguous.

Both memory-exhaustion signals are therefore settled by the advertised release: a patched release reports `FIXED` and records the overridden signal in the reason. FPM worker failures are settled the same way once the release is known: with `memory_limit` disabled the container's memory cap can kill a patched build just as readily, so a patched release reports `FIXED` and records the death instead of treating it as proof.

When PHP does not disclose its version — `expose_php` off, which is common in production — memory-exhaustion evidence cannot be resolved from the outside: the response is identical whether the build is patched and defending at `memory_limit` or unpatched and corrupting the parser. The scanner reports `INCONCLUSIVE` rather than guessing, and the reason records the signal. Confirm the installed release and its `memory_limit` before treating such a target as vulnerable. A worker death without an advertised version still reports `VULNERABLE`, so a target that hides its release and runs under a tight container cap can produce a false positive; confirm the release and the cap before acting on it.
