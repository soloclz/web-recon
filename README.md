# web-recon

`web-recon` performs a bounded first pass against one or more hostnames on one port. It checks Web and DNS services, saves the responses and scanner output, and prints discoveries while the scan runs. Run it again when you find another hostname or want to try a different wordlist.

Hostnames must resolve on the machine running the tool. It uses the system resolver and never edits `/etc/hosts`. If one hostname cannot resolve, that hostname is marked as failed and the remaining hosts continue.

## Requirements and setup

- Python 3.10 or newer, `curl`, `dig`, and `openssl` for the fixed checks.
- `ffuf` for HTTP vhost, path, and extension wordlists; `gobuster` for the DNS prefix wordlist.
- `jq` is optional and is useful for querying the finished JSON report.

For a Kali checkout:

```bash
git clone https://github.com/soloclz/web-recon.git ~/tools/web-recon
python3 ~/tools/web-recon/scripts/web-recon.py --help
```

For an existing checkout, use `git -C ~/tools/web-recon pull --ff-only`.

The repository supplies no wordlists. Provide the paths to wordlists installed on your machine. A hostname is a bare name such as `app.example.test`; do not include a scheme, path, or port in `--host` or `hosts.txt`. Set up any lab hosts entries before running the tool.

## First scan

Run from the engagement directory. The tool creates a new `web-recon-YYYYMMDD-HHMMSS/` directory there and prints its path at startup.

```bash
mkdir -p ~/engagements/example
cd ~/engagements/example

python3 ~/tools/web-recon/scripts/web-recon.py \
  --host app.example.test --port 8080 \
  --host-prefixes-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --extensions-wordlist /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

Use `--out-dir ./run-1` to choose an exact output path. The path must not exist; later runs need a different path under the same parent to continue automatically.

All three wordlists are optional. With no wordlist flags, the fixed Web, TLS, and DNS checks still run. Use `--hosts-file hosts.txt` instead of `--host` for a batch:

```text
app.example.test
admin.app.example.test # an already known vhost
```

The file takes one hostname per line. Blank lines and `#` comments are ignored; duplicate names are scanned once. Hosts in a file are processed sequentially. DNS and Web checks for one host can overlap.

### What each wordlist does

| Option | Scan |
| --- | --- |
| `--host-prefixes-wordlist FILE` | `gobuster dns` and `ffuf` HTTP vhost. Each entry is prepended to the **input hostname**: `admin` with `app.example.test` tests `admin.app.example.test`. The vhost scan changes the HTTP `Host` header. |
| `--paths-wordlist FILE` | `ffuf` guesses root paths such as `/admin`. It does not recurse. |
| `--extensions-wordlist FILE` | Tests extensions on known basenames, such as `/index.php`. If an extension differs from the missing-path control and a path wordlist is available, that list also guesses filenames such as `/admin.php`. |

The filename-guess phase is capped by `--max-extra-requests` (default: 100,000 requests per origin); setting it to `0` skips that phase. This cap does not include the known-basename extension probes. An HTTPS vhost hit based on the `Host` header is a candidate; verify it using that hostname as SNI.

## Read results

The finished run has two files at its root:

- `report.md` is the reading entry point: host and stage status, candidate tables, and links to the saved evidence. Tables show up to 30 rows.
- `report.json` contains the complete results for all hosts. Use this single file for `jq`; there is no need to find a per-host `summary.json`.

The JSON shape is `{"schema_version": 1, "run": {...}, "hosts": [...]}`. For example:

```bash
jq -r '.hosts[].new_hosts[].name' ./web-recon-YYYYMMDD-HHMMSS/report.json
jq -r '.hosts[].web[].pages[].comments[]' ./web-recon-YYYYMMDD-HHMMSS/report.json
jq '.hosts[] | select(.host == "app.example.test")' ./web-recon-YYYYMMDD-HHMMSS/report.json
```

`new-hosts.txt` lists candidate hostnames not already included as hosts in the merged run. Add the names you want to investigate to your hosts file for the next run. `new-hosts.jsonl` also records where each name came from and the starting host's connected IP:port; that address is not a confirmed address for the candidate.

The run root also contains `run.json` (run metadata and completion state) and `progress.jsonl` (live events). Under `hosts/<hostname>-<hash>/`, each host has a `summary.json` and the original Web responses, TLS data, DNS output, and scanner output. The tool keeps these files so a later run can reuse evidence and so you can verify a candidate against its missing-path or default-vhost control. Normal reading and `jq` queries start at the run root.

A `candidate` needs review against its saved response or scanner control. An `observed` event is data read directly from DNS or a Web response. A host can have status `partial` because one stage is unavailable even when other stages finished; check the stage table in `report.md`.

### See findings before the scan finishes

In an interactive terminal or tmux, progress updates on one line. Each new finding gets its own persistent line, then the progress line resumes. For example:

```text
[app.example.test] candidate HTTP path scan: ffuf_path: HTTP 200 http://app.example.test:8080/admin
[app.example.test] HTTP vhost scan 9,222/114,438 tried (8%), elapsed 7m43s
```

The fraction and percentage describe that stage only. In a non-interactive terminal, progress updates are printed as separate lines. Every finding, start, progress, and finish event is also appended immediately to `progress.jsonl`. To watch only findings in another terminal:

```bash
tail -f ./web-recon-YYYYMMDD-HHMMSS/progress.jsonl |
  jq --unbuffered -r 'select(.event == "finding") | "[\(.host)] \(.status): \(.display)"'
```

`report.md`, `report.json`, and `run.json` are written after all input hosts finish. Use the console or `progress.jsonl` during a long scan.

## Continue a run

Run again with the same hostname or hosts file and port from the same engagement directory. The tool automatically selects the latest finished run for that port. It creates a **new** output directory, carries forward finished results and their evidence, retries failed stages, and scans new input hostnames. It never adds results to the previous run directory.

For example, after the first scan above, changing only the prefix wordlist needs only that flag:

```bash
cd ~/engagements/example

python3 ~/tools/web-recon/scripts/web-recon.py \
  --host app.example.test --port 8080 \
  --host-prefixes-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

The path and extension wordlists are inherited. The tool runs the **entire** new prefix wordlist for DNS and vhost discovery; it does not subtract words tested in the previous list. Completed path, extension, and fixed checks are reused when their inputs are unchanged. Current runs save each wordlist's SHA-256, so a content change at the same path is detected. For an older run without saved hashes, pass the wordlist flag explicitly to update that stage. Repeating a completed run with unchanged inputs makes a new merged run without repeating its completed checks.

To add another known hostname, put it in `hosts.txt` and run:

```bash
python3 ~/tools/web-recon/scripts/web-recon.py \
  --hosts-file hosts.txt --port 8080
```

The new hostname gets a full first scan. Previously scanned hosts are retained in the new report even if they are absent from the new hosts file. The new run copies referenced old evidence, so the new directory can be moved on its own. If a retry fails, the previous usable result stays in the report and the failed attempt is saved separately.

Automatic continuation uses the current directory as the engagement scope. With `--out-dir PATH`, it uses `PATH`'s parent. The requested output directory must not exist. Different ports have separate histories. If multiple independent histories exist for the same port, choose one explicitly:

```bash
python3 ~/tools/web-recon/scripts/web-recon.py \
  --extend-run ./web-recon-YYYYMMDD-HHMMSS \
  --hosts-file hosts.txt
```

`--extend-run` inherits the source port, wordlists, and scan limits unless you override them. A supplied `--port` must match the source. The source must be a finished run with `run.json`.

To scan everything again, including pages that may have changed on the server, start a new history and supply the wordlists again:

```bash
python3 ~/tools/web-recon/scripts/web-recon.py \
  --fresh --host app.example.test --port 8080 \
  --host-prefixes-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --extensions-wordlist /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

`--fresh` does not inherit wordlists or limits. Supply each option you want for the new scan.

The tool can detect changed local wordlists and explicit limit changes. It cannot detect remote page changes without requesting the pages again. Changing `--max-pages`, `--max-depth`, `--max-body-bytes`, or `--max-requests` causes affected old hosts to repeat Web checks; changing only `--max-extra-requests` updates the extension stage. Changing only `--ffuf-rate` does not rerun a completed scan.

### Force selected wordlist stages

Use `--from-run` when you want to name a completed source run and force specific dictionary stages, even if the supplied wordlist has not changed. It reads the source host list and port; do not pass `--hosts-file`. Each wordlist flag selects a stage:

```bash
python3 ~/tools/web-recon/scripts/web-recon.py \
  --from-run ./web-recon-YYYYMMDD-HHMMSS \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/big.txt
```

Passing both path and extension flags reruns both stages, and the new path list is used for filename guesses. A prefix flag reruns both Gobuster DNS and ffuf vhost. `--from-run` cannot add a hostname; use ordinary continuation or `--extend-run` for that.

`--only` is an optional legacy selector for one stage. One useful case is an extension rerun when the previous path wordlist is gone: the path flag below supplies a replacement filename list without rerunning the path scan.

```bash
python3 ~/tools/web-recon/scripts/web-recon.py \
  --from-run ./web-recon-YYYYMMDD-HHMMSS \
  --only extensions \
  --extensions-wordlist /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

A source run still in progress cannot be used for `--from-run` or `--extend-run`.

## Checks and limits

For each resolvable hostname, the fixed checks:

1. Probe HTTP and HTTPS on the given port; save the root response, redirects, and TLS certificate SAN names. Lab self-signed certificates are accepted for inspection; this check does not validate the certificate trust chain.
2. Use two random missing paths as controls. Check `robots.txt`, common sitemap locations and `Sitemap:` entries, a small set of `/.well-known/` metadata, `.git/HEAD`, `.env`, OpenAPI/Swagger locations, and common product files. At most 10 sitemap files are read; URLs in sitemaps become candidates rather than new requests.
3. Crawl the same origin for links, forms, field names, comments, and loaded JavaScript URLs. Check source maps only for discovered JavaScript. The crawler currently does not make separate email or image inventories.
4. Query DNS records, PTR, SOA/NS, and a wildcard control. Try AXFR only when the input name is confirmed as a zone and its NS answers with an authoritative SOA. If a hosts entry makes Web access possible but DNS cannot answer for that zone, the DNS stage is `unavailable` while Web and vhost checks continue.
5. Compare fixed-path and ffuf hits with missing-path or default-vhost controls. A baseline match is not treated as a discovery; scanner errors and incomplete results are saved separately.

Default built-in Web limits are 50 crawled pages, depth 2, 1 MiB per saved body, and 200 built-in Web requests per host. URLs beyond a limit remain in the candidate list. `--max-requests` does not cap ffuf or Gobuster. Use `--max-pages`, `--max-depth`, `--max-body-bytes`, and `--max-requests` to change these limits.

DNS and Web checks can overlap within a host. By default, ffuf vhost, path, and extension stages run one at a time per origin. `--scanner-workers 2` or `3` allows that many ffuf stages to run together. `--ffuf-rate 10` caps **each ffuf process** at 10 requests per second; with two workers the combined upper bound can reach about 20 requests per second. If omitted, no `-rate` option is sent to ffuf. The rate does not control Gobuster or the built-in Web checks. Set it again on any later run that executes new ffuf work.

Add `--public-sources` to a normal invocation to query crt.sh and Wayback CDX for a public hostname. It records candidate names and historical URLs without probing them. The crt.sh result keeps at most 500 candidate names; Wayback keeps at most 500 URLs plus hostname candidates derived from them. Each response is limited to 4 MiB with a 15-second timeout. `.htb`, `.local`, and IP targets are skipped. The current service's TLS certificate SAN check runs regardless of this flag. See [public source details](docs/public-sources.md).

## Regenerate reports for an older run

A finished run made before `report.json` was added can create both reports from saved summaries without sending requests. Run the module from the repository root:

```bash
cd ~/tools/web-recon
python3 -m webrecon.report ~/engagements/example/web-recon-YYYYMMDD-HHMMSS
```

## Verification

From the repository root on macOS:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile webrecon/*.py scripts/*.py
python3 verification/local_web.py
```

On Kali, also verify the installed scanner and DNS tools against controlled loopback services:

```bash
python3 -m unittest discover -s tests -v
python3 verification/local_web.py
python3 verification/kali_scanners.py
python3 verification/kali_dns.py
```

The project draws on `pentest-notes` discovery/Web notes and `sec-notes` recon/protocol notes. `scripts/web-summary.py` was copied from `pentest-notes` commit `b602578fd06756ae8b3bea6020991994d3ad8976`.
