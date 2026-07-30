# Changelog

## v2.0.0

A ground-up rewrite. v1 was one 3,682-line file with no tests; v2 is a modular
tree that still ships as a single portable file.

### Added

- Eight analyzers: `auth_ssh`, `syslog`, `journald`, `web_access`,
  `wazuh_alerts`, `dns_route53`, `firewall`, `generic`.
- `-o json` / `-o ndjson` output, and an exit-code contract (`0` analyzed,
  `1` usage error, `2` unreadable input or `--strict` detection failure,
  `3` findings at or above `--fail-level`) so it works in cron and pipelines.
- Time-windowed brute-force detection (`--bf-threshold`, `--bf-window`) with a
  possible-compromise heuristic when a login succeeds right after a burst.
- IOC extraction (`--iocs`) for IPs, domains, URLs, and MD5/SHA1/SHA256, with
  optional `--defang`.
- Optional GeoIP/ASN enrichment: offline via `--mmdb-dir` (GeoLite2 +
  `mmdblookup`), or `--enrich-online` for Team Cymru ASN and PTR lookups.
  No network call is made unless `--enrich-online` is passed.
- Reads stdin with `-`, honors `NO_COLOR`, and `--list-formats` prints the
  registry.
- 72 bats tests, run in CI against both the source tree and the built
  single-file artifact, on Linux and macOS plus a bash 4.0 floor check.

### Fixed

- Brute-force detection is now a real per-source sliding window. v1 counted
  total keyword hits across the whole file, so ten failures spread over a day
  looked identical to ten in a second.
- Per-IP counts are token-exact with octet validation. v1 used
  `grep "$ip"`, where unescaped dots matched lookalike text and inflated
  counts.
- Format detection no longer relies on `return` inside a piped subshell, which
  was fragile under `set -euo pipefail`.
- `Invalid user` preamble lines are counted as enumeration signal instead of
  being double-counted as separate authentication failures.
- Removed an unreachable duplicate web-log analyzer (v1 dispatched web logs to
  a different function than the one that parsed them).

### Fixed in pre-release audit

A cross-vendor review before tagging found five real defects, all fixed with a
regression test each:

- Debian and Ubuntu sshd log both a `pam_unix` line and a `Failed password`
  line for a single failed attempt. Counting both reported double the real
  failures and alerted at roughly half the configured `--bf-threshold`. sshd's
  own line is now authoritative; PAM lines are used only when a log contains no
  sshd failure lines, and any skipped duplicates are disclosed in the report.
- IPv6 sources were invisible to every per-source detector. Failures were
  counted in the totals but produced no finding, which reads as "no attack".
  Address validation is now shared across analyzers and handles IPv6.
- ICMP firewall events have no ports, so the fields after source and
  destination are type and code. Those were being reported as ports; port
  extraction is now gated on tcp/udp.
- Wazuh alerts carry `manager.name` and `decoder.name` alongside `agent.name`,
  so a bare field lookup attributed every alert to the Wazuh server instead of
  the affected host. Lookups are now path-aware.
- Rule descriptions containing an escaped quote were truncated at the escape.

### Changed

- shellcheck-clean (v1 had 572 findings) and enforced in CI.
- Requires bash 4.0+, with a clear message on stock macOS bash 3.2.
- Dropped the CTF-oriented v1 analyzers (payments, IoT telemetry, Android
  logcat, SQLite, Squid, VSFTPD) to focus on SOC triage. They remain available
  at tag `v1.0.0`.

## v1.0.0

Original single-file release: auto-detection across ~30 log formats with
colored terminal reports.
