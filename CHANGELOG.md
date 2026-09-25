# Changelog

## v2.0.1

A security release. A Claude Security review of v2.0.0 found five ways a
crafted log could mislead the analyst reading the report. This release fixes
all five, plus two more found while fixing those.

### Fixed in security review

- sshd logs the username a client sends, and the text of a client disconnect,
  verbatim and with spaces. The analyzer read the source address from the first
  `from` on the line, so an attempt with the username `x from 198.51.100.7` put
  that address on the brute force, cleared the machine that was really
  attacking, and turned a later legitimate login from the framed address into a
  critical possible-compromise finding naming a real user. Addresses now come
  from sshd's own message, which starts after the program tag: the last `from`
  on a failure, the first on an accept, where a certificate key ID can follow,
  and `rhost=` alone on a PAM line. Event words quoted inside another program's
  message are no longer read as sshd's, so a daemon that logs client text
  cannot forge a burst by naming sshd in it. What decides is position rather
  than the tag text, because relays, rsyslog templates and container runtimes
  all rewrite the tag: requiring it to name ssh made a real brute force against
  a containerized sshd report no failures at all. Journald export, one-line and
  pretty JSON, RFC 5424 with a BOM, Solaris message IDs, rsyslog repeat
  wrappers, and tagless `journalctl -o cat` output all read the same event the
  same way.
- Pretty output printed text from the log as it was: usernames, request paths,
  DNS names, program names, Wazuh rule descriptions, IOC URLs, and the file
  name. An escape sequence in a log line could erase or rewrite findings
  already on screen, retitle the terminal, or write to the clipboard where the
  terminal allows OSC 52. `--no-color` did not help, since it only drops the
  tool's own colors. Every control character in log text now prints as a
  visible escape such as `\x1b[2J`. That covers C0, DEL, and the UTF-8 C1
  controls (U+0080 to U+009F). Under ISO-8859 and EUC locales the raw C1 bytes
  are escaped too. Under GBK, Shift-JIS, Big5, KOI8, and the Windows code pages
  those bytes are parts of characters, so they are left alone and legitimate
  text displays unchanged.
- The sanitizer runs in linear time. A per-character substitution takes
  minutes on bash 4.0 for a log dense with escape bytes, which would have
  traded terminal injection for a stalled report. CI now runs such a log under
  bash 4.0 and busybox and fails if the report takes longer than 20 seconds.
- Apache logs an embedded double quote as `\"`. Splitting fields on every `"`
  ended the request early, so a SQL injection, XSS, or traversal payload placed
  after an escaped quote never reached the checks, and attacker text was read
  as the status code. Quoted fields are now parsed with their escapes, in the
  request, user, referer, and user agent.

### Fixed while fixing those

- Error messages quoted a file name or option as it was on stderr, which
  reaches the same terminal as the report. A file name carrying escape
  sequences could run them through the `cannot read`, `--strict`, and
  `unknown option` messages. Those go through the same sanitizer now.
- Under a UTF-8 or EUC locale, macOS awk stops at the first byte sequence that
  is invalid in that locale. One such byte anywhere in a log ended the run with
  exit 2 and no report, and awk echoed the raw line, escape bytes included, to
  stderr. Under EUC, bash could also add a stray byte to text it passed along.
  The analyzers now run under `LC_ALL=C` and treat log text as bytes. The
  caller's locale still decides which bytes the report shows as C1 controls.
- A Solaris message id and an rsyslog repeat wrapper both sit between the
  program tag and the event, and a relay that re-stamps a line already carrying
  one leaves two. Only one of each was stripped, so the second stayed in front
  of the event words and the line was not read as a failure at all. On a
  re-stamped log a six-attempt burst counted as one and never alerted.
- Reading the SSH source from sshd's own message also fixed a miscount on
  journald JSON exports, where the closing quote is glued to the last field. A
  PAM line ending `user=root"` was not counted as an attempt on root, so a
  journald export of a root brute force reported no root attempts at all.

### Fixed

- Under bash 4.0, `--iocs -o json` wrote invalid JSON (`"domains":,`)
  whenever an IOC category was empty, and still exited 0. Run with no
  arguments, it printed `$@: unbound variable` instead of the usage text.
  bash 4.0 treats an empty `"$@"` as unbound under `set -u`, and the bash 5
  that most CI jobs run does not. The bash 4.0 CI job now checks both.

### Changed

- Entries tied on count in a top-N list are now ordered by byte value under
  every locale. They used to follow the caller's collation, so two machines
  could list different entries in the top five for the same log.
- Source files follow the code notation standard: a header on every file,
  section headings, and `NOTE:`, `WARN:`, and `SECURITY:` markers. Comments
  only. No executable line changed.
- 148 bats tests, up from 106.

### Known issues

- Attribution is trusted, not proved, so an app log mixed into an auth log can
  still put an address on a burst. Reading by position means any program whose
  message opens with sshd words is read as sshd, and an app that writes
  attacker-controlled text at the start of its own message into the same file
  can invent a burst against a machine that never connected. The reverse rule
  hides a real burst behind a rewritten tag, which is worse for a detector, and
  no text-only rule separates the two: once the tag is rewritten the line no
  longer carries what wrote it. Three more cases are open. A journald
  `MESSAGE=` record is read whatever its `SYSLOG_IDENTIFIER` says; a tag
  holding a character the tag pattern does not cover is not seen as a tag at
  all and the line falls through untested; and an accept takes the first
  `from`, so an account that exists and whose name contains
  ` from <ip> port <n>` re-attributes its own login. A cross-vendor audit of
  this release found those three. Closing all four means the report has to
  disclose how each line was attributed instead of assuming it, which is a
  change for the next release rather than a patch to this one.

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
- 106 bats tests, run in CI against both the source tree and the built
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
