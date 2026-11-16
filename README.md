# bashedlogs

[![ci](https://github.com/ktalons/bashedlogs/actions/workflows/ci.yml/badge.svg)](https://github.com/ktalons/bashedlogs/actions/workflows/ci.yml)
[![Bash 4.0+](https://img.shields.io/badge/Bash-4.0%2B-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)](https://github.com/ktalons/bashedlogs)
[![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://github.com/ktalons/bashedlogs)
[![License: MIT](https://img.shields.io/badge/License-MIT-3DA639?logo=opensourceinitiative&logoColor=white)](https://opensource.org/licenses/MIT)

Security log triage in one bash file. Point it at a log, it works out the
format, and it tells you what is worth looking at.

- Eight analyzers, auto-detected, with a generic fallback that says so.
- Real detections: windowed brute force, compromise leads, scanners,
  injection probes, port scans, DNS tunneling.
- Pretty, JSON, or NDJSON output, defanged IOCs, and exit codes for cron and CI.
- Every log byte is treated as hostile. No network calls unless you ask.

## Quick start

```bash
curl -fLO https://github.com/ktalons/bashedlogs/releases/latest/download/bashedlogs && chmod +x bashedlogs
./bashedlogs /var/log/auth.log
```

Needs bash 4.0+ and standard utilities. macOS ships bash 3.2, so
`brew install bash` first. In a checkout, run `bin/bashedlogs` or build the
single file with `tools/build.sh`.

```
bashedlogs v2.1.0-dev
  file    /var/log/auth.log
  format  auth_ssh

Metrics
  failed_auth                  12
  position_only_ssh_events     0
  ...
  top_attacking_ips            203.0.113.66 (12)
  targeted_users               admin (4), oracle (3), root (3), postgres (2)

Findings (3)
  critical possible-compromise successful login for 'admin' from 203.0.113.66 shortly after an SSH brute-force burst on the same host
  high     brute-force      12 failed logins from 203.0.113.66 within 40s (threshold: 10 in 60s)
  medium   root-attempts    3 failed login attempt(s) targeting root

Threat score  25/100 (high)
```

## What's new in 2.1

> [!NOTE]
> Not tagged yet. `main` has it, but `releases/latest` is still v2.0.1.

- SSH brute force groups by source IP and destination host, applies UTC
  offsets, and keeps file order when timestamps tie.
- Reports show how SSH events were attributed. `--ssh-named-only` drops
  position-only matches, and `possible-compromise` needs a named SSH producer.
- Wazuh and journald read structured fields. Route 53 takes fractional
  timestamps, pfSense reads its documented port fields, and web logs detect
  IPv6 clients.
- IPv6 IOC extraction, and enrichment results in NDJSON.
- Hardened file name handling, numeric options, and UTF-8 JSON. CI pins its
  actions.

Details in the [CHANGELOG](CHANGELOG.md).

## Recipes

```bash
# JSON for anything downstream
./bashedlogs -o json auth.log | jq '.findings[] | select(.severity=="critical")'

# IOCs, defanged for a ticket
./bashedlogs --iocs --defang -o json alerts.json | jq -r '.iocs.ips[]'

# Read stdin (use -- before a file name that starts with a dash)
journalctl -u sshd -o short-iso | ./bashedlogs -

# Gate cron or CI: exit 3 means a finding at or above the level
./bashedlogs --fail-level high auth.log

# Tune brute force (default: 10 failures in 60s)
./bashedlogs --bf-threshold 5 --bf-window 300 auth.log
```

`--help` lists every option.

## Formats

| Format | What it covers |
|---|---|
| `auth_ssh` | sshd and PAM auth: windowed brute force, compromise heuristic, user enumeration |
| `journald` | `journalctl -o short-iso` and `-o json` exports |
| `syslog` | classic syslog: OOM kills, segfaults, panics, sudo failures |
| `web_access` | Apache and NGINX common/combined logs: status mix, scanners, injection probes |
| `wazuh_alerts` | Wazuh `alerts.json`: level histogram, top rules and agents, MITRE ids |
| `dns_route53` | Route 53 public hosted-zone query logs: NXDOMAIN rate, tunneling heuristics |
| `firewall` | iptables and pfSense filterlog: port scans, repeat offenders |
| `generic` | fallback heuristics for anything unrecognized, and it says so |

`--format <name>` skips detection, and `--strict` exits 2 instead of falling
back to `generic`. Detection samples the first 200 lines (256 KiB at most),
so force the format when the records that matter sit deeper in a mixed file.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | analyzed, nothing at or above `--fail-level` |
| 1 | usage or runtime error |
| 2 | input unreadable, or `--strict` and detection failed |
| 3 | findings at or above `--fail-level` |

## SSH attribution

Brute-force windows are per source IP and destination host, with explicit
UTC offsets applied and file order kept for ties. Classic syslog has no year,
so set `BASHEDLOGS_ASSUME_YEAR` for older logs.

The client controls part of every sshd line, the username and the disconnect
text, so the source address comes only from sshd's own message. Position
decides, not the program tag, because relays and container runtimes rewrite
tags. Position-only matches show up as `position_only_ssh_events`, and
`--ssh-named-only` drops them.

`possible-compromise` needs an accepted login from one unambiguous peer after
enough named-producer failures on the same host and source IP. Producer names
are taken as the log states them, so treat it as a lead and confirm on the host.

Known limits:

- A host with native sshd failures is counted from those, not PAM. A mixed
  export with unmatched PAM failures from that host can undercount.
- For an SSH-only journal JSON export, use `--format auth_ssh` to get
  windowed correlation. `journalctl -o cat` has no timestamps, so it gives
  counts only.

References: [OpenSSH auth logging](https://github.com/openssh/openssh-portable/blob/master/auth.c) ·
[RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html) ·
[journalctl output](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)

## Enrichment

Off by default. **No network call is made unless you ask for one.** Both
modes enrich IOC IPs, so pair them with `--iocs`.

| Mode | Flag | Cap | Leaves the machine |
|---|---|---|---|
| Offline GeoIP and ASN | `--mmdb-dir DIR` (GeoLite2 + `mmdblookup`) | 25 IPs | nothing |
| Online ASN (Team Cymru) and PTR | `--enrich-online` | 10 IPs | those IPs |

Results land in the JSON `enrichment` object and as NDJSON `enrichment`
records. If neither mode is available the report marks enrichment skipped and
the rest still works. With `--defang`, IPv6 colons become `[:]`.

## Hostile logs

Whoever sends the traffic writes the log, so every byte of it is treated as
hostile.

- Nothing from a log is executed.
- No control character from a log reaches your terminal, in the report or in
  an error message. `\x1b[2J` prints as text, so a crafted line cannot rewrite
  the findings around it. Seeing one is a lead in itself.
- JSON escapes newlines, carriage returns, and tabs, drops other C0 controls,
  and replaces malformed UTF-8 with U+FFFD.
- Log text is handled as bytes in any locale, so an invalid byte cannot stop
  a run. C1 controls are escaped under UTF-8 and C, and GBK or Shift-JIS text
  displays unchanged under its own locale.

## Development

```bash
git clone https://github.com/ktalons/bashedlogs.git && cd bashedlogs
shellcheck -x bin/bashedlogs lib/core/*.sh lib/formats/*.sh tools/*.sh
bats tests/
tools/build.sh                 # -> dist/bashedlogs, the single-file artifact
BASHEDLOGS_UNDER_TEST="$PWD/dist/bashedlogs" bats tests/   # same suite, built file
```

`bats-core` and `jq` are test-only. Enrichment optionally uses `mmdblookup`
or your installed network lookup tools.

To add a format, drop one file in `lib/formats/` that calls
`register_format` and defines `<name>_detect` (reads `$SAMPLE`, echoes a
0-100 confidence) and `<name>_analyze <file>` (emits findings with
`report_add <severity> <category> <message> [key=value ...]`). Fixtures go in
`tests/fixtures/<name>/` via `tools/mkfixtures.sh`, so nothing real gets
committed.

Source files share one notation: a five-line banner header, `# *--- Section ---*`
headings, comments that say why, `NOTE:`/`WARN:`/`SECURITY:` markers, and
numbered `TODO-n` items listed at the top of the file. Leave ShellCheck
directives where they are, since inline ones apply to the next line only.
Repo specifics are in [CLAUDE.md](CLAUDE.md).

Every claim in this README maps to a test in [docs/CLAIMS.md](docs/CLAIMS.md).

## History

v1 was a 3,682-line script covering about 30 formats, written fast and never
tested. v2 is a rewrite with real detections, structured output, and CI. The
CTF-oriented v1 analyzers (payments, IoT telemetry, Android logcat, SQLite,
Squid, VSFTPD) were dropped to keep this a SOC triage tool, and still live at
tag [v1.0.0](https://github.com/ktalons/bashedlogs/tree/v1.0.0).

## License

MIT. See [LICENSE](LICENSE).
