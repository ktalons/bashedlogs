# bashedlogs

[![ci](https://github.com/ktalons/bashedlogs/actions/workflows/ci.yml/badge.svg)](https://github.com/ktalons/bashedlogs/actions/workflows/ci.yml)
[![Bash 4.0+](https://img.shields.io/badge/Bash-4.0%2B-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)](https://github.com/ktalons/bashedlogs)
[![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://github.com/ktalons/bashedlogs)
[![License: MIT](https://img.shields.io/badge/License-MIT-3DA639?logo=opensourceinitiative&logoColor=white)](https://opensource.org/licenses/MIT)

Security log triage in one bash file. Point it at a log, it works out the
format, and it tells you what is worth looking at.

## Install

One file, nothing to build:

```bash
curl -LO https://github.com/ktalons/bashedlogs/releases/latest/download/bashedlogs && chmod +x bashedlogs
```

Needs bash 4.0+ and standard `awk`/`grep`/`sort`. macOS ships bash 3.2 at
`/bin/bash`, so `brew install bash` first.

## Use

Auto-detect and report:

```bash
./bashedlogs /var/log/auth.log
```

```
bashedlogs v2.0.0
  file    /var/log/auth.log
  format  auth_ssh

Metrics
  total_lines                  21
  failed_auth                  12
  top_attacking_ips            203.0.113.66 (12)
  targeted_users               admin (4), oracle (3), root (3)

Findings (3)
  critical possible-compromise successful login for 'admin' from 203.0.113.66 shortly after a brute-force burst from the same IP
  high     brute-force      12 failed logins from 203.0.113.66 within 40s (threshold: 10 in 60s)
  medium   root-attempts    3 failed login attempt(s) targeting root

Threat score  25/100 (high)
```

JSON for anything downstream:

```bash
./bashedlogs -o json /var/log/auth.log | jq '.findings[] | select(.severity=="critical")'
```

Pull IOCs out, defanged for a ticket:

```bash
./bashedlogs --iocs --defang -o json alerts.json | jq -r '.iocs.ips[]'
```

Fail a cron job or CI step when something real shows up:

```bash
./bashedlogs --fail-level high -o json /var/log/auth.log || echo "escalate"
```

Read from a pipe:

```bash
journalctl -u sshd -o short-iso | ./bashedlogs -
```

Tune the brute-force window (default 10 failures in 60s):

```bash
./bashedlogs --bf-threshold 5 --bf-window 300 /var/log/auth.log
```

## Formats

| Format | What it covers |
|---|---|
| `auth_ssh` | sshd and PAM auth: windowed brute force, compromise heuristic, user enumeration |
| `journald` | `journalctl -o short-iso` and `-o json` exports |
| `syslog` | classic syslog: OOM kills, segfaults, panics, sudo failures |
| `web_access` | Apache and NGINX access logs: status mix, scanners, injection probes |
| `wazuh_alerts` | Wazuh `alerts.json`: level histogram, top rules and agents, MITRE ids |
| `dns_route53` | Route53 query logs: NXDOMAIN rate, tunneling heuristics |
| `firewall` | iptables and pfSense filterlog: port scans, repeat offenders |
| `generic` | fallback heuristics for anything unrecognized, and it says so |

`--list-formats` prints these. `--format <name>` skips detection. `--strict`
exits 2 instead of falling back to `generic`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | analyzed, nothing at or above `--fail-level` |
| 1 | usage or runtime error |
| 2 | input unreadable, or `--strict` and detection failed |
| 3 | findings at or above `--fail-level` |

## Enrichment

Off by default, and **no network call is made unless you ask for one**.

Offline GeoIP and ASN, using your own GeoLite2 databases and `mmdblookup`:

```bash
./bashedlogs --iocs --mmdb-dir ~/geoip -o json access.log
```

Online ASN (Team Cymru) and reverse DNS, explicitly opted into:

```bash
./bashedlogs --iocs --enrich-online -o json access.log
```

With neither available the report says enrichment was skipped and everything
else still works.

## Development

```bash
git clone https://github.com/ktalons/bashedlogs.git
cd bashedlogs
shellcheck -x bin/bashedlogs lib/core/*.sh lib/formats/*.sh tools/*.sh
bats tests/
tools/build.sh                 # -> dist/bashedlogs, the single-file artifact
```

`bats-core` and `jq` are test-only dependencies. The runtime has none.

Adding a format means one file in `lib/formats/` that calls
`register_format`, then defines `<name>_detect` (reads `$SAMPLE`, echoes a
0-100 confidence) and `<name>_analyze <file>` (emits findings with
`report_add <severity> <category> <message> [key=value ...]`). Fixtures go in
`tests/fixtures/<name>/` via `tools/mkfixtures.sh` so nothing real gets
committed.

Every claim in this README maps to a test in [docs/CLAIMS.md](docs/CLAIMS.md).

## History

v1 was a single 3,682-line script covering ~30 formats, written fast and never
tested. v2 is a rewrite: real detections instead of keyword counts, structured
output, and CI. The CTF-oriented v1 analyzers (payments, IoT telemetry,
Android logcat, SQLite, Squid, VSFTPD) were dropped to keep this a SOC triage
tool. They are still at tag
[v1.0.0](https://github.com/ktalons/bashedlogs/tree/v1.0.0). See
[CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
