# Claims

Every public claim about this tool, and the test that proves it. If a claim
here has no proof, it does not belong on the README, the project page, or a
resume.

| Claim | Where it lives | Proof |
|---|---|---|
| Zero dependencies (bash + coreutils/awk only) | README, site, resume | `floor-bash4` CI job runs the tree and the built artifact in a bare `bash:4.0` container with busybox userland |
| Automatic format detection | README, site, resume | `tests/detect.bats`, plus per-format detection assertions in `formats.bats` and `soc_formats.bats` |
| journald analyzer | site, resume | `tests/formats.bats` — both `-o short-iso` and `-o json` export modes |
| syslog analyzer | site, resume | `tests/formats.bats` |
| Wazuh alerts analyzer | site, resume | `tests/soc_formats.bats` — level histogram, MITRE ids, agent counts |
| SSH/auth analyzer | README, resume | `tests/auth.bats` |
| Web access analyzer | README, resume | `tests/formats.bats` — status accounting, scanner and injection detection |
| DNS analyzer | README, resume | `tests/soc_formats.bats` |
| Firewall analyzer (iptables + pfSense) | README | `tests/soc_formats.bats` — both shapes in one file, port-scan detection |
| Time-windowed brute-force detection | README, site | `tests/auth.bats` — a 12-in-40s burst alerts, 10 failures over 24h do not, and the flags flip the verdict |
| GeoIP/ASN enrichment | site, resume | `tests/iocs.bats` — offline tier via a mock `mmdblookup`, and the graceful-skip path |
| No network calls by default | README, `--help` | `tests/iocs.bats` — stub `whois`/`dig`/`host` on PATH that would fail loudly are never invoked |
| IOC extraction with defang | README, site | `tests/iocs.bats` — exact expected IOC set, defanged variants, hashes left intact |
| One-liner triage reporting (JSON + exit codes) | site, resume | `tests/output.bats` (jq-validated JSON/NDJSON), `tests/exitcodes.bats` (0/1/2/3) |
| shellcheck-clean | README badge | `lint` CI job, `shellcheck -x` must exit 0 on the tree; `build` job also lints the artifact |
| Tested on Linux and macOS | README badge | `test-linux` and `test-macos` CI jobs run the full suite on both userlands |
| Single-file install | README | `build` CI job builds `dist/bashedlogs` and reruns the whole suite against it |
| Counts one attempt once on dual-logging hosts | CHANGELOG | `tests/regressions.bats` — Debian sshd+PAM fixture reports 3, not 6 |
| IPv4 and IPv6 both detected | CHANGELOG | `tests/regressions.bats` — IPv6 burst alerts; validator accepts 5 real forms and rejects 7 malformed |
| ICMP contributes no ports | CHANGELOG | `tests/regressions.bats` — ICMP fixture yields only real tcp ports |
| Alerts attributed to the affected host | CHANGELOG | `tests/regressions.bats` — `agent.name` wins over `manager.name` |
| Untrusted log content cannot execute or corrupt output | README | `tests/hostile.bats` — shell metacharacters, printf specifiers, globs, unicode, CRLF, no trailing newline |
| No control character from a log reaches the terminal | README, CHANGELOG | `tests/hostile.bats` — every C0 control, DEL, and UTF-8 C1 control shown as `\xHH`, byte by byte and through each printing site: usernames, request paths, IOCs, enrichment text, the file name, and stderr messages |
| Legitimate multibyte text displays unchanged | README | `tests/hostile.bats` — GBK and Shift-JIS text byte-identical under their own locales, raw C1 escaped under ISO-8859 and EUC. Linux runners lack those locales and skip; `test-macos` runs every case |
| Sanitizing stays fast on bash 4.0 | CHANGELOG | `floor-bash4` CI step — 13,000 escape sequences through the tree and the artifact under bash 4.0 and busybox, each under 20s |
| An invalid byte cannot stop a run | README, CHANGELOG | `tests/hostile.bats` — `\377` beside an escape sequence under a UTF-8 locale exits 0 in pretty and JSON with no raw ESC; EUC stray bytes pass through unchanged |
| Escaped quotes in Apache logs do not hide payloads | CHANGELOG | `tests/regressions.bats` — SQLi and XSS after `\"`, spoofed status, user field, referer and user agent, CRLF |
| No analyzer aborts on mismatched input | — | `tests/robustness.bats` — all 8 analyzers over every fixture, plus empty and junk files |

## Audit note

The defects behind the four v2.0.0 CHANGELOG rows were found by a
cross-vendor review before v2.0.0 was tagged, not by the test suite. Two of
them were invisible because the fixtures were unrealistically clean: the Wazuh
fixture had no `manager.name` sibling field, so nothing exercised the
misattribution. Fixtures now carry the sibling fields real logs have, and each
fixed defect has a regression test naming what the tool used to report.

## Security review note (v2.0.1)

The v2.0.1 fixes were also found by review, or while fixing what it found,
not by the suite. `hostile.bats` proved that log content could not execute,
but never asked whether it could reach the terminal raw, so every printing
site passed escape sequences through while every test passed. The new tests
assert on the bytes that reach the terminal, and a mutation run confirmed that
removing the sanitizer from any printing site that carries log text fails at
least one of them. One finding from that review, SSH source-IP framing, is
still open. See the CHANGELOG's Known issues.
