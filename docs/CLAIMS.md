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
