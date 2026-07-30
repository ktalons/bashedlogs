#!/usr/bin/env bash
# mkfixtures.sh - regenerate the committed test fixtures under tests/fixtures/
# All fixtures are synthetic and deterministic: fixed timestamps, RFC 5737 /
# private IPs, invented hostnames. No real-world log data is ever committed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/tests/fixtures"

mkdir -p "$FIX/generic"

# generic/mixed.log: app-style log that should stay in the generic analyzer
# and produce auth-failure, injection, and traversal findings.
cat > "$FIX/generic/mixed.log" <<'EOF'
2025-06-01T10:00:01Z appsvc INFO request id=1001 client=203.0.113.7 path=/api/health status=200
2025-06-01T10:00:02Z appsvc INFO request id=1002 client=203.0.113.7 path=/api/items status=200
2025-06-01T10:00:03Z appsvc WARN slow query id=1003 client=198.51.100.23 elapsed=2103ms
2025-06-01T10:00:04Z appsvc ERROR upstream timeout id=1004 client=198.51.100.23 path=/api/items status=502
2025-06-01T10:00:05Z appsvc INFO request id=1005 client=203.0.113.7 path=/api/items?q=union+select+password+from+users status=400
2025-06-01T10:00:06Z appsvc INFO request id=1006 client=192.0.2.44 path=/download?file=../../etc/passwd status=403
2025-06-01T10:00:07Z appsvc INFO request id=1007 client=192.0.2.44 path=/search?q=<script>alert(1)</script> status=400
2025-06-01T10:00:08Z appsvc INFO login attempt user=admin client=192.0.2.44 result=failed password
2025-06-01T10:00:09Z appsvc INFO login attempt user=admin client=192.0.2.44 result=failed password
2025-06-01T10:00:10Z appsvc INFO login attempt user=svc_backup client=203.0.113.7 result=access denied
2025-06-01T10:00:11Z appsvc INFO request id=1008 client=203.0.113.7 path=/api/items status=200
2025-06-01T10:00:12Z appsvc ERROR disk usage 91 percent on /var
2025-06-01T10:00:13Z appsvc INFO request id=1009 client=198.51.100.23 path=/api/items status=200
2025-06-01T10:00:14Z appsvc INFO request id=1010 client=203.0.113.7 path=/api/items status=200
2025-06-01T10:00:15Z appsvc INFO heartbeat ok version=4.2.1 build=20250601
EOF

# generic/clean.log: boring healthy log; zero findings, exit 0 even with
# --fail-level low.
cat > "$FIX/generic/clean.log" <<'EOF'
2025-06-01T09:00:01Z appsvc INFO service started version=4.2.1
2025-06-01T09:00:02Z appsvc INFO request id=900 client=203.0.113.7 path=/api/health status=200
2025-06-01T09:00:03Z appsvc INFO request id=901 client=203.0.113.7 path=/api/items status=200
2025-06-01T09:00:04Z appsvc INFO request id=902 client=198.51.100.23 path=/api/items status=200
2025-06-01T09:00:05Z appsvc INFO heartbeat ok version=4.2.1 build=20250601
EOF

mkdir -p "$FIX/auth"

# auth/bruteforce.log: 12 failures from one IP inside 40s (must trip the
# default 10-in-60s window), then a successful login from the same IP 50s
# later (must trip the possible-compromise heuristic). Note "Jun  1" single
# digit days exercise syslog's double-space alignment.
cat > "$FIX/auth/bruteforce.log" <<'EOF'
Jun  1 09:58:11 bastion sshd[2188]: Accepted publickey for kyle from 198.51.100.7 port 50122 ssh2: RSA SHA256:aBcD
Jun  1 09:58:11 bastion sshd[2188]: pam_unix(sshd:session): session opened for user kyle by (uid=0)
Jun  1 10:00:00 bastion sshd[2201]: Invalid user admin from 203.0.113.66 port 44321
Jun  1 10:00:00 bastion sshd[2201]: Failed password for invalid user admin from 203.0.113.66 port 44321 ssh2
Jun  1 10:00:02 bastion sshd[2202]: Failed password for invalid user admin from 203.0.113.66 port 44322 ssh2
Jun  1 10:00:05 bastion sshd[2203]: Failed password for invalid user admin from 203.0.113.66 port 44323 ssh2
Jun  1 10:00:08 bastion sshd[2204]: Failed password for invalid user admin from 203.0.113.66 port 44324 ssh2
Jun  1 10:00:11 bastion sshd[2205]: Invalid user oracle from 203.0.113.66 port 44325
Jun  1 10:00:11 bastion sshd[2205]: Failed password for invalid user oracle from 203.0.113.66 port 44325 ssh2
Jun  1 10:00:14 bastion sshd[2206]: Failed password for invalid user oracle from 203.0.113.66 port 44326 ssh2
Jun  1 10:00:17 bastion sshd[2207]: Failed password for invalid user oracle from 203.0.113.66 port 44327 ssh2
Jun  1 10:00:20 bastion sshd[2208]: Invalid user postgres from 203.0.113.66 port 44328
Jun  1 10:00:20 bastion sshd[2208]: Failed password for invalid user postgres from 203.0.113.66 port 44328 ssh2
Jun  1 10:00:25 bastion sshd[2209]: Failed password for invalid user postgres from 203.0.113.66 port 44329 ssh2
Jun  1 10:00:30 bastion sshd[2210]: Failed password for root from 203.0.113.66 port 44330 ssh2
Jun  1 10:00:35 bastion sshd[2211]: Failed password for root from 203.0.113.66 port 44331 ssh2
Jun  1 10:00:40 bastion sshd[2212]: Failed password for root from 203.0.113.66 port 44332 ssh2
Jun  1 10:01:30 bastion sshd[2215]: Accepted password for admin from 203.0.113.66 port 44340 ssh2
Jun  1 10:01:30 bastion sshd[2215]: pam_unix(sshd:session): session opened for user admin by (uid=0)
Jun  1 10:05:00 bastion sshd[2220]: Did not receive identification string from 192.0.2.200
Jun  1 10:06:00 bastion sshd[2221]: Connection closed by 192.0.2.200 port 55001 [preauth]
EOF

# auth/slowdrip.log: 10 failures spread over ~24h from one IP; the default
# 10-in-60s window must NOT alert. With --bf-threshold 5 --bf-window 86400 it
# must (that is the flag test).
cat > "$FIX/auth/slowdrip.log" <<'EOF'
Jun  2 00:15:09 bastion sshd[3101]: Failed password for invalid user guest from 192.0.2.99 port 40001 ssh2
Jun  2 02:40:18 bastion sshd[3110]: Failed password for invalid user guest from 192.0.2.99 port 40002 ssh2
Jun  2 05:05:27 bastion sshd[3122]: Failed password for invalid user guest from 192.0.2.99 port 40003 ssh2
Jun  2 07:30:36 bastion sshd[3135]: Failed password for invalid user guest from 192.0.2.99 port 40004 ssh2
Jun  2 08:12:00 bastion sshd[3140]: Accepted publickey for kyle from 198.51.100.7 port 50188 ssh2: RSA SHA256:aBcD
Jun  2 08:12:00 bastion sshd[3140]: pam_unix(sshd:session): session opened for user kyle by (uid=0)
Jun  2 09:55:45 bastion sshd[3149]: Failed password for invalid user guest from 192.0.2.99 port 40005 ssh2
Jun  2 12:20:54 bastion sshd[3160]: Failed password for invalid user guest from 192.0.2.99 port 40006 ssh2
Jun  2 14:45:03 bastion sshd[3171]: Failed password for invalid user guest from 192.0.2.99 port 40007 ssh2
Jun  2 17:10:12 bastion sshd[3182]: Failed password for invalid user guest from 192.0.2.99 port 40008 ssh2
Jun  2 18:30:00 bastion sshd[3188]: pam_unix(sshd:session): session closed for user kyle
Jun  2 19:35:21 bastion sshd[3193]: Failed password for invalid user guest from 192.0.2.99 port 40009 ssh2
Jun  2 23:45:30 bastion sshd[3204]: Failed password for invalid user guest from 192.0.2.99 port 40010 ssh2
EOF

# auth/normal.log: healthy day; zero findings.
cat > "$FIX/auth/normal.log" <<'EOF'
Jun  3 08:00:01 bastion sshd[4001]: Accepted publickey for kyle from 198.51.100.7 port 50201 ssh2: RSA SHA256:aBcD
Jun  3 08:00:01 bastion sshd[4001]: pam_unix(sshd:session): session opened for user kyle by (uid=0)
Jun  3 12:15:40 bastion sshd[4001]: pam_unix(sshd:session): session closed for user kyle
Jun  3 13:02:11 bastion sshd[4010]: Accepted publickey for sandra from 198.51.100.8 port 50230 ssh2: RSA SHA256:eFgH
Jun  3 13:02:11 bastion sshd[4010]: pam_unix(sshd:session): session opened for user sandra by (uid=0)
Jun  3 13:40:00 bastion sshd[4015]: Connection closed by 198.51.100.8 port 50231 [preauth]
Jun  3 17:22:05 bastion sshd[4010]: pam_unix(sshd:session): session closed for user sandra
EOF

mkdir -p "$FIX/syslog" "$FIX/journald" "$FIX/web"

# syslog/system.log: general system log with oom, segfault, sudo failures.
cat > "$FIX/syslog/system.log" <<'EOF'
Jun 10 06:25:01 webserv CRON[9101]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)
Jun 10 06:30:11 webserv systemd[1]: Starting Daily apt download activities...
Jun 10 06:30:12 webserv systemd[1]: apt-daily.service: Succeeded.
Jun 10 07:02:44 webserv kernel: [812345.678901] Out of memory: Killed process 4321 (java) total-vm:8388608kB
Jun 10 07:02:45 webserv systemd[1]: app-worker.service: Main process exited, code=killed, status=9/KILL
Jun 10 07:02:46 webserv systemd[1]: app-worker.service: Failed with result 'signal'.
Jun 10 07:05:00 webserv systemd[1]: app-worker.service: Scheduled restart job, restart counter is at 1.
Jun 10 08:14:09 webserv kernel: [816754.321098] reportgen[5150]: segfault at 7f3a00000000 ip 00005584a1b2c3d4 sp 00007ffd11223344 error 4 in reportgen[5584a1a00000+200000]
Jun 10 09:00:00 webserv sudo: kyle : TTY=pts/0 ; PWD=/home/kyle ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Jun 10 09:00:00 webserv sudo: pam_unix(sudo:session): session opened for user root by kyle(uid=1000)
Jun 10 09:00:04 webserv sudo: pam_unix(sudo:session): session closed for user root
Jun 10 11:41:33 webserv sudo: sandra : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/sandra ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Jun 10 12:00:07 webserv CRON[9310]: (www-data) CMD (php /var/www/queue-runner.php)
Jun 10 12:10:22 webserv systemd[1]: logrotate.service: Succeeded.
EOF

# journald/short-iso.log: journalctl -o short-iso shape.
cat > "$FIX/journald/short-iso.log" <<'EOF'
2025-06-10T09:00:01-0700 webserv systemd[1]: Started Session 42 of user kyle.
2025-06-10T09:00:05-0700 webserv sshd[7001]: Accepted publickey for kyle from 198.51.100.7 port 51000 ssh2
2025-06-10T09:15:12-0700 webserv nginx[1200]: 2025/06/10 09:15:12 [error] 1200#1200: *44 open() failed (2: No such file or directory)
2025-06-10T09:30:00-0700 webserv kernel[0]: Out of memory: Killed process 5900 (chromium) total-vm:4194304kB
2025-06-10T09:30:02-0700 webserv systemd[1]: render.service: Failed with result 'oom-kill'.
2025-06-10T10:00:00-0700 webserv systemd[1]: Starting Cleanup of Temporary Directories...
2025-06-10T10:00:01-0700 webserv systemd[1]: systemd-tmpfiles-clean.service: Succeeded.
2025-06-10T10:30:44-0700 webserv myapp[6100]: request completed in 120ms
EOF

# journald/export.json: journalctl -o json (one object per line).
cat > "$FIX/journald/export.json" <<'EOF'
{"__REALTIME_TIMESTAMP":"1749574801000000","_HOSTNAME":"webserv","SYSLOG_IDENTIFIER":"systemd","PRIORITY":"6","MESSAGE":"Started Session 42 of user kyle."}
{"__REALTIME_TIMESTAMP":"1749574805000000","_HOSTNAME":"webserv","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"6","MESSAGE":"Accepted publickey for kyle from 198.51.100.7 port 51000 ssh2"}
{"__REALTIME_TIMESTAMP":"1749575712000000","_HOSTNAME":"webserv","SYSLOG_IDENTIFIER":"nginx","PRIORITY":"3","MESSAGE":"open() failed (2: No such file or directory) while reading upstream"}
{"__REALTIME_TIMESTAMP":"1749576600000000","_HOSTNAME":"webserv","SYSLOG_IDENTIFIER":"kernel","PRIORITY":"2","MESSAGE":"Out of memory: Killed process 5900 (chromium) total-vm:4194304kB"}
{"__REALTIME_TIMESTAMP":"1749576602000000","_HOSTNAME":"webserv","SYSLOG_IDENTIFIER":"kernel","PRIORITY":"4","MESSAGE":"reportgen[5150]: segfault at 7f3a00000000 ip 00005584a1b2c3d4 error 4"}
{"__REALTIME_TIMESTAMP":"1749578444000000","_HOSTNAME":"webserv","SYSLOG_IDENTIFIER":"myapp","PRIORITY":"6","MESSAGE":"request completed in 120ms"}
EOF

# web/access.log: combined format; a scanner, one sqli probe, one traversal.
cat > "$FIX/web/access.log" <<'EOF'
198.51.100.23 - - [10/Jun/2025:10:00:01 -0700] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
198.51.100.23 - - [10/Jun/2025:10:00:05 -0700] "GET /blog HTTP/1.1" 200 8200 "-" "Mozilla/5.0"
198.51.100.23 - - [10/Jun/2025:10:00:09 -0700] "GET /styles.css HTTP/1.1" 200 1100 "-" "Mozilla/5.0"
198.51.100.23 - - [10/Jun/2025:10:01:00 -0700] "GET /blog HTTP/1.1" 304 0 "-" "Mozilla/5.0"
203.0.113.50 - - [10/Jun/2025:10:02:00 -0700] "GET / HTTP/1.1" 200 5120 "-" "curl/8.0"
198.51.100.23 - - [10/Jun/2025:10:03:11 -0700] "POST /api/contact HTTP/1.1" 200 310 "-" "Mozilla/5.0"
192.0.2.15 - - [10/Jun/2025:10:04:00 -0700] "GET /products.php?id=1+union+select+password+from+users HTTP/1.1" 500 0 "-" "sqlmap/1.7"
192.0.2.15 - - [10/Jun/2025:10:04:05 -0700] "GET /download?file=../../../etc/passwd HTTP/1.1" 403 0 "-" "sqlmap/1.7"
203.0.113.99 - - [10/Jun/2025:10:05:00 -0700] "GET /wp-login.php HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:05 -0700] "GET /.env HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:10 -0700] "GET /phpmyadmin/ HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:15 -0700] "GET /admin/config.php HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:20 -0700] "GET /.git/config HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:25 -0700] "GET /xmlrpc.php HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:30 -0700] "GET /backup.zip HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:35 -0700] "GET /old/ HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:40 -0700] "GET /test.php HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:45 -0700] "GET /wp-admin/ HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:50 -0700] "GET /config.bak HTTP/1.1" 404 0 "-" "python-requests/2.31"
203.0.113.99 - - [10/Jun/2025:10:05:55 -0700] "GET /robots.txt HTTP/1.1" 200 120 "-" "python-requests/2.31"
198.51.100.23 - - [10/Jun/2025:10:06:00 -0700] "GET /blog/post-1 HTTP/1.1" 200 6100 "-" "Mozilla/5.0"
198.51.100.23 - - [10/Jun/2025:10:07:00 -0700] "GET /favicon.ico HTTP/1.1" 404 0 "-" "Mozilla/5.0"
EOF

# web/quiet.log: healthy traffic only; zero findings.
cat > "$FIX/web/quiet.log" <<'EOF'
198.51.100.23 - - [11/Jun/2025:09:00:01 -0700] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
198.51.100.23 - - [11/Jun/2025:09:00:04 -0700] "GET /blog HTTP/1.1" 200 8200 "-" "Mozilla/5.0"
203.0.113.50 - - [11/Jun/2025:09:01:00 -0700] "GET /about HTTP/1.1" 200 4100 "-" "Mozilla/5.0"
198.51.100.23 - - [11/Jun/2025:09:02:10 -0700] "GET /blog HTTP/1.1" 304 0 "-" "Mozilla/5.0"
203.0.113.50 - - [11/Jun/2025:09:03:00 -0700] "GET /contact HTTP/1.1" 200 2900 "-" "Mozilla/5.0"
198.51.100.23 - - [11/Jun/2025:09:04:30 -0700] "POST /api/contact HTTP/1.1" 200 310 "-" "Mozilla/5.0"
EOF

echo "fixtures written under $FIX"
