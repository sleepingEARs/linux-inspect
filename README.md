# linux-inspect

**English** | [中文](README.zh-CN.md)

A pure-Bash Linux host inspection tool: one command collects 7 categories of checks — system / performance / disk / network / security / services / logs & kernel — and generates a text or JSON report with an alert summary and issue list. Fully read-only; it never modifies system configuration.

Main script: `linux_inspect.sh`

**Current version**: v1.2.1 (see the "版本历史" comment block at the top of the script for the changelog)

> **Note**: report content is generated in **Chinese** (the tool targets Chinese-language ops environments). The `-h` help output is bilingual English/Chinese. Exit codes, thresholds and the JSON output structure are language-neutral and easy to consume programmatically.

## Quick Start

```bash
# Root recommended (complete data); non-root degrades gracefully with notes in the report
sudo bash linux_inspect.sh

# Common combinations
sudo bash linux_inspect.sh -o /var/log/inspect --stdout   # custom output dir + print report to terminal
sudo bash linux_inspect.sh -f json -o /var/log/inspect    # JSON format, for monitoring platforms
bash linux_inspect.sh --fast -q                           # fast + quiet, prints only the report path (cron-friendly)

# Show help
bash linux_inspect.sh -h
```

**Command-line options**

| Option | Description |
|---|---|
| `-o DIR` | Report output directory (default: current directory, created if missing) |
| `-f text\|json` | Report format, default `text` |
| `-q, --quiet` | Quiet mode; prints only the report file path |
| `--stdout` | Also print the full report to the terminal when done |
| `--fast` | Fast mode = skip large-file scan + SSL certificate check |
| `--no-large-file-scan` | Skip only the large-file scan |
| `--skip-ssl-check` | Skip only the SSL certificate scan |
| `--ascii-name` | Use an ASCII report filename (`inspect_<host>_<time>`) to avoid encoding issues with Zabbix/ELK pipelines or cross-platform copying |

Report file: `巡检报告_<host>_<timestamp>.txt|.json` (or `inspect_<host>_<timestamp>.txt|.json` with `--ascii-name`)

**Exit codes**: `0` all checks passed; `1` critical issues found; `2` warnings found; `3` script runtime error. Ready for cron + alerting integration.

```cron
# Daily inspection at 02:00, reports to /var/log/inspect (-q avoids cron mail; /bin/bash works everywhere)
# Note: this is the /etc/crontab system-wide format (with the "root" user field);
# for a personal crontab -e, remove the "root" field
0 2 * * * root /bin/bash /opt/linux_inspect.sh -q -o /var/log/inspect
```

## Check Coverage

| Category | Contents |
|----------|----------|
| 1 System | distro / kernel / virtualization / uptime / CPU model & cores / reboot history / file handles / **kernel parameter baseline** (syncookies/somaxconn/backlog/tw_reuse/file-max; deviations are info-only, not counted as alerts) |
| 2 Performance | CPU usage (sampled from /proc), load per core, memory/Swap usage, disk I/O utilization (diskstats sampling), Top CPU/memory processes, zombie processes, **D-state processes** |
| 3 Disk | partition capacity & usage, inode usage, read-only mounted partitions, **large-file scan** (Top N + large files created in the last 7 days) |
| 4 Network | NIC IPs, default gateway / external connectivity (ping), DNS resolution test, listening ports, ESTABLISHED/TIME_WAIT/**CLOSE_WAIT**, NIC error/drop counters |
| 5 Security | UID=0 accounts, empty-password accounts, password aging policy, SSH PermitRootLogin, SSH brute-force count (includes rotated logs secure-\*/auth.log.\*; only logs written within the last 30 days by default, tunable via `BRUTE_LOG_DAYS`), SELinux/AppArmor, firewall (firewalld/ufw/SuSEfirewall2/iptables/nft), SUID files, world-writable files, root crontab, umask, **SSL certificate expiry scan** |
| 6 Services | systemd failed units, key service status (sshd/cron/rsyslog/time sync), autostart stats, **Docker/Podman container inspection** (running/stopped/images/abnormal containers), detection of 35+ common middleware processes (mysql/redis/nginx/k8s/monitoring agents, etc.) |
| 7 Logs & Kernel | dmesg OOM / hardware I/O errors, system log error digest (messages/syslog, journalctl fallback), recent logins |

The report ends with an auto-generated **recommendations** section: remediation advice matched to the alert types triggered in this run.

**JSON output structure** (`-f json`): `meta` (host/OS/duration) + `summary` (ok/warn/crit/verdict) + `recommendations` (array) + `items` (verdict entries kv/ok/info/warn/crit with `sec` section, `type`, `text`; tabular details only appear in the text report). Ready for monitoring platforms / CMDB consumption.

## Compatibility

- RHEL/CentOS 6-9, Rocky/Alma/Fedora, Ubuntu 14.04+, Debian 7+, openEuler, Kylin, UOS, Anolis, Alibaba Cloud Linux, TencentOS, SLES 12+.
- Auto-detects systemd vs SysV init and degrades per check (runs on CentOS 6 too).
- A missing command only skips its own checks (`ss`/`netstat`, `ip`/`ifconfig`, `chrony`/`ntp`, firewalld/ufw all have fallback paths).
- Depends only on bash + common coreutils/procps tools (`ps`/`timeout`/`sort`, etc.) — no python/perl/frameworks. Commands that may hang (`df`/`lastb`) are wrapped in `timeout`, so an NFS outage won't stall the script.
- Falls back to Free+Buffers+Cached+SReclaimable when `MemAvailable` is missing on old kernels.

## Thresholds & Configuration

Edit the tunable-parameters block at the top of the script:

```bash
THRESH_CPU_WARN=80      THRESH_CPU_CRIT=90
THRESH_MEM_WARN=80      THRESH_MEM_CRIT=90
THRESH_SWAP_WARN=60     THRESH_SWAP_CRIT=90
THRESH_DISK_WARN=80     THRESH_DISK_CRIT=90
THRESH_INODE_WARN=80    THRESH_INODE_CRIT=90
THRESH_ZOMBIE_CRIT=20                            # zombie count (crit at this value, >=1 is warn)
THRESH_FILENR_PCT=80                             # system-wide file handle usage (%)
THRESH_LOAD_WARN=80     THRESH_LOAD_CRIT=100     # 5-min load / core count (%)
THRESH_BRUTE_WARN=50    THRESH_BRUTE_CRIT=500    # SSH "Failed password" count
BRUTE_LOG_DAYS=30                                # only count logs written within N days, 0=all history
DSTATE_WARN=3           DSTATE_CRIT=20           # D-state process count
CONN_CLOSE_WAIT_WARN=50                          # CLOSE_WAIT connection count
TIME_WAIT_WARN=20000                             # above this only an info note, never an alert
LARGE_FILE_SIZE="+100M" LARGE_FILE_TOTAL_WARN_GB=10
SSL_CERT_DAYS_WARN=30   SSL_CERT_DAYS_INFO=90
PING_TARGETS=("223.5.5.5" "114.114.114.114" "1.1.1.1")
DNS_TEST_DOMAIN="www.baidu.com"
TOP_PROC_NUM=10
```

## Notes

- Non-root runs: `/etc/shadow`, `lastb`, iptables, dmesg, system logs and the SUID scan degrade; the report marks them as info and results may be incomplete.
- On systemd hosts the SSH service check follows unit state; hosts without sshd installed get an info note and are skipped — only an installed-but-stopped sshd is critical.
- The SUID scan uses `-xdev` and covers only the root filesystem; extend the scan paths yourself if `/usr` etc. are separate partitions.
- Gateway / external connectivity alerts can be ignored in ICMP-blocked environments (noted in the report).
- The large-file scan counts **apparent size**: sparse files (e.g. VM qcow2 images) show inflated values; tune scope/thresholds via `LARGE_FILE_*` at the top of the script. `/var/lib/docker|containers|podman` are auto-excluded; set `LARGE_FILE_TOTAL_WARN_GB=0` to disable the total-size alert.
- SSL scanning covers the standard paths in `SSL_CERT_PATHS`; add your own cert directories for self-deployed services. Expired root certificates in the system CA store are normal and can be ignored.
- High CLOSE_WAIT indicates an application connection leak; large TIME_WAIT counts are normal and only trigger an info note, never an alert.
- Reports are plaintext and contain sensitive data (ports, accounts). They are created with `600` permissions automatically; keep them restricted when archiving or copying.
- The kernel parameter baseline (built into `sec_system`) is a recommended-value comparison: some parameters are auto-sized by the kernel based on memory (e.g. `tcp_max_syn_backlog`), so deviations are info-only and never counted as alerts or reflected in the exit code.
- With `--fast`, disk alerting is limited to space/inode/read-only checks; large-file totals and recent-file stats are skipped.
- The repo pins LF line endings via `.gitattributes`; if a Windows editor converts the script to CRLF, fix it with `sed -i 's/\r$//' linux_inspect.sh`.

## License

MIT — see [LICENSE](LICENSE). Original project by Aidan-996, maintained by sleepingEARs.
