# Linux 巡检脚本

[English](README.md) | **中文**

纯 Bash 主机巡检工具：一条命令采集 系统 / 性能 / 磁盘 / 网络 / 安全 / 服务 / 日志 七大类检查项，生成带 告警汇总 + 问题清单 的中文文本/JSON 报告。全程只读，不改动系统配置。

主脚本：`linux_inspect.sh`

**当前版本**：v1.2.0（更新内容详见脚本内"版本历史"注释块）

## 快速使用

```bash
# 推荐 root 运行（数据完整）；非 root 会自动降级并在报告标注
sudo bash linux_inspect.sh

# 常用组合
sudo bash linux_inspect.sh -o /var/log/inspect --stdout   # 指定目录 + 终端同步输出
sudo bash linux_inspect.sh -f json -o /var/log/inspect    # JSON 格式, 供监控平台采集
bash linux_inspect.sh --fast -q                           # 快速+静默, 仅输出报告路径 (cron 适用)

# 查看帮助
bash linux_inspect.sh -h
```

**命令行参数**

| 参数 | 说明 |
|---|---|
| `-o 目录` | 报告输出目录（默认当前目录） |
| `-f text\|json` | 报告格式，默认 text |
| `-q, --quiet` | 静默模式，仅输出报告文件路径 |
| `--stdout` | 巡检完成后将完整报告打印到终端 |
| `--fast` | 快速模式 = 跳过大文件扫描 + SSL 证书检查 |
| `--no-large-file-scan` | 仅跳过大文件扫描 |
| `--skip-ssl-check` | 仅跳过 SSL 证书扫描 |
| `--ascii-name` | 报告文件名改用 ASCII（`inspect_<主机名>_<时间>`），对接 zabbix/ELK 采集或跨平台转存时避免编码问题 |

报告文件：`巡检报告_<主机名>_<时间>.txt|.json`（`--ascii-name` 时为 `inspect_<主机名>_<时间>.txt|.json`）

**退出码**：`0` 全部正常；`1` 存在严重问题；`2` 存在警告；`3` 脚本自身异常。可直接用于 cron + 告警联动。

```cron
# 每天凌晨 2 点巡检，报告落盘 /var/log/inspect（-q 静默避免 cron 邮件；/bin/bash 全平台通用）
# 注意: 以下为 /etc/crontab 系统级格式(含用户字段 root)；用 crontab -e 个人 crontab 时请去掉 root 字段
0 2 * * * root /bin/bash /opt/linux_inspect.sh -q -o /var/log/inspect
```

## 检查项覆盖

| 分类 | 内容 |
|------|------|
| 1 系统信息 | 发行版/内核/虚拟化/运行时长/CPU 型号核数/重启记录/文件句柄/**内核参数基线**(syncookies/somaxconn/backlog/tw_reuse/file-max，偏离建议值仅提示、不计入告警) |
| 2 性能 | CPU 使用率（/proc 采样）、负载折合每核、内存/Swap 使用率、磁盘 I/O 利用率（diskstats 采样）、Top CPU/内存进程、僵尸进程、**D 状态进程** |
| 3 磁盘 | 分区容量与使用率、inode 使用率、只读挂载分区、**大文件扫描**(TOP N + 近 7 天新产生大文件) |
| 4 网络 | 网卡 IP、默认网关/外网连通性（ping）、DNS 解析测试、监听端口、ESTABLISHED/TIME_WAIT/**CLOSE_WAIT**、网卡收发错误与丢包计数 |
| 5 安全 | UID=0 账户、空密码账户、密码有效期策略、SSH PermitRootLogin、SSH 暴力破解计数（含轮转日志 secure-\*/auth.log.\*，默认只统计近 30 天写入的日志，`BRUTE_LOG_DAYS` 可调）、SELinux/AppArmor、防火墙（firewalld/ufw/SuSEfirewall2/iptables/nft）、SUID 文件、全局可写文件、root 计划任务、umask、**SSL 证书有效期扫描** |
| 6 服务 | systemd failed 单元、sshd/cron/rsyslog/时间同步关键服务状态、开机自启统计、**Docker/Podman 容器巡检**(运行/停止/镜像/异常容器)、常见中间件进程探测（mysql/redis/nginx/k8s/监控组件等 35+） |
| 7 日志内核 | dmesg OOM/硬件 IO 错误、系统日志错误摘要（messages/syslog，均缺失时 journalctl 兜底）、最近登录记录 |

报告尾部自动生成**运维建议**段：按本次触发的告警类型给出对应处置动作。

**JSON 输出结构**（`-f json`）：`meta`（主机/系统/耗时）+ `summary`（ok/warn/crit/结论）+ `recommendations`（建议数组）+ `items`（判定类条目 kv/ok/info/warn/crit，含 `sec` 章节、`type` 类型、`text` 文本；表格类明细仅进文本报告），可直接被监控平台/资产系统消费。

## 兼容性设计

- 覆盖 RHEL/CentOS 6-9、Rocky/Alma/Fedora、Ubuntu 14.04+、Debian 7+、openEuler、Kylin、UOS、Anolis、Alibaba Cloud Linux、TencentOS、SLES 12+。
- systemd 与 SysV init 自动识别，逐项降级（CentOS 6 也可跑）。
- 缺失的命令自动跳过对应检查（`ss`/`netstat`、`ip`/`ifconfig`、`chrony`/`ntp`、firewalld/ufw 等均有备选链路）。
- 依赖仅 bash + coreutils/procps 常规命令（`ps`/`timeout`/`sort` 等），无 python/perl/框架；`df`/`lastb` 等可能卡住的命令用 `timeout` 包裹，NFS 掉线不会挂死脚本。
- 老内核无 `MemAvailable` 时自动用 Free+Buffers+Cached+SReclaimable 估算。

## 阈值与配置

脚本头部"可调参数"区直接改：

```bash
THRESH_CPU_WARN=80      THRESH_CPU_CRIT=90
THRESH_MEM_WARN=80      THRESH_MEM_CRIT=90
THRESH_SWAP_WARN=60     THRESH_SWAP_CRIT=90
THRESH_DISK_WARN=80     THRESH_DISK_CRIT=90
THRESH_INODE_WARN=80    THRESH_INODE_CRIT=90
THRESH_ZOMBIE_CRIT=20                            # 僵尸进程数 (达到即 crit, ≥1 即 warn)
THRESH_FILENR_PCT=80                             # 系统级文件句柄使用率(%)
THRESH_LOAD_WARN=80     THRESH_LOAD_CRIT=100     # 负载/核数 百分比
THRESH_BRUTE_WARN=50    THRESH_BRUTE_CRIT=500    # SSH 失败登录条数
BRUTE_LOG_DAYS=30                              # 只统计最近 N 天写入的日志, 0=全部历史
DSTATE_WARN=3           DSTATE_CRIT=20           # D 状态进程数
CONN_CLOSE_WAIT_WARN=50                          # CLOSE_WAIT 连接数
TIME_WAIT_WARN=20000                             # TIME_WAIT 超限仅提示, 不计入告警
LARGE_FILE_SIZE="+100M" LARGE_FILE_TOTAL_WARN_GB=10
SSL_CERT_DAYS_WARN=30   SSL_CERT_DAYS_INFO=90
PING_TARGETS=("223.5.5.5" "114.114.114.114" "1.1.1.1")
DNS_TEST_DOMAIN="www.baidu.com"
TOP_PROC_NUM=10
```

## 注意事项

- 非 root 运行时：`/etc/shadow`、`lastb`、iptables、dmesg、系统日志、SUID 扫描等会降级，报告内标注 `[提示]`，判定结果可能不完整。
- SSH 关键服务检查在 systemd 主机上以单元状态为准；未安装 sshd 的主机判 `[提示]` 并跳过，已安装但未运行才判 `[严重]`。
- SUID 文件清单按 `-xdev` 仅扫描根分区：`/usr` 等独立分区的机器如需全覆盖，请自行扩展扫描路径。
- 禁 ICMP 环境下网关/外网连通性告警可忽略（报告已注明）。
- 大文件扫描按 **apparent size** 统计：稀疏文件（虚机 qcow2 镜像等）显示值偏大；扫描范围/阈值在脚本头部 `LARGE_FILE_*` 调整，`/var/lib/docker|containers|podman` 已自动排除；总量告警可设 `LARGE_FILE_TOTAL_WARN_GB=0` 关闭。
- SSL 证书扫描覆盖脚本头部 `SSL_CERT_PATHS` 中的标准路径，自部署服务的证书目录请自行追加；系统 CA 仓库中的过期根证书属正常现象，可忽略。
- CLOSE_WAIT 高才是应用连接泄漏；TIME_WAIT 大量存在属正常，超阈值仅 `[提示]`、不计入告警统计。
- 报告为明文，含端口、账户等敏感信息；生成时已自动设为 600 权限，归档/转存时注意保持受限。
- 内核参数基线（`sec_system` 内置表）为建议值对照：部分参数内核会按内存自动定值（如 tcp_max_syn_backlog），偏离仅 `[提示]`、不计入告警与退出码。
- `--fast` 跳过大文件扫描后，磁盘类告警只剩空间/inode/只读维度，大文件总量与近期新增统计不再输出。
- 仓库带 `.gitattributes` 锁定 LF 行尾；若脚本被 Windows 编辑器改成 CRLF，用 `sed -i 's/\r$//' linux_inspect.sh` 修复。
