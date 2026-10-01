#!/usr/bin/env bash
# =============================================================================
#  linux_inspect.sh — Linux 主机巡检脚本（纯 Bash，无框架依赖）
#
#  兼容发行版:
#    RHEL / CentOS 6~9 / Rocky / Alma / Fedora
#    Ubuntu 14.04+ / Debian 7+ / Linux Mint
#    openEuler / Kylin / UOS / Anolis / Alibaba Cloud Linux / TencentOS
#    SLES 12+（基础项）
#  兼容 init:  systemd 与 SysV init（自动识别，逐项降级）
#
#  巡检范围: 系统信息 / 性能(CPU·内存·负载·进程) / 磁盘 / 网络 / 安全 / 服务 / 日志内核
#  报告输出: 文本/JSON 报告（汇总结论 + 告警清单 + 分项详情），文件名形如
#            巡检报告_<主机名>_<时间>.txt
#
#  用法:
#    bash linux_inspect.sh [选项]
#      -o 目录        指定报告输出目录（默认当前目录，目录不存在会自动创建）
#      -f 格式        报告格式: text (默认) | json
#      -q, --quiet    静默模式, 仅输出报告文件路径 (适合 cron/脚本调用)
#      --stdout       巡检完成后将完整报告同时打印到终端
#      --fast         快速模式: 跳过大文件扫描与 SSL 证书检查
#      --ascii-name   报告文件名改用 ASCII: inspect_<主机名>_<时间>.<ext>
#                     (对接 zabbix/ELK 等采集链或跨平台转存时避免编码问题)
#      --no-large-file-scan  跳过大文件扫描 (大磁盘环境提速)
#      --skip-ssl-check      跳过 SSL 证书有效期扫描
#  退出码: 0=各项正常  1=存在严重问题  2=存在警告  3=脚本运行异常
#
#  说明: 全程只读采集，不修改任何系统配置。建议以 root 运行以获得完整数据；
#        非 root 时涉及 /etc/shadow、lastb、防火墙、系统日志等检查会自动
#        降级，并在报告中标注。报告含端口/账户等敏感信息，生成时自动 600 权限。
# =============================================================================

#------------------------------ 版本历史 --------------------------------------
#  v1.1.0  新增: 大文件扫描 / D状态进程 / TCP连接状态 / SSL证书 / 容器巡检 /
#          JSON 输出 / 内核参数基线 / 总体建议段
#  v1.2.0  修复: 容器 unhealthy 小写漏判; diskstats 排除正则漏 loop0/sr10;
#          inode 与空间检查过滤口径不一致(snap squashfs 误报); trap INT/TERM
#          清理后不退出
#          改进: 内核基线偏离降为提示; 未装 sshd 改判提示(sshd_installed);
#          暴力破解统计限近 BRUTE_LOG_DAYS 天; df 卡死时 df -l 本地盘兜底;
#          报告预建 600 权限并校验写盘结果; find 表达式改数组传参;
#          timeout 补 -k SIGKILL; 近期大文件扫描排除容器存储目录;
#          新增 --ascii-name 报告文件名选项(对接监控平台采集)
#------------------------------------------------------------------------------

#------------------------------ 可调参数（按需修改） --------------------------
THRESH_CPU_WARN=80            # CPU 使用率告警阈值(%)
THRESH_CPU_CRIT=90            # CPU 使用率严重阈值(%)
THRESH_MEM_WARN=80            # 内存使用率告警阈值(%)
THRESH_MEM_CRIT=90            # 严重阈值(%)
THRESH_SWAP_WARN=60           # Swap 使用率告警阈值(%)
THRESH_SWAP_CRIT=90           # 严重阈值(%)
THRESH_LOAD_WARN=80           # 负载告警阈值: 5分钟负载/CPU核数(%)
THRESH_LOAD_CRIT=100          # 严重阈值(%)
THRESH_DISK_WARN=80           # 磁盘空间告警阈值(%)
THRESH_DISK_CRIT=90           # 严重阈值(%)
THRESH_INODE_WARN=80          # inode 使用率告警阈值(%)
THRESH_INODE_CRIT=90          # 严重阈值(%)
THRESH_ZOMBIE_CRIT=20         # 僵尸进程数严重阈值(达到此值 crit; ≥1 即 warn)
THRESH_FILENR_PCT=80          # 系统级文件句柄使用率告警阈值(%)
THRESH_BRUTE_WARN=50          # SSH "Failed password" 条数告警阈值
THRESH_BRUTE_CRIT=500         # 严重阈值(条)
BRUTE_LOG_DAYS=30             # 只统计最近 N 天内有写入的日志文件, 0=统计全部(防历史累计误报)
PING_TARGETS=("223.5.5.5" "114.114.114.114" "1.1.1.1")   # 外网连通性测试目标
DNS_TEST_DOMAIN="www.baidu.com"                          # DNS 解析测试域名
TOP_PROC_NUM=10               # Top 进程展示条数

# --- 大文件扫描 (v1.1) ---
LARGE_FILE_SIZE="+100M"       # 大文件阈值
LARGE_FILE_RECENT_SIZE="+50M" # 最近修改大文件阈值
LARGE_FILE_RECENT_DAYS=7      # "最近"天数
LARGE_FILE_SCAN_PATHS="/var /home /opt /usr/local"       # 扫描范围
LARGE_FILE_TOTAL_WARN_GB=10   # 大文件总量告警阈值(GB), 0=不告警
SKIP_LARGE_FILE_SCAN=0        # 1=跳过 (由 --no-large-file-scan/--fast 置位)

# --- 进程状态 (v1.1) ---
DSTATE_WARN=3                 # D 状态(不可中断)进程告警阈值
DSTATE_CRIT=20                # 严重阈值(个)

# --- TCP 连接 (v1.1) ---
CONN_CLOSE_WAIT_WARN=50       # CLOSE_WAIT 告警阈值 (连接泄漏信号)
TIME_WAIT_WARN=20000          # TIME_WAIT 提示阈值 (大量属正常, 超限仅 b_info 提示, 无需处理)

# --- SSL 证书 (v1.1) ---
SSL_CERT_PATHS="/etc/pki/tls/certs /etc/ssl/certs /etc/nginx/ssl /etc/httpd/ssl /etc/apache2/ssl /usr/local/nginx/conf/ssl /etc/haproxy/ssl"
SSL_CERT_DAYS_WARN=30         # 剩余有效期告警阈值(天)
SSL_CERT_DAYS_INFO=90         # 剩余有效期提示阈值(天)
SKIP_SSL_CHECK=0              # 1=跳过 (由 --skip-ssl-check/--fast 置位)

#------------------------------------------------------------------------------

SCRIPT_VERSION="1.2.0"
SCRIPT_NAME="linux_inspect.sh"
export LC_ALL=C   # 解析外部命令输出 (df/ps/sort 等) 对 locale 免疫; 报告中文为字面量不受影响

#------------------------------ 基础工具函数 ----------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

if [ -t 1 ]; then
    C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'
    C_CYAN='\033[36m'; C_BOLD='\033[1m'; C_OFF='\033[0m'
else
    C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_BOLD=''; C_OFF=''
fi

p()      { [ "$QUIET" = "1" ] && return 0; printf '%b\n' "${C_CYAN}>>> $*${C_OFF}"; }   # 终端进度输出
p_ok()   { [ "$QUIET" = "1" ] && return 0; printf '%b\n' "${C_GREEN}>>> $*${C_OFF}"; }
p_warn() { [ "$QUIET" = "1" ] && return 0; printf '%b\n' "${C_YELLOW}>>> $*${C_OFF}"; }
p_crit() { [ "$QUIET" = "1" ] && return 0; printf '%b\n' "${C_RED}>>> $*${C_OFF}"; }

usage() {
    # 输出头部注释块 (从第 3 行到 "# ====" 结束线)
    sed -n '3,/^# ==*$/p' "$0" | sed 's/^# \{0,1\}//'
}

# 报告写入与告警计数
OK_COUNT=0; WARN_COUNT=0; CRIT_COUNT=0; ALERTS=""

# JSON 采集 (v1.1): kv/判定类条目同步写入 JSON_ITEMS 供 -f json 输出;
# 表格类内容 (df 明细/Top 进程/SUID 清单等) 仅进文本报告
JSON_ITEMS=""; CUR_SEC="0"
QUIET=0; OUTPUT_FORMAT="text"; ASCII_NAME=0

# "总体建议"触发标记 (v1.1)
REC_CPU=0; REC_LOAD=0; REC_MEM=0; REC_SWAP=0; REC_FILENR=0
REC_DISK=0; REC_INODE=0; REC_RO=0; REC_LARGEFILE=0
REC_ZOMBIE=0; REC_DSTATE=0; REC_CLOSEWAIT=0; REC_NIC=0
REC_UID0=0; REC_EMPTYPW=0; REC_PASSWD=0; REC_BRUTE=0; REC_FW=0; REC_SSL=0
REC_SVC=0; REC_NTP=0; REC_OOM=0; REC_HW=0; REC_ROOTLOGIN=0; REC_SELINUX=0

j_esc() {  # JSON 字符串转义: 反斜杠/双引号/制表符/回车/换行
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' \
        | awk '{printf "%s\\n", $0}' | sed 's/\\n$//'
}

j_item() {  # j_item <类型 ok|info|warn|crit|kv> <文本> — 追加一条 JSON 条目
    local esc
    esc=$(j_esc "$2")
    if [ -n "$JSON_ITEMS" ]; then JSON_ITEMS="${JSON_ITEMS},"; fi
    JSON_ITEMS="${JSON_ITEMS}{\"sec\":\"${CUR_SEC}\",\"type\":\"$1\",\"text\":\"${esc}\"}"
}

section() {  # section <编号> <标题>
    CUR_SEC="$1"
    printf '\n================================================================\n' >>"$BODY"
    printf '  [%s] %s\n' "$1" "$2" >>"$BODY"
    printf '================================================================\n' >>"$BODY"
}

kv() {  # kv <键> <值>
    printf '  %-24s: %s\n' "$1" "$2" >>"$BODY"
    j_item kv "$1: $2"
}

b_ok()   { printf '  [正常] %s\n' "$*" >>"$BODY"; OK_COUNT=$((OK_COUNT+1)); j_item ok "$*"; }
b_info() { printf '  [提示] %s\n' "$*" >>"$BODY"; j_item info "$*"; }
b_warn() {
    printf '  [警告] %s\n' "$*" >>"$BODY"
    WARN_COUNT=$((WARN_COUNT+1))
    ALERTS="${ALERTS}  - [警告] $*"$'\n'
    j_item warn "$*"
}
b_crit() {
    printf '  [严重] %s\n' "$*" >>"$BODY"
    CRIT_COUNT=$((CRIT_COUNT+1))
    ALERTS="${ALERTS}  - [严重] $*"$'\n'
    j_item crit "$*"
}

# 按百分比阈值判定并写报告: pct_check <使用率> <warn阈值> <crit阈值> <正常描述> <异常描述前缀> <建议标记变量名>
pct_check() {
    local st
    st=$(awk -v v="$1" -v w="$2" -v c="$3" 'BEGIN{
        if (v+0>=c) print "crit"; else if (v+0>=w) print "warn"; else print "ok"}')
    case "$st" in
        ok)   b_ok "$4" ;;
        warn) b_warn "$5${1}%"; [ -n "$6" ] && eval "$6=1" ;;
        crit) b_crit "$5${1}%"; [ -n "$6" ] && eval "$6=1" ;;
    esac
}

# 优先用 timeout 包裹，防止 df/lastb 等命令在异常环境(如 NFS 卡死)下挂住
# -k 2: D 状态卡死的进程可能忽略 SIGTERM, 2 秒后补 SIGKILL
safe_run() {
    local t="$1"; shift
    if have timeout; then timeout -k 2 "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi
}

kb2g() { awk -v k="$1" 'BEGIN{printf "%.2f", k/1048576}'; }   # kB -> GB

#------------------------------ 环境探测 --------------------------------------
IS_ROOT=no
[ "$(id -u 2>/dev/null)" = "0" ] && IS_ROOT=yes

if [ -d /run/systemd/system ] && have systemctl; then
    INIT_TYPE="systemd"
else
    INIT_TYPE="SysV"
fi

# 有 -T 支持(GNU df)时带文件系统类型输出
if df -PT >/dev/null 2>&1; then
    DF_T="yes"
else
    DF_T="no"
fi

#------------------------------ [1] 系统信息 ----------------------------------
get_os() {
    local s
    if [ -r /etc/os-release ]; then
        s=$(awk -F'"' '/^PRETTY_NAME=/{print $2; exit}' /etc/os-release)
        [ -z "$s" ] && s=$(awk -F'"' '/^NAME=/{print $2; exit}' /etc/os-release)
    fi
    [ -z "$s" ] && [ -r /etc/redhat-release ] && s=$(cat /etc/redhat-release)
    [ -z "$s" ] && [ -r /etc/debian_version ] && s="Debian $(cat /etc/debian_version 2>/dev/null)"
    [ -z "$s" ] && s="$(uname -sr)"
    printf '%s' "$s"
}

sec_system() {
    section "1" "系统信息"
    local HOST virt ncpu sockets threads cpu_model

    HOST=$(hostname 2>/dev/null)
    [ -z "$HOST" ] && HOST="unknown"
    kv "主机名" "$HOST"
    kv "巡检时间" "$(date '+%Y-%m-%d %H:%M:%S')"
    kv "操作系统" "$(get_os)"
    kv "内核版本" "$(uname -r) ($(uname -m))"

    virt=$(systemd-detect-virt 2>/dev/null)
    case "$virt" in
        "")    virt="未检测(无 systemd-detect-virt)" ;;
        none)  virt="物理机" ;;
        kvm|qemu|vmware|xen|oracle|microsoft|bochs|uml|zvm) virt="$virt (虚拟机)" ;;
        *)     virt="$virt" ;;
    esac
    kv "虚拟化环境" "$virt"

    kv "运行时长" "$(awk '{s=int($1);printf "%d天%d小时%d分钟",int(s/86400),int(s%86400/3600),int(s%3600/60)}' /proc/uptime 2>/dev/null)"
    if [ "$INIT_TYPE" = "systemd" ]; then kv "Init 系统" "systemd"; else kv "Init 系统" "SysV init"; fi
    kv "时区/系统时间" "$(date '+%Z %z')  $(date '+%Y-%m-%d %H:%M:%S')"
    kv "默认语言" "${LANG:-未设置}"

    cpu_model=$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)
    [ -z "$cpu_model" ] && cpu_model="$(uname -m)"
    ncpu=$(nproc 2>/dev/null)
    [ -z "$ncpu" ] && ncpu=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
    [ -z "$ncpu" -o "$ncpu" = "0" ] && ncpu=1
    N_CPU="$ncpu"
    if have lscpu; then
        sockets=$(lscpu 2>/dev/null | awk -F: '/^Socket\(s\)/{gsub(/ /,"",$2);print $2}')
        threads=$(lscpu 2>/dev/null | awk -F: '/^Thread\(s\) per core/{gsub(/ /,"",$2);print $2}')
        kv "CPU 型号" "$cpu_model"
        kv "CPU 核心" "逻辑 ${ncpu} 核 | 物理 ${sockets:-?} 路 | 每核 ${threads:-?} 线程"
    else
        kv "CPU 型号" "$cpu_model"
        kv "CPU 核心" "逻辑 ${ncpu} 核"
    fi

    if have last; then
        local last_reboot
        last_reboot=$(safe_run 5 last reboot 2>/dev/null | head -n 4)
        if [ -n "$last_reboot" ]; then
            kv "最近重启记录" ""
            printf '%s\n' "$last_reboot" | sed 's/^/    /' >>"$BODY"
        else
            kv "最近重启记录" "无法获取(缺少 wtmp 或 last)"
        fi
    fi

    # 系统级文件句柄
    local fnr_used fnr_rest fnr_max fnr_pct
    if [ -r /proc/sys/fs/file-nr ]; then
        read -r fnr_used fnr_rest fnr_max < /proc/sys/fs/file-nr
        if [ -n "$fnr_max" ] && [ "$fnr_max" -gt 0 ] 2>/dev/null; then
            fnr_pct=$(awk -v u="$fnr_used" -v m="$fnr_max" 'BEGIN{printf "%.1f", u*100/m}')
            kv "系统文件句柄" "已用 $fnr_used / 上限 $fnr_max (${fnr_pct}%)"
            pct_check "$fnr_pct" "$THRESH_FILENR_PCT" "95" \
                "系统文件句柄使用正常 (${fnr_pct}%)" "系统文件句柄使用率过高: " "REC_FILENR"
        fi
    fi
    kv "进程句柄限制(ulimit -n)" "$(ulimit -n 2>/dev/null)"

    # ---- 内核参数基线: 与内置建议值对照, 抓"被改过没恢复"的配置漂移 ----
    # (v1.2 调整) 偏离仅提示不计告警/退出码: 部分参数内核按内存自动定值
    # (如 tcp_max_syn_backlog), 偏离≠异常, 直接告警会对默认系统误报
    kv "内核参数基线" ""
    local kp kp_desc kp_expect kp_op kp_cur kp_state kern_bad=0
    while IFS='|' read -r kp kp_desc kp_expect kp_op; do
        [ -z "$kp" ] && continue
        kp_cur=$(cat "/proc/sys/${kp//.//}" 2>/dev/null)
        if [ -z "$kp_cur" ]; then
            printf '    [缺省] %-34s %-12s 内核未提供该参数\n' "$kp" "$kp_desc" >>"$BODY"
            continue
        fi
        kp_state=$(awk -v v="$kp_cur" -v e="$kp_expect" -v op="$kp_op" 'BEGIN{
            if (op=="eq") { if (v+0==e+0) print "ok"; else print "bad" }
            else          { if (v+0>=e+0) print "ok"; else print "bad" } }')
        if [ "$kp_state" = "ok" ]; then
            printf '    [符合] %-34s %-12s 当前=%s (期望 %s %s)\n' "$kp" "$kp_desc" "$kp_cur" "$kp_op" "$kp_expect" >>"$BODY"
        else
            kern_bad=$((kern_bad+1))
            printf '    [偏离] %-34s %-12s 当前=%s (期望 %s %s)\n' "$kp" "$kp_desc" "$kp_cur" "$kp_op" "$kp_expect" >>"$BODY"
        fi
    done <<EOF
net.ipv4.tcp_syncookies|SYN Cookies|1|eq
net.core.somaxconn|连接队列|1024|ge
net.ipv4.tcp_max_syn_backlog|SYN队列|1024|ge
net.ipv4.tcp_tw_reuse|TW复用|1|ge
fs.file-max|句柄上限|65535|ge
EOF
    if [ "$kern_bad" -gt 0 ]; then
        # 基线为建议值对照: 部分参数内核按内存自动定值(如 tcp_max_syn_backlog),
        # 偏离不等于异常, 仅提示不计入告警/退出码
        b_info "内核参数 ${kern_bad} 项偏离建议基线 (仅提示, 不计告警; 详见上表)"
    else
        b_ok "内核参数基线符合建议值"
    fi
}

#------------------------------ [2] 性能状况 ----------------------------------
sec_perf() {
    section "2" "性能状况 (CPU / 内存 / 负载 / 进程)"
    local c1 c2 d1 d2 l1 l5 l15

    # ---- 1 秒采样窗口: CPU 使用率 + 磁盘 I/O 利用率 ----
    c1=$(awk '/^cpu /{t=0; for(i=2;i<=9;i++) t+=$i; print t, $5+$6}' /proc/stat 2>/dev/null)
    d1=$(awk '$3 !~ /^(loop[0-9]*|ram[0-9]*|sr[0-9]+|fd[0-9]+|nvme[0-9]+n[0-9]+p[0-9]+|sd[a-z]+[0-9]+|mmcblk[0-9]+p[0-9]+|vd[a-z]+[0-9]+|xvd[a-z]+[0-9]+)$/{print $3, $13}' /proc/diskstats 2>/dev/null)
    sleep 1
    c2=$(awk '/^cpu /{t=0; for(i=2;i<=9;i++) t+=$i; print t, $5+$6}' /proc/stat 2>/dev/null)
    d2=$(awk '$3 !~ /^(loop[0-9]*|ram[0-9]*|sr[0-9]+|fd[0-9]+|nvme[0-9]+n[0-9]+p[0-9]+|sd[a-z]+[0-9]+|mmcblk[0-9]+p[0-9]+|vd[a-z]+[0-9]+|xvd[a-z]+[0-9]+)$/{print $3, $13}' /proc/diskstats 2>/dev/null)

    # ---- CPU ----
    local cpu_use
    cpu_use=$(awk -v a="$c1" -v b="$c2" 'BEGIN{
        split(a,x); split(b,y)
        dt=y[1]-x[1]; di=y[2]-x[2]
        if (dt<=0) printf "0.0"; else printf "%.1f", (dt-di)*100/dt }')
    if [ -n "$cpu_use" ]; then
        pct_check "$cpu_use" "$THRESH_CPU_WARN" "$THRESH_CPU_CRIT" \
            "CPU 使用率 ${cpu_use}% (1秒采样)" "CPU 使用率过高: " "REC_CPU"
    else
        b_info "无法采集 CPU 使用率"
    fi

    # ---- 负载 ----
    read -r l1 l5 l15 _rest < /proc/loadavg 2>/dev/null
    [ -z "$l5" ] && { l1=0; l5=0; l15=0; }
    local load_pct
    load_pct=$(awk -v l="$l5" -v c="${N_CPU:-1}" 'BEGIN{if(c<1)c=1; printf "%.0f", l*100/c}')
    kv "系统负载" "1分钟 $l1 | 5分钟 $l5 | 15分钟 $l15  (CPU 逻辑核数 ${N_CPU:-1})"
    pct_check "$load_pct" "$THRESH_LOAD_WARN" "$THRESH_LOAD_CRIT" \
        "系统负载正常 (5分钟平均 $l5, 折合每核 ${load_pct}%)" "系统负载过高(5分钟 $l5, 折合每核): " "REC_LOAD"

    # ---- 内存 ----
    local mt mf mb mc msr ma mem_pct swt swf sw_pct
    mt=$(awk '$1=="MemTotal:"{print $2}' /proc/meminfo 2>/dev/null)
    if [ -n "$mt" ]; then
        mf=$(awk '$1=="MemFree:"{print $2}' /proc/meminfo)
        mb=$(awk '$1=="Buffers:"{print $2}' /proc/meminfo)
        mc=$(awk '/^Cached:/{print $2}' /proc/meminfo)
        msr=$(awk '$1=="SReclaimable:"{print $2}' /proc/meminfo); msr=${msr:-0}
        ma=$(awk '$1=="MemAvailable:"{print $2}' /proc/meminfo)
        [ -z "$ma" ] && ma=$(( mf + mb + mc + msr ))
        mem_pct=$(awk -v t="$mt" -v a="$ma" 'BEGIN{printf "%.1f", (t-a)*100/t}')
        kv "内存" "总量 $(kb2g "$mt")GB | 可用 $(kb2g "$ma")GB | 使用率 ${mem_pct}%"
        pct_check "$mem_pct" "$THRESH_MEM_WARN" "$THRESH_MEM_CRIT" \
            "内存使用正常 (${mem_pct}%)" "内存使用率过高(可用 $(kb2g "$ma")GB): " "REC_MEM"

        swt=$(awk '$1=="SwapTotal:"{print $2}' /proc/meminfo); swt=${swt:-0}
        swf=$(awk '$1=="SwapFree:"{print $2}' /proc/meminfo);  swf=${swf:-0}
        if [ "$swt" -gt 0 ] 2>/dev/null; then
            sw_pct=$(awk -v t="$swt" -v f="$swf" 'BEGIN{printf "%.1f", (t-f)*100/t}')
            kv "Swap" "总量 $(kb2g "$swt")GB | 使用率 ${sw_pct}%"
            pct_check "$sw_pct" "$THRESH_SWAP_WARN" "$THRESH_SWAP_CRIT" \
                "Swap 使用正常 (${sw_pct}%)" "Swap 使用率过高: " "REC_SWAP"
        else
            b_info "未配置 Swap 分区"
        fi
    else
        b_info "无法读取 /proc/meminfo"
    fi

    # ---- 磁盘 I/O 利用率(来自 diskstats 采样) ----
    kv "磁盘 I/O (1秒采样)" ""
    local util_out
    util_out=$(awk -v a="$d1" -v b="$d2" 'BEGIN{
        n=split(a,x,"\n")
        for(i=1;i<=n;i++){ split(x[i],f," "); if(f[1]!="") base[f[1]]=f[2] }
        n=split(b,y,"\n")
        for(i=1;i<=n;i++){
            split(y[i],f," "); dev=f[1]
            if(dev=="" || !(dev in base)) continue
            d=f[2]-base[dev]
            if(d>5) printf "    %-12s 利用率约 %d%%\n", dev, d/10
        }}' </dev/null)
    if [ -n "$util_out" ]; then
        printf '%s\n' "$util_out" >>"$BODY"
        local busy
        busy=$(printf '%s\n' "$util_out" | awk '$NF+0>=80{c++} END{print c+0}')
        [ "$busy" -gt 0 ] 2>/dev/null && b_warn "存在高负载磁盘设备(利用率≥80%), 详见上方 I/O 采样"
    else
        kv "磁盘 I/O (1秒采样)" "采样窗口内磁盘基本空闲"
    fi

    # ---- Top 进程 ----
    local PS_CPU PS_MEM
    if ps aux --sort=-%cpu >/dev/null 2>&1; then
        PS_CPU=$(ps aux --sort=-%cpu 2>/dev/null | awk -v n="$TOP_PROC_NUM" -v sn="$SCRIPT_NAME" 'NR>1 && NR<=n+12 && $11!="ps" && $0 !~ sn{
            cmd=""; for(i=11;i<=NF;i++) cmd=cmd" "$i
            printf "    %-9s %6s%% %6s%% %s\n", $1,$3,$4,substr(cmd,2,66)}' | head -n "$TOP_PROC_NUM")
        PS_MEM=$(ps aux --sort=-%mem 2>/dev/null | awk -v n="$TOP_PROC_NUM" -v sn="$SCRIPT_NAME" 'NR>1 && NR<=n+12 && $11!="ps" && $0 !~ sn{
            cmd=""; for(i=11;i<=NF;i++) cmd=cmd" "$i
            printf "    %-9s %6s%% %6s%% %s\n", $1,$3,$4,substr(cmd,2,66)}' | head -n "$TOP_PROC_NUM")
    else
        PS_CPU=$(ps aux 2>/dev/null | sort -k3 -rn | head -n "$TOP_PROC_NUM" | \
            awk '{cmd=""; for(i=11;i<=NF;i++) cmd=cmd" "$i
                 printf "    %-9s %6s%% %6s%% %s\n", $1,$3,$4,substr(cmd,2,66)}')
        PS_MEM=$(ps aux 2>/dev/null | sort -k4 -rn | head -n "$TOP_PROC_NUM" | \
            awk '{cmd=""; for(i=11;i<=NF;i++) cmd=cmd" "$i
                 printf "    %-9s %6s%% %6s%% %s\n", $1,$3,$4,substr(cmd,2,66)}')
    fi
    kv "Top ${TOP_PROC_NUM} CPU 进程" "  (用户 / %CPU / %MEM / 命令)"
    printf '%s\n' "$PS_CPU" >>"$BODY"
    kv "Top ${TOP_PROC_NUM} 内存进程" ""
    printf '%s\n' "$PS_MEM" >>"$BODY"

    # ---- 僵尸进程 / 进程总数 ----
    local zb proc_n
    zb=$(ps aux 2>/dev/null | awk '$8~/^Z/{n++} END{print n+0}')
    if [ "${zb:-0}" -ge "$THRESH_ZOMBIE_CRIT" ] 2>/dev/null; then
        REC_ZOMBIE=1
        b_crit "僵尸进程数量 ${zb} 个 (≥${THRESH_ZOMBIE_CRIT})"
    elif [ "${zb:-0}" -ge 1 ] 2>/dev/null; then
        REC_ZOMBIE=1
        b_warn "存在 ${zb} 个僵尸进程, 建议排查其父进程"
    else
        b_ok "无僵尸进程"
    fi
    [ "${zb:-0}" -ge 1 ] 2>/dev/null && \
        ps aux 2>/dev/null | awk '$8~/^Z/{print "    僵尸 PID="$2" 命令="$11; c++} c>=5{exit}' >>"$BODY"

    # ---- D 状态进程 (v1.1): 不可中断睡眠, 堆积多为存储/IO 卡死前兆 ----
    local dst
    dst=$(ps -eo stat= 2>/dev/null | grep -c '^D'); dst=${dst:-0}
    kv "D 状态进程" "${dst} 个 (不可中断睡眠, 短暂出现属正常)"
    if [ "$dst" -ge "$DSTATE_CRIT" ] 2>/dev/null; then
        REC_DSTATE=1
        b_crit "D 状态进程 ${dst} 个 (≥${DSTATE_CRIT}), 多为存储/IO 链路卡死"
    elif [ "$dst" -ge "$DSTATE_WARN" ] 2>/dev/null; then
        REC_DSTATE=1
        b_warn "D 状态进程 ${dst} 个 (≥${DSTATE_WARN}), 持续存在需检查存储/NFS 链路"
    else
        b_ok "无 D 状态进程堆积"
    fi
    [ "$dst" -ge "$DSTATE_WARN" ] 2>/dev/null && \
        ps -eo pid,stat,comm 2>/dev/null | awk '$2~/^D/{print "    D状态 PID="$1" 命令="$3; c++} c>=5{exit}' >>"$BODY"

    proc_n=$(ps aux 2>/dev/null | awk 'END{print NR-1}')
    kv "进程总数" "${proc_n:-未知}"
}

#------------------------------ [3] 磁盘状况 ----------------------------------
sec_disk() {
    section "3" "磁盘状况 (空间 / inode / 只读挂载)"
    local dfout dfcmd
    if [ "$DF_T" = "yes" ]; then dfout=$(safe_run 15 df -PT); else dfout=$(safe_run 15 df -P); fi
    if [ -z "$dfout" ]; then
        # 全量 df 超时(常见于 NFS 挂载点卡死): 降级为仅本地文件系统再试一次
        b_warn "df 全量采集失败(可能有挂载点卡死), 改用仅本地文件系统 (df -l) 兜底"
        if [ "$DF_T" = "yes" ]; then dfout=$(safe_run 15 df -PlT); else dfout=$(safe_run 15 df -Pl); fi
    fi
    if [ -z "$dfout" ]; then
        b_crit "df 命令执行失败(可能存在挂载点卡死)"
        return
    fi
    [ "$DF_T" = "yes" ] && dfcmd=7 || dfcmd=6

    kv "分区使用情况" "  (使用率≥${THRESH_DISK_WARN}% 告警, ≥${THRESH_DISK_CRIT}% 严重)"
    local header
    header=$(printf '    %-24s %-9s %8s %8s %8s %6s  %s\n' "文件系统" "类型" "容量" "已用" "可用" "使用%" "挂载点")
    printf '%s\n' "$header" >>"$BODY"
    printf '%s\n' "$dfout" | awk -v w="$THRESH_DISK_WARN" -v c="$THRESH_DISK_CRIT" -v m="$dfcmd" '
        function hu(k){ if(k>=1073741824) return sprintf("%.1fG",k/1073741824)
                       if(k>=1048576)  return sprintf("%.1fM",k/1048576)
                       return sprintf("%.0fK",k/1024) }
        NR>1 && $1 !~ /:$/ && $1 !~ /^Filesystem/ && $1 !~ /^文件系统/ {
            # 按设备名再过滤一层, 覆盖无 df -T 时 type="?" 导致类型过滤失效的情况 (snap 的 /dev/loop 等)
            if ($1 ~ /^(tmpfs|devtmpfs|overlay|udev)$/ || $1 ~ /^\/dev\/loop/) next
            if (m==7 && NF>=7){ fs=$1; type=$2; total=$3; used=$4; avail=$5; pct=$6; mnt=$7 }
            else if (m==6){ fs=$1; type="?"; total=$2; used=$3; avail=$4; pct=$5; mnt=$6 }
            else next
            sub(/%/,"",pct)
            skip="^(tmpfs|devtmpfs|squashfs|proc|sysfs|devpts|cgroup|cgroup2|cgroupfs|pstore|bpf|tracefs|debugfs|securityfs|configfs|fusectl|hugetlbfs|mqueue|nsfs|ramfs|autofs|fuse\..*|revokefs-fuse|binfmt_misc|fuse.gvfsd-fuse|efivarfs|btrfs_ctl)$"
            if (type ~ skip) next
            st=""; flag=""
            if (pct+0>=c){ st="严重"; flag="crit" } else if (pct+0>=w){ st="警告"; flag="warn" }
            printf "    %-24s %-9s %8s %8s %8s %5s%%  %-20s %s\n", fs, type, hu(total), hu(used), hu(avail), pct, mnt, st
        }' >>"$BODY"

    local crit_mnts warn_mnts
    crit_mnts=$(printf '%s\n' "$dfout" | awk -v c="$THRESH_DISK_CRIT" -v m="$dfcmd" '
        NR>1 && $1 !~ /:$/ {
            if ($1 ~ /^(tmpfs|devtmpfs|overlay|udev)$/ || $1 ~ /^\/dev\/loop/) next
            if (m==7 && NF>=7){ type=$2; pct=$6; mnt=$7 } else if (m==6){ type="?"; pct=$5; mnt=$6 } else next
            sub(/%/,"",pct)
            if (type ~ /^(tmpfs|devtmpfs|squashfs|proc|sysfs|devpts|cgroup|cgroup2|pstore|bpf|tracefs|debugfs|securityfs|configfs|fusectl|hugetlbfs|mqueue|ramfs|autofs|fuse\..*|revokefs-fuse|efivarfs)$/) next
            if (pct+0>=c) printf "%s(%s%%) ", mnt, pct }')
    warn_mnts=$(printf '%s\n' "$dfout" | awk -v w="$THRESH_DISK_WARN" -v c="$THRESH_DISK_CRIT" -v m="$dfcmd" '
        NR>1 && $1 !~ /:$/ {
            if ($1 ~ /^(tmpfs|devtmpfs|overlay|udev)$/ || $1 ~ /^\/dev\/loop/) next
            if (m==7 && NF>=7){ type=$2; pct=$6; mnt=$7 } else if (m==6){ type="?"; pct=$5; mnt=$6 } else next
            sub(/%/,"",pct)
            if (type ~ /^(tmpfs|devtmpfs|squashfs|proc|sysfs|devpts|cgroup|cgroup2|pstore|bpf|tracefs|debugfs|securityfs|configfs|fusectl|hugetlbfs|mqueue|ramfs|autofs|fuse\..*|revokefs-fuse|efivarfs)$/) next
            if (pct+0>=w && pct+0<c) printf "%s(%s%%) ", mnt, pct }')
    if [ -n "$crit_mnts" ]; then
        REC_DISK=1
        b_crit "以下分区磁盘使用率≥${THRESH_DISK_CRIT}%: $crit_mnts"
    fi
    if [ -n "$warn_mnts" ]; then
        REC_DISK=1
        b_warn "以下分区磁盘使用率≥${THRESH_DISK_WARN}%: $warn_mnts"
    fi
    if [ -z "$crit_mnts" ] && [ -z "$warn_mnts" ]; then
        b_ok "所有分区磁盘使用率低于 ${THRESH_DISK_WARN}%"
    fi

    # ---- inode ----
    local ino_out crit_ino warn_ino
    ino_out=$(safe_run 15 df -Pi)
    crit_ino=$(printf '%s\n' "$ino_out" | awk -v c="$THRESH_INODE_CRIT" '
        NR>1 && $1 !~ /:$/ && $1 !~ /^(tmpfs|devtmpfs|overlay|udev)$/ && $1 !~ /^\/dev\/loop/ { p=$5; sub(/%/,"",p)
            if (p+0>=c) printf "%s(%s%%) ", $6, p }')
    warn_ino=$(printf '%s\n' "$ino_out" | awk -v w="$THRESH_INODE_WARN" -v c="$THRESH_INODE_CRIT" '
        NR>1 && $1 !~ /:$/ && $1 !~ /^(tmpfs|devtmpfs|overlay|udev)$/ && $1 !~ /^\/dev\/loop/ { p=$5; sub(/%/,"",p)
            if (p+0>=w && p+0<c) printf "%s(%s%%) ", $6, p }')
    if [ -n "$crit_ino" ]; then
        REC_INODE=1
        b_crit "以下分区 inode 使用率≥${THRESH_INODE_CRIT}%: $crit_ino"
    fi
    if [ -n "$warn_ino" ]; then
        REC_INODE=1
        b_warn "以下分区 inode 使用率≥${THRESH_INODE_WARN}%: $warn_ino"
    fi
    if [ -z "$crit_ino" ] && [ -z "$warn_ino" ]; then
        b_ok "所有分区 inode 使用率低于 ${THRESH_INODE_WARN}%"
    fi

    # ---- 数据分区只读(硬件/文件系统故障常见信号) ----
    local ro_mnts
    ro_mnts=$(awk '$3 ~ /^(ext[234]|xfs|btrfs|vfat|exfat|ntfs|f2fs|jfs|reiserfs|zfs)$/ && ($4=="ro" || $4 ~ /^ro,/) {print $2" ("$3")"}' /proc/mounts 2>/dev/null | tr '\n' ' ')
    if [ -n "$ro_mnts" ]; then
        REC_RO=1
        b_crit "检测到数据分区处于只读挂载(多为文件系统/磁盘故障后自动切换): $ro_mnts"
    else
        b_ok "无只读挂载的数据分区"
    fi

    # ---- 大文件扫描 (v1.1) ----
    if [ "$SKIP_LARGE_FILE_SCAN" = "1" ]; then
        b_info "大文件扫描已跳过 (--no-large-file-scan / --fast)"
    else
        # 排除容器存储目录(镜像层数量庞大且无巡检意义); -printf 不支持时退化为纯列表
        local lf_all="" lf_n=0 lf_total_gb=0 p
        local -a find_expr
        for p in $LARGE_FILE_SCAN_PATHS; do
            [ -d "$p" ] || continue
            find_expr=( -xdev \( -path "$p/lib/docker" -o -path "$p/lib/containers" -o -path "$p/lib/podman" \) -prune -o -type f -size "$LARGE_FILE_SIZE" )
            if safe_run 5 find / -maxdepth 0 -printf '%s' >/dev/null 2>&1; then
                lf_all="${lf_all}
$(safe_run 30 find "$p" "${find_expr[@]}" -printf '%s %p\n' 2>/dev/null)"
            else
                lf_all="${lf_all}
$(safe_run 30 find "$p" "${find_expr[@]}" 2>/dev/null | sed 's/^/0 /')"
            fi
        done
        lf_n=$(printf '%s\n' "$lf_all" | grep -c .); lf_n=${lf_n:-0}
        if [ "$lf_n" -gt 0 ]; then
            # GB 取整用于阈值比较 (find -size 为 apparent size, 稀疏文件如虚机镜像会偏大)
            lf_total_gb=$(printf '%s\n' "$lf_all" | grep . | awk '{s+=$1} END{printf "%d", s/1073741824}')
            kv "大文件清单 (TOP10, 共 ${lf_n} 个, 合计约 ${lf_total_gb}GB, 按 apparent size)" ""
            printf '%s\n' "$lf_all" | grep . | sort -rn | head -n 10 | \
                awk '{printf "    %8.1fMB  %s\n", $1/1048576, substr($0, index($0," ")+1)}' >>"$BODY"
            # 近期新产生的大文件 (更可能是垃圾/泄漏增长点; 天数/大小阈值见 LARGE_FILE_RECENT_*)
            local p2 recent_n=0
            local -a recent_expr
            for p2 in $LARGE_FILE_SCAN_PATHS; do
                [ -d "$p2" ] || continue
                recent_expr=( -xdev \( -path "$p2/lib/docker" -o -path "$p2/lib/containers" -o -path "$p2/lib/podman" \) -prune -o -type f -size "$LARGE_FILE_RECENT_SIZE" -mtime "-${LARGE_FILE_RECENT_DAYS}" )
                recent_n=$(( recent_n + $(safe_run 30 find "$p2" "${recent_expr[@]}" 2>/dev/null | wc -l) ))
            done
            kv "最近${LARGE_FILE_RECENT_DAYS}天新产生 >${LARGE_FILE_RECENT_SIZE#+} 文件数" "${recent_n} 个"
            if [ "$LARGE_FILE_TOTAL_WARN_GB" -gt 0 ] && [ "$lf_total_gb" -ge "$LARGE_FILE_TOTAL_WARN_GB" ] 2>/dev/null; then
                REC_LARGEFILE=1
                b_warn "大文件合计约 ${lf_total_gb}GB (≥${LARGE_FILE_TOTAL_WARN_GB}GB), 建议确认后清理或轮转"
            else
                b_info "存在 ${lf_n} 个大文件 (总量未超 ${LARGE_FILE_TOTAL_WARN_GB}GB 阈值), 清单见上"
            fi
        else
            b_ok "未发现 >${LARGE_FILE_SIZE#+} 的大文件"
        fi
    fi
}

#------------------------------ [4] 网络状况 ----------------------------------
ping_ok() {  # ping_ok <目标> ; 返回 0=通 1=不通 2=无法测试
    if have ping; then
        safe_run 6 ping -c 2 -W 2 "$1" >/dev/null 2>&1 && return 0 || return 1
    fi
    return 2
}

sec_network() {
    section "4" "网络状况 (网卡 / 连通性 / 端口 / 连接数)"
    local GW EXT_OK EXT_USED DNS_OK

    # ---- 网卡与 IP ----
    kv "网卡 IP 地址" ""
    if have ip; then
        ip -o -4 addr show 2>/dev/null | awk '{printf "    %-14s %s\n", $2, $4}' >>"$BODY"
    elif have ifconfig; then
        safe_run 5 ifconfig 2>/dev/null | awk '
            /^[a-zA-Z0-9_:]+[ :]/ { ifc=$1; sub(/:$/,"",ifc) }
            /inet[^6]/ && /addr[: ]/ { gsub(/.*addr[: ]+/,""); split($0,a," "); printf "    %-14s %s\n", ifc, a[1] }' >>"$BODY"
    else
        kv "网卡 IP 地址" "缺少 ip / ifconfig 命令, 无法采集"
    fi

    # ---- 网关 ----
    GW=""
    if have ip; then
        GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
    elif have route; then
        GW=$(route -n 2>/dev/null | awk '/^0\.0\.0\.0/{print $2; exit}')
    fi
    if [ -n "$GW" ]; then
        kv "默认网关" "$GW"
        case "$(ping_ok "$GW"; echo $?)" in
            0) b_ok "网关 $GW 连通正常" ;;
            *) b_warn "网关 $GW ping 不通 (若环境禁 ICMP 可忽略)" ;;
        esac
    else
        b_warn "未检测到默认网关"
    fi

    # ---- 外网连通性 ----
    EXT_OK=no; EXT_USED=""
    local t
    for t in "${PING_TARGETS[@]}"; do
        if [ "$(ping_ok "$t"; echo $?)" = "0" ]; then EXT_OK=yes; EXT_USED="$t"; break; fi
    done
    if [ "$EXT_OK" = "yes" ]; then
        b_ok "外网连通正常 (ICMP 测试目标 $EXT_USED)"
    else
        b_warn "外网 ping 不通 (测试目标: ${PING_TARGETS[*]}; 若禁 ICMP/无外网可忽略)"
    fi

    # ---- DNS ----
    kv "DNS 服务器" "$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    DNS_OK=no
    if have getent && getent hosts "$DNS_TEST_DOMAIN" >/dev/null 2>&1; then DNS_OK=yes
    elif have nslookup && safe_run 5 nslookup "$DNS_TEST_DOMAIN" >/dev/null 2>&1; then DNS_OK=yes
    elif have dig && safe_run 5 dig +short "$DNS_TEST_DOMAIN" >/dev/null 2>&1; then DNS_OK=yes
    elif have host && safe_run 5 host "$DNS_TEST_DOMAIN" >/dev/null 2>&1; then DNS_OK=yes
    fi
    if [ "$DNS_OK" = "yes" ]; then
        b_ok "域名解析正常 ($DNS_TEST_DOMAIN)"
    else
        b_warn "域名解析失败或无法测试 ($DNS_TEST_DOMAIN)"
    fi

    # ---- 监听端口 ----
    kv "监听端口 (TCP/UDP)" ""
    if have ss; then
        if [ "$IS_ROOT" = "yes" ]; then
            safe_run 8 ss -tulnp 2>/dev/null | sed '1d' | head -n 60 | sed 's/^/    /' >>"$BODY"
        else
            safe_run 8 ss -tuln 2>/dev/null | sed '1d' | head -n 60 | sed 's/^/    /' >>"$BODY"
            b_info "非 root 运行, 监听端口不显示进程名"
        fi
    elif have netstat; then
        if [ "$IS_ROOT" = "yes" ]; then
            safe_run 8 netstat -tulnp 2>/dev/null | sed '1,2d' | head -n 60 | sed 's/^/    /' >>"$BODY"
        else
            safe_run 8 netstat -tuln 2>/dev/null | sed '1,2d' | head -n 60 | sed 's/^/    /' >>"$BODY"
        fi
    else
        b_info "缺少 ss / netstat 命令, 无法采集监听端口"
    fi

    # ---- 连接数 ----
    local est tw cw
    if have ss; then
        est=$(ss -tan 2>/dev/null | grep -c 'ESTAB')
        tw=$(ss -tan 2>/dev/null | grep -c 'TIME-WAIT')
        cw=$(ss -tan 2>/dev/null | grep -c 'CLOSE-WAIT')
    elif have netstat; then
        est=$(netstat -tan 2>/dev/null | grep -c 'ESTABLISHED')
        tw=$(netstat -tan 2>/dev/null | grep -c 'TIME_WAIT')
        cw=$(netstat -tan 2>/dev/null | grep -c 'CLOSE_WAIT')
    fi
    kv "TCP 连接状态" "ESTABLISHED ${est:-?} 条 | TIME_WAIT ${tw:-?} 条 | CLOSE_WAIT ${cw:-?} 条"
    # TIME_WAIT 大量存在属正常(客户端主动关闭的正常回收); CLOSE_WAIT 堆积才是应用未关闭连接的泄漏信号
    [ "${tw:-0}" -ge "$TIME_WAIT_WARN" ] 2>/dev/null && \
        b_info "TIME_WAIT ${tw} 条, 数量较大但属正常现象, 无需处理"
    if [ "${cw:-0}" -ge "$CONN_CLOSE_WAIT_WARN" ] 2>/dev/null; then
        REC_CLOSEWAIT=1
        b_warn "CLOSE_WAIT ${cw} 条 (≥${CONN_CLOSE_WAIT_WARN}): 对端已关闭但应用未释放连接, 疑似连接泄漏, 需排查应用"
    else
        b_ok "CLOSE_WAIT ${cw:-0} 条 (阈值 ${CONN_CLOSE_WAIT_WARN})"
    fi

    # ---- 网卡错误/丢包计数 ----
    local d name rx_e tx_e rx_d tx_d total_err err_flag=""
    kv "网卡错误计数 (rx_err/tx_err/rx_drop/tx_drop)" ""
    for d in /sys/class/net/*; do
        name=${d##*/}
        [ "$name" = "lo" ] && continue
        rx_e=$(cat "$d/statistics/rx_errors"  2>/dev/null || echo 0)
        tx_e=$(cat "$d/statistics/tx_errors"  2>/dev/null || echo 0)
        rx_d=$(cat "$d/statistics/rx_dropped" 2>/dev/null || echo 0)
        tx_d=$(cat "$d/statistics/tx_dropped" 2>/dev/null || echo 0)
        printf '    %-14s %s / %s / %s / %s\n' "$name" "$rx_e" "$tx_e" "$rx_d" "$tx_d" >>"$BODY"
        total_err=$(( rx_e + tx_e ))
        local total_drop=$(( rx_d + tx_d ))
        if [ "$total_err" -gt 0 ] 2>/dev/null; then
            REC_NIC=1
            b_warn "网卡 $name 存在收/发错误包 (rx_err=$rx_e, tx_err=$tx_e)"
            err_flag=yes
        elif [ "$total_drop" -ge 1000 ] 2>/dev/null; then
            b_info "网卡 $name 丢包计数较高 (rx_dropped=$rx_d, tx_dropped=$tx_d), 无线网卡常见, 持续增长需关注"
            err_flag=info
        fi
    done
    [ -z "$err_flag" ] && b_ok "网卡无错误/丢包计数"
}

#------------------------------ [5] 安全检查 ----------------------------------
sec_security() {
    section "5" "安全检查 (账户 / SSH / 防火墙 / 文件权限)"
    local u0 empty_pw login_users pass_max permit_root permit_pass

    # ---- 账户 ----
    u0=$(awk -F: '$3==0{printf "%s ", $1}' /etc/passwd 2>/dev/null)
    kv "UID=0 账户" "${u0:-未知}"
    local u0_n
    u0_n=$(echo "$u0" | awk '{print NF}')
    if [ "${u0_n:-0}" -gt 1 ] 2>/dev/null; then
        REC_UID0=1
        b_crit "存在多个 UID=0 账户: $u0 (除 root 外不应有 UID=0 账户)"
    else
        b_ok "UID=0 账户仅 root"
    fi

    if [ -r /etc/shadow ]; then
        empty_pw=$(awk -F: 'length($2)==0{printf "%s ", $1}' /etc/shadow 2>/dev/null)
        if [ -n "$empty_pw" ]; then
            REC_EMPTYPW=1
            b_crit "以下账户密码为空: $empty_pw"
        else
            b_ok "无空密码账户"
        fi
        pass_max=$(awk '/^PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs 2>/dev/null)
        kv "密码最长有效期" "${pass_max:-未配置}"
        if [ -n "$pass_max" ] && [ "$pass_max" -gt 90 ] 2>/dev/null; then
            REC_PASSWD=1
            b_warn "密码最长有效期 ${pass_max} 天, 建议不超过 90 天 (/etc/login.defs PASS_MAX_DAYS)"
        fi
        local aged_users
        aged_users=$(awk -F: '$5>90 && $1!="root"{printf "%s(max="$5") ", $1}' /etc/shadow 2>/dev/null)
        [ -n "$aged_users" ] && { REC_PASSWD=1; b_warn "以下账户密码策略超过 90 天: $aged_users"; }
    else
        b_info "无权限读取 /etc/shadow, 跳过空密码/密码策略检查 (需 root)"
    fi

    login_users=$(awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ && $7!=""{printf "%s ", $1}' /etc/passwd 2>/dev/null)
    kv "可登录账户" "${login_users:-未知}"

    # ---- SSH 配置 ----
    # root 且有 sshd 二进制时用 sshd -T 取实际生效配置(含 Include/Match);
    # 否则直读 sshd_config 兜底(不含 sshd_config.d, 结论可能不完整, 报告会标注)
    local SSHD_BIN=""
    for SSHD_BIN in /usr/sbin/sshd /usr/local/sbin/sshd; do
        [ -x "$SSHD_BIN" ] && break
        SSHD_BIN=""
    done
    local ssh_cfg_src=""
    if [ -n "$SSHD_BIN" ] && [ "$IS_ROOT" = "yes" ]; then
        permit_root=$("$SSHD_BIN" -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')
        permit_pass=$("$SSHD_BIN" -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')
    else
        ssh_cfg_src="file"
        permit_root=$(awk 'tolower($1)=="permitrootlogin"{v=$2} END{print v}' /etc/ssh/sshd_config 2>/dev/null)
        permit_pass=$(awk 'tolower($1)=="passwordauthentication"{v=$2} END{print v}' /etc/ssh/sshd_config 2>/dev/null)
        [ -z "$permit_root" ] && permit_root="(未显式配置, 默认 prohibit-password)"
        [ -z "$permit_pass" ] && permit_pass="(未显式配置, 默认 yes)"
    fi
    kv "SSH PermitRootLogin" "${permit_root:-未知}"
    kv "SSH PasswordAuthentication" "${permit_pass:-未知}"
    [ "$ssh_cfg_src" = "file" ] && \
        b_info "SSH 配置为直读 sshd_config (未解析 Include/sshd_config.d), 结论可能不完整"
    case "$permit_root" in
        yes)    REC_ROOTLOGIN=1; b_warn "SSH 允许 root 直接登录 (PermitRootLogin yes)" ;;
        ""|未知) b_info "无法确定 SSH PermitRootLogin 配置" ;;
        *)      b_ok "SSH 未开放 root 密码直登 ($permit_root)" ;;
    esac

    # ---- SSH 暴力破解痕迹 ----
    local fp=0 lg c
    # 含轮转日志 (secure-*/auth.log.*); zgrep 对普通与 .gz 文件均可计数
    # 按文件 mtime 限定统计窗口, 避免多年轮转日志的历史累计造成误报
    for lg in /var/log/secure /var/log/secure-* /var/log/auth.log /var/log/auth.log.*; do
        [ -r "$lg" ] || continue
        if [ "$BRUTE_LOG_DAYS" -gt 0 ] 2>/dev/null && \
           [ -z "$(find "$lg" -mtime "-${BRUTE_LOG_DAYS}" 2>/dev/null)" ]; then
            continue
        fi
        if have zgrep; then
            c=$(safe_run 8 zgrep -c 'Failed password' "$lg" 2>/dev/null)
        else
            c=$(grep -c 'Failed password' "$lg" 2>/dev/null)
        fi
        c=${c:-0}
        fp=$(( fp + c ))
    done
    if [ "$BRUTE_LOG_DAYS" -gt 0 ] 2>/dev/null; then
        kv "SSH 失败登录计数" "最近 ${BRUTE_LOG_DAYS} 天内日志中 'Failed password' 共 ${fp} 条"
    else
        kv "SSH 失败登录计数" "日志中 'Failed password' 共 ${fp} 条 (全部轮转历史累计)"
    fi
    if [ "$fp" -ge "$THRESH_BRUTE_CRIT" ]; then
        REC_BRUTE=1
        b_crit "SSH 暴力破解迹象明显: 'Failed password' 达 ${fp} 条"
    elif [ "$fp" -ge "$THRESH_BRUTE_WARN" ]; then
        REC_BRUTE=1
        b_warn "SSH 失败登录较多: 'Failed password' ${fp} 条 (阈值 ${THRESH_BRUTE_WARN})"
    else
        b_ok "SSH 失败登录次数正常 (${fp} 条)"
    fi
    if [ "$IS_ROOT" = "yes" ] && have lastb; then
        kv "最近失败登录 (lastb)" ""
        safe_run 8 lastb -n 8 2>/dev/null | sed 's/^/    /' >>"$BODY"
    fi

    # ---- SELinux / AppArmor ----
    if have getenforce; then
        local se
        se=$(getenforce 2>/dev/null)
        kv "SELinux" "$se"
        case "$se" in
            Enforcing)  b_ok "SELinux 处于 Enforcing 模式" ;;
            Permissive) b_info "SELinux 处于 Permissive 模式 (仅告警不拦截)" ;;
            Disabled)   REC_SELINUX=1; b_warn "SELinux 已关闭" ;;
            *)          b_info "SELinux 状态未知" ;;
        esac
    elif [ -d /sys/module/apparmor ]; then
        kv "AppArmor" "已启用"
        b_info "系统使用 AppArmor (未安装 SELinux)"
    else
        b_info "未检测到 SELinux / AppArmor"
    fi

    # ---- 防火墙 ----
    local fw_active="" fw_detail=""
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        fw_active=yes; fw_detail="firewalld 运行中"
    elif have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        fw_active=yes; fw_detail="ufw 已启用"
    elif have SuSEfirewall2 && safe_run 5 SuSEfirewall2 status >/dev/null 2>&1; then
        fw_active=yes; fw_detail="SuSEfirewall2 运行中"
    fi
    local ipt_rules="?" nft_rules="?"
    if [ "$IS_ROOT" = "yes" ]; then
        ipt_rules=0; nft_rules=0
        if have iptables; then ipt_rules=$(safe_run 8 iptables -S 2>/dev/null | wc -l); fi
        if have nft; then nft_rules=$(safe_run 8 nft list ruleset 2>/dev/null | wc -l); fi
    fi
    kv "防火墙状态" "${fw_detail:-未检测到 firewalld/ufw} | iptables规则 ${ipt_rules} 条 | nft规则 ${nft_rules} 条"
    if [ "$fw_active" = "yes" ]; then
        b_ok "防火墙已启用 ($fw_detail)"
    elif [ "$IS_ROOT" = "no" ]; then
        b_info "非 root 运行, 无法核实防火墙规则 (iptables/nft 需 root 查看)"
    elif [ "${ipt_rules:-0}" -gt 6 ] || [ "${nft_rules:-0}" -gt 5 ]; then
        b_ok "防火墙已启用 (iptables/nft 规则非空)"
    else
        REC_FW=1
        b_warn "未检测到启用的防火墙 (firewalld/ufw 未运行且 iptables/nft 无规则)"
    fi

    # ---- 关键文件权限 ----
    if [ "$IS_ROOT" = "yes" ]; then
        local suid_list
        suid_list=$(safe_run 20 find / -xdev -type f -perm -4000 2>/dev/null | sort)
        kv "SUID 文件清单 ($(echo "$suid_list" | grep -c .) 个, -xdev 仅覆盖根分区)" ""
        printf '%s\n' "$suid_list" | sed 's/^/    /' >>"$BODY"

        local etc_ww
        etc_ww=$(safe_run 10 find /etc -xdev -type f -perm -0002 2>/dev/null)
        if [ -n "$etc_ww" ]; then
            b_crit "/etc 下存在全局可写文件: $(echo "$etc_ww" | tr '\n' ' ')"
        else
            b_ok "/etc 下无全局可写文件"
        fi
    else
        b_info "非 root 运行, 跳过全盘 SUID / 全局可写文件扫描"
    fi

    # ---- 计划任务 ----
    if [ "$IS_ROOT" = "yes" ] && have crontab; then
        local root_cron
        root_cron=$(safe_run 5 crontab -l 2>/dev/null)
        if [ -n "$root_cron" ]; then
            kv "root 计划任务 (crontab -l)" "(内容见下)"
            printf '%s\n' "$root_cron" | sed 's/^/    /' >>"$BODY"
        else
            kv "root 计划任务 (crontab -l)" "(空)"
        fi
    else
        kv "root 计划任务 (crontab -l)" "(需 root 查看)"
    fi
    if [ -d /etc/cron.d ]; then
        kv "/etc/cron.d 任务文件" "$(ls /etc/cron.d 2>/dev/null | tr '\n' ' ')"
    fi
    local umask_cfg
    umask_cfg=$(grep -hE '^[[:space:]]*umask' /etc/profile /etc/bash.bashrc /etc/bashrc 2>/dev/null | head -n 3 | tr '\n' ' ')
    [ -z "$umask_cfg" ] && umask_cfg=$(awk '/^[[:space:]]*UMASK[[:space:]]/{print "login.defs UMASK="$2; exit}' /etc/login.defs 2>/dev/null)
    kv "全局 umask 配置" "${umask_cfg:-未显式配置}"

    # ---- SSL 证书有效期 (v1.1) ----
    if [ "$SKIP_SSL_CHECK" = "1" ]; then
        b_info "SSL 证书检查已跳过 (--skip-ssl-check / --fast)"
    elif ! have openssl; then
        b_info "缺少 openssl 命令, 跳过证书有效期检查"
    else
        kv "SSL 证书扫描 (标准路径 .pem/.crt)" ""
        local cdir cfile end_date end_epoch days_left now_epoch
        local total_cert=0 expiring_n=0 soon_n=0
        now_epoch=$(date +%s)
        for cdir in $SSL_CERT_PATHS; do
            [ -d "$cdir" ] || continue
            # 用 glob 代替 find -name 组合, 兼容受限环境; 跳过 CA 证书包(永远远期, 纯噪音)
            for cfile in "$cdir"/*.pem "$cdir"/*.crt "$cdir"/*/*.pem "$cdir"/*/*.crt; do
                [ -f "$cfile" ] || continue
                case "$cfile" in *ca-certificates*|*ca-bundle*|*cacert*) continue ;; esac
                end_date=$(safe_run 5 openssl x509 -in "$cfile" -noout -enddate 2>/dev/null | cut -d= -f2)
                [ -z "$end_date" ] && continue
                end_epoch=$(safe_run 5 date -d "$end_date" +%s 2>/dev/null)
                [ -z "$end_epoch" ] && continue
                total_cert=$((total_cert+1))
                days_left=$(( (end_epoch - now_epoch) / 86400 ))
                if [ "$days_left" -lt "$SSL_CERT_DAYS_WARN" ]; then
                    expiring_n=$((expiring_n+1))
                    printf '    [临期] %-64s 剩余 %s 天\n' "$cfile" "$days_left" >>"$BODY"
                elif [ "$days_left" -lt "$SSL_CERT_DAYS_INFO" ]; then
                    soon_n=$((soon_n+1))
                    printf '    [注意] %-64s 剩余 %s 天\n' "$cfile" "$days_left" >>"$BODY"
                fi
            done
        done
        kv "证书统计" "共扫描 ${total_cert} 张 | 剩余 <${SSL_CERT_DAYS_INFO} 天: ${soon_n} 张 | 剩余 <${SSL_CERT_DAYS_WARN} 天: ${expiring_n} 张"
        if [ "$expiring_n" -gt 0 ]; then
            REC_SSL=1
            b_warn "存在 ${expiring_n} 张证书剩余有效期不足 ${SSL_CERT_DAYS_WARN} 天, 需尽快续签 (含已过期; 系统 CA 仓库中的过期根证书可忽略)"
        elif [ "$total_cert" = "0" ]; then
            b_info "未在标准路径发现证书文件 (自部署服务请把证书目录加入脚本 SSL_CERT_PATHS)"
        else
            b_ok "无临期证书 (阈值 ${SSL_CERT_DAYS_WARN} 天, 共扫描 ${total_cert} 张)"
        fi
    fi
}

#------------------------------ [6] 服务检查 ----------------------------------
svc_line() { printf '    %-22s %s\n' "$1" "$2" >>"$BODY"; }

# sshd_installed: 探测主机是否安装了 SSH 服务 (未安装时不应判"严重")
sshd_installed() {
    [ -x /usr/sbin/sshd ] || [ -x /usr/local/sbin/sshd ] || have sshd && return 0
    if [ "$INIT_TYPE" = "systemd" ]; then
        safe_run 5 systemctl list-unit-files 'ssh*.service' --no-legend 2>/dev/null | \
            grep -qE '^(sshd|ssh)\.service' && return 0
    fi
    ls /etc/init.d/sshd /etc/init.d/ssh >/dev/null 2>&1 && return 0
    return 1
}

# check_key_svc <标签> <候选服务名/进程名...> ; 结果存 SVC_ST
check_key_svc() {
    local label="$1"; shift
    local n st="未运行"
    if [ "$INIT_TYPE" = "systemd" ]; then
        for n in "$@"; do
            case "$n" in *.service) ;; *) n="${n}.service";; esac
            if [ "$(safe_run 5 systemctl is-active "$n")" = "active" ]; then st="运行中 ($n)"; break; fi
        done
    fi
    if [ "$st" = "未运行" ] && [ "$INIT_TYPE" != "systemd" ]; then
        # SysV 主机无 systemctl, 用进程名兜底探测 (systemd 主机以单元状态为准,
        # 避免把 ssh 等客户端进程误判为服务端守护进程)
        for n in "$@"; do
            if have pgrep && pgrep -x "$n" >/dev/null 2>&1; then st="运行中 (进程 $n)"; break; fi
        done
    fi
    SVC_ST="$st"
    svc_line "$label" "$st"
}

sec_service() {
    section "6" "服务检查 (systemd / 关键服务 / 时间同步)"

    if [ "$INIT_TYPE" = "systemd" ]; then
        kv "服务管理器" "systemd"
        local failed
        failed=$(safe_run 10 systemctl list-units --state=failed --no-pager --no-legend 2>/dev/null | awk '{printf "%s ", $1}')
        if [ -n "$failed" ]; then
            REC_SVC=1
            b_crit "systemd 存在失败(failed)服务: $failed"
        else
            b_ok "无失败(failed)服务"
        fi
        local run_n en_n
        run_n=$(safe_run 10 systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l)
        en_n=$(safe_run 10 systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | wc -l)
        kv "服务统计" "运行中 ${run_n} 个 | 开机自启 ${en_n} 个"
    else
        kv "服务管理器" "SysV init"
        if have chkconfig; then
            kv "自启服务数(chkconfig)" "$(chkconfig --list 2>/dev/null | grep -c ':on')"
        fi
    fi

    # ---- 关键服务 ----
    kv "关键基础服务状态" ""
    check_key_svc "SSH 服务"     sshd ssh;  local ssh_st="$SVC_ST"
    check_key_svc "计划任务"     crond cron
    local cron_st="$SVC_ST"
    check_key_svc "系统日志服务" rsyslog syslog-ng systemd-journald
    local syslog_st="$SVC_ST"
    check_key_svc "时间同步服务" chronyd chrony ntpd ntp systemd-timesyncd
    local ntp_st="$SVC_ST"

    case "$ssh_st" in
        运行中*) b_ok "SSH 服务运行正常";;
        *) if sshd_installed; then b_crit "SSH 服务未运行"; else b_info "未安装 SSH 服务, 跳过状态判定"; fi;;
    esac
    case "$cron_st" in 运行中*) b_ok "计划任务服务运行正常";; *) b_warn "计划任务服务 (crond/cron) 未运行";; esac
    case "$syslog_st" in 运行中*) b_ok "系统日志服务运行正常";; *) b_warn "系统日志服务 (rsyslog/journald) 未运行";; esac

    # ---- 时间同步详情 ----
    case "$ntp_st" in
        运行中*)
            local leap off
            if have chronyc; then
                leap=$(safe_run 5 chronyc tracking 2>/dev/null | awk -F': *' '/^Leap status/{print $2}')
                off=$(safe_run 5 chronyc tracking 2>/dev/null | awk -F': *' '/^System time/{print $2}')
                kv "时间同步详情" "Leap=${leap:-未知} | 与NTP服务器偏差: ${off:-未知}"
                if [ "$leap" = "Normal" ]; then b_ok "时间同步正常 (chrony)"
                else REC_NTP=1; b_warn "chrony 运行但未完成同步 (Leap=$leap)"; fi
            elif have ntpq; then
                if safe_run 5 ntpq -pn 2>/dev/null | grep -q '^\*'; then
                    b_ok "时间同步正常 (ntpd)"
                else
                    REC_NTP=1
                    b_warn "ntpd 运行但未同步到 NTP 服务器"
                fi
            elif have ntpstat; then
                if safe_run 5 ntpstat >/dev/null 2>&1; then
                    b_ok "时间同步正常 (ntpstat 确认已同步)"
                else
                    REC_NTP=1
                    b_warn "ntpd 运行但 ntpstat 显示未同步到时间源"
                fi
            else
                b_ok "时间同步正常 — $ntp_st"
            fi
            ;;
        *)
            if have ntpctl && safe_run 5 ntpctl -s status 2>/dev/null | grep -q 'clock synced'; then
                b_ok "时间同步正常 (openntpd/ntpctl)"
            elif [ "$INIT_TYPE" = "systemd" ] && have timedatectl; then
                if safe_run 5 timedatectl 2>/dev/null | grep -qE 'NTP service: *active|NTP synchronized: *yes'; then
                    b_ok "时间同步已启用 (systemd-timesyncd)"
                else
                    REC_NTP=1
                    b_warn "未检测到时间同步机制 (chrony/ntpd/timesyncd 均未启用), 长期运行会导致时钟漂移"
                fi
            else
                REC_NTP=1
                b_warn "未检测到时间同步机制 (chrony/ntpd 均未运行)"
            fi
            ;;
    esac

    # ---- 容器巡检 (v1.1): Docker 优先, Podman 兜底 (RHEL8+/Fedora 默认) ----
    local CT=""
    if have docker && safe_run 5 docker info >/dev/null 2>&1; then
        CT="docker"
    elif have podman && safe_run 5 podman info >/dev/null 2>&1; then
        CT="podman"
    fi
    if [ -z "$CT" ]; then
        b_info "未检测到 Docker/Podman (未安装或无权限访问)"
    else
        local ct_run ct_all ct_img ct_bad
        ct_run=$(safe_run 10 "$CT" ps -q 2>/dev/null | wc -l)
        ct_all=$(safe_run 10 "$CT" ps -aq 2>/dev/null | wc -l)
        ct_img=$(safe_run 10 "$CT" images -q 2>/dev/null | wc -l)
        # -i 必须: docker 健康状态输出为小写 "(unhealthy)", 大小写敏感会漏判
        ct_bad=$(safe_run 10 "$CT" ps -a --format '{{.Status}}' 2>/dev/null | grep -icE 'Restarting|Unhealthy|Exited \([1-9]')
        kv "容器环境" "$CT | 运行中 ${ct_run} 个 | 已停止 $(( ct_all - ct_run )) 个 | 镜像 ${ct_img} 个"
        if [ "${ct_bad:-0}" -gt 0 ]; then
            REC_SVC=1
            b_warn "容器存在异常状态 (重启中/不健康/异常退出) ${ct_bad} 个, 明细如下:"
            safe_run 10 "$CT" ps -a --format '{{.Names}}  {{.Status}}  {{.Image}}' 2>/dev/null | \
                grep -iE 'Restarting|Unhealthy|Exited \([1-9]' | head -n 5 | sed 's/^/    /' >>"$BODY"
        else
            b_ok "容器全部正常 (运行 ${ct_run} 个)"
        fi
        [ "${ct_run:-0}" = "0" ] && [ "${ct_all:-0}" -gt 0 ] && \
            b_info "无运行中容器, 有 $(( ct_all - ct_run )) 个已停止容器 (如非预期请核查)"
    fi

    # ---- 常见业务进程探测 ----
    local bp found=""
    if have pgrep; then
        for bp in mysqld mariadbd redis-server mongod postgres nginx httpd apache2 php-fpm \
                  java tomcat docker dockerd containerd keepalived haproxy etcd kubelet \
                  kube-apiserver kube-proxy node_exporter process_exporter blackbox_exporter \
                  prometheus grafana-server zabbix_agentd zabbix-agent2 elasticsearch \
                  named dnsmasq postfix dovecot vsftpd smbd sssd supervisord \
                  consul minio clickhouse-server rabbitmq-server beam.smp; do
            pgrep -x "$bp" >/dev/null 2>&1 && found="$found $bp"
        done
    fi
    kv "检测到的业务进程" "${found:-未检测到常见中间件/容器进程}"
}

#------------------------------ [7] 日志与内核 --------------------------------
sec_logs() {
    section "7" "日志与内核 (dmesg / 系统日志 / OOM / 登录记录)"
    local dmsg oom_n=0 hw_n=0 lg

    # ---- dmesg ----
    dmsg=$(safe_run 8 dmesg 2>/dev/null)
    if [ -n "$dmsg" ]; then
        oom_n=$(printf '%s\n' "$dmsg" | grep -ci 'out of memory\|oom-kill'); oom_n=${oom_n:-0}
        hw_n=$(printf '%s\n' "$dmsg" | grep -ci 'i/o error\|hardware error\|mce:\|segfault');  hw_n=${hw_n:-0}
        kv "内核日志 (dmesg)" "OOM相关 ${oom_n} 条 | 硬件/IO错误 ${hw_n} 条"
        if [ "$oom_n" -gt 0 ]; then
            REC_OOM=1
            b_warn "内核日志存在 OOM (内存耗尽杀进程) 记录 ${oom_n} 条, 建议评估内存容量"
            printf '%s\n' "$dmsg" | grep -i 'out of memory\|oom-kill' | tail -n 5 | sed 's/^/    /' >>"$BODY"
        fi
        if [ "$hw_n" -gt 0 ]; then
            REC_HW=1
            b_warn "内核日志存在硬件/IO 错误记录 ${hw_n} 条"
            printf '%s\n' "$dmsg" | grep -i 'i/o error\|hardware error\|mce:\|segfault' | tail -n 5 | sed 's/^/    /' >>"$BODY"
        fi
        [ "$oom_n" = "0" ] && [ "$hw_n" = "0" ] && b_ok "内核日志 (dmesg) 无 OOM / 硬件错误记录"
    else
        b_info "无法读取内核日志 dmesg (需 root 或未限制解禁)"
    fi

    # ---- 系统日志 ----
    kv "系统日志错误摘要 (最近)" ""
    local found_log=no
    for lg in /var/log/messages /var/log/syslog; do
        if [ -r "$lg" ]; then
            found_log=yes
            local errs
            errs=$(tail -n 1000 "$lg" 2>/dev/null | grep -iE ' error| fail|oom|panic|kernel bug' | tail -n 10)
            if [ -n "$errs" ]; then
                printf '    --- %s ---\n' "$lg" >>"$BODY"
                printf '%s\n' "$errs" | sed 's/^/    /' >>"$BODY"
            else
                printf '    %s: 最近 1000 行无明显 error/fail/oom/panic\n' "$lg" >>"$BODY"
            fi
        fi
    done
    if [ "$found_log" = "no" ]; then
        # 无传统 syslog 文件的系统 (如 Ubuntu 20.04+ 默认仅 journald) 用 journalctl 兜底
        local jerrs=""
        if have journalctl; then
            jerrs=$(safe_run 8 journalctl -p err -n 10 --no-pager 2>/dev/null | grep -v '^-- ' | grep .)
        fi
        if [ -n "$jerrs" ]; then
            kv "系统日志错误摘要 (journalctl -p err, 最近 10 条)" ""
            printf '%s\n' "$jerrs" | sed 's/^/    /' >>"$BODY"
        else
            b_info "未找到可读的系统日志 (/var/log/messages|syslog, journalctl 无内容或无权限)"
        fi
    fi

    # ---- 最近登录 ----
    if have last; then
        kv "最近登录记录" ""
        safe_run 8 last -n 6 2>/dev/null | head -n 6 | sed 's/^/    /' >>"$BODY"
    fi
}

#------------------------------ 报告汇总 --------------------------------------
add_rec() {  # 追加一条运维建议 (text/json 双写)
    RECS="${RECS}  * $1"$'\n'
    if [ -n "$RECS_JSON" ]; then RECS_JSON="${RECS_JSON},"; fi
    RECS_JSON="${RECS_JSON}\"$(j_esc "$1")\""
}

build_summary() {
    RECS=""; RECS_JSON=""
    if [ "$CRIT_COUNT" -gt 0 ]; then
        VERDICT="存在严重问题 ${CRIT_COUNT} 项, 需立即处理"
    elif [ "$WARN_COUNT" -gt 0 ]; then
        VERDICT="存在告警 ${WARN_COUNT} 项, 建议关注"
    else
        VERDICT="各项检查正常"
    fi

    if [ "$IS_ROOT" = "yes" ]; then R_USER_DESC="root"; else R_USER_DESC="普通用户 $(id -un 2>/dev/null)"; fi
    R_HOST=$(hostname 2>/dev/null); R_HOST=${R_HOST:-unknown}
    R_OS=$(get_os)
    R_KERNEL="$(uname -r) ($(uname -m))"
    R_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    if [ -n "${START_TS:-}" ]; then
        R_DURATION=$(( $(date +%s) - START_TS ))
    else
        R_DURATION=0
    fi

    [ "$REC_DISK" = 1 ]      && add_rec "磁盘使用率超阈值: 按大文件清单清理日志/临时文件, 评估扩容"
    [ "$REC_INODE" = 1 ]     && add_rec "inode 紧张: 多为海量小文件, 清理会话/缓存目录后评估扩容"
    [ "$REC_RO" = 1 ]        && add_rec "分区只读: 立即备份该分区数据, 排查磁盘/文件系统并修复后重新挂载"
    [ "$REC_LARGEFILE" = 1 ] && add_rec "大文件总量超阈值: 核实清单中文件归属, 清理或配置轮转"
    [ "$REC_MEM" = 1 ]       && add_rec "内存使用率高: 定位 Top 内存进程, 排查泄漏并评估扩容"
    [ "$REC_SWAP" = 1 ]      && add_rec "Swap 使用率过高: 结合内存排查, 避免 Swap 抖动拖垮性能"
    [ "$REC_CPU" = 1 ]       && add_rec "CPU 使用率高: 结合 Top CPU 进程定位热点, 必要时扩容或限流"
    [ "$REC_LOAD" = 1 ]      && add_rec "系统负载高: 区分 CPU 密集与 IO 等待(结合 D 状态进程), 排查资源瓶颈"
    [ "$REC_FILENR" = 1 ]    && add_rec "文件句柄紧张: 排查连接/文件泄漏, 调大进程 ulimit 与 fs.file-max"
    [ "$REC_ZOMBIE" = 1 ]    && add_rec "僵尸进程: 找到父进程修复回收逻辑, 必要时重启父进程"
    [ "$REC_DSTATE" = 1 ]    && add_rec "D 状态进程堆积: 检查后端存储/NFS 可达性与磁盘健康"
    [ "$REC_CLOSEWAIT" = 1 ] && add_rec "CLOSE_WAIT 过多: 应用未释放远端连接, 排查代码中连接关闭逻辑"
    [ "$REC_NIC" = 1 ]       && add_rec "网卡错误包: 检查链路/光模块/交换机端口与驱动, 观察计数是否持续增长"
    [ "$REC_UID0" = 1 ]      && add_rec "存在多余 UID=0 账户: 核实用途后降权或删除"
    [ "$REC_EMPTYPW" = 1 ]   && add_rec "存在空密码账户: 立即设置强密码或锁定账户"
    [ "$REC_PASSWD" = 1 ]    && add_rec "密码策略过松: 将 PASS_MAX_DAYS 调整到 90 天以内并同步存量账户"
    [ "$REC_BRUTE" = 1 ]     && add_rec "SSH 暴力破解迹象: 改用密钥登录, 配合 fail2ban/白名单/改端口加固"
    [ "$REC_ROOTLOGIN" = 1 ] && add_rec "SSH 允许 root 直登: 设 PermitRootLogin prohibit-password, 改用普通账户+sudo"
    [ "$REC_SELINUX" = 1 ]   && add_rec "SELinux 已关闭: 建议设为 Enforcing (至少 Permissive), 保留强制访问控制"
    [ "$REC_FW" = 1 ]        && add_rec "防火墙未启用: 启用 firewalld/ufw, 仅放行业务必需端口"
    [ "$REC_SSL" = 1 ]       && add_rec "证书临期/过期: 尽快续签并更新部署, 建议接入证书到期监控"
    [ "$REC_SVC" = 1 ]       && add_rec "服务异常: 用 systemctl status <服务名> 定位原因, 处理后再重启"
    [ "$REC_NTP" = 1 ]       && add_rec "时间未同步: 部署 chrony/ntp 指向统一时间源, 时间漂移影响日志审计与认证"
    [ "$REC_OOM" = 1 ]       && add_rec "发生过 OOM: 评估内存容量, 为关键进程设置内存限制避免误杀"
    [ "$REC_HW" = 1 ]        && add_rec "内核报硬件/IO 错误: 检查磁盘 SMART/RAID 状态, 提前更换故障盘"
    return 0
}

assemble_text() {
    {
        printf '================================================================\n'
        printf '                    Linux 主机巡检报告\n'
        printf '         脚本: %s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '================================================================\n'
        printf '  主机名    : %s\n' "$R_HOST"
        printf '  操作系统  : %s\n' "$R_OS"
        printf '  内核版本  : %s\n' "$R_KERNEL"
        printf '  巡检账号  : %s\n' "$R_USER_DESC"
        printf '  采集时间  : %s (耗时 %s 秒)\n' "$R_TIME" "$R_DURATION"
        printf -- '----------------------------------------------------------------\n'
        printf '  巡检结论  : %s\n' "$VERDICT"
        printf '  检查统计  : 通过 %d 项 | 告警 %d 项 | 严重 %d 项\n' "$OK_COUNT" "$WARN_COUNT" "$CRIT_COUNT"
        [ "$IS_ROOT" = "no" ] && printf '  [提示] 当前非 root 运行, 部分 安全/日志/进程类 检查已降级\n'
        if [ -n "$ALERTS" ]; then
            printf -- '----------------------------------------------------------------\n'
            printf '  问题清单:\n%s' "$ALERTS"
        fi
        if [ -n "$RECS" ]; then
            printf -- '----------------------------------------------------------------\n'
            printf '  运维建议:\n%s' "$RECS"
        fi
        cat "$BODY"
        printf '\n================================================================\n'
        printf '  报告结束 | 建议结合业务特点复核各项阈值 (脚本头部可配置)\n'
        printf '================================================================\n'
    } > "$REPORT_FILE"
}

assemble_json() {
    {
        printf '{\n'
        printf '  "meta": {\n'
        printf '    "hostname": "%s",\n' "$(j_esc "$R_HOST")"
        printf '    "os": "%s",\n' "$(j_esc "$R_OS")"
        printf '    "kernel": "%s",\n' "$(j_esc "$R_KERNEL")"
        printf '    "user": "%s",\n' "$(j_esc "$R_USER_DESC")"
        printf '    "time": "%s",\n' "$R_TIME"
        printf '    "duration_sec": %d,\n' "$R_DURATION"
        printf '    "script_version": "%s"\n' "$SCRIPT_VERSION"
        printf '  },\n'
        printf '  "summary": {"ok": %d, "warn": %d, "crit": %d, "verdict": "%s"},\n' \
            "$OK_COUNT" "$WARN_COUNT" "$CRIT_COUNT" "$(j_esc "$VERDICT")"
        printf '  "recommendations": [%s],\n' "$RECS_JSON"
        printf '  "items": [%s]\n' "$JSON_ITEMS"
        printf '}\n'
    } > "$REPORT_FILE"
}

assemble() {
    build_summary
    # 报告含端口/账户等敏感信息: 预建 600 权限; 同时校验输出目录可写
    if ! touch "$REPORT_FILE" 2>/dev/null; then
        echo "无法写入报告文件: $REPORT_FILE (目录不可写?)" >&2
        exit 3
    fi
    chmod 600 "$REPORT_FILE" 2>/dev/null
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        assemble_json
    else
        assemble_text
    fi
    if [ ! -s "$REPORT_FILE" ]; then
        echo "报告生成失败: $REPORT_FILE" >&2
        exit 3
    fi
}

#------------------------------ 主流程 ----------------------------------------
main() {
    if [ -z "${BASH_VERSION:-}" ]; then
        echo "请使用 bash 运行本脚本: bash $0" >&2
        exit 3
    fi

    local out_dir=""
    STDOUT=0
    while [ $# -gt 0 ]; do
        case "$1" in
            -o) [ -n "${2:-}" ] || { echo "参数 -o 需要目录参数" >&2; exit 3; }
                out_dir="$2"; shift 2 ;;
            -f) if [ "${2:-}" = "json" ] || [ "${2:-}" = "text" ]; then
                    OUTPUT_FORMAT="$2"; shift 2
                else
                    echo "错误: -f 仅支持 text | json" >&2; exit 3
                fi ;;
            -q|--quiet) QUIET=1; shift ;;
            --stdout) STDOUT=1; shift ;;
            --fast) SKIP_LARGE_FILE_SCAN=1; SKIP_SSL_CHECK=1; shift ;;
            --ascii-name) ASCII_NAME=1; shift ;;
            --no-large-file-scan) SKIP_LARGE_FILE_SCAN=1; shift ;;
            --skip-ssl-check) SKIP_SSL_CHECK=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) echo "未知参数: $1 (用 -h 查看帮助)" >&2; exit 3 ;;
        esac
    done

    if [ -n "$out_dir" ]; then
        mkdir -p "$out_dir" 2>/dev/null || { echo "无法创建输出目录: $out_dir" >&2; exit 3; }
    else
        out_dir="."
    fi

    local host ts rep_ext rep_prefix
    host=$(hostname 2>/dev/null); host=${host:-unknown}
    ts=$(date '+%Y%m%d_%H%M%S')
    rep_ext="txt"
    [ "$OUTPUT_FORMAT" = "json" ] && rep_ext="json"
    if [ "$ASCII_NAME" = "1" ]; then rep_prefix="inspect"; else rep_prefix="巡检报告"; fi
    REPORT_FILE="${out_dir%/}/${rep_prefix}_${host}_${ts}.${rep_ext}"
    START_TS=$(date +%s)

    BODY="$(mktemp "${TMPDIR:-/tmp}/linux_inspect_body.XXXXXX")" || { echo "创建临时文件失败" >&2; exit 3; }
    trap 'rm -f "$BODY"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    p "开始巡检主机 $(hostname 2>/dev/null) — 报告将输出到 $REPORT_FILE"
    [ "$IS_ROOT" = "no" ] && p_warn "当前非 root 运行, 安全/日志类检查将降级 (建议 sudo 执行)"

    p "[1/7] 系统信息 ...";   sec_system
    p "[2/7] 性能状况 ...";   sec_perf
    p "[3/7] 磁盘状况 ...";   sec_disk
    p "[4/7] 网络状况 ...";   sec_network
    p "[5/7] 安全检查 ...";   sec_security
    p "[6/7] 服务检查 ...";   sec_service
    p "[7/7] 日志与内核 ..."; sec_logs

    assemble

    # 终端输出结论 (quiet 模式仅输出报告路径)
    if [ "$QUIET" = "1" ]; then
        printf '%s\n' "$REPORT_FILE"
    else
        printf '%b\n' "${C_BOLD}------------------------------------------------${C_OFF}"
        p_ok  "巡检完成: 报告文件 $REPORT_FILE"
        if [ "$CRIT_COUNT" -gt 0 ]; then
            p_crit "巡检结论: 存在严重问题 ${CRIT_COUNT} 项 | 告警 ${WARN_COUNT} 项 | 通过 ${OK_COUNT} 项"
        elif [ "$WARN_COUNT" -gt 0 ]; then
            p_warn "巡检结论: 存在告警 ${WARN_COUNT} 项 | 通过 ${OK_COUNT} 项 (无严重问题)"
        else
            p_ok  "巡检结论: 各项检查正常 (通过 ${OK_COUNT} 项)"
        fi
    fi
    [ "$STDOUT" = "1" ] && cat "$REPORT_FILE"

    [ "$CRIT_COUNT" -gt 0 ] && exit 1
    [ "$WARN_COUNT" -gt 0 ] && exit 2
    exit 0
}

main "$@"
