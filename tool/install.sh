#!/usr/bin/env bash
# nakis-quic 服务端一键脚本 (=^･ω･^=)
# 用法:  bash install.sh            打开菜单
#        bash install.sh install --host 1.2.3.4 --port 443 --yes
#        bash install.sh help
set -euo pipefail

REPO="${NQ_REPO:-n-yarvex/nakis}"           # 二进制发布在哪个 GitHub 仓库的 Releases
BIN="${NQ_BIN:-/usr/local/bin/nakis-quic}"
CONF="${NQ_CONF:-/etc/nakis-quic}"
UNIT="${NQ_UNIT:-/etc/systemd/system/nakis-quic.service}"
SYSCTL="${NQ_SYSCTL:-/etc/sysctl.d/99-nakis-quic.conf}"
SVC_USER="nakisq"
NO_TUNE=0; NO_FW=0; YES=0; TMP=""
trap '[ -z "$TMP" ] || rm -f "$TMP"' EXIT
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ]; then P=$'\e[38;5;211m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; Z=$'\e[0m'; else P=; G=; Y=; R=; Z=; fi
say()  { echo "${P}(=^･ω･^=)${Z} $*"; }
ok()   { echo "  ${G}✓${Z} $*"; }
warn() { echo "  ${Y}!${Z} $*" >&2; }
die()  { echo "${R}(;ω;)${Z} $*" >&2; exit 1; }

need_root() { [ "$(id -u)" = 0 ] || die "要用 root 跑哦：sudo bash $0 ${*:-}"; }
have()      { command -v "$1" >/dev/null 2>&1; }
has_systemd() { have systemctl && [ -d /run/systemd/system ]; }

ask() { # ask "问题" 默认值  → 回显答案
  local a=""
  if [ "${YES:-0}" = 1 ] || [ ! -t 0 ]; then echo "$2"; return; fi
  read -r -p "  $1 [${2:-留空跳过}]: " a || true
  echo "${a:-$2}"
}
yesno() { # yesno "问题" y|n
  local a=""
  if [ "${YES:-0}" = 1 ] || [ ! -t 0 ]; then [ "$2" = y ]; return; fi
  read -r -p "  $1 [$( [ "$2" = y ] && echo Y/n || echo y/N )]: " a || true
  a="${a:-$2}"; [ "$a" = y ] || [ "$a" = Y ]
}

usage() {
cat <<EOF
nakis-quic 服务端一键脚本

  bash install.sh                 打开菜单
  bash install.sh install [选项]  安装并启动
  bash install.sh update [选项]   只换程序，配置不动
  bash install.sh link            再打印一次分享链接
  bash install.sh port N          改 UDP 端口
  bash install.sh status | logs | restart | stop | start
  bash install.sh build [all|OS ARCH]   用旁边的源码编译 (自带补丁版 quic-go)，产物在 dist/
  bash install.sh uninstall       卸载

install / update 的选项:
  --host HOST   客户端连哪个域名或IP (默认自动探测公网IP)
  --port N      UDP 端口 (默认 443)
  --ech NAME    开 ECH，NAME 是旁观者看到的域名；--host 必须是域名
  --bin FILE    用本地二进制，不联网下载
  --url URL     从这个地址下载二进制
  --no-tune     不动 sysctl
  --no-firewall 不动防火墙
  --yes         不提问，全用默认

找二进制的顺序: --bin → --url → 脚本旁边的 nakis-quic-linux-<架构> → GitHub Releases ($REPO) → 用脚本旁边的源码编译
EOF
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;;
    armv7*|armv6*|arm) echo arm;; i386|i686) echo 386;;
    riscv64) echo riscv64;; *) die "没见过这个 CPU 架构: $(uname -m)";;
  esac
}

is_elf() { [ "$(head -c4 "$1" 2>/dev/null | od -An -c | tr -d ' ')" = '177ELF' ]; }

get_bin() { # 把二进制放到 $1
  local out="$1" a src=""; a="$(arch)"
  if [ -n "${OPT_BIN:-}" ]; then src="$OPT_BIN"; [ -f "$src" ] || die "找不到 $src"; cp "$src" "$out"
  elif [ -n "${OPT_URL:-}" ]; then say "下载 $OPT_URL"; fetch "$OPT_URL" "$out"
  elif [ -f "$HERE/nakis-quic-linux-$a" ]; then cp "$HERE/nakis-quic-linux-$a" "$out"
  else
    local url="https://github.com/$REPO/releases/latest/download/nakis-quic-linux-$a"
    say "从 GitHub 下载 (linux/$a)"
    if ! fetch "$url" "$out" 2>/dev/null; then
      warn "下载没成功 ($url)"
      if ls "$HERE"/*.go >/dev/null 2>&1 && have go; then
        say "本机有 Go，直接用旁边的源码编译"
        build_bin linux "$a" || die "编译失败"
        cp "$HERE/dist/nakis-quic-linux-$a" "$out"
      else
        die "没有可用的二进制。可以: --bin 文件 / --url 地址，或把源码放在脚本旁边并装好 Go 1.25+ 后重试"
      fi
    fi
  fi
  is_elf "$out" || die "拿到的不是 Linux 可执行文件 (可能是 404 页面)"
  chmod 0755 "$out"
}

# 打补丁的 quic-go (固定在文件末尾)。普通 go build 用的是原版拥塞控制，所以必须走这里。
build_bin() { # build_bin [all | OS ARCH]
  have go    || die "需要 Go 1.25+ (https://go.dev/dl/)"
  have patch || die "需要 patch 命令 (apt install patch)"
  ls "$HERE"/*.go >/dev/null 2>&1 || die "脚本旁边没有 .go 源码"
  local QG=github.com/quic-go/quic-go VER=v0.61.0 W="$HERE/.build" src
  rm -rf "$W"; mkdir -p "$W" "$HERE/dist"
  (
    cd "$HERE"
    export GOFLAGS=-mod=mod
    go mod download "$QG@$VER"
    src="$(go list -m -f '{{.Dir}}' "$QG@$VER")"
    cp -r "$src" "$W/quic-go"; chmod -R u+w "$W/quic-go"
    sed -n '/^__NQ_PATCH__$/,/^__NQ_PATCH_END__$/p' "${BASH_SOURCE[0]}" | sed '1d;$d' > "$W/quicgo.patch"
    ( cd "$W/quic-go" && patch -p1 -s < "$W/quicgo.patch" )
    cp go.mod "$W/go.mod"; [ -f go.sum ] && cp go.sum "$W/go.sum" || true
    go mod edit -modfile="$W/go.mod" -replace "$QG=$W/quic-go"
    go mod tidy -modfile="$W/go.mod" >/dev/null 2>&1 || true
    one() {
      local ext=""; [ "$1" = windows ] && ext=".exe"
      CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -modfile="$W/go.mod" -trimpath -ldflags "-s -w" -o "dist/nakis-quic-$1-$2$ext" . \
        && echo "  dist/nakis-quic-$1-$2$ext"
    }
    if [ "${1:-}" = all ]; then
      for t in linux:amd64 linux:arm64 linux:arm linux:386 darwin:arm64 darwin:amd64 windows:amd64 windows:arm64; do one "${t%%:*}" "${t##*:}"; done
    elif [ $# -ge 2 ]; then one "$1" "$2"
    else one "$(go env GOOS)" "$(go env GOARCH)"; fi
  )
  local rc=$?
  rm -rf "$W"
  return $rc
}

fetch() {
  if have curl; then curl -fsSL --retry 3 --connect-timeout 10 -o "$2" "$1"
  elif have wget; then wget -q -T 10 -t 3 -O "$2" "$1"
  else die "需要 curl 或 wget"; fi
}

public_ip() {
  local ip="" u
  for u in https://api.ipify.org https://ifconfig.me https://ipv4.icanhazip.com; do
    ip="$(fetch "$u" /dev/stdout 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { echo "$ip"; return; }
  done
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1 || true)"
  echo "$ip"
}

tune() {
  say "调内核参数 (UDP 缓冲区 + BBR)"
  mkdir -p "$(dirname "$SYSCTL")"
  {
    echo "# nakis-quic: QUIC 要大的 UDP 缓冲区，不然高速率下会丢包"
    echo "net.core.rmem_max = 33554432"
    echo "net.core.wmem_max = 33554432"
    echo "net.core.rmem_default = 4194304"
    echo "net.core.wmem_default = 4194304"
    echo "net.core.netdev_max_backlog = 16384"
    if have modprobe; then modprobe tcp_bbr 2>/dev/null || true; fi
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      echo "net.core.default_qdisc = fq"
      echo "net.ipv4.tcp_congestion_control = bbr"
    fi
  } > "$SYSCTL"
  sysctl -q -p "$SYSCTL" >/dev/null 2>&1 && ok "已生效 ($SYSCTL)" || warn "sysctl 没完全生效 (容器里很常见)，不影响运行"
}

fw_open()  { # $1 = port
  local p="$1" done=0
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow "$p"/udp >/dev/null && ok "ufw 已放行 UDP $p" && done=1; fi
  if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$p"/udp >/dev/null && firewall-cmd --reload >/dev/null && ok "firewalld 已放行 UDP $p" && done=1
  fi
  if [ $done = 0 ] && have iptables && iptables -S INPUT 2>/dev/null | grep -q -- '-P INPUT DROP'; then
    iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$p" -j ACCEPT
    ok "iptables 已放行 UDP $p (重启后可能失效，请自行持久化)"; done=1
  fi
  [ $done = 1 ] || ok "没发现要改的本机防火墙"
  warn "云服务器还要在控制台安全组里放行 UDP $p，这一步脚本管不到"
}
fw_close() {
  local p="$1"
  have ufw && ufw delete allow "$p"/udp >/dev/null 2>&1 || true
  have firewall-cmd && firewall-cmd --state >/dev/null 2>&1 && { firewall-cmd --permanent --remove-port="$p"/udp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1; } || true
  have iptables && iptables -D INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || true
}

write_unit() {
  has_systemd || { warn "没有 systemd，请自己运行: $BIN server -c $CONF/server.json"; return 1; }
  cat > "$UNIT" <<EOF
[Unit]
Description=nakis-quic server
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
ExecStart=$BIN server -c $CONF/server.json
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

conf_port() { sed -n 's/.*"listen": *"[^"]*:\([0-9]*\)".*/\1/p' "$CONF/server.json" | head -1; }
installed() { [ -x "$BIN" ] && [ -f "$CONF/server.json" ]; }
svc()       { has_systemd && systemctl "$@" nakis-quic; }

show_link() {
  [ -f "$CONF/client.json" ] || die "还没安装"
  local host; host="$(sed -n 's/.*"server": *"\(.*\):[0-9]*".*/\1/p' "$CONF/client.json" | head -1)"
  echo
  say "分享链接 (导入到客户端，或 nakis-quic client -link ...):"
  echo
  echo "  $("$BIN" link -name "${host:-nakis-quic}" "$CONF/client.json")"
  echo
  echo "  客户端配置文件在 $CONF/client.json"
  have qrencode && { echo; qrencode -t ANSIUTF8 "$("$BIN" link -name "${host:-nakis-quic}" "$CONF/client.json")" || true; }
}

parse_opts() {
  OPT_HOST=""; OPT_PORT=""; OPT_ECH=""; OPT_BIN=""; OPT_URL=""
  NO_TUNE=0; NO_FW=0; YES=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) OPT_HOST="${2:?}"; shift 2;; --port) OPT_PORT="${2:?}"; shift 2;;
      --ech) OPT_ECH="${2:?}"; shift 2;;
      --bin) OPT_BIN="${2:?}"; shift 2;; --url) OPT_URL="${2:?}"; shift 2;;
      --no-tune) NO_TUNE=1; shift;; --no-firewall) NO_FW=1; shift;; --yes|-y) YES=1; shift;;
      *) die "不认识的选项: $1 (bash $0 help)";;
    esac
  done
}
isnum() { [[ "$1" =~ ^[0-9]+$ ]]; }

do_install() {
  need_root install
  parse_opts "$@"
  [ "$(uname -s)" = Linux ] || die "服务端脚本只支持 Linux"
  if installed && ! yesno "已经装过了，重装会生成新的证书和 uuid (旧链接作废)，继续吗" n; then
    say "那就不动啦。想只换程序请用: bash $0 update"; return
  fi
  say "开始安装 nakis-quic 服务端"

  local host port ech
  host="${OPT_HOST:-$(ask "客户端连哪个域名或 IP" "$(public_ip)")}"
  [ -n "$host" ] || die "没拿到公网 IP，请用 --host 指定"
  port="${OPT_PORT:-$(ask "UDP 端口" 443)}"
  isnum "$port" && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "端口要在 1-65535"
  ech="$OPT_ECH"
  if [ -z "$ech" ] && [[ ! "$host" =~ ^[0-9.]+$ ]] && [ "${YES:-0}" != 1 ] && yesno "要开 ECH 吗 (host 是域名才行)" n; then
    ech="$(ask "ECH 对外显示的域名" "cloudflare-ech.com")"
  fi

  TMP="$(mktemp)"; local tmp="$TMP"
  get_bin "$tmp"
  [ "$NO_TUNE" = 1 ] || tune

  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || useradd -r -M -s /sbin/nologin "$SVC_USER"
  if installed && has_systemd; then systemctl stop nakis-quic 2>/dev/null || true; fi
  install -m 0755 "$tmp" "$BIN"
  rm -rf "$CONF"; mkdir -p "$CONF"
  local args=(init -host "$host" -port "$port" -dir "$CONF" -force -q)
  [ -n "$ech" ] && args+=(-ech "$ech")
  "$BIN" "${args[@]}" >/dev/null
  chown -R "$SVC_USER":"$SVC_USER" "$CONF"; chmod 0700 "$CONF"; chmod 0600 "$CONF"/*
  "$BIN" check -server -c "$CONF/server.json" >/dev/null || die "配置没通过自检，看上面的提示"
  ok "程序 $BIN，配置 $CONF"

  [ "$NO_FW" = 1 ] || fw_open "$port"
  if write_unit; then
    systemctl enable --now nakis-quic >/dev/null 2>&1 || true
    sleep 1
    if systemctl is-active --quiet nakis-quic; then ok "服务已启动，开机自启"
    else warn "服务没起来，看: journalctl -u nakis-quic -n 30"; fi
  fi
  show_link
}

do_update() {
  need_root update
  parse_opts "$@"
  installed || die "还没安装，先 bash $0 install"
  TMP="$(mktemp)"; local tmp="$TMP"
  get_bin "$tmp"
  "$tmp" version >/dev/null 2>&1 || die "新程序跑不起来，没有替换"
  install -m 0755 "$tmp" "$BIN"
  svc restart && ok "已更新并重启: $("$BIN" version | head -1)" || ok "已更新: $("$BIN" version | head -1)"
}

do_port() {
  need_root port
  installed || die "还没安装"
  local n="${1:-}" old; old="$(conf_port)"
  isnum "$n" && [ "$n" -ge 1 ] && [ "$n" -le 65535 ] || die "用法: bash $0 port 1-65535"
  sed -i "s/\(\"listen\": *\"[^\"]*:\)[0-9]*\"/\1$n\"/" "$CONF/server.json"
  sed -i "s/\(\"server\": *\"[^\"]*:\)[0-9]*\"/\1$n\"/" "$CONF/client.json"
  [ "$NO_FW" = 1 ] || { [ -n "$old" ] && fw_close "$old"; fw_open "$n"; }
  svc restart || true
  ok "端口改为 $n"; show_link
}

do_uninstall() {
  need_root uninstall
  [ "${1:-}" = --yes ] && YES=1
  installed || warn "好像没装，也清一下残留"
  [ "${YES:-0}" = 1 ] || yesno "真的要卸载吗" n || { say "不卸啦"; return; }
  local p; p="$(conf_port 2>/dev/null || true)"
  if has_systemd; then systemctl disable --now nakis-quic >/dev/null 2>&1 || true; rm -f "$UNIT"; systemctl daemon-reload; fi
  [ -n "$p" ] && fw_close "$p"
  rm -f "$BIN" "$SYSCTL"
  if yesno "配置、证书和 uuid 也一起删掉吗 (删了旧链接就作废)" n; then rm -rf "$CONF"; ok "配置已删"; else ok "配置留在 $CONF"; fi
  id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
  say "拜拜，下次再来玩 (=^･ω･^=)ﾉ"
}

do_status() {
  installed || { echo "还没安装"; return; }
  echo "程序:  $BIN ($("$BIN" version | head -1))"
  echo "配置:  $CONF"
  echo "端口:  UDP $(conf_port)"
  echo "发送:  自适应 (自己测速，不用配置)"
  if has_systemd; then echo "状态:  $(systemctl is-active nakis-quic 2>/dev/null || true) / 开机自启 $(systemctl is-enabled nakis-quic 2>/dev/null || true)"; fi
  have ss && { ss -lun 2>/dev/null | grep -q ":$(conf_port) " && echo "监听:  ✓" || echo "监听:  ✗ 没看到 UDP $(conf_port)"; }
}

menu() {
  need_root
  while true; do
    echo; say "nakis-quic 服务端"
    installed && do_status || echo "  (还没安装)"
    cat <<EOF

  1) 安装 / 重装        6) 改端口
  2) 更新程序           7) 重启
  3) 看分享链接         8) 卸载
  4) 看日志             0) 退出
  5) 状态
EOF
    local c; read -r -p "  选一个: " c || exit 0
    case "$c" in
      1) do_install;; 2) do_update;; 3) show_link;;
      4) has_systemd && journalctl -u nakis-quic -n 60 --no-pager || true;;
      5) do_status;;
      6) local n; read -r -p "  新端口: " n; do_port "$n";;
      7) svc restart && ok "已重启";; 8) do_uninstall;; 0|q) exit 0;; *) ;;
    esac
  done
}

cmd="${1:-menu}"; [ $# -gt 0 ] && shift
case "$cmd" in
  menu) menu;; install) do_install "$@";; update) do_update "$@";;
  link) show_link;; port) do_port "$@";;
  status) do_status;; logs) journalctl -u nakis-quic -n 100 -f;;
  restart) need_root; svc restart && ok "已重启";; stop) need_root; svc stop;; start) need_root; svc start;;
  build) build_bin "$@"; echo "好啦 (=^･ω･^=)";;
  uninstall) do_uninstall "$@";; help|-h|--help) usage;;
  *) usage; exit 1;;
esac
exit 0
: <<'__NQ_PATCH_END__'
__NQ_PATCH__
diff -ruN a/internal/ackhandler/sent_packet_handler.go b/internal/ackhandler/sent_packet_handler.go
--- a/internal/ackhandler/sent_packet_handler.go	2026-11-22 17:53:56.176298675 +0800
+++ b/internal/ackhandler/sent_packet_handler.go	2026-11-22 18:21:35.870900056 +0800
@@ -18,9 +18,9 @@
 const (
 	// Maximum reordering in time space before time based loss detection considers a packet lost.
 	// Specified as an RTT multiplier.
-	timeThreshold = 9.0 / 8
+	timeThreshold = 1.5
 	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
-	packetThreshold = 3
+	packetThreshold = 8
 	// Before validating the client's address, the server won't send more than 3x bytes than it received.
 	amplificationFactor = 3
 	// We use Retry packets to derive an RTT estimate. Make sure we don't set the RTT to a super low value yet.
@@ -129,14 +129,7 @@
 	qlogger qlogwriter.Recorder,
 	logger utils.Logger,
 ) SentPacketHandler {
-	congestion := congestion.NewCubicSender(
-		congestion.DefaultClock{},
-		rttStats,
-		connStats,
-		initialMaxDatagramSize,
-		true, // use Reno
-		qlogger,
-	)
+	congestion := congestion.NewAdaptive(rttStats, initialMaxDatagramSize)
 
 	h := &sentPacketHandler{
 		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
@@ -1131,13 +1124,6 @@
 	for pn := range h.appDataPackets.history.PathProbes() {
 		h.appDataPackets.history.RemovePathProbe(pn)
 	}
-	h.congestion = congestion.NewCubicSender(
-		congestion.DefaultClock{},
-		h.rttStats,
-		h.connStats,
-		initialMaxDatagramSize,
-		true, // use Reno
-		h.qlogger,
-	)
+	h.congestion = congestion.NewAdaptive(h.rttStats, initialMaxDatagramSize)
 	h.setLossDetectionTimer(now)
 }
diff -ruN a/internal/congestion/adaptive.go b/internal/congestion/adaptive.go
--- a/internal/congestion/adaptive.go	1970-01-01 08:00:00.000000000 +0800
+++ b/internal/congestion/adaptive.go	2026-11-22 18:30:25.626644672 +0800
@@ -0,0 +1,182 @@
+package congestion
+
+import (
+	"time"
+
+	"github.com/quic-go/quic-go/internal/monotime"
+	"github.com/quic-go/quic-go/internal/protocol"
+	"github.com/quic-go/quic-go/internal/utils"
+)
+
+// adaptiveSender measures the path itself and paces at the rate it finds.
+// Loss is not a congestion signal here. A growing round trip time is.
+// Everything below runs on the connection's single event loop.
+const (
+	adInitRate    = 2_000_000 // bytes/s before any measurement
+	adMinRate     = 125_000   // bytes/s floor
+	adMaxRate     = 1_250_000_000
+	adMinRound    = 20 * time.Millisecond
+	adGrow        = 1.25
+	adHeadroom    = 1.05
+	adFullEnough  = 0.85
+	adMinRoundB   = 40 * 1200 // ignore rounds that carried less than this
+	adSlots       = 5
+	adMinAckRate  = 0.7
+	adMinSamples  = 60_000
+	adCwndMul     = 1.5
+	adMinCwndPkts = 16
+	adJitterSlack = 20 * time.Millisecond
+)
+
+type adSlot struct {
+	sec   int64
+	acked uint64
+	lost  uint64
+}
+
+type adaptiveSender struct {
+	rtt        *utils.RTTStats
+	pacer      *pacer
+	mds        protocol.ByteCount
+	rate       float64 // bytes/s the path is believed to carry
+	ackRate    float64
+	slots      [adSlots]adSlot
+	roundStart monotime.Time
+	roundBytes uint64
+	inflation  bool
+}
+
+var _ SendAlgorithmWithDebugInfos = &adaptiveSender{}
+
+func NewAdaptive(rtt *utils.RTTStats, mds protocol.ByteCount) *adaptiveSender {
+	a := &adaptiveSender{rtt: rtt, mds: mds, rate: adInitRate, ackRate: 1}
+	a.pacer = newPacer(a.paceRate)
+	a.pacer.SetMaxDatagramSize(mds)
+	return a
+}
+
+func (a *adaptiveSender) minRTT() time.Duration {
+	if m := a.rtt.MinRTT(); m > 0 {
+		return m
+	}
+	if s := a.rtt.SmoothedRTT(); s > 0 {
+		return s
+	}
+	return 100 * time.Millisecond
+}
+
+func (a *adaptiveSender) compensation() float64 {
+	if a.inflation {
+		return 1
+	}
+	return a.ackRate
+}
+
+// the pacer wants bits/s and multiplies by 5/4 itself
+func (a *adaptiveSender) paceRate() Bandwidth {
+	return Bandwidth(a.rate / a.compensation() * 8 * 4 / 5)
+}
+
+func (a *adaptiveSender) window() protocol.ByteCount {
+	w := a.rate * (a.minRTT() + adJitterSlack).Seconds() * adCwndMul / a.compensation()
+	if lo := float64(adMinCwndPkts * a.mds); w < lo {
+		w = lo
+	}
+	if w > 1<<30 {
+		w = 1 << 30
+	}
+	return protocol.ByteCount(w)
+}
+
+func (a *adaptiveSender) note(acked, lost uint64) {
+	now := time.Now().Unix()
+	s := &a.slots[now%adSlots]
+	if s.sec != now {
+		*s = adSlot{sec: now}
+	}
+	s.acked += acked
+	s.lost += lost
+	var ack, lst uint64
+	for _, x := range a.slots {
+		if now-x.sec < adSlots {
+			ack += x.acked
+			lst += x.lost
+		}
+	}
+	if ack+lst < adMinSamples {
+		a.ackRate = 1
+		return
+	}
+	r := float64(ack) / float64(ack+lst)
+	if r < adMinAckRate {
+		r = adMinAckRate
+	}
+	a.ackRate = r
+}
+
+// endRound looks at what actually got through in the last round and moves the rate.
+func (a *adaptiveSender) endRound(el time.Duration) {
+	d := float64(a.roundBytes) / el.Seconds()
+	big := a.roundBytes >= adMinRoundB
+	srtt, mrtt := a.rtt.SmoothedRTT(), a.minRTT()
+	a.inflation = srtt > 0 && srtt > mrtt*5/4+8*time.Millisecond
+	switch {
+	case !big:
+		// too little data to say anything, probably the app is the limit
+	case a.inflation:
+		a.rate = d
+	case d >= adFullEnough*a.rate:
+		a.rate *= adGrow
+	case d < 0.5*a.rate:
+		a.rate = max(d*adHeadroom, a.rate*0.5)
+	default:
+		a.rate = max(d*adHeadroom, a.rate*0.92)
+	}
+	a.rate = min(max(a.rate, adMinRate), adMaxRate)
+}
+
+func (a *adaptiveSender) TimeUntilSend(protocol.ByteCount) monotime.Time {
+	return a.pacer.TimeUntilSend()
+}
+func (a *adaptiveSender) HasPacingBudget(now monotime.Time) bool {
+	return a.pacer.Budget(now) >= a.mds
+}
+func (a *adaptiveSender) OnPacketSent(t monotime.Time, _ protocol.ByteCount, _ protocol.PacketNumber, n protocol.ByteCount, _ bool) {
+	a.pacer.SentPacket(t, n)
+}
+func (a *adaptiveSender) CanSend(inFlight protocol.ByteCount) bool { return inFlight < a.window() }
+func (a *adaptiveSender) MaybeExitSlowStart()                      {}
+func (a *adaptiveSender) OnPacketAcked(_ protocol.PacketNumber, n protocol.ByteCount, _ protocol.ByteCount, t monotime.Time) {
+	a.note(uint64(n), 0)
+	if a.roundStart.IsZero() {
+		a.roundStart = t
+		return
+	}
+	a.roundBytes += uint64(n)
+	round := max(a.minRTT(), adMinRound)
+	el := t.Sub(a.roundStart)
+	if el < round {
+		return
+	}
+	if el > 6*round { // it sat idle; that says nothing about the path
+		a.roundStart, a.roundBytes = t, 0
+		return
+	}
+	a.endRound(el)
+	a.roundStart, a.roundBytes = t, 0
+}
+func (a *adaptiveSender) OnCongestionEvent(_ protocol.PacketNumber, lost protocol.ByteCount, _ protocol.ByteCount) {
+	if lost > 0 {
+		a.note(0, uint64(lost))
+	}
+}
+func (a *adaptiveSender) OnRetransmissionTimeout(bool) {}
+func (a *adaptiveSender) SetMaxDatagramSize(s protocol.ByteCount) {
+	if s > a.mds {
+		a.mds = s
+	}
+	a.pacer.SetMaxDatagramSize(a.mds)
+}
+func (a *adaptiveSender) InSlowStart() bool                       { return false }
+func (a *adaptiveSender) InRecovery() bool                        { return false }
+func (a *adaptiveSender) GetCongestionWindow() protocol.ByteCount { return a.window() }
__NQ_PATCH_END__
