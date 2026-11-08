#!/usr/bin/env bash
[ -n "${BASH_VERSION:-}" ] || { echo "请用 bash 运行本脚本：bash $0（Alpine 请先 apk add bash）" >&2; exit 1; }
# nakis 一键安装 / 运行脚本（服务端 VPS、客户端 Linux / Termux 通用）
#
# 用法：
#   bash nakis-install.sh              交互安装（先问你是服务端还是客户端）
#   nakisctl status|start|stop|restart|logs [server|client] [-f]
#   nakisctl uninstall
#
# 无人值守（全部用环境变量，设置了的项不会再询问）：
#   服务端: NAKIS_ROLE=server NAKIS_PORT=8443 NAKIS_HOST=<公网IP或域名> bash nakis-install.sh
#   客户端: NAKIS_ROLE=client NAKIS_SERVER=<ip:port> NAKIS_UUID=<uuid> NAKIS_PIN=<指纹> bash nakis-install.sh
# 其他可选变量：
#   NAKIS_YES=1          遇到已有配置时一律沿用，不再询问
#   NAKIS_SNI=<名字>     客户端 TLS 的 sni（有 pin 时默认 example.com）
#   NAKIS_REPO / NAKIS_BRANCH   仓库地址与分支
#   NAKIS_GH_PROXY=<前缀>       访问不了 GitHub 时的加速前缀，如 https://ghfast.top/
#   NAKIS_GO_VERSION=1.24.7     需要安装 Go 时使用的版本
#   NAKIS_HOME=<目录>           强制使用「普通用户」布局，全部装进这个目录

set -u
set -o pipefail

REPO_URL="${NAKIS_REPO:-https://github.com/n-yarvex/nakis.git}"
BRANCH="${NAKIS_BRANCH:-main}"
GO_VER="${NAKIS_GO_VERSION:-1.24.7}"
CLIENT_PORT=1053

SELF="${BASH_SOURCE[0]:-$0}"

if [ -t 1 ]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_0=$'\033[0m'
else
  C_R=; C_G=; C_Y=; C_B=; C_0=
fi
say()  { printf '%s\n' "${C_B}•${C_0} $*"; }
ok()   { printf '%s\n' "${C_G}✓${C_0} $*"; }
warn() { printf '%s\n' "${C_Y}!${C_0} $*" >&2; }
die()  { printf '%s\n' "${C_R}✗ $*${C_0}" >&2; exit 1; }

# ---------------------------------------------------------------- 环境 ----

IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [[ "${PREFIX:-}" == *com.termux* ]]; then IS_TERMUX=1; fi
UID_NOW=$(id -u)

if [ -n "${NAKIS_HOME:-}" ]; then
  LAYOUT=user; BASE=$NAKIS_HOME
elif [ "$IS_TERMUX" = 1 ] || [ "$UID_NOW" != 0 ]; then
  LAYOUT=user; BASE="${HOME:-/tmp}/.nakis"
else
  LAYOUT=system; BASE=
fi

if [ "$LAYOUT" = system ]; then
  CONF=/etc/nakis; BIN_DIR=/usr/local/bin; STATE=/var/lib/nakis; SRC=/var/lib/nakis/src; GO_ROOT=/usr/local/go
else
  CONF=$BASE/conf; BIN_DIR=$BASE/bin; STATE=$BASE/state; SRC=$BASE/src; GO_ROOT=$BASE/go
fi
BIN=$BIN_DIR/nakis

SUDO=""
if [ "$UID_NOW" != 0 ] && [ "$IS_TERMUX" = 0 ] && command -v sudo >/dev/null 2>&1; then SUDO=sudo; fi

case "$(uname -m)" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  armv7l|armv8l|armv6l|arm) GOARCH=armv6l ;;
  i386|i686) GOARCH=386 ;;
  *) GOARCH= ;;
esac

use_systemd() {
  [ "$LAYOUT" = system ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

# ---------------------------------------------------------------- 提问 ----

have_tty() { { : </dev/tty; } 2>/dev/null; }

# ask 变量名 提示 [默认值] [校验函数]   —— 变量已有值（环境变量）时直接校验，不提问
ask() {
  local name=$1 prompt=$2 def=${3:-} check=${4:-} val
  if [ -n "${!name:-}" ]; then
    if [ -n "$check" ] && ! "$check" "${!name}"; then die "环境变量里的 $name 不合法：${!name}"; fi
    return 0
  fi
  have_tty || die "没有可交互的终端，请改用环境变量传入（见脚本开头的说明）：缺少 $name"
  while :; do
    if [ -n "$def" ]; then
      read -r -p "$prompt [$def]: " val </dev/tty || die "读取输入失败"
      val=${val:-$def}
    else
      read -r -p "$prompt: " val </dev/tty || die "读取输入失败"
    fi
    val=${val#"${val%%[![:space:]]*}"}; val=${val%"${val##*[![:space:]]}"}
    if [ -z "$val" ]; then warn "不能为空"; continue; fi
    if [ -n "$check" ] && ! "$check" "$val"; then warn "格式不对，请重新输入"; continue; fi
    printf -v "$name" '%s' "$val"
    return 0
  done
}

# yesno 提示 默认(y/n) —— 返回 0 表示是
yesno() {
  local prompt=$1 def=${2:-y} val
  if [ "${NAKIS_YES:-}" = 1 ] || ! have_tty; then [ "$def" = y ]; return; fi
  read -r -p "$prompt [$([ "$def" = y ] && echo Y/n || echo y/N)]: " val </dev/tty || return 1
  val=${val:-$def}
  case "$val" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_role() { [ "$1" = server ] || [ "$1" = client ]; }
valid_uuid() { local u=${1//-/}; [[ "$u" =~ ^[0-9a-fA-F]{32}$ ]]; }
valid_pin()  { local p=${1//:/}; [[ "$p" =~ ^[0-9a-fA-F]{64}$ ]]; }
valid_pin_or_none() { [ "$1" = - ] || valid_pin "$1"; }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9._:-]+$ ]] && [[ "$1" != *..* ]]; }
valid_hostport() {
  local h p
  if [[ "$1" =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]+)$ ]]; then h=${BASH_REMATCH[1]}; p=${BASH_REMATCH[2]}
  elif [[ "$1" =~ ^([A-Za-z0-9._-]+):([0-9]+)$ ]]; then h=${BASH_REMATCH[1]}; p=${BASH_REMATCH[2]}
  else return 1; fi
  [ -n "$h" ] && valid_port "$p"
}

port_in_use() {
  local p=$1
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"
  else
    return 1
  fi
}

port_open() { ( exec 3<>"/dev/tcp/127.0.0.1/$1" ) 2>/dev/null; }

# ---------------------------------------------------------------- 依赖 ----

pkg_install() {
  if [ "$IS_TERMUX" = 1 ]; then
    pkg install -y "$@" || { pkg update -y >/dev/null 2>&1; pkg install -y "$@"; }
    return
  fi
  if [ "$UID_NOW" != 0 ] && [ -z "$SUDO" ]; then
    die "缺少依赖（$*），而且当前不是 root 也没有 sudo，请先手动安装它们再重试"
  fi
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y "$@"
  elif command -v apk >/dev/null 2>&1; then $SUDO apk add --no-cache "$@"
  elif command -v pacman >/dev/null 2>&1; then $SUDO pacman -Sy --noconfirm "$@"
  elif command -v zypper >/dev/null 2>&1; then $SUDO zypper --non-interactive install "$@"
  else die "不认识这个系统的包管理器，请手动安装：$*"
  fi
}

ensure_tools() {
  local need=() c
  for c in git curl tar; do command -v "$c" >/dev/null 2>&1 || need+=("$c"); done
  if [ ${#need[@]} -gt 0 ]; then
    say "安装依赖：${need[*]}"
    if [ "$IS_TERMUX" = 1 ]; then pkg_install "${need[@]}"; else pkg_install "${need[@]}" ca-certificates gzip; fi || die "依赖安装失败"
    for c in git curl tar; do command -v "$c" >/dev/null 2>&1 || die "$c 仍然不可用"; done
  fi
}

use_go_path() {
  if ! command -v go >/dev/null 2>&1 && [ -x "$GO_ROOT/bin/go" ]; then export PATH="$GO_ROOT/bin:$PATH"; fi
}

go_new_enough() {
  command -v go >/dev/null 2>&1 || return 1
  local v ma mi rest
  v=$(go env GOVERSION 2>/dev/null) || return 1
  v=${v#go}; v=${v%% *}
  ma=${v%%.*}; rest=${v#*.}; mi=${rest%%.*}; mi=${mi%%[!0-9]*}
  [[ "$ma" =~ ^[0-9]+$ ]] && [[ "$mi" =~ ^[0-9]+$ ]] || return 1
  [ "$ma" -gt 1 ] || { [ "$ma" -eq 1 ] && [ "$mi" -ge 24 ]; }
}

install_go_tarball() {
  [ -n "$GOARCH" ] || die "不支持的 CPU 架构：$(uname -m)，请自行安装 Go ≥ 1.24 后重试"
  [ "$(uname -s)" = Linux ] || die "自动安装 Go 只支持 Linux，请自行安装 Go ≥ 1.24 后重试"
  local file="go${GO_VER}.linux-${GOARCH}.tar.gz" tmp base got=0 want sum
  tmp=$(mktemp -d) || die "无法创建临时目录"
  for base in "https://go.dev/dl" "https://golang.google.cn/dl" "https://mirrors.aliyun.com/golang"; do
    say "下载 Go：$base/$file"
    if curl -fL --retry 3 --connect-timeout 15 -o "$tmp/$file" "$base/$file" && tar -tzf "$tmp/$file" >/dev/null 2>&1; then got=1; break; fi
    warn "这个源下载失败，换下一个"
  done
  [ "$got" = 1 ] || { rm -rf "$tmp"; die "Go 下载失败，请检查网络，或自行安装 Go ≥ 1.24 后重试"; }
  want=$(curl -fsSL --connect-timeout 10 "https://go.dev/dl/$file.sha256" 2>/dev/null | tr -d '[:space:]' | cut -c1-64)
  if [[ "$want" =~ ^[0-9a-f]{64}$ ]]; then
    if command -v sha256sum >/dev/null 2>&1; then sum=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then sum=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)
    else sum=; fi
    if [ -n "$sum" ] && [ "$sum" != "$want" ]; then rm -rf "$tmp"; die "Go 安装包校验失败（sha256 不一致），已中止"; fi
    [ -n "$sum" ] && ok "Go 安装包校验通过"
  else
    warn "没能取到官方校验值，跳过 sha256 校验（压缩包完整性已检查）"
  fi
  if [ "$LAYOUT" = system ]; then
    $SUDO rm -rf "$GO_ROOT" && $SUDO tar -C "$(dirname "$GO_ROOT")" -xzf "$tmp/$file" || { rm -rf "$tmp"; die "解压 Go 失败"; }
  else
    mkdir -p "$BASE" && rm -rf "$GO_ROOT" && tar -C "$BASE" -xzf "$tmp/$file" || { rm -rf "$tmp"; die "解压 Go 失败"; }
  fi
  rm -rf "$tmp"
  export PATH="$GO_ROOT/bin:$PATH"
}

TOOLCHAIN=local
ensure_go() {
  use_go_path
  if go_new_enough; then ok "Go 已就绪：$(go env GOVERSION)"; return; fi
  if [ "$IS_TERMUX" = 1 ]; then
    say "在 Termux 里安装 Go（pkg install golang）"
    pkg_install golang || die "Go 安装失败"
    if go_new_enough; then ok "Go 已就绪：$(go env GOVERSION)"; return; fi
    warn "Termux 仓库里的 Go 版本偏旧，编译时会让 Go 自己下载 1.24 工具链，需要能访问 proxy.golang.org"
    TOOLCHAIN=auto
    return
  fi
  say "安装 Go ${GO_VER}"
  install_go_tarball
  go_new_enough || die "Go 安装后仍不可用（需要 ≥ 1.24）"
  ok "Go 已就绪：$(go env GOVERSION)"
}

# ---------------------------------------------------------------- 拉取与编译 ----

fetch_source() {
  local url=$REPO_URL
  if [ -n "${NAKIS_GH_PROXY:-}" ]; then url="${NAKIS_GH_PROXY%/}/$REPO_URL"; fi
  export GIT_TERMINAL_PROMPT=0
  mkdir -p "$(dirname "$SRC")" || die "无法创建 $(dirname "$SRC")"
  if [ -d "$SRC/.git" ]; then
    say "更新源码：$url ($BRANCH)"
    if git -C "$SRC" fetch --depth 1 origin "$BRANCH" >/dev/null 2>&1 && git -C "$SRC" reset --hard FETCH_HEAD >/dev/null 2>&1; then
      return 0
    fi
    warn "更新失败，改为重新克隆"
  fi
  rm -rf "$SRC"
  say "克隆源码：$url ($BRANCH)"
  if ! git clone --depth 1 -b "$BRANCH" "$url" "$SRC" 2>"$STATE/clone.err"; then
    warn "$(tail -n 3 "$STATE/clone.err" 2>/dev/null)"
    rm -f "$STATE/clone.err"
    die "克隆失败。如果是网络问题，可以设置 NAKIS_GH_PROXY=https://ghfast.top/ 之类的加速前缀后重试；如果仓库是私有的，请先改成公开"
  fi
  rm -f "$STATE/clone.err"
}

build_binary() {
  [ -f "$SRC/go.mod" ] || die "源码目录里没有 go.mod，仓库结构不对：$SRC"
  local ver tmpbin
  ver=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo dev)
  tmpbin="$STATE/nakis.build.$$"
  say "编译中（第一次可能要一两分钟）…"
  if ! ( cd "$SRC" && GOTOOLCHAIN=$TOOLCHAIN CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -trimpath -ldflags "-s -w -X main.version=$ver" -o "$tmpbin" . ); then
    rm -f "$tmpbin"
    die "编译失败，请把上面的错误信息发给作者"
  fi
  if [ "$LAYOUT" = system ]; then
    $SUDO mkdir -p "$BIN_DIR" && $SUDO install -m 0755 "$tmpbin" "$BIN" || { rm -f "$tmpbin"; die "安装二进制失败"; }
  else
    mkdir -p "$BIN_DIR" && install -m 0755 "$tmpbin" "$BIN" || { rm -f "$tmpbin"; die "安装二进制失败"; }
  fi
  rm -f "$tmpbin"
  "$BIN" version >/dev/null 2>&1 || die "编译出的程序无法运行"
  ok "已安装 $BIN （版本 $("$BIN" version 2>/dev/null)）"
}

# ---------------------------------------------------------------- 配置 ----

new_uuid() {
  local u=
  if [ -r /proc/sys/kernel/random/uuid ]; then u=$(cat /proc/sys/kernel/random/uuid 2>/dev/null); fi
  if ! valid_uuid "$u"; then
    local h; h=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    u="${h:0:8}-${h:8:4}-${h:12:4}-${h:16:4}-${h:20:12}"
  fi
  valid_uuid "$u" || die "生成 uuid 失败"
  printf '%s' "$u"
}

detect_ip() {
  local u ip
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
    ip=$(curl -fsS4 -m 5 "$u" 2>/dev/null | tr -d '[:space:]')
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf '%s' "$ip"; return; fi
  done
}

info_get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n1; }

write_file() { # 路径 模式 （内容走 stdin）
  local path=$1 mode=$2
  if [ "$LAYOUT" = system ]; then $SUDO tee "$path" >/dev/null && $SUDO chmod "$mode" "$path"
  else cat >"$path" && chmod "$mode" "$path"; fi
}

mk_conf_dir() {
  if [ "$LAYOUT" = system ]; then $SUDO mkdir -p "$CONF" "$STATE" && $SUDO chmod 755 "$STATE"
  else mkdir -p "$CONF" "$STATE" && chmod 700 "$CONF"; fi || die "无法创建配置目录"
}

setup_server() {
  mk_conf_dir
  local info=$CONF/server.info
  if [ -f "$CONF/server.json" ] && [ -f "$info" ] && [ -f "$CONF/cert.pem" ] && [ -f "$CONF/key.pem" ]; then
    if yesno "发现已有的服务端配置，沿用它（保持 uuid / 证书 / 端口不变）吗？" y; then
      S_HOST=$(info_get "$info" HOST); S_PORT=$(info_get "$info" PORT)
      S_UUID=$(info_get "$info" UUID); S_PIN=$(info_get "$info" PIN)
      if [ -n "$S_HOST" ] && valid_port "$S_PORT" && valid_uuid "$S_UUID" && valid_pin "$S_PIN"; then
        ok "沿用已有配置"; return 0
      fi
      warn "已有配置信息不完整，重新生成"
    fi
  fi

  S_PORT=${NAKIS_PORT:-}
  while :; do
    ask S_PORT "服务端监听端口" 8443 valid_port
    if port_in_use "$S_PORT"; then
      [ -n "${NAKIS_PORT:-}" ] && die "端口 $S_PORT 已被占用"
      warn "端口 $S_PORT 已被占用，换一个"; S_PORT=; continue
    fi
    break
  done
  if [ "$LAYOUT" = user ] && [ "$S_PORT" -lt 1024 ]; then warn "普通用户通常不能绑定 1024 以下的端口，如果启动失败请换成大端口或用 root 运行"; fi

  S_HOST=${NAKIS_HOST:-}
  if [ -z "$S_HOST" ]; then
    say "正在探测本机公网 IP …"
    local guess; guess=$(detect_ip)
    ask S_HOST "服务器的公网 IP 或域名（客户端要连的地址，也会写进证书）" "$guess" valid_host
  else
    valid_host "$S_HOST" || die "NAKIS_HOST 不合法：$S_HOST"
  fi

  S_UUID=${NAKIS_UUID:-}
  if [ -n "$S_UUID" ]; then valid_uuid "$S_UUID" || die "NAKIS_UUID 不合法"; else S_UUID=$(new_uuid); fi

  say "生成自签证书（10 年）…"
  local out
  if [ "$LAYOUT" = system ]; then out=$($SUDO "$BIN" cert -name "$S_HOST" -out "$CONF" 2>&1)
  else out=$("$BIN" cert -name "$S_HOST" -out "$CONF" 2>&1); fi || die "生成证书失败：$out"
  S_PIN=$(printf '%s' "$out" | grep -oE '[0-9a-f]{64}' | tail -n1)
  valid_pin "$S_PIN" || die "没能从 nakis cert 的输出里读到指纹：$out"

  write_file "$CONF/server.json" 640 <<EOF
{
  "listen": "0.0.0.0:$S_PORT",
  "uuid": "$S_UUID",
  "tls_cert": "$CONF/cert.pem",
  "tls_key": "$CONF/key.pem"
}
EOF
  [ -s "$CONF/server.json" ] || die "写入 server.json 失败"
  write_file "$info" 600 <<EOF
HOST=$S_HOST
PORT=$S_PORT
UUID=$S_UUID
PIN=$S_PIN
EOF
  ok "服务端配置已写入 $CONF/server.json"
}

setup_client() {
  mk_conf_dir
  if [ -f "$CONF/client.json" ]; then
    if yesno "发现已有的客户端配置，沿用它吗？" y; then ok "沿用已有配置"; return 0; fi
  fi

  C_SERVER=${NAKIS_SERVER:-}
  ask C_SERVER "服务端地址（IP:端口 或 域名:端口）" "" valid_hostport
  C_UUID=${NAKIS_UUID:-}
  ask C_UUID "UUID（服务端安装结束时打印的那个）" "" valid_uuid
  C_PIN=${NAKIS_PIN:-}
  if [ -z "$C_PIN" ]; then
    ask C_PIN "证书指纹 pin（服务端安装结束时打印的 64 位十六进制；用 CA 正规证书的话输入 - ）" "" valid_pin_or_none
  else
    valid_pin_or_none "$C_PIN" || die "NAKIS_PIN 不合法"
  fi

  local host=${C_SERVER%:*}; host=${host#[}; host=${host%]}
  local is_ip=0
  if [[ "$host" =~ ^[0-9.]+$ ]] || [[ "$host" == *:* ]]; then is_ip=1; fi
  C_SNI=${NAKIS_SNI:-}
  if [ "$C_PIN" = - ]; then
    C_PIN=
    if [ -z "$C_SNI" ] && [ "$is_ip" = 0 ]; then C_SNI=$host; fi
    ask C_SNI "证书里的域名（sni）" "" valid_host
  else
    if [ -z "$C_SNI" ]; then C_SNI=example.com; fi
    valid_host "$C_SNI" || die "NAKIS_SNI 不合法：$C_SNI"
  fi
  C_PIN=${C_PIN//:/}; C_PIN=$(printf '%s' "$C_PIN" | tr 'A-F' 'a-f')

  local pins='[]'
  [ -n "$C_PIN" ] && pins="[\"$C_PIN\"]"
  write_file "$CONF/client.json" 640 <<EOF
{
  "listen": "127.0.0.1:$CLIENT_PORT",
  "server": "$C_SERVER",
  "uuid": "$C_UUID",
  "sni": "$C_SNI",
  "tls_pins": $pins
}
EOF
  [ -s "$CONF/client.json" ] || die "写入 client.json 失败"
  ok "客户端配置已写入 $CONF/client.json"

  local h=${C_SERVER%:*} p=${C_SERVER##*:}; h=${h#[}; h=${h%]}
  if command -v timeout >/dev/null 2>&1 && ! timeout 6 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then
    warn "暂时连不上 $C_SERVER（可能是防火墙/安全组没放行、地址写错或服务端没启动），仍会继续安装，装好后可用 nakisctl logs 查看"
  fi
}

# ---------------------------------------------------------------- 运行 ----

SVC_USER=
prepare_service_user() {
  SVC_USER=
  [ "$LAYOUT" = system ] || return 0
  if ! id nakis >/dev/null 2>&1; then
    local nologin=/usr/sbin/nologin; [ -x "$nologin" ] || nologin=/sbin/nologin; [ -x "$nologin" ] || nologin=/bin/false
    $SUDO useradd --system --no-create-home --shell "$nologin" nakis >/dev/null 2>&1 || return 0
  fi
  local f
  if $SUDO chgrp -R nakis "$CONF" 2>/dev/null && $SUDO chmod 750 "$CONF"; then
    for f in "$CONF"/*.json "$CONF"/*.pem; do
      [ -f "$f" ] && $SUDO chmod 640 "$f"
    done
    SVC_USER=nakis
  fi
}

unit_name() { printf 'nakis-%s' "$1"; }
log_file() { printf '%s/%s.log' "$STATE" "$1"; }
pid_file() { printf '%s/%s.pid' "$STATE" "$1"; }

bg_alive() {
  local pf; pf=$(pid_file "$1")
  [ -f "$pf" ] && kill -0 "$(cat "$pf" 2>/dev/null)" 2>/dev/null
}

is_nakis_pid() {
  local pid=$1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  if [ -r "/proc/$pid/cmdline" ]; then tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q nakis; else ps -p "$pid" -o args= 2>/dev/null | grep -q nakis; fi
}

bg_stop() {
  local role=$1 pf cf pid child i
  pf=$(pid_file "$role"); cf="$STATE/$role.child"
  pid=$(cat "$pf" 2>/dev/null); child=$(cat "$cf" 2>/dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    for i in $(seq 1 16); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
  fi
  if is_nakis_pid "$child"; then
    for i in 1 2 3 4; do is_nakis_pid "$child" || break; sleep 0.5; done
    is_nakis_pid "$child" && kill -9 "$child" 2>/dev/null
  fi
  rm -f "$pf" "$cf"
}

bg_start() {
  local role=$1 run log
  run=$STATE/$role.run; log=$(log_file "$role")
  mkdir -p "$STATE"
  bg_stop "$role"
  if [ -f "$log" ] && [ "$(wc -c <"$log" 2>/dev/null || echo 0)" -gt 5242880 ]; then tail -c 1048576 "$log" >"$log.tmp" && mv "$log.tmp" "$log"; fi
  cat >"$run" <<EOF
#!/usr/bin/env bash
echo \$\$ > "$(pid_file "$role")"
child=
trap 'kill \$child 2>/dev/null; wait \$child 2>/dev/null; exit 0' TERM INT HUP
while :; do
  "$BIN" $role -c "$CONF/$role.json" >>"$log" 2>&1 &
  child=\$!
  echo \$child > "$STATE/$role.child"
  wait \$child
  sleep 2
done
EOF
  chmod 700 "$run"
  if [ "$IS_TERMUX" = 1 ] && command -v termux-wake-lock >/dev/null 2>&1; then termux-wake-lock 2>/dev/null; fi
  if command -v setsid >/dev/null 2>&1; then
    setsid nohup bash "$run" >/dev/null 2>&1 </dev/null &
  else
    nohup bash "$run" >/dev/null 2>&1 </dev/null &
  fi
  disown 2>/dev/null
}

svc_stop() {
  local role=$1
  if use_systemd && [ -f "/etc/systemd/system/$(unit_name "$role").service" ]; then
    $SUDO systemctl stop "$(unit_name "$role")" >/dev/null 2>&1
  fi
  bg_stop "$role"
}

svc_start() {
  local role=$1 unit
  unit=$(unit_name "$role")
  if use_systemd; then
    prepare_service_user
    {
      echo "[Unit]"
      echo "Description=nakis $role"
      echo "After=network-online.target"
      echo "Wants=network-online.target"
      echo
      echo "[Service]"
      [ -n "$SVC_USER" ] && echo "User=$SVC_USER"
      echo "ExecStart=$BIN $role -c $CONF/$role.json"
      echo "Restart=always"
      echo "RestartSec=2"
      echo "TimeoutStopSec=30"
      echo "LimitNOFILE=1048576"
      echo "NoNewPrivileges=yes"
      echo "AmbientCapabilities=CAP_NET_BIND_SERVICE"
      echo "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
      echo
      echo "[Install]"
      echo "WantedBy=multi-user.target"
    } | write_file "/etc/systemd/system/$unit.service" 644
    $SUDO systemctl daemon-reload || die "systemctl daemon-reload 失败"
    $SUDO systemctl enable "$unit" >/dev/null 2>&1
    $SUDO systemctl restart "$unit" || die "启动服务失败，请运行：journalctl -u $unit -n 50 --no-pager"
    ok "已作为 systemd 服务运行：$unit（开机自启、崩溃自动重启）"
  else
    bg_start "$role"
    ok "已在后台运行（带自动重启的守护循环）；日志：$(log_file "$role")"
    if [ "$IS_TERMUX" = 1 ]; then
      warn "Termux 提示：请在系统设置里把 Termux 的电池优化设为「不限制」，否则切到后台后可能被系统杀掉；开机自启需要安装 Termux:Boot"
    fi
  fi
}

role_alive() {
  local role=$1
  if use_systemd && [ -f "/etc/systemd/system/$(unit_name "$role").service" ]; then
    $SUDO systemctl is-active --quiet "$(unit_name "$role")"
  else
    bg_alive "$role"
  fi
}

show_log() {
  local role=$1 n=${2:-40}
  if use_systemd && [ -f "/etc/systemd/system/$(unit_name "$role").service" ]; then
    $SUDO journalctl -u "$(unit_name "$role")" -n "$n" --no-pager 2>/dev/null
  elif [ -f "$(log_file "$role")" ]; then
    tail -n "$n" "$(log_file "$role")"
  else
    echo "（还没有日志）"
  fi
}

wait_listening() { # 角色 端口
  local role=$1 port=$2 i
  for i in $(seq 1 20); do
    if port_open "$port"; then return 0; fi
    sleep 0.5
  done
  return 1
}

open_firewall() {
  local port=$1
  if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q "Status: active"; then
    $SUDO ufw allow "$port"/tcp >/dev/null 2>&1 && ok "已在 ufw 放行 $port/tcp"
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && $SUDO firewall-cmd --state >/dev/null 2>&1; then
    $SUDO firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1 && $SUDO firewall-cmd --reload >/dev/null 2>&1 && ok "已在 firewalld 放行 $port/tcp"
  fi
}

install_self() {
  if [ -f "$SELF" ] && [ "$(basename "$SELF")" != bash ]; then
    if [ "$LAYOUT" = system ]; then $SUDO install -m 0755 "$SELF" "$BIN_DIR/nakisctl" 2>/dev/null
    else install -m 0755 "$SELF" "$BIN_DIR/nakisctl" 2>/dev/null; fi && CTL=$BIN_DIR/nakisctl
  fi
}

# ---------------------------------------------------------------- 流程 ----

do_install() {
  local role=${NAKIS_ROLE:-}
  if [ -z "$role" ]; then
    have_tty || die "没有可交互的终端，请设置 NAKIS_ROLE=server 或 client"
    echo
    echo "  1) 服务端（在 VPS 上运行）"
    echo "  2) 客户端（在你自己的电脑 / 手机 Termux 上运行，提供本地 SOCKS5 代理）"
    echo
    local pick
    while :; do
      read -r -p "这台机器是？请输入 1 或 2: " pick </dev/tty || die "读取输入失败"
      case "$pick" in 1|server|s) role=server; break ;; 2|client|c) role=client; break ;; *) warn "请输入 1 或 2" ;; esac
    done
  fi
  valid_role "$role" || die "NAKIS_ROLE 只能是 server 或 client"

  say "环境：$([ "$IS_TERMUX" = 1 ] && echo Termux || uname -s)/$(uname -m)，$([ "$LAYOUT" = system ] && echo "系统级安装（root）" || echo "用户级安装（$BASE）")，角色：$role"
  [ "$LAYOUT" = system ] || [ "$IS_TERMUX" = 1 ] || { [ -n "${NAKIS_HOME:-}" ] || warn "当前不是 root，将安装到 $BASE，且不会注册 systemd 服务"; }

  mkdir -p "$STATE" 2>/dev/null || { [ "$LAYOUT" = system ] && $SUDO mkdir -p "$STATE"; }
  [ -d "$STATE" ] || die "无法创建 $STATE"
  if [ "$LAYOUT" = system ] && [ "$UID_NOW" != 0 ]; then die "系统级安装需要 root"; fi

  svc_stop "$role"

  ensure_tools
  ensure_go
  fetch_source
  build_binary

  CTL=
  if [ "$role" = server ]; then setup_server; else setup_client; fi

  svc_start "$role"
  local port=$CLIENT_PORT
  [ "$role" = server ] && port=$S_PORT
  if ! wait_listening "$role" "$port"; then
    warn "服务没有在 $port 端口起来，最近的日志："
    show_log "$role" 30 >&2
    die "启动失败，请根据上面的日志排查"
  fi
  ok "已经在监听 ${port} 端口"
  [ "$role" = server ] && open_firewall "$S_PORT"
  install_self

  echo
  if [ "$role" = server ]; then
    echo "${C_G}══════════ 服务端已就绪 ══════════${C_0}"
    echo "把下面三项填到客户端："
    echo "  服务端地址  ${S_HOST}:${S_PORT}"
    echo "  UUID        ${S_UUID}"
    echo "  证书指纹    ${S_PIN}"
    echo
    echo "客户端一行命令（Linux / Termux）："
    echo "  NAKIS_ROLE=client NAKIS_SERVER=${S_HOST}:${S_PORT} NAKIS_UUID=${S_UUID} NAKIS_PIN=${S_PIN} bash nakis-install.sh"
    echo
    echo "注意：1) 云厂商的安全组 / 防火墙也要放行 TCP ${S_PORT}；2) 两端时钟误差必须小于 30 秒（当前服务器 UTC 时间：$(date -u '+%F %T')）。"
  else
    echo "${C_G}══════════ 客户端已就绪 ══════════${C_0}"
    echo "SOCKS5 代理：127.0.0.1:${CLIENT_PORT}（勾选「通过代理解析域名」）"
    say "试一下通不通 …"
    local code="" i
    if command -v curl >/dev/null 2>&1; then
      for i in 1 2 3; do
        code=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' --socks5-hostname "127.0.0.1:${CLIENT_PORT}" https://example.com 2>/dev/null || true)
        [ "$code" = 200 ] && break
        sleep 2
      done
    fi
    if [ "$code" = 200 ]; then ok "通过代理访问 https://example.com 成功（HTTP 200）"
    else
      warn "测试访问没成功（返回：${code:-无}），最近的日志："
      show_log client 20 >&2
      warn "常见原因：uuid / 指纹填错、服务端端口没放行、两端时间差超过 30 秒。修好后运行：${CTL:-bash nakis-install.sh}"
    fi
    echo
    echo "测试命令：curl --socks5-hostname 127.0.0.1:${CLIENT_PORT} https://example.com"
  fi
  echo
  if [ -n "$CTL" ]; then
    echo "日常管理：$CTL status | logs [-f] | restart | stop | uninstall"
  else
    echo "查看日志：$(if use_systemd; then echo "journalctl -u nakis-$role -f"; else echo "tail -f $(log_file "$role")"; fi)"
    echo "（想要 nakisctl 管理命令：先把本脚本保存成文件再运行，而不是用管道执行）"
  fi
}

roles_installed() {
  local r out=()
  for r in server client; do [ -f "$CONF/$r.json" ] && out+=("$r"); done
  printf '%s\n' "${out[@]:-}"
}

pick_roles() { # 参数: 可选 role
  if [ -n "${1:-}" ]; then valid_role "$1" || die "角色只能是 server 或 client"; printf '%s\n' "$1"; else roles_installed | sed '/^$/d'; fi
}

do_status() {
  local r found=0
  for r in $(pick_roles "${1:-}"); do
    found=1
    if role_alive "$r"; then ok "$r：运行中"; else warn "$r：没有运行"; fi
  done
  [ "$found" = 1 ] || warn "没有找到已安装的配置（$CONF）"
}

do_ctl_simple() { # start|stop|restart [role]
  local act=$1 r found=0
  shift
  for r in $(pick_roles "${1:-}"); do
    found=1
    case "$act" in
      stop) svc_stop "$r"; ok "$r 已停止" ;;
      start|restart) svc_stop "$r"; svc_start "$r" ;;
    esac
  done
  [ "$found" = 1 ] || warn "没有找到已安装的配置（$CONF）"
}

do_logs() {
  local role="" follow=0 a
  for a in "$@"; do
    case "$a" in -f) follow=1 ;; server|client) role=$a ;; *) die "用法：nakisctl logs [server|client] [-f]" ;; esac
  done
  [ -n "$role" ] || role=$(roles_installed | sed '/^$/d' | head -n1)
  [ -n "$role" ] || die "没有找到已安装的配置"
  if [ "$follow" = 1 ]; then
    if use_systemd && [ -f "/etc/systemd/system/$(unit_name "$role").service" ]; then $SUDO journalctl -u "$(unit_name "$role")" -f
    else tail -n 40 -f "$(log_file "$role")"; fi
  else
    show_log "$role" 80
  fi
}

do_uninstall() {
  local r
  for r in server client; do
    svc_stop "$r"
    if use_systemd && [ -f "/etc/systemd/system/$(unit_name "$r").service" ]; then
      $SUDO systemctl disable "$(unit_name "$r")" >/dev/null 2>&1
      $SUDO rm -f "/etc/systemd/system/$(unit_name "$r").service"
    fi
    rm -f "$STATE/$r.run" "$STATE/$r.pid"
  done
  use_systemd && $SUDO systemctl daemon-reload >/dev/null 2>&1
  if [ "$LAYOUT" = system ]; then $SUDO rm -f "$BIN" "$BIN_DIR/nakisctl"; else rm -f "$BIN" "$BIN_DIR/nakisctl"; fi
  if [ "$LAYOUT" = system ]; then $SUDO rm -rf "$SRC"; else rm -rf "$SRC"; fi
  ok "已停止服务并删除程序和源码"
  if yesno "同时删除配置（含 uuid、证书、日志）吗？" n; then
    if [ "$LAYOUT" = system ]; then $SUDO rm -rf "$CONF" "$STATE"; else rm -rf "$CONF" "$STATE"; fi
    ok "配置已删除"
  else
    say "配置保留在 $CONF"
  fi
  say "Go 环境没有动（如需删除：$GO_ROOT）"
}

usage() {
  cat <<EOF
用法：
  bash $(basename "$SELF")                    交互安装
  nakisctl status|start|stop|restart [server|client]
  nakisctl logs [server|client] [-f]
  nakisctl uninstall
EOF
}

main() {
  case "${1:-}" in
    "")
      if [ "$(basename "$SELF")" = nakisctl ]; then usage; else do_install; fi ;;
    install) do_install ;;
    status) shift; do_status "${1:-}" ;;
    start|stop|restart) a=$1; shift; do_ctl_simple "$a" "${1:-}" ;;
    logs) shift; do_logs "$@" ;;
    uninstall) do_uninstall ;;
    -h|--help|help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"