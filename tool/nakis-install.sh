#!/usr/bin/env bash
[ -n "${BASH_VERSION:-}" ] || { echo "请用 bash 运行本脚本：bash $0（Alpine 请先 apk add bash）" >&2; exit 1; }
# nakis 服务端一键脚本（只管服务端；客户端请用支持 nakis:// 链接的图形客户端导入）
#
# 用法：
#   bash nakis-install.sh                  没装过就走安装向导，装过就进管理菜单
#   nakisctl <命令>                         安装后会把自己复制成 nakisctl，之后直接用它
#
# 命令：
#   install      安装 / 重装：拉源码、编译、向导配置、启动服务
#   config       重新配置（每一项都显示当前值，回车保持不变）
#   link         显示分享链接与订阅内容（nakis://… 与 base64 订阅文本）
#   start | stop | restart | status
#   logs [-f]    查看日志，-f 持续跟随
#   update       拉最新源码并重新编译，保留全部配置
#   uuid         重新生成 uuid（旧链接立刻失效）
#   cert         重新生成自签证书（旧链接里的指纹会失效）
#   ech          重新生成 ECH 密钥
#   sync-cert    把你自己的证书重新复制进来（续期之后用）
#   check        体检：端口、防火墙、拥塞控制、公网地址
#   uninstall [-y]  卸载（-y 不再确认）
#   menu         打开管理菜单
#
# 无人值守：任何设置项都可以用 NAKIS_<名字> 环境变量给出，给了就不再询问：
#   NAKIS_HOSTS=1.2.3.4,vpn.example.com  客户端连接用的地址（可多个，每个出一条链接）
#   NAKIS_PORT=8443          监听端口            NAKIS_PUBLIC_PORT=443  对外端口（端口转发时才需要）
#   NAKIS_BIND=0.0.0.0       监听地址            NAKIS_UUID=<uuid>      不给就随机生成
#   NAKIS_NODE_NAME=nakis    客户端里显示的节点名
#   NAKIS_TLS_MODE=self|own|plain
#   NAKIS_CERT_SRC=<证书文件> NAKIS_KEY_SRC=<私钥文件>   （own 模式）
#   NAKIS_SNI=<名字>         链接里的 sni         NAKIS_ECH=0|1  NAKIS_ECH_PUBLIC=<外层 SNI>
#   NAKIS_DNS=1.1.1.1,8.8.8.8  NAKIS_ALLOW_PRIVATE=true|false  NAKIS_MAX_CONNS=4096
#   NAKIS_KEEPALIVE=15s  NAKIS_CONGESTION=bbr  NAKIS_LOG_LEVEL=info|debug|warn|error
#   NAKIS_DIAL_TIMEOUT NAKIS_HANDSHAKE_TIMEOUT NAKIS_IDLE_TIMEOUT NAKIS_SHUTDOWN_TIMEOUT
#   NAKIS_SEND_PACK NAKIS_SEND_TAIL NAKIS_SEND_QUIET NAKIS_MERGE_PACK NAKIS_MAX_QUEUE
# 其他：
#   NAKIS_YES=1          不提问，全部用环境变量 / 当前值 / 默认值
#   NAKIS_ADVANCED=1     交互时直接进入高级参数（否则会先问你要不要）
#   NAKIS_REPO / NAKIS_BRANCH / NAKIS_GH_PROXY / NAKIS_GO_VERSION
#   NAKIS_HOME=<目录>    强制使用「普通用户」布局，全部装进这个目录

set -u
set -o pipefail

REPO_URL="${NAKIS_REPO:-https://github.com/n-yarvex/nakis.git}"
BRANCH="${NAKIS_BRANCH:-main}"
GO_VER="${NAKIS_GO_VERSION:-1.24.7}"

SELF="${BASH_SOURCE[0]:-$0}"

if [ -t 1 ]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_D=$'\033[2m'; C_0=$'\033[0m'
else
  C_R=; C_G=; C_Y=; C_B=; C_D=; C_0=
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
CTL=$BIN_DIR/nakisctl
SETTINGS=$CONF/settings.env
UNIT=nakis-server
UNIT_FILE=/etc/systemd/system/$UNIT.service

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

# ---------------------------------------------------------------- 校验 ----

# validate 类型 值 —— 返回 0 表示合法
validate() {
  local kind=$1 v=$2
  case "$kind" in
    port)   [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 65535 ] ;;
    uuid)   local u=${v//-/}; [[ "$u" =~ ^[0-9a-fA-F]{32}$ ]] ;;
    bool)   [ "$v" = true ] || [ "$v" = false ] ;;
    bit)    [ "$v" = 0 ] || [ "$v" = 1 ] ;;
    int:*)  local lo hi; IFS=: read -r _ lo hi <<<"$kind"
            [[ "$v" =~ ^[0-9]+$ ]] && [ "${#v}" -le 12 ] && [ "$v" -ge "$lo" ] && [ "$v" -le "$hi" ] ;;
    dur)    [[ "$v" =~ ^[0-9]+(\.[0-9]+)?(ms|s|m|h)$ ]] ;;
    level)  [ "$v" = debug ] || [ "$v" = info ] || [ "$v" = warn ] || [ "$v" = error ] ;;
    cc)     [[ "$v" =~ ^[a-z0-9_-]{1,15}$ ]] ;;
    host)   [[ "$v" =~ ^[A-Za-z0-9._:-]+$ ]] && [[ "$v" != *..* ]] ;;
    hosts)  local h; [ -n "$v" ] || return 1
            while IFS= read -r h; do validate host "$h" || return 1; done < <(tr ',' '\n' <<<"$v") ;;
    dns)    local d; while IFS= read -r d; do
              [ -n "$d" ] || return 1
              [[ "$d" =~ ^[0-9A-Fa-f:.]+$ ]] || [[ "$d" =~ ^\[[0-9A-Fa-f:.]+\]:[0-9]+$ ]] || [[ "$d" =~ ^[0-9.]+:[0-9]+$ ]] || return 1
            done < <(tr ',' '\n' <<<"$v") ;;
    bind)   [[ "$v" =~ ^[0-9A-Fa-f:.]+$ ]] ;;
    name)   [ "${#v}" -le 60 ] && [[ "$v" != *[\"\\\&\#\?%\$\`]* ]] && [[ "$v" =~ ^[^[:cntrl:]]+$ ]] ;;
    tls)    [ "$v" = self ] || [ "$v" = own ] || [ "$v" = plain ] ;;
    file)   [ -f "$v" ] && [ -r "$v" ] ;;
    *)      return 1 ;;
  esac
}

# ---------------------------------------------------------------- 设置 ----

KEYS=(HOSTS PORT PUBLIC_PORT BIND UUID NODE_NAME TLS_MODE CERT_SRC KEY_SRC SNI ECH ECH_PUBLIC
      DNS ALLOW_PRIVATE MAX_CONNS KEEPALIVE CONGESTION LOG_LEVEL
      DIAL_TIMEOUT HANDSHAKE_TIMEOUT IDLE_TIMEOUT SHUTDOWN_TIMEOUT
      SEND_PACK SEND_TAIL SEND_QUIET MERGE_PACK MAX_QUEUE)

set_defaults() {
  HOSTS=; PORT=8443; PUBLIC_PORT=; BIND=0.0.0.0; UUID=; NODE_NAME=nakis
  TLS_MODE=self; CERT_SRC=; KEY_SRC=; SNI=; ECH=0; ECH_PUBLIC=cloudflare-ech.com
  DNS=; ALLOW_PRIVATE=false; MAX_CONNS=4096; KEEPALIVE=15s; CONGESTION=; LOG_LEVEL=info
  DIAL_TIMEOUT=5s; HANDSHAKE_TIMEOUT=10s; IDLE_TIMEOUT=120s; SHUTDOWN_TIMEOUT=20s
  SEND_PACK=32768; SEND_TAIL=512; SEND_QUIET=4; MERGE_PACK=20480; MAX_QUEUE=4194304
}

kind_of() {
  case "$1" in
    HOSTS) echo hosts ;; PORT|PUBLIC_PORT) echo port ;; BIND) echo bind ;; UUID) echo uuid ;;
    NODE_NAME) echo name ;; TLS_MODE) echo tls ;; CERT_SRC|KEY_SRC) echo file ;; SNI|ECH_PUBLIC) echo host ;;
    ECH) echo bit ;; DNS) echo dns ;; ALLOW_PRIVATE) echo bool ;; MAX_CONNS) echo int:1:1048576 ;;
    KEEPALIVE|DIAL_TIMEOUT|HANDSHAKE_TIMEOUT|IDLE_TIMEOUT|SHUTDOWN_TIMEOUT) echo dur ;;
    CONGESTION) echo cc ;; LOG_LEVEL) echo level ;;
    SEND_PACK) echo int:1024:65533 ;; SEND_TAIL) echo int:0:65532 ;; SEND_QUIET) echo int:0:64 ;;
    MERGE_PACK) echo int:1024:65533 ;; MAX_QUEUE) echo int:65536:268435456 ;;
  esac
}

load_settings() {
  set_defaults
  [ -f "$SETTINGS" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Z_]+$ ]] || continue
    case " ${KEYS[*]} " in *" $k "*) ;; *) continue ;; esac
    printf -v "$k" '%s' "$v"
  done <"$SETTINGS"
}

save_settings() {
  local k
  mk_conf_dir
  {
    echo "# nakisctl 的设置存档，请用 nakisctl config 修改"
    for k in "${KEYS[@]}"; do printf '%s=%s\n' "$k" "${!k}"; done
  } | write_file "$SETTINGS" 600
}

write_file() { # 路径 模式 （内容走 stdin）
  local path=$1 mode=$2 tmp
  tmp="$path.tmp.$$"
  cat >"$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$path" || { rm -f "$tmp"; die "写入失败：$path"; }
}

mk_conf_dir() {
  mkdir -p "$CONF" "$STATE" || die "无法创建配置目录"
  if [ "$LAYOUT" = system ]; then chmod 755 "$STATE"; else chmod 700 "$CONF"; fi
}

# ---------------------------------------------------------------- 提问 ----

have_tty() { { : </dev/tty; } 2>/dev/null; }
interactive() { [ "${NAKIS_YES:-}" != 1 ] && have_tty; }

ADVANCED=${NAKIS_ADVANCED:-0}

# prompt 键 说明 [opt] [adv]
#   opt：允许留空（输入 - 表示清空）； adv：属于高级参数，只在进入高级模式时才问
prompt() {
  local key=$1 text=$2 opt=${3:-} adv=${4:-} kind env val cur shown
  kind=$(kind_of "$key"); env="NAKIS_$key"; cur=${!key}
  if [ -n "${!env+x}" ]; then
    val=${!env}
    case "$kind" in hosts|dns) val=${val// /} ;; esac
    if [ -z "$val" ] && [ "$opt" = opt ]; then printf -v "$key" '%s' ""; return 0; fi
    validate "$kind" "$val" || die "环境变量 $env 不合法：$val"
    printf -v "$key" '%s' "$val"; return 0
  fi
  if ! interactive; then return 0; fi
  if [ "$adv" = adv ] && [ "$ADVANCED" != 1 ]; then return 0; fi
  while :; do
    shown=$cur; [ -z "$shown" ] && shown="空"
    read -r -p "  $text [${shown}]: " val </dev/tty || die "读取输入失败"
    val=${val#"${val%%[![:space:]]*}"}; val=${val%"${val##*[![:space:]]}"}
    if [ -z "$val" ]; then val=$cur; fi
    if [ "$val" = - ]; then val=; fi
    case "$kind" in hosts|dns) val=${val// /} ;; esac
    if [ -z "$val" ]; then
      if [ "$opt" = opt ]; then printf -v "$key" '%s' ""; return 0; fi
      warn "这一项不能为空"; continue
    fi
    validate "$kind" "$val" || { warn "格式不对，请重新输入"; continue; }
    printf -v "$key" '%s' "$val"; return 0
  done
}

# choose 键 说明 选项1 选项2 …   （选项是值本身）
choose() {
  local key=$1 text=$2; shift 2
  local env="NAKIS_$key" val i n=$#
  if [ -n "${!env+x}" ]; then
    val=${!env}; validate "$(kind_of "$key")" "$val" || die "环境变量 $env 不合法：$val"
    printf -v "$key" '%s' "$val"; return 0
  fi
  interactive || return 0
  local opts=("$@")
  echo "  $text"
  for ((i = 0; i < n; i++)); do echo "    $((i + 1))) ${opts[$i]}"; done
  while :; do
    read -r -p "  请选择 [当前：${!key}]: " val </dev/tty || die "读取输入失败"
    [ -z "$val" ] && return 0
    if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge 1 ] && [ "$val" -le "$n" ]; then
      val=$(sed 's/ .*//' <<<"${opts[$((val - 1))]}")
    fi
    validate "$(kind_of "$key")" "$val" && { printf -v "$key" '%s' "$val"; return 0; }
    warn "请输入编号"
  done
}

yesno() { # 提示 默认(y/n)
  local prompt=$1 def=${2:-y} val
  interactive || { [ "$def" = y ]; return; }
  read -r -p "$prompt [$([ "$def" = y ] && echo Y/n || echo y/N)]: " val </dev/tty || return 1
  val=${val:-$def}
  case "$val" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

pause() { interactive && { read -r -p "按回车继续…" _ </dev/tty || true; }; return 0; }

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

port_open() { ( exec 3<>"/dev/tcp/$1/$2" ) 2>/dev/null; }

probe_hosts() {
  local h
  case "${BIND:-}" in
    ""|0.0.0.0) echo 127.0.0.1 ;;
    ::|"[::]") echo ::1; echo 127.0.0.1 ;;
    *) h=${BIND#\[}; echo "${h%\]}" ;;
  esac
}

listening() {
  local h
  while IFS= read -r h; do
    port_open "$h" "$PORT" && return 0
  done < <(probe_hosts)
  return 1
}

# ---------------------------------------------------------------- 依赖 ----

pkg_install() {
  if [ "$IS_TERMUX" = 1 ]; then
    pkg install -y "$@" || { pkg update -y >/dev/null 2>&1; pkg install -y "$@"; }
    return
  fi
  if [ "$UID_NOW" != 0 ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO=sudo; else die "缺少依赖（$*），而且当前不是 root 也没有 sudo，请先手动安装它们再重试"; fi
  else SUDO=; fi
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
SUDO=

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
  mkdir -p "$(dirname "$GO_ROOT")" && rm -rf "$GO_ROOT" && tar -C "$(dirname "$GO_ROOT")" -xzf "$tmp/$file" || { rm -rf "$tmp"; die "解压 Go 失败"; }
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
  mkdir -p "$(dirname "$SRC")" "$STATE" || die "无法创建 $(dirname "$SRC")"
  if [ -d "$SRC/.git" ]; then
    say "更新源码：$url ($BRANCH)"
    if git -C "$SRC" fetch --depth 1 "$url" "$BRANCH" >/dev/null 2>&1 && git -C "$SRC" reset --hard FETCH_HEAD >/dev/null 2>&1; then
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
  mkdir -p "$BIN_DIR" && install -m 0755 "$tmpbin" "$BIN" || { rm -f "$tmpbin"; die "安装二进制失败"; }
  rm -f "$tmpbin"
  "$BIN" version >/dev/null 2>&1 || die "编译出的程序无法运行"
  ok "已安装 $BIN （版本 $("$BIN" version 2>/dev/null)）"
}

install_self() {
  local from= fresh=${1:-}
  if [ "$fresh" = fresh ]; then
    if [ -f "$SRC/tool/nakis-install.sh" ]; then from=$SRC/tool/nakis-install.sh
    elif [ -f "$SRC/nakis-install.sh" ]; then from=$SRC/nakis-install.sh; fi
  fi
  if [ -z "$from" ]; then
    if [ -f "$SELF" ] && [ "$(basename "$SELF")" != bash ]; then from=$SELF
    elif [ -f "$SRC/tool/nakis-install.sh" ]; then from=$SRC/tool/nakis-install.sh
    elif [ -f "$SRC/nakis-install.sh" ]; then from=$SRC/nakis-install.sh; fi
  fi
  [ -n "$from" ] || return 0
  [ "$from" -ef "$CTL" ] && return 0
  [ -f "$CTL" ] && cmp -s "$from" "$CTL" && return 0
  local tmp="$CTL.new.$$"
  if mkdir -p "$BIN_DIR" && cp "$from" "$tmp" 2>/dev/null && chmod 0755 "$tmp" && mv -f "$tmp" "$CTL" 2>/dev/null; then
    return 0
  fi
  rm -f "$tmp"
  warn "管理脚本没能更新到 $CTL，请手动重新下载安装脚本"
  return 1
}

# ---------------------------------------------------------------- 生成材料 ----

new_uuid() {
  local u=
  if [ -r /proc/sys/kernel/random/uuid ]; then u=$(cat /proc/sys/kernel/random/uuid 2>/dev/null); fi
  if ! validate uuid "$u"; then
    local h; h=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    u="${h:0:8}-${h:8:4}-${h:12:4}-${h:16:4}-${h:20:12}"
  fi
  validate uuid "$u" || die "生成 uuid 失败"
  printf '%s' "$u"
}

detect_ip() {
  local u ip
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
    ip=$(curl -fsS4 -m 5 "$u" 2>/dev/null | tr -d '[:space:]')
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then printf '%s' "$ip"; return; fi
  done
}

make_cert() {
  local names=${HOSTS:-localhost}
  "$BIN" cert -name "$names" -out "$CONF" >/dev/null || die "生成证书失败"
  chmod 644 "$CONF/cert.pem"; chmod 600 "$CONF/key.pem"
  ok "已生成自签证书（${names}），链接里会带上它的指纹"
}

sync_own_cert() {
  validate file "$CERT_SRC" || die "证书文件读不了：$CERT_SRC"
  validate file "$KEY_SRC" || die "私钥文件读不了：$KEY_SRC"
  cp "$CERT_SRC" "$CONF/cert.pem" && cp "$KEY_SRC" "$CONF/key.pem" || die "复制证书失败"
  chmod 644 "$CONF/cert.pem"; chmod 600 "$CONF/key.pem"
  ok "已复制你的证书到 $CONF（续期后运行 nakisctl sync-cert 即可更新）"
}

make_ech() {
  "$BIN" ech -public-name "$ECH_PUBLIC" -out "$CONF" || die "生成 ECH 密钥失败"
  chmod 600 "$CONF/ech_keys.json"
  ok "已生成 ECH 密钥（外层 SNI：$ECH_PUBLIC）"
}

render_server_json() {
  local listen=$BIND dns= first=1 d ech_json=
  if [ "$TLS_MODE" != plain ] && [ "$ECH" = 1 ]; then
    ech_json=$(cat "$CONF/ech_keys.json" 2>/dev/null) && [ -n "$ech_json" ] || { warn "读不到 ECH 密钥：$CONF/ech_keys.json"; return 1; }
  fi
  [[ "$listen" == *:* ]] && listen="[$listen]"
  listen="$listen:$PORT"
  if [ -n "$DNS" ]; then
    while IFS= read -r d; do
      if [ "$first" = 1 ]; then dns="\"$d\""; first=0; else dns="$dns, \"$d\""; fi
    done < <(tr ',' '\n' <<<"$DNS")
  fi
  {
    echo "{"
    echo "  \"listen\": \"$listen\","
    echo "  \"uuid\": \"$UUID\","
    echo "  \"dns\": [$dns],"
    echo "  \"allow_private\": $ALLOW_PRIVATE,"
    echo "  \"max_conns\": $MAX_CONNS,"
    echo "  \"keepalive\": \"$KEEPALIVE\","
    echo "  \"congestion\": \"$CONGESTION\","
    echo "  \"log_level\": \"$LOG_LEVEL\","
    echo "  \"dial_timeout\": \"$DIAL_TIMEOUT\","
    echo "  \"handshake_timeout\": \"$HANDSHAKE_TIMEOUT\","
    echo "  \"idle_timeout\": \"$IDLE_TIMEOUT\","
    echo "  \"shutdown_timeout\": \"$SHUTDOWN_TIMEOUT\","
    echo "  \"send_pack\": $SEND_PACK,"
    echo "  \"send_tail\": $SEND_TAIL,"
    echo "  \"send_quiet\": $SEND_QUIET,"
    echo "  \"merge_pack\": $MERGE_PACK,"
    echo "  \"max_queue\": $MAX_QUEUE,"
    if [ "$TLS_MODE" = plain ]; then
      echo "  \"tls\": false"
    else
      echo "  \"tls\": true,"
      echo "  \"tls_cert\": \"$CONF/cert.pem\","
      echo "  \"tls_key\": \"$CONF/key.pem\"$([ "$ECH" = 1 ] && echo ,)"
      if [ "$ECH" = 1 ]; then echo "  \"ech_keys\": $ech_json"; fi
    fi
    echo "}"
  } | write_file "$CONF/server.json" 640
}

# ---------------------------------------------------------------- 链接 ----

link_for_host() { # 地址
  local h=$1 sni=$SNI name=$NODE_NAME args=()
  local pubport=${PUBLIC_PORT:-$PORT}
  [ -n "$sni" ] || { [[ "$h" =~ ^[0-9.]+$ ]] || [[ "$h" == *:* ]] || sni=$h; }
  if [ -z "$sni" ] && [ "$ECH" = 1 ]; then sni=$ECH_PUBLIC; fi
  [ -n "$sni" ] && args+=(-sni "$sni")
  [ "$TLS_MODE" = own ] && args+=(-nopin)
  if [ "$(wc -w <<<"${HOSTS//,/ }")" -gt 1 ]; then name="$NODE_NAME $h"; fi
  "$BIN" link -s "$CONF/server.json" -host "$h" -port "$pubport" ${args[@]+"${args[@]}"} -name "$name"
}

build_links() {
  [ -f "$CONF/server.json" ] || die "还没有配置，请先运行：nakisctl install"
  local h out=
  : >"$CONF/links.txt.new"
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    out=$(link_for_host "$h") || die "生成链接失败（地址 $h）：$out"
    echo "$out" >>"$CONF/links.txt.new"
  done < <(tr ',' '\n' <<<"$HOSTS")
  mv -f "$CONF/links.txt.new" "$CONF/links.txt"
  base64 <"$CONF/links.txt" | tr -d '\n' >"$CONF/sub.txt"
  chmod 600 "$CONF/links.txt" "$CONF/sub.txt"
}

show_links() {
  load_settings
  build_links
  echo
  echo "${C_B}分享链接${C_0}（复制到客户端「从剪贴板导入」即可）："
  echo
  cat "$CONF/links.txt"
  echo
  echo "${C_B}订阅文本${C_0}（base64，多个节点；放到任意静态网址，客户端订阅它）："
  echo
  cat "$CONF/sub.txt"; echo
  echo
  echo "${C_D}文件：$CONF/links.txt（明文链接）、$CONF/sub.txt（订阅文本）${C_0}"
  echo
}

# ---------------------------------------------------------------- 向导 ----

check_cc() { # 查看系统支持的拥塞控制
  local avail=
  [ -r /proc/sys/net/ipv4/tcp_available_congestion_control ] && avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)
  printf '%s' "$avail"
}

tune_congestion() {
  [ -n "$CONGESTION" ] || return 0
  [ "$(uname -s)" = Linux ] || { warn "拥塞控制只有 Linux 支持，已忽略"; return 0; }
  local avail allowed
  avail=$(check_cc)
  if [[ " $avail " != *" $CONGESTION "* ]] && [ "$UID_NOW" = 0 ]; then
    modprobe "tcp_$CONGESTION" 2>/dev/null
    avail=$(check_cc)
  fi
  if [[ " $avail " != *" $CONGESTION "* ]]; then
    warn "系统当前不提供 $CONGESTION（可用：${avail:-未知}），服务会回退到系统默认"
    return 0
  fi
  if [ "$LAYOUT" = system ] && [ -r /proc/sys/net/ipv4/tcp_allowed_congestion_control ]; then
    allowed=$(cat /proc/sys/net/ipv4/tcp_allowed_congestion_control)
    if [[ " $allowed " != *" $CONGESTION "* ]]; then
      sysctl -w "net.ipv4.tcp_allowed_congestion_control=$allowed $CONGESTION" >/dev/null 2>&1 &&
        { echo "net.ipv4.tcp_allowed_congestion_control=$allowed $CONGESTION" >/etc/sysctl.d/99-nakis.conf; ok "已允许普通服务账号使用 $CONGESTION"; }
    fi
  fi
}

wizard() {
  local first=${1:-0} ip
  echo
  echo "${C_B}—— 基本设置 ——${C_0}（直接回车 = 使用方括号里的值；可选项输入 - 表示清空）"
  if [ -z "$HOSTS" ] && [ -z "${NAKIS_HOSTS:-}${NAKIS_HOST:-}" ]; then
    ip=$(detect_ip); HOSTS=${ip:-}
  fi
  [ -n "${NAKIS_HOST:-}" ] && [ -z "${NAKIS_HOSTS:-}" ] && NAKIS_HOSTS=$NAKIS_HOST
  prompt HOSTS "客户端连接用的地址（公网 IP 或域名，多个用逗号隔开，每个出一条链接）"
  [ -n "$HOSTS" ] || die "必须提供服务器地址（NAKIS_HOSTS=ip 或域名）"
  prompt PORT "监听端口"
  prompt NODE_NAME "节点名称（客户端里显示）"
  if [ -z "$UUID" ]; then UUID=$(new_uuid); fi
  prompt UUID "uuid（回车沿用；想换就粘贴你自己的）"

  choose TLS_MODE "传输加密方式：" \
    "self 自签证书（推荐，链接里自带证书指纹，无需域名）" \
    "own 使用你自己的证书（域名 + 受信任证书，如 Let's Encrypt）" \
    "plain 不加密（只建议内网 / 调试；明文协议可被识别）"
  if [ "$TLS_MODE" = own ]; then
    prompt CERT_SRC "证书文件路径（fullchain.pem）"
    prompt KEY_SRC "私钥文件路径"
  fi
  if [ "$TLS_MODE" != plain ]; then
    prompt ECH "是否启用 ECH（0 = 不启用，1 = 启用；把真实 SNI 加密，外层只显示一个公共名字）"
    if [ "$ECH" = 1 ]; then
      prompt ECH_PUBLIC "ECH 外层 SNI（旁观者看到的名字）"
    fi
    prompt SNI "链接里的 sni（留空 = 域名地址用它自己，IP 地址不设）" opt
  fi
  prompt PUBLIC_PORT "对外端口（和监听端口不同才填，比如做了端口转发；留空 = 同监听端口）" opt

  if interactive && [ "$ADVANCED" != 1 ]; then
    echo
    if yesno "要自定义高级参数吗（监听地址、DNS、限制、超时、合包 / 整形、拥塞控制…）？" n; then ADVANCED=1; fi
  fi
  echo
  echo "${C_B}—— 高级参数 ——${C_0}"
  prompt BIND "监听地址（0.0.0.0 = 所有 IPv4；:: = 所有地址）" "" adv
  prompt DNS "解析目标域名用的 DNS 服务器（逗号分隔，留空 = 系统默认）" opt adv
  prompt ALLOW_PRIVATE "是否允许访问内网 / 本机地址（true 有风险：别人可借你的服务器探测内网）" "" adv
  prompt MAX_CONNS "同时最多多少条隧道连接" "" adv
  prompt CONGESTION "拥塞控制算法（如 bbr，留空 = 系统默认）" opt adv
  prompt KEEPALIVE "TCP keepalive 间隔（如 15s）" "" adv
  prompt LOG_LEVEL "日志级别（debug / info / warn / error）" "" adv
  prompt DIAL_TIMEOUT "连接目标网站的超时" "" adv
  prompt HANDSHAKE_TIMEOUT "握手超时（等客户端发认证的最长时间）" "" adv
  prompt IDLE_TIMEOUT "空闲超时" "" adv
  prompt SHUTDOWN_TIMEOUT "停止服务时等待现有连接收尾的最长时间" "" adv
  prompt SEND_PACK "下行合包上限（字节）" "" adv
  prompt SEND_TAIL "合包尾部阈值（字节）" "" adv
  prompt SEND_QUIET "合包安静延长轮数" "" adv
  prompt MERGE_PACK "上行合并上限（字节）" "" adv
  prompt MAX_QUEUE "每条连接的待发队列上限（字节）" "" adv
  if [ "$SEND_TAIL" -ge "$SEND_PACK" ]; then die "send_tail 必须小于 send_pack"; fi
}

apply_config() { # 写文件 + 证书 + 重启
  mk_conf_dir
  [ -x "$BIN" ] || die "还没有安装程序，请先运行：nakisctl install"
  case "$TLS_MODE" in
    self)
      if [ ! -f "$CONF/cert.pem" ] || [ "${FORCE_CERT:-0}" = 1 ] || [ "$(cat "$CONF/cert.hosts" 2>/dev/null)" != "$HOSTS" ] || [ -f "$CONF/.own" ]; then
        make_cert; echo "$HOSTS" >"$CONF/cert.hosts"; rm -f "$CONF/.own"
      fi ;;
    own) sync_own_cert; touch "$CONF/.own" ;;
  esac
  if [ "$TLS_MODE" != plain ] && [ "$ECH" = 1 ]; then
    if [ ! -f "$CONF/ech_keys.json" ] || [ "${FORCE_ECH:-0}" = 1 ] || [ "$(cat "$CONF/ech.public" 2>/dev/null)" != "$ECH_PUBLIC" ]; then
      make_ech; echo "$ECH_PUBLIC" >"$CONF/ech.public"
    fi
  fi
  save_settings || die "保存设置失败"
  render_server_json || die "写入 server.json 失败"
  ( build_links ) >/dev/null 2>&1 ||
    warn "配置文件已写入，但生成链接没通过校验（多半是 sni / 证书设置不匹配），请用 nakisctl link 查看详情"
  tune_congestion
}

# ---------------------------------------------------------------- 运行 ----

SVC_USER=
prepare_service_user() {
  SVC_USER=
  [ "$LAYOUT" = system ] || return 0
  if ! id nakis >/dev/null 2>&1; then
    local nologin=/usr/sbin/nologin; [ -x "$nologin" ] || nologin=/sbin/nologin; [ -x "$nologin" ] || nologin=/bin/false
    useradd --system --no-create-home --shell "$nologin" nakis >/dev/null 2>&1 || return 0
  fi
  local f
  if chgrp -R nakis "$CONF" 2>/dev/null && chmod 750 "$CONF"; then
    for f in "$CONF"/server.json "$CONF"/cert.pem "$CONF"/key.pem; do
      [ -f "$f" ] && chmod 640 "$f"
    done
    SVC_USER=nakis
  fi
}

log_file() { printf '%s/server.log' "$STATE"; }
pid_file() { printf '%s/server.pid' "$STATE"; }

proc_is() { # pid 命令行里必须出现的片段（防止 pid 被别的进程复用后误杀）
  local pid=$1 want=$2 cmd=
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  if [ -r "/proc/$pid/cmdline" ]; then cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)
  else cmd=$(ps -p "$pid" -o args= 2>/dev/null); fi
  [[ "$cmd" == *"$want"* ]]
}

bg_alive() {
  proc_is "$(cat "$(pid_file)" 2>/dev/null)" "$STATE/server.run"
}

stop_pid() {
  local pid=$1 want=$2 tries=$3 i
  proc_is "$pid" "$want" || return 0
  kill "$pid" 2>/dev/null
  for i in $(seq 1 "$tries"); do proc_is "$pid" "$want" || return 0; sleep 0.5; done
  proc_is "$pid" "$want" && kill -9 "$pid" 2>/dev/null
  return 0
}

bg_stop() {
  local pf cf pid child
  pf=$(pid_file); cf="$STATE/server.child"
  pid=$(cat "$pf" 2>/dev/null); child=$(cat "$cf" 2>/dev/null)
  stop_pid "$pid" "$STATE/server.run" 16
  stop_pid "$child" "$BIN" 4
  rm -f "$pf" "$cf"
}

bg_start() {
  local run log
  run=$STATE/server.run; log=$(log_file)
  mkdir -p "$STATE"
  bg_stop
  if [ -f "$log" ] && [ "$(wc -c <"$log" 2>/dev/null || echo 0)" -gt 5242880 ]; then tail -c 1048576 "$log" >"$log.tmp" && mv "$log.tmp" "$log"; fi
  cat >"$run" <<EOF
#!/usr/bin/env bash
echo \$\$ > "$(pid_file)"
child=
trap 'kill \$child 2>/dev/null; wait \$child 2>/dev/null; exit 0' TERM INT HUP
while :; do
  "$BIN" server -c "$CONF/server.json" >>"$log" 2>&1 &
  child=\$!
  echo \$child > "$STATE/server.child"
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

has_unit() { use_systemd && [ -f "$UNIT_FILE" ]; }

svc_stop() {
  if has_unit; then systemctl stop "$UNIT" >/dev/null 2>&1; fi
  bg_stop
}

svc_start() {
  [ -f "$CONF/server.json" ] || die "还没有配置，请先运行：nakisctl install"
  if use_systemd; then
    bg_stop
    prepare_service_user
    {
      echo "[Unit]"
      echo "Description=nakis server"
      echo "After=network-online.target"
      echo "Wants=network-online.target"
      echo
      echo "[Service]"
      [ -n "$SVC_USER" ] && echo "User=$SVC_USER"
      echo "ExecStart=$BIN server -c $CONF/server.json"
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
    } | write_file "$UNIT_FILE" 644
    systemctl daemon-reload || die "systemctl daemon-reload 失败"
    systemctl enable "$UNIT" >/dev/null 2>&1
    systemctl restart "$UNIT" || die "启动服务失败，请运行：journalctl -u $UNIT -n 50 --no-pager"
    ok "已作为 systemd 服务运行：$UNIT（开机自启、崩溃自动重启）"
  else
    bg_start
    ok "已在后台运行（带自动重启的守护循环）；日志：$(log_file)"
    if [ "$IS_TERMUX" = 1 ]; then
      warn "Termux 提示：请把 Termux 的电池优化设为「不限制」；开机自启需要安装 Termux:Boot"
    fi
  fi
}

server_alive() {
  if has_unit; then systemctl is-active --quiet "$UNIT"; else bg_alive; fi
}

show_log() {
  local n=${1:-40}
  if has_unit; then journalctl -u "$UNIT" -n "$n" --no-pager 2>/dev/null
  elif [ -f "$(log_file)" ]; then tail -n "$n" "$(log_file)"
  else echo "（还没有日志）"; fi
}

follow_log() {
  if has_unit; then journalctl -u "$UNIT" -f
  elif [ -f "$(log_file)" ]; then tail -n 40 -f "$(log_file)"
  else echo "（还没有日志）"; fi
}

server_sig() {
  if has_unit; then systemctl show -p MainPID --value "$UNIT" 2>/dev/null
  else cat "$STATE/server.child" 2>/dev/null; fi
}

wait_listening() {
  local i s1 s2
  for i in $(seq 1 24); do
    if server_alive && listening; then
      s1=$(server_sig); sleep 1; s2=$(server_sig)
      if [ "$s1" = "$s2" ] && server_alive && listening; then return 0; fi
    else
      sleep 0.5
    fi
  done
  return 1
}

open_firewall() {
  local port=$1
  [ "$LAYOUT" = system ] || return 0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$port"/tcp >/dev/null 2>&1 && ok "已在 ufw 放行 $port/tcp"
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 && ok "已在 firewalld 放行 $port/tcp"
  fi
}

restart_and_report() {
  svc_start
  if wait_listening; then
    ok "服务已在端口 $PORT 上监听"
  else
    warn "服务没有在 $PORT 上监听，最近日志："
    show_log 20
    die "启动失败，请根据日志修正后运行 nakisctl config / restart"
  fi
}

# ---------------------------------------------------------------- 流程 ----

is_installed() { [ -x "$BIN" ] && [ -f "$CONF/server.json" ] && [ -f "$SETTINGS" ]; }

check_port_free() {
  if port_in_use "$PORT" && ! server_alive; then
    warn "端口 $PORT 已被别的程序占用"
    if interactive; then prompt PORT "换一个监听端口"; fi
  fi
}

do_install() {
  ensure_tools
  ensure_go
  mk_conf_dir
  fetch_source
  build_binary
  install_self
  load_settings
  wizard 1
  check_port_free
  apply_config
  open_firewall "$PORT"
  restart_and_report
  show_links
  echo "管理命令：$([ -x "$CTL" ] && echo "$CTL" || echo "bash nakis-install.sh")  （菜单 / status / logs / config / update / uninstall）"
}

do_config() {
  is_installed || die "还没有安装，请先运行：nakisctl install"
  load_settings
  wizard 0
  check_port_free
  apply_config
  open_firewall "$PORT"
  restart_and_report
  show_links
}

do_update() {
  is_installed || die "还没有安装，请先运行：nakisctl install"
  ensure_tools; ensure_go; fetch_source; build_binary
  install_self fresh || true
  load_settings
  apply_config
  restart_and_report
}

do_uuid() {
  is_installed || die "还没有安装"
  load_settings
  UUID=$(new_uuid)
  apply_config; restart_and_report; show_links
}

do_cert() {
  is_installed || die "还没有安装"
  load_settings
  [ "$TLS_MODE" = self ] || die "只有自签证书模式才需要重新生成（当前模式：$TLS_MODE）"
  FORCE_CERT=1 apply_config; restart_and_report; show_links
}

do_ech() {
  is_installed || die "还没有安装"
  load_settings
  [ "$ECH" = 1 ] || die "还没有启用 ECH，请先运行 nakisctl config"
  FORCE_ECH=1 apply_config; restart_and_report; show_links
}

do_sync_cert() {
  is_installed || die "还没有安装"
  load_settings
  [ "$TLS_MODE" = own ] || die "只有「自己的证书」模式需要同步（当前模式：$TLS_MODE）"
  apply_config; restart_and_report
}

do_check() {
  load_settings
  echo "系统：$(uname -sm)  布局：$LAYOUT  systemd：$(use_systemd && echo 是 || echo 否)"
  [ -x "$BIN" ] && echo "程序：$BIN（$("$BIN" version 2>/dev/null)）" || echo "程序：未安装"
  echo "监听端口 $PORT：$(listening && echo 正在监听 || echo 未监听)"
  local ip; ip=$(detect_ip); echo "公网 IPv4：${ip:-取不到}"
  if [ -n "$HOSTS" ] && [ -n "$ip" ] && [[ "$HOSTS" =~ ^[0-9.,]+$ ]] && [[ ",$HOSTS," != *",$ip,"* ]]; then
    warn "配置里的地址（$HOSTS）和本机公网 IP（$ip）不一致，如果不是 NAT / 转发请用 nakisctl config 修改"
  fi
  local avail; avail=$(check_cc)
  echo "可用拥塞控制：${avail:-未知}（当前设置：${CONGESTION:-系统默认}）"
  if [[ " $avail " != *" bbr "* ]]; then echo "  提示：本机没有加载 bbr，想用的话先运行：modprobe tcp_bbr"; fi
  if command -v ufw >/dev/null 2>&1; then echo "ufw：$(ufw status 2>/dev/null | head -n1)"; fi
  if command -v firewall-cmd >/dev/null 2>&1; then echo "firewalld：$(firewall-cmd --state 2>/dev/null)"; fi
  echo "云厂商的安全组 / 防火墙需要你自己在控制台放行 TCP $PORT"
}

do_status() {
  is_installed || { echo "未安装"; return 0; }
  load_settings
  if server_alive; then ok "服务运行中"; else warn "服务没有运行"; fi
  echo "  程序版本：$("$BIN" version 2>/dev/null)"
  echo "  监听：$BIND:$PORT（本机 $(listening && echo 可连接 || echo 连不上)）"
  echo "  加密：$TLS_MODE，ECH：$([ "$ECH" = 1 ] && echo "开（$ECH_PUBLIC）" || echo 关)"
  echo "  地址：$HOSTS    节点名：$NODE_NAME"
  echo "  uuid：${UUID:0:8}…"
  echo "  配置目录：$CONF"
  echo
  show_log 8
}

do_uninstall() {
  if [ "${1:-}" != -y ] && ! yesno "确定卸载 nakis 服务端并删除全部配置吗？" n; then echo "已取消（无人值守卸载请加 -y）"; return 0; fi
  svc_stop
  if has_unit; then
    systemctl disable "$UNIT" >/dev/null 2>&1
    rm -f "$UNIT_FILE"; systemctl daemon-reload >/dev/null 2>&1
  fi
  rm -f /etc/sysctl.d/99-nakis.conf 2>/dev/null
  rm -rf "$CONF" "$STATE"
  rm -f "$BIN" "$CTL"
  [ "$LAYOUT" = system ] && id nakis >/dev/null 2>&1 && userdel nakis >/dev/null 2>&1
  [ "$LAYOUT" = user ] && [ -n "$BASE" ] && rmdir "$BIN_DIR" "$BASE" 2>/dev/null
  ok "已卸载（Go 工具链保留在 $GO_ROOT，不需要可手动删除）"
}

menu() {
  have_tty || die "没有可交互的终端，请直接用命令（nakisctl help）"
  local pick
  while :; do
    echo
    echo "${C_B}nakis 服务端管理${C_0}"
    echo "  1) 查看分享链接 / 订阅"
    echo "  2) 修改配置"
    echo "  3) 启动   4) 停止   5) 重启"
    echo "  6) 状态   7) 日志"
    echo "  8) 更新到最新版"
    echo "  9) 重新生成 uuid   10) 重新生成证书   11) 重新生成 ECH 密钥"
    echo "  12) 体检   13) 卸载   0) 退出"
    read -r -p "请选择: " pick </dev/tty || exit 0
    case "$pick" in
      1) show_links; pause ;;
      2) do_config; pause ;;
      3) load_settings; svc_start; pause ;;
      4) svc_stop; ok "已停止"; pause ;;
      5) load_settings; svc_start; pause ;;
      6) do_status; pause ;;
      7) show_log 60; pause ;;
      8) do_update; pause ;;
      9) yesno "重新生成后所有旧链接立刻失效，继续吗？" n && do_uuid; pause ;;
      10) yesno "重新生成后旧链接里的指纹失效，继续吗？" n && do_cert; pause ;;
      11) yesno "重新生成后旧链接里的 ECH 配置失效，继续吗？" n && do_ech; pause ;;
      12) do_check; pause ;;
      13) do_uninstall; pause ;;
      0|q|"") exit 0 ;;
      *) warn "请输入菜单里的编号" ;;
    esac
  done
}

usage() {
  sed -n '3,24p' "$SELF" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

main() {
  local cmd=${1:-}
  [ $# -gt 0 ] && shift
  case "$cmd" in
    "")        if is_installed; then menu; else do_install; fi ;;
    install)   do_install ;;
    config)    do_config ;;
    link|links|sub) show_links ;;
    start)     is_installed || die "还没有安装"; load_settings; svc_start ;;
    stop)      svc_stop; ok "已停止" ;;
    restart)   is_installed || die "还没有安装"; load_settings; svc_start ;;
    status)    do_status ;;
    logs)      if [ "${1:-}" = -f ]; then follow_log; else show_log 80; fi ;;
    update)    do_update ;;
    uuid)      do_uuid ;;
    cert)      do_cert ;;
    ech)       do_ech ;;
    sync-cert) do_sync_cert ;;
    check)     do_check ;;
    uninstall) do_uninstall "${1:-}" ;;
    menu)      menu ;;
    help|-h|--help) usage ;;
    *)         usage; exit 2 ;;
  esac
}

main "$@"
