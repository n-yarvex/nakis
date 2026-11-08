# nakis 配置文档


## 目录

1. [五分钟跑起来](#1-五分钟跑起来)
2. [命令行](#2-命令行)
3. [配置文件通用规则](#3-配置文件通用规则)
4. [client.json 全部字段](#4-clientjson-全部字段)
5. [server.json 全部字段](#5-serverjson-全部字段)
6. [完整配置示例](#6-完整配置示例)
7. [常见场景怎么配](#7-常见场景怎么配)
8. [证书、指纹与 ECH 怎么用](#8-证书指纹与-ech-怎么用)
9. [前几个包整形 `shape_up` 要不要用](#9-前几个包整形-shape_up-要不要用)
10. [日志怎么看](#10-日志怎么看)
11. [部署与运维](#11-部署与运维)
12. [注意事项与常见坑](#12-注意事项与常见坑)
13. [排错速查表](#13-排错速查表)

---

## 1. 五分钟跑起来

需要 Go 1.24 或更新版本（只在编译时需要，编译好的程序是单个静态文件）。

**第一步：编译**

```sh
make build            # 产物在 bin/nakis
# 或者一次编出四个平台：make release   (linux amd64/arm64, macOS arm64, windows amd64)
```

**第二步：在服务器上准备证书和 uuid**

```sh
uuid=$(cat /proc/sys/kernel/random/uuid)     # 两端共用的密钥，自己留好
bin/nakis cert -name 你的服务器IP或域名 -out /etc/nakis
```

`nakis cert` 会写出 `cert.pem` / `key.pem`，并打印一个 **pin（公钥指纹）**，下一步要用。

**第三步：写两个最小配置**

服务器 `/etc/nakis/server.json`：

```json
{
  "uuid": "<上面的 uuid>",
  "tls_cert": "/etc/nakis/cert.pem",
  "tls_key": "/etc/nakis/key.pem"
}
```

本机 `client.json`：

```json
{
  "server": "你的服务器IP:8443",
  "uuid": "<同一个 uuid>",
  "sni": "example.com",
  "tls_pins": ["<nakis cert 打印的 pin>"]
}
```

**第四步：启动**

```sh
bin/nakis server -c /etc/nakis/server.json     # 服务器
bin/nakis client -c client.json                # 本机，SOCKS5 在 127.0.0.1:1080
```

浏览器或系统里把 SOCKS5 代理设成 `127.0.0.1:1080`（选 SOCKS5，并勾选「通过代理解析域名 / remote DNS」）。想快速自测：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

## 2. 命令行

```
nakis client  -c client.json [-v]        运行本地 SOCKS5 客户端
nakis server  -c server.json [-v]        运行隧道服务端
nakis cert    -name 主机[,主机...] [-out 目录]   生成自签证书，并打印客户端要填的 pin
nakis ech     -public-name 主机 [-id N]      生成一对 ECH 密钥，并打印两端的配置片段
nakis version
```

| 参数 | 说明 |
|---|---|
| `-c` | 配置文件路径。不写时 client 默认 `/etc/nakis/client.json`，server 默认 `/etc/nakis/server.json` |
| `-v` | 强制开启 debug 日志（压过配置里的 `log_level`） |
| `cert -name` | 证书里的名字，可以是域名或 IP，多个用逗号分隔（IP 会写进 IP SAN，域名写进 DNS SAN）；证书有效期 10 年，ECDSA P-256 |
| `cert -out` | 输出目录，默认当前目录；`key.pem` 权限为 0600 |
| `ech -public-name` | 外层 SNI，路径上的观察者看到的名字 |
| `ech -id` | ECH 配置编号 0–255，默认 1；轮换密钥时请换一个新的编号 |

程序收到 `SIGINT` / `SIGTERM` 会优雅退出：不再接新连接，给进行中的会话收尾（服务端最长 `shutdown_timeout`，客户端 5 秒）。

## 3. 配置文件通用规则

- **纯 JSON**，一端一个文件：客户端用 `client.json`，服务端用 `server.json`。不支持注释（JSON 本身不允许）。
- **不认识的键会直接报错**并拒绝启动——拼错字母在启动时就会被发现，不会悄悄失效。
- **没写的键用默认值**，下面的表格里都标了。
- **时间**写成字符串：`"500ms"`、`"5s"`、`"2m"`、`"1h"`。写成数字会报错。
- **超出范围的数字会被自动拉回最近的合法值**（不报错），具体范围见各字段。
- **时间字段写成 0 或负数**会被换成内置值（不是默认值！）：`dial_timeout` → 8 s（服务端 5 s）、`handshake_timeout` → 10 s、`keepalive` → 15 s、`shape_wait` → 20 ms、服务端 `idle_timeout` → 120 s、`shutdown_timeout` → 20 s、客户端 `pool_max_age` → **15 s**（注意它的默认值是 45 s）。
- **监听地址**写 `主机:端口`；`:1080` 表示所有网卡；IPv6 写 `[::1]:1080`。
- **UUID**：32 个十六进制字符，横线随意（`550e8400-e29b-41d4-a716-446655440000` 与去掉横线的写法等价），大小写不限。两端必须相同。

> 以下三件事**没有开关，永远开着**：**预连接**（热连接池）、**连接复用**、**IPv4/IPv6 双栈交错拨号**。这些是协议性能的根基，关掉只会变慢。
> 仍然保留的三个布尔值是：`tls`（要用明文模式就得有它）、`allow_private`（默认关才安全）、`ech_keys[].retry`（轮换密钥时要用）。

## 4. client.json 全部字段

### 4.1 基本

| 字段 | 默认值 | 取值 / 范围 | 说明 |
|---|---|---|---|
| `listen` | `127.0.0.1:1080` | `主机:端口` | 本地 SOCKS5 监听地址。**没有认证**，请只监听本机；改成 `0.0.0.0` 等于对整个网络开放一个无密码代理 |
| `server` | **必填** | `主机:端口`，多个用逗号 | 服务端地址。写域名会被解析出所有 IP（IPv4/IPv6 交错），写多个地址时需要赛跑（见 `race_count`） |
| `uuid` | **必填** | 32 位十六进制 | 共享密钥，两端一致 |

### 4.2 连接池与复用（性能的核心）

| 字段 | 默认值 | 范围 | 说明 |
|---|---|---|---|
| `pool_lo` | `2` | 1–1024 | **始终保持**的热隧道数。有了它，新的会话几乎不用等握手。流量大的设备可以调高（如 4–8） |
| `pool_hi` | `32` | `pool_lo`+1 – 4096 | 高负载时热隧道的上限，也是池里最多闲置多少条。程序会根据命中率在这个数附近自己调节 |
| `pool_max_age` | `45s` | >0 | 闲置隧道超过这个时间会被退役。**必须比服务端 `idle_timeout` 小**，否则池里会放着已经被服务端关掉的连接（客户端会自己发现并丢弃，但浪费一次探测） |
| `pool_max_uses` | `8` | 0–100，0 = 不限 | 一条隧道最多承载几个会话。数字越小，每条隧道的「寿命」越短、越不容易被按连接统计限速，但握手更多。被限速时程序会自动把它压到 1–2 |
| `race_count` | `3` | 2–12 | 池里没有可用隧道时，**同时尝试**的最多地址数（前两个立即开始，之后每个多等 50 ms）。程序会按实际命中情况，在「慢档 3 / 你的设置 / 快档 10」之间自行调节；只有一个服务端地址（一个 IP）时没有影响 |

### 4.3 超时与链路

| 字段 | 默认值 | 说明 |
|---|---|---|
| `dial_timeout` | `8s` | 建立 TCP 连接的超时 |
| `handshake_timeout` | `10s` | TLS 握手以及 SOCKS5 握手的超时 |
| `keepalive` | `15s` | TCP 保活间隔，让 NAT/防火墙记得住池里闲置的隧道。NAT 很激进的网络把它和 `pool_max_age` 一起调短 |
| `congestion` | 空 | TCP 拥塞控制算法名，如 `"bbr"`。**仅 Linux 支持**，且需要内核已加载对应模块；失败只会打一条警告并继续用系统默认值。高延迟、有丢包的长距离链路值得一试 |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` |

### 4.4 发送调度（小包合并）

| 字段 | 默认值 | 范围 | 说明 |
|---|---|---|---|
| `send_pack` | `20480` | 1024–65533 | 上行方向一个帧的**目标大小**（字节）。合并到这么大就直接发 |
| `send_tail` | `512` | 0 – `send_pack`−1 | 离装满只差这么多字节时不再等，直接发 |
| `send_quiet` | `4` | 0–64（毫秒） | 合并等待的**上限**。只要还有新数据紧跟着到来，最多持续合并这么久；空闲时的第一个小包不会等（立即发出），所以交互延迟不受它影响 |

一般不用动。聊天、SSH 这类以交互为主的流量可以把 `send_quiet` 调到 `1`–`2`；大文件下载保持默认。

### 4.5 流量整形

| 字段 | 默认值 | 说明 |
|---|---|---|
| `shape_up` | 空（关） | 最多 8 组 `[最小, 最大]`，手动指定**上行前几个包**的大小，要求 `1 ≤ 最小 ≤ 最大 ≤ 16382`。**留空时使用自动随机画像**（推荐，见第 9 节） |
| `shape_wait` | `20ms` | 设置了 `shape_up` 之后，一个包凑不够最小值时最多等多久，超时就按现有数据发（不填充） |

### 4.6 TLS / ECH

| 字段 | 默认值 | 说明 |
|---|---|---|
| `tls` | `true` | `false` = 明文 TCP，**必须与服务端一致**。明文模式没有加密，仅用于内网或外层已有加密隧道的场景；此时 `sni`、`tls_pins`、`ech_config` 都不能设置（会报错） |
| `sni` | 空 | 服务器名。不用 pin 时必填（用来校验证书域名）；用 ECH 时也必填（它是藏在加密握手里的真实名字） |
| `tls_pins` | 空 | 服务端**公钥**的 SHA-256（64 位十六进制，可带冒号）。设置后用它**代替**系统 CA 校验（不再检查证书有效期、域名、签发链）。可以写多个，用于证书轮换。`nakis cert` 会打印 |
| `ech_config` | 空 | `nakis ech` 打印出的 base64 配置。开启后 TLS 最低版本固定为 1.3，并且必须设置 `sni` |

**TLS 的校验方式二选一**：`tls_pins`（自签证书、最省事）或不写 pin 而写 `sni`（服务端用 CA 签发的证书，客户端按系统根证书和 `sni` 校验）。两者都不写会报错。

## 5. server.json 全部字段

### 5.1 基本

| 字段 | 默认值 | 说明 |
|---|---|---|
| `listen` | `0.0.0.0:8443` | 监听地址。绑定 443 以下端口需要权限（见第 11 节的 systemd 例子） |
| `uuid` | **必填** | 共享密钥 |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` |

### 5.2 出站（连接目标）

| 字段 | 默认值 | 说明 |
|---|---|---|
| `dns` | 空 | 解析目标域名时使用的 DNS 服务器，`"1.1.1.1"` 或 `"8.8.8.8:53"`，可写多个（按顺序尝试）；空则用系统解析器。答案缓存 60 秒，同一个域名的并发解析会合并，上游挂了会暂时继续使用旧答案 |
| `allow_private` | `false` | 是否允许代理访问**回环、私网、链路本地（含云厂商元数据地址 169.254.169.254）、组播**地址。默认关闭：这样即使 uuid 泄露，别人也没法拿你的服务器去戳它所在的内网。真要代理内网请设为 `true` |
| `dial_timeout` | `5s` | 连接目标的超时 |
| `congestion` | 空 | 作用在服务器连向目标的连接和监听口上，同客户端 |
| `keepalive` | `15s` | TCP 保活间隔 |

目标域名解析出多个地址时，服务端会 IPv4 / IPv6 交错、最多取 4 个、每隔 120 ms 错峰尝试，先连上的获胜。

### 5.3 容量与超时

| 字段 | 默认值 | 范围 | 说明 |
|---|---|---|---|
| `max_conns` | `4096` | 1 – 1048576 | 同时处理的连接数上限（含还没完成认证的）。超过的新连接会被直接关闭。**别设太小**，否则探测者占满槽位后真正的用户进不来 |
| `idle_timeout` | `2m` | >0 | 隧道在两个会话之间最多空闲多久；也是新连接发来第一个帧的最长等待时间。调小可以更快腾出被慢连接占用的槽位，但要大于客户端的 `pool_max_age` |
| `handshake_timeout` | `10s` | >0 | TLS 握手的超时 |
| `shutdown_timeout` | `20s` | >0 | 收到退出信号后，给进行中的会话多长时间收尾，超时强制关闭 |

### 5.4 发送与队列

| 字段 | 默认值 | 范围 | 说明 |
|---|---|---|---|
| `send_pack` | `32768` | 1024–65533 | 下行帧目标大小 |
| `send_tail` | `512` | 0 – `send_pack`−1 | 同客户端 |
| `send_quiet` | `4` | 0–64（毫秒） | 同客户端 |
| `merge_pack` | `20480` | 1024–65534 | 隧道里收到的上行小帧，会合并成至多这么大的一次写入再发给目标 |
| `max_queue` | `4194304`（4 MiB） | 64 KiB – 256 MiB | **每个会话**排队等写给目标的字节数上限。超过就暂停读取隧道，TCP 反压会让客户端自然变慢。它限定了每个会话的内存占用：服务器小、用户多的时候调低一点 |

### 5.5 TLS / ECH

| 字段 | 默认值 | 说明 |
|---|---|---|
| `tls` | `true` | `false` = 明文 TCP（必须与客户端一致）。此时不能设置 `ech_keys` |
| `tls_cert`、`tls_key` | 空 | PEM 文件路径，开 TLS 时**必填**。可以用 `nakis cert` 生成，也可以用 CA 签发的证书（链放进 `cert.pem`） |
| `ech_keys` | 空 | `{config, key, retry}` 的列表，由 `nakis ech` 生成。可配置多个：**轮换密钥时把旧的保留、加上新的**，旧客户端不会掉线。`retry: true` 表示把这条配置作为「重试配置」下发给持有旧配置的客户端 |

服务端 TLS **最低版本固定为 1.3**，ALPN 只回应 `http/1.1`。

## 6. 完整配置示例

下面两份就是发布包里的 `client.json` 和 `server.json`，**每个字段都写出来了**，可以直接复制后按需删减。

> ⚠️ **ECH 配置与 pin 是互相配套的一次性样本，只用来演示格式**，请务必用 `nakis cert`、`nakis ech` 生成你自己的，并且 uuid 也要换。
> ⚠️ 示例里 `shape_up` 是填满的，用来展示格式。**如果你想用推荐的自动随机画像，请把它改成 `[]` 或整个删掉。**

### client.json

```json
{
  "listen": "127.0.0.1:1080",
  "server": "203.0.113.10:8443",
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "race_count": 3,
  "pool_lo": 2,
  "pool_hi": 32,
  "pool_max_age": "45s",
  "pool_max_uses": 8,

  "dial_timeout": "8s",
  "handshake_timeout": "10s",
  "keepalive": "15s",
  "congestion": "bbr",
  "log_level": "info",

  "send_pack": 20480,
  "send_tail": 512,
  "send_quiet": 4,
  "shape_up": [
    [300, 520],
    [80, 120],
    [900, 1400],
    [200, 200],
    [1200, 2000],
    [64, 128],
    [500, 800],
    [1400, 1400]
  ],
  "shape_wait": "20ms",

  "tls": true,
  "sni": "example.com",
  "tls_pins": ["800a9556c36686a89f819d7b68d3902695f9e6f788c6793ba6dd8cd11f1a1eb4"],
  "ech_config": "AEj+DQBEBwAgACC2+1s4ES5mJftnFXI72piDDxztMZARRwZ5rwI40K1sDQAIAAEAAQABAANAEWZyb250LmV4YW1wbGUubmV0AAA="
}
```

### server.json

```json
{
  "listen": "0.0.0.0:8443",
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "dns": ["1.1.1.1", "8.8.8.8:53"],
  "allow_private": false,
  "max_conns": 4096,
  "keepalive": "15s",
  "congestion": "bbr",
  "log_level": "info",

  "dial_timeout": "5s",
  "handshake_timeout": "10s",
  "idle_timeout": "2m",
  "shutdown_timeout": "20s",

  "send_pack": 32768,
  "send_tail": 512,
  "send_quiet": 4,
  "merge_pack": 20480,
  "max_queue": 4194304,

  "tls": true,
  "tls_cert": "/etc/nakis/cert.pem",
  "tls_key": "/etc/nakis/key.pem",
  "ech_keys": [
    {
      "config": "/g0ARAcAIAAgtvtbOBEuZiX7ZxVyO9qYgw8c7TGQEUcGea8CONCtbA0ACAABAAEAAQADQBFmcm9udC5leGFtcGxlLm5ldAAA",
      "key": "R6NrBmkS0kPHmY/1d4VyuaJGLU+LoRuVlAXZi3T9DHg=",
      "retry": true
    }
  ]
}
```

## 7. 常见场景怎么配

**① 最省事：自签证书 + 指纹固定（推荐起步）**
服务端 `tls_cert`/`tls_key`（`nakis cert` 生成），客户端 `sni` + `tls_pins`。这就是第 1 节的配置。

**② 有域名和正规证书**
服务端用 CA 签发的证书；客户端不写 `tls_pins`，写 `sni`（你的域名）。校验走系统根证书。证书续期不需要动客户端。

**③ 想让握手更不显眼：加 ECH**
`nakis ech -public-name 一个常见的大站域名`，把打印出的片段分别贴进两边的配置。客户端 `sni` 仍然填你的真实域名。详见第 8 节。

**④ 内网 / 外层已有加密：明文模式**
两端都设 `"tls": false`，并删掉 `sni`/`tls_pins`/`ech_config`（服务端删掉 `tls_cert`/`tls_key`/`ech_keys`）。**没有加密也没有服务端身份验证**，路径上的人能看到所有内容。

**⑤ 多台服务器（高可用 / 就近）**
`"server": "a.example.com:8443,b.example.com:8443"`。客户端会把所有地址的 IP 汇总，按历史握手延迟排序，同时尝试前 `race_count` 个，谁快用谁；落选的连接不浪费，会放进池里备用。

**⑥ 高延迟、有丢包的长链路**
两端都设 `"congestion": "bbr"`（Linux），客户端把 `pool_lo` 提高到 4 左右，让热隧道多一点。

**⑦ 小内存 VPS、很多用户**
服务端调低 `max_queue`（如 `1048576`）和 `max_conns`；`send_pack` 保持默认。

**⑧ 主要跑交互流量（SSH、聊天）**
两端 `send_quiet` 设 `1`。

**⑨ 前面有 NAT 会超时掐连接**
`keepalive` 和 `pool_max_age` 一起调短（如 `10s` / `30s`），并保持 `pool_max_age < idle_timeout`。

## 8. 证书、指纹与 ECH 怎么用

### 8.1 自签证书 + pin

```sh
nakis cert -name 203.0.113.10 -out /etc/nakis
# 输出：
#   server.json:  "tls_cert": "/etc/nakis/cert.pem", "tls_key": "/etc/nakis/key.pem"
#   client.json:  "tls_pins": ["800a95…"]
```

`-name` 可以写多个（逗号分隔），域名和 IP 都行。**换了证书（重新生成）后，所有客户端的 `tls_pins` 都要同步更新**；平滑过渡的办法是客户端 `tls_pins` 里同时写新旧两个 pin。

### 8.2 ECH

```sh
nakis ech -public-name front.example.net
# 输出两段：
#   server.json:  "ech_keys": [ { "config": "...", "key": "...", "retry": true } ]
#   client.json:  "ech_config": "..."
```

- **`public-name`** 是路径上的观察者会看到的外层 SNI，应该选一个「看起来自然」的名字，并且最好和服务器 IP 的归属相称——一台孤零零的服务器配一个编出来的外层名字依旧显眼。
- 客户端 `sni` 填你**真实**的服务器名（它会藏在加密的内层里）。
- ECH 需要 TLS 1.3；客户端开启后会把最低版本设为 1.3。
- **轮换**：再运行一次 `nakis ech -public-name … -id 2`（换个 id），把新的 `ech_keys` 条目**追加**到服务端列表里；等所有客户端都换成新的 `ech_config` 后再删掉旧条目。
- 客户端目前**不会**自动采用服务端下发的 retry 配置：配置失配时握手会失败，请手动更新 `ech_config`。

## 9. 前几个包整形 `shape_up` 要不要用

**默认不用（留空）。** 不设置时，nakis 会为**每一个新会话、每一个方向**随机抽取前 2–5 个包的大小（对数均匀分布，从几十字节到几 KB，上行首包保证放得下认证和请求），并用随机填充补足，让每条隧道的开头都长得不一样；服务端下行同理。被判断为遭到限速时（见 README 的「自适应对抗」），包数会增加、范围会变宽。

只有当你**确切知道**要模仿某种固定的包长序列时才设置 `shape_up`：

- 第 *i* 个包会不断合并应用写来的数据，直到至少有 `最小[i]` 字节，然后最多发 `最大[i]` 字节，多出来的留给下一个包。
- **不会做任何填充**：应用在 `shape_wait` 内凑不够最小值，短包照发。想要严格就调大 `shape_wait`（代价是慢热的连接要多等一会儿）。
- 第一组的下限实际不会低于认证 + 请求的长度（约 70–100 字节）。
- 走 TLS 时一个包正好是一条记录，记录体 = 载荷 + 19 字节（TLS 1.3：2 字节帧头 + 1 字节内部类型 + 16 字节认证标签）。
- 设置后，**上行的自动画像让位给你的设置**；服务端下行仍用自动画像。
- 前几个包之后恢复正常合并。每个新会话都重新走一遍，复用的隧道也一样。

## 10. 日志怎么看

日志是 **JSON 行**，输出在标准错误，例如：

```json
{"time":"2026-11-08T00:01:04.45+08:00","level":"INFO","msg":"listening for tunnels","addr":"127.0.0.1:18443"}
```

用 `journalctl -u nakis -o cat | jq .` 之类的工具查看。关键日志（人话）举例：

| 级别 | 内容（节选） | 含义 |
|---|---|---|
| INFO | `first tunnel to the server is up` | 客户端第一条隧道建好 |
| INFO | `tunnels to the server are working again` | 失败后恢复 |
| WARN | `couldn't open a tunnel to the server (N failed in a row), will keep retrying with a growing pause` | 连不上服务器，退避重试 |
| WARN | `the server hung up on a tunnel without answering. Usually that means a wrong uuid, or clocks more than 30s apart` | 认证没通过，检查 uuid 和两端时间 |
| WARN | `the server wouldn't connect to <目标>` | 服务端连不上目标（或被私网规则拒绝） |
| WARN | `a download slowed from about X to Y after roughly Z went through one tunnel; that looks like per-flow throttling. From now on I'll retire tunnels after … (alert level N)` | 检测到疑似单流限速，已经提高警戒档位 |
| INFO | `it's been quiet for a while, relaxing the alert level to N` | 10 分钟没再触发，放松一档 |
| WARN | `N tunnel attempts in a row failed. That's either a flaky link or something cutting the connections…` | 连续握手失败，可能是网络差也可能有东西在掐连接 |
| WARN（服务端） | `a client's clock is Xs away from mine; the allowed gap is 30s` | 客户端时钟偏差过大 |
| WARN（服务端） | `turned away N connection(s) in the last minute that didn't present a valid proof…` | 有人（可能是探测、也可能是你自己配错）没通过认证 |
| WARN（服务端） | `already at the limit of N connections, dropping new ones…` | 达到 `max_conns` |
| WARN | `couldn't switch the congestion control, carrying on with the system default` | 拥塞算法设置失败（非 Linux 或内核没有该算法） |

`debug` 级别还会记录每个会话的目标地址、认证被拒的来源和原因等，排错时用 `-v` 临时打开，**平时不建议常开**（会留下你访问了什么的记录）。

## 11. 部署与运维

**systemd（服务端）**

```ini
[Unit]
Description=nakis server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/nakis server -c /etc/nakis/server.json
Restart=always
DynamicUser=yes
ConfigurationDirectory=nakis
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

客户端同理，把 `server` 换成 `client`，并去掉 `AmbientCapabilities` 那一行（监听 1080 不需要特权）。

注意：`DynamicUser=yes` 时证书/密钥文件要让该动态用户可读（放在 `/etc/nakis`，即 `ConfigurationDirectory`，并设置合适的属主/权限）。

**其他建议**

- **时间同步**：两端都开启 NTP。时钟差超过 30 秒认证会失败。
- **防火墙**：只开放 `listen` 的端口；服务端的 `max_conns` 是最后一道保险，不是 DoS 防护。
- **文件描述符**：每个会话约占 2 个（隧道连接 + 目标连接），`LimitNOFILE` 请设大。
- **升级**：停掉旧进程换新二进制再启动；进行中的会话会在 `shutdown_timeout` 内收尾。重启之后重启前抓到的认证信息不能被重放（有启动时刻检查）。
- **不要让 `uuid` 出现在命令行、URL、日志里**。

## 12. 注意事项与常见坑

1. **SOCKS5 没有认证。** 客户端默认只监听 `127.0.0.1`，不要随手改成 `0.0.0.0`。
2. **uuid 就是全部凭据。** 谁拿到谁就能用你的服务器（但默认不能访问内网）。泄露后两端一起换。
3. **两边的 `tls` 必须一致。** 一边明文一边 TLS，连接会直接失败（客户端看到的是握手错误或被关闭）。
4. **两端时钟差 ≤ 30 秒。**
5. **pin 模式不检查证书有效期和域名**——只看公钥指纹。换证书 = 换指纹 = 更新所有客户端。
6. **`pool_max_age` 要小于服务端 `idle_timeout`**，否则池里会有已经被服务端关掉的连接。（默认 45 s < 120 s，没问题。）
7. **ECH 的 `public-name` 别乱填。** 外层名字和服务器 IP 对不上，本身就是特征。
8. **明文模式没有任何保护**，也没有服务端身份验证。
9. **没有半关闭。** 任何一端先结束，整个会话就结束；依赖半关闭的应用（例如某些先发完请求再 `shutdown(SHUT_WR)` 等回应的工具）可能被提前截断。
10. **`congestion` 只在 Linux 有效**，且依赖内核模块（`bbr` 需要 `modprobe tcp_bbr` 或内核自带）。
11. **只代理 TCP。** 不支持 UDP（QUIC/HTTP3、DNS over UDP 等需要由应用回退到 TCP，或在别处处理）。浏览器若默认走 QUIC，请禁用它。
12. **远端解析域名**：用 SOCKS5 时让应用把域名交给代理解析（curl 用 `--socks5-hostname`；浏览器勾选「代理 DNS」），否则本机 DNS 查询会泄露访问记录。
13. **探测者看到的是一个 nginx 默认页**，但它不是完美的 nginx 复刻（见 SPEC 第 15 章）；想更像一点，建议在 443 端口配合正规证书和域名。
14. **被限速时第一次仍然会慢**：自适应控制器是「学到之后保护后面的会话」，不能把正在进行中的会话搬到新隧道上。
15. **没有 Windows/macOS 上的实测。** 这两个平台只做了编译和静态检查，请自行验证；`congestion` 在它们上无效。

## 13. 排错速查表

| 现象 | 最可能的原因 | 怎么办 |
|---|---|---|
| 启动即报 `parse json: json: unknown field "xxx"` | 键名拼错或用了已删除的旧字段 | 对照第 4/5 节；预连接、连接复用的开关已经删除，写了会报这个错 |
| 启动报 `tls needs "sni" or "tls_pins"` | 客户端开了 TLS 却没写校验方式 | 写 `tls_pins`（自签）或 `sni`（CA 证书） |
| 启动报 `ech needs "sni"…` | 用了 `ech_config` 却没写 `sni` | 写上真实服务器名 |
| 启动报 `ech_config / tls_pins need "tls": true` | 明文模式下设置了 TLS 相关字段 | 删掉或打开 `tls` |
| 启动报 `tls needs tls_cert and tls_key` | 服务端开 TLS 却没给证书 | 运行 `nakis cert` 并填路径 |
| 服务端启动报 `load tls_cert/tls_key` | 文件不存在或无权读取 | 检查路径和权限（尤其是 `DynamicUser`） |
| 客户端日志反复 `couldn't open a tunnel to the server` | 网络不通 / 端口被封 / 地址写错 / `tls` 不一致 / pin 不匹配 | 先 `nc -vz 服务器 端口`；再检查 `tls`、`tls_pins`；`-v` 看具体错误 |
| 日志 `server certificate does not match any tls_pins entry` | pin 和服务端证书不一致（可能换过证书） | 重新用 `nakis cert` 的输出，或把新 pin 加进列表 |
| 日志 `the server hung up on a tunnel without answering` | uuid 不一致，或时钟差 > 30 s | 核对 uuid；两端同步时间 |
| 服务端日志 `a client's clock is … away` | 客户端时间不准 | 校时 |
| 浏览器能打开 IP 站点但打不开域名 | 没有让代理解析域名 | 勾选「通过代理解析 DNS」；curl 用 `--socks5-hostname` |
| 访问内网地址失败 | `allow_private` 默认 `false` | 确认确实需要后设为 `true` |
| 速度忽快忽慢 | 可能被运营商限速 | 看客户端 WARN 日志有没有「per-flow throttling」；试着调低 `pool_max_uses`、更换端口、使用 ECH |
| 配置了 `congestion` 但有警告 | 非 Linux 或内核没有该算法 | `sysctl net.ipv4.tcp_available_congestion_control` |
| 服务端日志 `already at the limit of N connections` | 达到 `max_conns`（也可能被大量慢连接占用） | 调大 `max_conns`、调小 `idle_timeout`、防火墙限速 |
