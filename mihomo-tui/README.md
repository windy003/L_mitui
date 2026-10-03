# mitui

Linux 终端下的代理客户端，TUI 界面，mihomo（Clash.Meta）内核。
支持解析订阅链接、连接 trojan 节点、测延迟、切换节点。

纯 Python 标准库实现，**无需 pip 安装任何依赖**（curses / urllib 都是自带的；
装了 PyYAML 的话会用它来解析订阅，没装则用内置的精简 YAML 解析器）。

```
┌ mitui ─────────────────────────────────────────────────────────────────────┐
│ mitui  mihomo TUI client                                 12 nodes          │
│ ● running  v1.19.2  mode:rule  port:7890  node:HK 香港 01   ↑121K/s ↓9.4M/s │
│ ─────────────────────────────────────────────────────────────────────────── │
│  1 Nodes   2 Subs   3 Logs   4 Settings                                    │
│   NAME               TYPE     SERVER          DELAY   │ DETAILS            │
│ ▶ HK 香港 01          trojan   hk.example.com  85ms    │ name    HK 香港 01  │
│   JP 東京 02          trojan   jp.example.com  132ms   │ type    trojan     │
│   SG 新加坡 03        trojan   sg.example.com  timeout │ server  hk.example │
│                                                       │ sni     hk.example │
│ enter select  t/T test  o sort  s start  x stop  m mode  q quit            │
└────────────────────────────────────────────────────────────────────────────┘
```

## 安装

```bash
git clone <this repo> mihomo-tui && cd mihomo-tui
./install.sh                 # 在 ~/.local/bin 放一个 mitui 启动器
```

内核也可以用包管理器装（`pacman -S mihomo`、AUR、`nix`…），`mitui` 会自动在
PATH 上找 `mihomo` / `clash-meta`。想指定路径就在设置里改 `mihomo binary`。

不想装启动器的话，直接 `python3 -m mitui`（在仓库目录下）也一样。

## 上手

```bash
mitui       # 没有任何命令行参数，一切都在界面里做
```

在 TUI 里：

- `2` 进订阅页 → `n` 粘贴订阅链接 → 回车拉取。只有一个 trojan 链接时按 `L` 直接粘。
- `1` 回节点页 → `T` 测全部延迟 → `o` 按延迟排序 → 回车选中节点。
- `s` 启动内核，`x` 停止，`r` 重启；`m` 切换 rule / global / direct。
- 改了订阅或设置后按 `a` 应用（重新生成配置并热重载内核）。
- `?` 看完整快捷键，`q` 退出（退出时可以选择保留代理在后台继续跑）。

然后让程序走代理：

```bash
export http_proxy=http://127.0.0.1:7890 https_proxy=http://127.0.0.1:7890
export all_proxy=socks5h://127.0.0.1:7890
curl https://ifconfig.me
```

（端口改过的话按设置页里的 `mixed port` 来。）

默认在 `127.0.0.1:7890` 开一个 mixed 端口（HTTP 和 SOCKS5 同一个端口）。

退出 TUI 时可以选择把内核留在后台继续跑，下次打开 `mitui` 会自动识别并接管显示。

## 支持的节点

重点支持 **trojan**，分享链接里的这些参数都会映射到 mihomo 配置：

| 链接参数 | mihomo 字段 |
| --- | --- |
| `trojan://密码@host:port#名字` | `password` / `server` / `port` / `name` |
| `sni=` / `peer=` | `sni` |
| `allowInsecure=1` / `insecure=1` | `skip-cert-verify: true` |
| `alpn=h2,http/1.1` | `alpn: [h2, http/1.1]` |
| `fp=chrome` | `client-fingerprint` |
| `type=ws` + `path=` + `host=` | `network: ws` + `ws-opts` |
| `type=grpc` + `serviceName=` | `network: grpc` + `grpc-opts` |

密码里的 URL 编码（`%40` → `@` 等）会正确还原。

订阅里混着的其他协议也一并解析，不会因为一个节点看不懂就整份失败：
`ss`（含 obfs / v2ray-plugin / shadow-tls）、`vmess`、`vless`（含 reality）、
`hysteria` / `hysteria2`、`socks5`。Clash/mihomo 格式的 YAML 订阅直接取
`proxies:`，所以 `tuic`、`wireguard`、`anytls` 这些也能透传。

订阅内容的三种常见形态都支持：Clash YAML、base64 整块、以及一行一个链接的纯文本。

## 生成的配置

`mitui` 不让你手写 YAML，它根据设置生成 `~/.local/share/mitui/core/config.yaml`：

- `mixed-port` 混合端口，`external-controller` 本地 API（随机 secret，文件权限 600）
- 两个策略组：`PROXY`（手动选择，含 DIRECT）和 `AUTO`（url-test 自动选最快）
- 规则：私有地址段直连 → `GEOIP,CN,DIRECT`（可关）→ `MATCH,PROXY`
- 内置 DNS，默认 fake-ip；国内 DoH 解析，节点域名用 `proxy-server-nameserver`
  本地解析，避免套娃

这个文件每次应用都会被覆盖，别直接改它——改设置页，或改
`~/.config/mitui/settings.json`。

## TUN 模式（全局透明代理）

设置页打开 `TUN mode` 即可，但需要权限：

```bash
sudo setcap cap_net_admin,cap_net_bind_service=+ep "$(command -v mihomo)"
```

没给权限就开 TUN 的话，`mitui` 会直接提示上面这条命令，而不是让内核静默起不来。

## 故障排查

| 现象 | 处理 |
| --- | --- |
| `mihomo not found` | 用包管理器装 mihomo，或把二进制放到 `~/.local/share/mitui/bin/mihomo`，或设置页里指定路径 |
| 订阅拉不到 | 多数机房要求特定 UA，设置页改 `Subscription User-Agent`；或先用别的代理拉：设置 `Fetch subs via proxy` |
| 内核起不来 | `3` 看日志（里面有 `mihomo -t` 的报错） |
| 提示 GeoIP 数据库下载失败 | 首次启动没法访问 GitHub 时会自动关掉「CN 直连」规则并提示；网络好了再在设置页打开 |
| 节点全 timeout | 换测速 URL（设置页 `Latency test URL`），或确认节点本身可用 |
| 中文节点名错位 | 终端需要 UTF-8 locale（`locale` 看 `LANG=*.UTF-8`） |
| `install.sh` 一闪就没了 | 这是正常的：它只装一个启动器就退出，不是界面程序。要在终端里执行（WSL 用户别在资源管理器里双击），界面是装完之后的 `mitui` |
| `mitui: command not found` | `~/.local/bin` 不在 PATH 上，`export PATH="$HOME/.local/bin:$PATH"` 写进 `~/.bashrc` |

日志、配置、pid 文件都在 `~/.local/share/mitui/`，设置在 `~/.config/mitui/settings.json`。

## 开发

```bash
python -m unittest discover -s tests -v
```

27 个测试覆盖分享链接解析（trojan 各种变体、ss/vmess/vless/hysteria2）、
三种订阅载荷、YAML 读写往返、配置生成，以及一条从链接到 `config.yaml` 的端到端流程。

代码结构：

| 文件 | 作用 |
| --- | --- |
| `mitui/subs.py` | 订阅抓取 + 分享链接解析 |
| `mitui/confgen.py` | 生成 mihomo 配置 |
| `mitui/core.py` | 内核二进制查找 / 下载 / 进程管理 |
| `mitui/api.py` | mihomo external-controller REST 客户端 |
| `mitui/app.py` | 业务逻辑（界面之下的一层） |
| `mitui/ui.py` | curses 界面 |
| `mitui/yamlio.py` | 自带的 YAML 读写（无依赖） |

## 说明

本工具只做「本地客户端」这一层：解析你自己的订阅、生成内核配置、管理内核进程。
节点和订阅都由你自己提供。
