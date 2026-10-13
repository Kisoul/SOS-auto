# 服务器优选工具

一个简化版的Cloudflare Workers优选工具，用来生成订阅链接。

GitHub: https://github.com/byJoey/yx-auto

## 主要功能

- 优选域名：内置了一些常用的优选域名
- 优选IP：默认从 api.uouin.com 获取动态IP，可切换 wetest，支持IPv4/IPv6和失败回退
- GitHub优选：可以从GitHub仓库拉取IP列表
- 多协议支持：VLESS、Trojan、VMess
- 多客户端格式：Clash、Surge、Quantumult X等
- 运营商筛选：可以按移动/联通/电信筛选

## 部署

1. 去Cloudflare Dashboard，找到Workers & Pages
2. 创建个新Worker
3. 把`_worker.js`的代码复制进去
4. 保存部署就完事了

## 使用

打开你的Worker地址，会看到一个界面：

1. 填域名和UUID
2. 选协议（VLESS/Trojan/VMess）
3. 选客户端类型
4. 点按钮生成订阅链接

就这么简单。

## 订阅链接格式

生成的链接大概长这样：
```
https://your-worker.workers.dev/{UUID}/sub?domain=your-domain.com&epd=yes&epi=yes&egi=yes
```

可以通过`&target=`参数指定输出格式：
- `base64` - 默认格式
- `clash` - Clash配置
- `surge` - Surge配置  
- `quantumult` - Quantumult配置
- `sing-box` - Worker 原生生成的 sing-box 1.14 JSON 配置

## URL参数

节点配置通过 URL 参数控制。环境变量 `scu` 可覆盖订阅转换器地址，默认 `https://url.v1.mk/sub`。

主要参数：
- `domain` - 你的域名（必填）
- `epd` - 启用优选域名（默认yes）
- `epi` - 启用优选IP（默认yes）
- `egi` - 启用GitHub优选（默认yes）
- `piu` - 自定义IP来源URL（可选）
- `ipSource` - 动态优选来源（默认 `uouin`，可选 `wetest`），仅影响 `epi` 来源
- `dynamicIPUrl` - 自定义兼容 uouin JSON 分组及签名协议的 HTTPS API 地址（可选）
- `ipFallback` - 新 API 失败/无有效结果时回退 wetest（默认开启，`no` 关闭）；请求超时 5 秒
- `ech` - ECH 开关（默认关闭，`yes` 开启），开启后强制仅 TLS；自定义端口没有 TLS 节点时返回 400
- `customECHDomain` - ECH 配置查询域名，默认 `cloudflare-ech.com`
- `customDNS` - ECH 查询的 HTTPS DoH 地址，默认 `https://dns.alidns.com/dns-query`，支持自定义端口、路径和查询参数
- `ev` - 启用VLESS（默认yes）
- `et` - 启用Trojan（默认no）
- `mess` - 启用VMess（默认no，注意不是vm，会被屏蔽）
- `ipv4/ipv6` - IP版本选择（默认都开启）
- `ispMobile/ispUnicom/ispTelecom` - 运营商筛选（默认都开启）
- `target` - 输出格式（base64/clash/surge/quantumult/sing-box）
- `GitHub优选URL` - 可输入优选ip的网站，例如：https://ip.164746.xyz/ipTop10.html

## 注意事项

- CLASH 选择远程模板且开启 ECH 时，生成 Worker 的 `target=clash&ech=yes&config=...` 链接。Worker 仍调用 `scu` 转换器生成模板分组和规则，再使用内嵌 js-yaml 4.1.1 解析 YAML、匹配 TLS 节点补入 `ech-opts`，并为 ECH 查询域名补入自定义 DoH 的 nameserver-policy。无需额外安装依赖，复制单个 `_worker.js` 即可部署。
- 仅匹配本次来源的节点类型、地址、端口、UUID/Password，不为转换器插入的其他节点启用 ECH。转换器请求超时 20 秒；HTTP 错误、无效 YAML 或无匹配 TLS 节点会返回明确的 502 错误，不返回悄悄丢失 ECH 的配置。
- ECH 关闭的 Clash、STASH、其他客户端及 sing-box 继续使用原来的路径。旧的直接指向转换器的 Clash 链接不会被修复，需要重新生成链接。Clash ECH 需要支持该字段的 Mihomo 内核；配置有字段不等于握手成功，查询 DoH 也必须能从客户端网络访问。

- 界面按连接信息、来源、协议、动态筛选和连接选项分区，支持窄屏和深色模式；开关可用键盘空格/回车操作。
- 界面将来源、动态 IP 筛选与失败回退放在同一面板；关闭来源收起其配置，切换 wetest 隐藏不适用的 API/回退输入。ECH 开启时显示查询域名/DoH 和联动状态，关闭时收起。客户端使用下拉选择和单个生成按钮，选择时立即更新选项支持范围，转换器选项单独折叠。启用 ECH/仅 TLS 时如只填写 HTTP 端口，生成前提示冲突；非法端口也会提示。
- ECH 开启时界面自动开启并锁定仅 TLS，关闭 ECH 恢复此前 TLS 状态；后端同样强制过滤。UDP 关闭时界面关闭并禁用 XUDP，sing-box 也停止写入 XUDP 编码。至少保留一种协议，关闭 VLESS 明确传入 `ev=no`。过滤后没有节点统一返回 400，不生成错误占位节点。
- 动态优选关闭时禁用来源、IP/运营商筛选；wetest 不使用自定义新 API/回退设置；ECH 关闭时禁用查询域名与 DoH 输入。选项值保留，重新启用后可继续使用。
- 点击客户端生成订阅后，界面按其实际输出方式禁用不生效的开关并标明原因。原始 V2Ray 订阅不使用模板；sing-box 不使用转换器专属开关，模板规则始终内嵌。禁用仅表示该输出不使用此设置，不删除其他客户端的已选参数。

- ECH 关闭时沿用原节点输出。开启时 VLESS/Trojan 链接和 VMess JSON 携带 `ech=查询域名+DoH地址`；原生 sing-box 使用 `tls.ech.query_server_name` 并以独立直连 DoH 查询 HTTPS 记录，避免代理启动的 DNS 循环。原生 Clash 的 VLESS 输出添加 `ech-opts`，使用 Clash 自身的 DNS；远程转换器及其他客户端是否保留和使用 ECH 参数，需要实际客户端支持，不能保证。ECH 不改变现有 WebSocket 端口、路径、模板和 SCV 设置，不强制设置 h3/h2 ALPN。
- 新 API 沿用上游 MD5/时间戳签名，解析电信/联通/移动/多线/IPv6 分组，并校验地址、去重；来源无运营商细分的多线与 IPv6 组，仅在至少选择一个运营商时保留。`egi`/`piu` 自定义 IP 来源独立于此次来源切换。签名协议或接口变更时可切换 wetest。

- SING-BOX 按钮直接生成 Worker 的 `/{UUID}/sub?...&target=sing-box` 链接，不经过订阅转换器。其他客户端保持原来的转换器流程；Clash 的默认原生输出和远程模板流程也保持原样。
- sing-box 复用现有的域名、UUID/Password、路径、端口、协议、节点来源和筛选参数，并将前端开关传递为 `xudp`、`udp`、`tfo`、`scv`（`true/false`）。直接调用时前三项默认开启，`scv` 默认关闭；`udp=false` 限制代理节点为 TCP，`xudp` 控制 VLESS 的 UDP 编码，`scv` 控制 TLS 证书校验。
- WebSocket 路径中的 `?ed=2560` 等参数会转换为 sing-box 的 `max_early_data` 和 `early_data_header_name`，数值来自填写的路径。
- sing-box 基础配置包含 Android TUN、系统 DNS 解析节点域名、代理 DoH、手动/自动节点选择，以及局域网直连；其他流量默认走 PROXY。`ipv6=no` 使用 IPv4 DNS 策略。
- SING-BOX 也会使用上方选中的内置/自定义远程 INI 模板：动态转换 `custom_proxy_group` 和 `ruleset`，保留分组顺序、默认选择、节点正则筛选、测速间隔与分流顺序。未选模板时沿用基础配置。
- 原生 sing-box 支持 INI 的 `select`/`url-test` 分组，以及 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6、PROCESS-NAME、GEOIP、FINAL/MATCH 规则。规则下载后内嵌到配置；GEOIP 国家规则使用 MetaCubeX 的 sing-box JSON 数据。URL-REGEX 无法在 TUN 中等价转换，会跳过并记录数量；Android 不支持进程名路由。其他不支持的分组/规则、无匹配节点、循环引用、远程下载失败会返回明确的 HTTP 422 错误，不静默退回基础配置。
- 直接调用 sing-box 订阅时可以传入 `config=<HTTPS INI 地址>` 或 `config_mode=acl_Kisoul/acl_default/acl_nospeed/acl_mini`，模板地址及分组从远程文件读取，不写死分组。模板和规则缓存 5 分钟，下载超时 10 秒，最多 40 个远程规则来源。大型模板首次刷新需要下载更多规则，生成的 JSON 也会更大。
- Emoji、Expand、New Name、FDN 转换器选项继续用于原有订阅转换流程；sing-box 模板规则固定内嵌，不依赖这些选项。
- 更新并部署 `_worker.js` 后，需要重新点击 SING-BOX 生成订阅；已有的 `url.v1.mk/sub?target=sing-box` 链接不会自动切换。

- 这只是一个订阅生成工具，不提供代理服务
- 生成的节点需要配合你自己的服务器使用
- UUID必须是标准格式（xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx）
- VMess参数用的是`mess`不是`vm`，因为`vm`会被某些地方屏蔽


