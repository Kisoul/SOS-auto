# Mihomo ECH / XHTTP 修复验证

基线：Kisoul/SOS-auto main `9a8f51298d4522898a953842a6f80d2abab5b74e`。
修复先在独立本地分支 `fix/mihomo-ech-xhttp-compat` 验证；用户随后明确授权提交至 main。GitHub main 更新与 Cloudflare 线上发布状态需分别确认。

## 修改

- 在 Worker 调用转换器之前清理嵌套源订阅中的 ECH 开关、自定义 ECH 域名与 DoH；以 `dkby=yes` 保留 ECH 原本隐含的仅 TLS 节点选择。用户完整设置保留于外层 URL。
- XHTTP 同样在请求边界回退 WS，兼容之前保存的 converterQuery，避免只依赖网页生成时的清理。
- ECH 恢复限定 VLESS / VMess UUID 或 Trojan password 与本次 UUID 匹配、servername 与本次代理域名匹配的 TLS 节点。XHTTP 只恢复对应 VLESS WS 节点；不按容易被转换器重命名的节点名称判断。
- 保留转换器查询中模板、策略组、规则及其他选项；ECH DNS 沿用已有合并逻辑，恢复外层自定义域名和 DoH。
- 原生 Mihomo 和远程兼容输出默认 `mode: auto`、`x-padding-bytes: "100-1000"`，路径沿用 `path`，支持 `/244341896@qq.com`。可在 Worker 订阅 URL 添加 `xhttpMode` 与 `xhttpPaddingBytes`；模式校验四种官方值，padding 校验有序非负整数范围，生成器上限 1000000。此上限是本工具的输入约束。
- Stash 保持 packet-up；原始 Xray/Shadowrocket 链接、sing-box 与其他客户端分支未改动。Mihomo 原有纯路径校验及去除 WS `?ed=数字` 行为保留。

官方依据：https://wiki.metacubex.one/config/proxies/transport/ （XHTTP 仅适用于 VLESS；支持 auto、path、字符串 padding 范围）。当前文档不能代表用户已安装内核版本。

## target 差异

main 仅为 `clash-ech` 和 `clash-compat` 设置兼容处理路由。前者可用于 WS+ECH，后者用于 XHTTP 或 XHTTP+ECH；两者共用处理逻辑，实际按开关恢复。

`clash-template` 在该版本没有专用路由或别名，会落入普通订阅处理，无法启动这里的转换后恢复流程。因未取得旧线上 Worker 源码，无法证明线上实现与 main 相同，也不能直接把旧 URL 改名视为已完成迁移。没有添加猜测性的旧路由兼容；以后部署此修复版本时应由页面重新生成完整订阅 URL（包含 converterQuery）。

## 验证

执行 `node tests/verify-ech.mjs`、`node tests/verify-ui.mjs`、`node tests/verify-compat.mjs` 均通过。

新增用例覆盖块/flow YAML、远程 WS+ECH / XHTTP / XHTTP+ECH、实际递归执行第三方将抓取的源 URL、TLS 选择、自定义 ECH/含查询参数 DoH、默认与自定义 XHTTP 参数、无效参数在联网前拒绝、异 UUID 或异域名节点不修改，以及模板策略组/规则文本保留。既有测试覆盖 sing-box、原始三协议 ECH、UI 及动态 IP 回退。

这些验证使用模拟转换器结果，没有向 url.v1.mk 发送真实用户凭据，没有部署临时 Worker，也没有运行 Mihomo 内核配置解析或实际代理连接测试。因此确认的是代码流程及字段输出，不能据此声称线上 HTTP 422 已实测消失或 ECH 握手已成功。上游 422 的原始根因仍缺少真实响应证据。
