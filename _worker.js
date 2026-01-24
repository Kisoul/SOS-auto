// Cloudflare Worker - 简化版优选工具 (最终完美版 v2.1)
// 包含：并发修复、性能优化、Surge生成修复
// 适配：Clash Meta(Mihomo) VLESS 支持、Surge 协议检测

// --- 1. 常量定义 ---
const DEFAULT_SCU = 'https://url.v1.mk/sub';
const DEFAULT_IP_URL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';

const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

// 默认优选域名列表
const DIRECT_DOMAINS = [
    { name: "cloudflare.182682.xyz", domain: "cloudflare.182682.xyz" },
    { domain: "freeyx.cloudflare88.eu.org" },
    { domain: "bestcf.top" },
    { domain: "cdn.2020111.xyz" },
    { domain: "cf.0sm.com" },
    { domain: "cf.090227.xyz" },
    { domain: "cf.zhetengsha.eu.org" },
    { domain: "cfip.1323123.xyz" },
    { domain: "cloudflare-ip.mofashi.ltd" },
    { domain: "cf.877771.xyz" },
    { domain: "xn--b6gac.eu.org" }
];

// --- 2. 辅助工具函数 ---

// 端口生成策略
function getPortsForNode(item, customPorts, disableNonTLS) {
    let portsToGenerate = [];
    const useCustom = Array.isArray(customPorts) && customPorts.length > 0;

    if (useCustom) {
        customPorts.forEach(port => {
            const isHttp = CF_HTTP_PORTS.includes(port);
            const isHttps = CF_HTTPS_PORTS.includes(port);
            if (disableNonTLS && isHttp) return;
            const tls = isHttps || (!isHttp);
            portsToGenerate.push({ port, tls });
        });
        return portsToGenerate;
    }

    if (item.port) {
        const port = parseInt(item.port);
        const isHttp = CF_HTTP_PORTS.includes(port);
        const isHttps = CF_HTTPS_PORTS.includes(port);
        if (disableNonTLS && isHttp) return [];
        const tls = isHttps || (!isHttp);
        portsToGenerate.push({ port, tls });
        return portsToGenerate;
    }

    // 默认策略
    portsToGenerate.push({ port: 2053, tls: true });
    if (!disableNonTLS) {
        portsToGenerate.push({ port: 80, tls: false });
    }
    return portsToGenerate;
}

// 节点名称处理
function parseNodeName(item) {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
    if (item.colo && item.colo.trim()) {
        nodeNameBase = `${nodeNameBase}-${item.colo.trim()}`;
    }
    return nodeNameBase;
}

// 获取动态IP列表
async function fetchDynamicIPs(ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
    const v4Url = "https://www.wetest.vip/page/cloudflare/address_v4.html";
    const v6Url = "https://www.wetest.vip/page/cloudflare/address_v6.html";
    
    const promises = [];
    if (ipv4Enabled) promises.push(fetchAndParseWetest(v4Url));
    if (ipv6Enabled) promises.push(fetchAndParseWetest(v6Url));

    try {
        const resultsArray = await Promise.all(promises);
        let results = resultsArray.flat();
        if (results.length > 0) {
            results = results.filter(item => {
                const isp = item.isp || '';
                if (isp.includes('移动') && !ispMobile) return false;
                if (isp.includes('联通') && !ispUnicom) return false;
                if (isp.includes('电信') && !ispTelecom) return false;
                return true;
            });
        }
        return results;
    } catch (e) {
        return [];
    }
}

// 解析 wetest
async function fetchAndParseWetest(url) {
    try {
        const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) return [];
        const html = await response.text();
        const results = [];
        const rowRegex = /<tr[\s\S]*?<\/tr>/g;
        const cellRegex = /<td data-label="线路名称">(.+?)<\/td>[\s\S]*?<td data-label="优选地址">([\d.:a-fA-F]+)<\/td>[\s\S]*?<td data-label="数据中心">(.+?)<\/td>/;

        let match;
        while ((match = rowRegex.exec(html)) !== null) {
            const rowHtml = match[0];
            const cellMatch = rowHtml.match(cellRegex);
            if (cellMatch && cellMatch[1] && cellMatch[2]) {
                const colo = cellMatch[3] ? cellMatch[3].trim().replace(/<.*?>/g, '') : '';
                results.push({
                    isp: cellMatch[1].trim().replace(/<.*?>/g, ''),
                    ip: cellMatch[2].trim(),
                    colo: colo
                });
            }
        }
        return results;
    } catch (error) {
        return [];
    }
}

// 整理成数组
function splitLinesToIPArray(content) {
    const replaced = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
    const cleanContent = replaced.replace(/^,/, '').replace(/,$/, '');
    if (!cleanContent) return [];
    return cleanContent.split(',');
}

// 请求优选API
async function fetchPreferredAPI(urls, defaultPort = '2053', timeoutMs = 3000) {
    if (!urls?.length) return [];
    const results = new Set();
    
    const fetchPromises = urls.map(async (url) => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            const response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (!response.ok) return;

            const buffer = await response.arrayBuffer();
            const contentType = (response.headers.get('content-type') || '').toLowerCase();
            const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';
            
            let text = '';
            let decoders = ['utf-8', 'gb2312'];
            if (charset.includes('gb')) decoders = ['gb2312', 'utf-8'];

            for (const decoder of decoders) {
                try {
                    const decoded = new TextDecoder(decoder).decode(buffer);
                    if (decoded && !decoded.includes('\ufffd')) {
                        text = decoded;
                        break;
                    }
                } catch(e) { continue; }
            }
            if (!text) text = await new Response(buffer).text();

            const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
            if (lines.length === 0) return;

            const isCSV = lines.length > 1 && lines[0].includes(',');
            const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
            
            if (!isCSV) {
                lines.forEach(line => {
                    if (line.startsWith('#') || line.startsWith('//')) return;
                    const hashIndex = line.indexOf('#');
                    const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
                    let hasPort = false;
                    if (hostPart.startsWith('[')) {
                        hasPort = /\]:(\d+)$/.test(hostPart);
                    } else {
                        const colonIndex = hostPart.lastIndexOf(':');
                        hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
                    }
                    const port = new URL(url).searchParams.get('port') || defaultPort;
                    results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
                });
            } else {
                const headers = lines[0].split(',').map(h => h.trim());
                const dataLines = lines.slice(1);
                const idxMap = {
                    ip: headers.indexOf('IP地址'),
                    port: headers.indexOf('端口'),
                    tls: headers.indexOf('TLS'),
                    remark: -1,
                    delay: headers.findIndex(h => h.includes('延迟')),
                    speed: headers.findIndex(h => h.includes('下载速度'))
                };
                if (headers.indexOf('数据中心') > -1) idxMap.remark = headers.indexOf('数据中心');
                else if (headers.indexOf('国家') > -1) idxMap.remark = headers.indexOf('国家');
                else if (headers.indexOf('城市') > -1) idxMap.remark = headers.indexOf('城市');

                if (idxMap.ip !== -1 && idxMap.port !== -1 && idxMap.remark !== -1) {
                     dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        if (idxMap.tls !== -1 && cols[idxMap.tls]?.toLowerCase() !== 'true') return;
                        const rawIP = cols[idxMap.ip];
                        const wrappedIP = IPV6_PATTERN.test(rawIP) && !rawIP.startsWith('[') ? `[${rawIP}]` : rawIP;
                        results.add(`${wrappedIP}:${cols[idxMap.port]}#${cols[idxMap.remark]}`);
                    });
                } else if (headers.some(h => h.includes('IP')) && idxMap.delay !== -1 && idxMap.speed !== -1) {
                    const ipIdx = headers.findIndex(h => h.includes('IP'));
                    const port = new URL(url).searchParams.get('port') || defaultPort;
                    dataLines.forEach(line => {
                        const cols = line.split(',').map(c => c.trim());
                        const rawIP = cols[ipIdx];
                        const wrappedIP = IPV6_PATTERN.test(rawIP) && !rawIP.startsWith('[') ? `[${rawIP}]` : rawIP;
                        results.add(`${wrappedIP}:${port}#CF优选 ${cols[idxMap.delay]}ms ${cols[idxMap.speed]}MB/s`);
                    });
                }
            }
        } catch (e) {}
    });
    await Promise.allSettled(fetchPromises);
    return Array.from(results);
}

// 解析优选行
function parsePreferredLine(line) {
    if (!line) return null;
    const s = String(line).trim();
    if (!s || s.startsWith('#') || s.startsWith('//')) return null;

    if (s.includes(',')) {
        const cols = s.split(',').map(c => c.trim());
        if (cols.length >= 2 && /^\d+$/.test(cols[1])) {
            const ipRaw = cols[0].replace(/^[\[]|[\]]$/g, '');
            const port = parseInt(cols[1], 10);
            if (!Number.isFinite(port) || port <= 0 || port >= 65536) return null;
            const cc = cols[2] ? cols[2] : '';
            const remark = cols.slice(3).join(',').trim();
            const name = (cc && remark) ? `${cc}-${remark}` : (remark || cc || ipRaw);
            return { ip: ipRaw, port, name };
        }
    }

    const m = s.match(/^(\[[^\]]+\]|[^:#]+):(\d+)(?:#(.*))?$/);
    if (m) {
        const ipRaw = m[1].replace(/[\[\]]/g, '');
        const port = parseInt(m[2], 10);
        if (!Number.isFinite(port) || port <= 0 || port >= 65536) return null;
        const remark = (m[3] || '').trim();
        return { ip: ipRaw, port, name: remark || ipRaw };
    }
    return null;
}

// 获取GitHub IP
async function fetchAndParseNewIPs(piu) {
    const url = piu || DEFAULT_IP_URL;
    try {
        const response = await fetch(url);
        if (!response.ok) return [];
        const text = await response.text();
        const results = [];
        const lines = text.replace(/\r/g, "").split('\n');
        for (const line of lines) {
            const parsed = parsePreferredLine(line);
            if (parsed) results.push(parsed);
        }
        return results;
    } catch (error) {
        return [];
    }
}

// --- 3. 节点链接生成 ---

function generateLinks(list, user, workerDomain, protocol, disableNonTLS, customPath, customPorts) {
    const links = [];
    const wsPath = customPath || '/';
    
    list.forEach(item => {
        const nodeNameBase = parseNodeName(item);
        const safeIP = item.ip.includes(':') && !item.ip.startsWith('[') ? `[${item.ip}]` : item.ip;
        const ports = getPortsForNode(item, customPorts, disableNonTLS);

        ports.forEach(({ port, tls }) => {
            const remark = `${nodeNameBase}-${port}-${protocol.toUpperCase()}-${tls ? 'TLS' : 'WS'}`;
            const remarkEnc = encodeURIComponent(remark);

            if (protocol === 'vless') {
                const wsParams = new URLSearchParams({
                    encryption: 'none',
                    type: 'ws',
                    host: workerDomain,
                    path: wsPath
                });
                if (tls) {
                    wsParams.append('security', 'tls');
                    wsParams.append('sni', workerDomain);
                    wsParams.append('fp', 'chrome');
                } else {
                    wsParams.append('security', 'none');
                }
                links.push(`vless://${user}@${safeIP}:${port}?${wsParams.toString()}#${remarkEnc}`);
            }
            else if (protocol === 'trojan') {
                const wsParams = new URLSearchParams({
                    type: 'ws',
                    host: workerDomain,
                    path: wsPath
                });
                if (tls) {
                    wsParams.append('security', 'tls');
                    wsParams.append('sni', workerDomain);
                    wsParams.append('fp', 'chrome');
                } else {
                    wsParams.append('security', 'none');
                }
                links.push(`trojan://${user}@${safeIP}:${port}?${wsParams.toString()}#${remarkEnc}`);
            }
            else if (protocol === 'vmess') {
                 const vmessConfig = {
                    v: "2",
                    ps: remark,
                    add: safeIP,
                    port: port.toString(),
                    id: user,
                    aid: "0",
                    scy: "auto",
                    net: "ws",
                    type: "none",
                    host: workerDomain,
                    path: wsPath,
                    tls: tls ? "tls" : "none"
                };
                if (tls) {
                    vmessConfig.sni = workerDomain;
                    vmessConfig.fp = "chrome";
                }
                const jsonStr = JSON.stringify(vmessConfig);
                const utf8Bytes = new TextEncoder().encode(jsonStr);
                const latin1Str = String.fromCharCode(...utf8Bytes); 
                const vmessBase64 = btoa(latin1Str);
                links.push(`vmess://${vmessBase64}`);
            }
        });
    });
    return links;
}

// --- 4. 核心逻辑 ---

async function handleSubscriptionRequest(request, envParams) {
    const { 
        user, domain: customDomain, workerDomain, 
        piu, ipv4Enabled, ipv6Enabled, 
        ispMobile, ispUnicom, ispTelecom, 
        evEnabled, etEnabled, vmEnabled, 
        disableNonTLS, customPath, customPorts,
        epd, epi, egi
    } = envParams;

    const finalLinks = [];
    const nodeDomain = customDomain || workerDomain; 

    // 原生地址
    const nativeList = [{ ip: workerDomain, isp: '原生地址' }];
    
    // 并行任务
    const tasks = [];
    tasks.push(Promise.resolve(nativeList));
    if (epd) tasks.push(Promise.resolve(DIRECT_DOMAINS.map(d => ({ ip: d.domain, isp: d.name || d.domain }))));
    else tasks.push(Promise.resolve([]));

    if (epi) tasks.push(fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom));
    else tasks.push(Promise.resolve([]));

    if (egi) {
        tasks.push((async () => {
            try {
                const githubUrl = piu || DEFAULT_IP_URL;
                if (githubUrl.includes('\n') || !githubUrl.startsWith('http')) {
                    const lines = splitLinesToIPArray(githubUrl);
                    const apiUrls = [], staticIPs = [];
                    lines.forEach(l => {
                        if (l.toLowerCase().startsWith('http')) apiUrls.push(l);
                        else staticIPs.push(l);
                    });
                    const ipList = [];
                    staticIPs.forEach(l => {
                        const parsed = parsePreferredLine(l);
                        if (parsed) ipList.push(parsed);
                    });
                    if (apiUrls.length > 0) {
                        const apiIPs = await fetchPreferredAPI(apiUrls);
                        apiIPs.forEach(l => {
                            const parsed = parsePreferredLine(l);
                            if (parsed) ipList.push(parsed);
                        });
                    }
                    return ipList;
                } else {
                    let list = await fetchAndParseNewIPs(githubUrl);
                    if (list.length === 0) {
                        const rawApiList = await fetchPreferredAPI([githubUrl]);
                        list = rawApiList.map(l => parsePreferredLine(l)).filter(Boolean);
                    }
                    return list;
                }
            } catch (e) {
                return [];
            }
        })());
    } else {
        tasks.push(Promise.resolve([]));
    }

    const results = await Promise.allSettled(tasks);
    const flatList = results.map(r => r.status === 'fulfilled' ? r.value : []).flat();

    const useVL = (evEnabled || etEnabled || vmEnabled) ? evEnabled : true;
    if (useVL) finalLinks.push(...generateLinks(flatList, user, nodeDomain, 'vless', disableNonTLS, customPath, customPorts));
    if (etEnabled) finalLinks.push(...generateLinks(flatList, user, nodeDomain, 'trojan', disableNonTLS, customPath, customPorts));
    if (vmEnabled) finalLinks.push(...generateLinks(flatList, user, nodeDomain, 'vmess', disableNonTLS, customPath, customPorts));

    if (finalLinks.length === 0) {
        finalLinks.push(`vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#${encodeURIComponent("所有节点获取失败")}`);
    }

    const target = new URL(request.url).searchParams.get('target') || 'base64';
    let content = '';
    let contentType = 'text/plain; charset=utf-8';

    switch (target.toLowerCase()) {
        case 'clash':
        case 'clashr':
            content = generateClashConfig(finalLinks);
            contentType = 'text/yaml; charset=utf-8';
            break;
        case 'surge':
        case 'surge2':
        case 'surge3':
        case 'surge4':
            content = generateSurgeConfig(finalLinks);
            break;
        default:
            content = btoa(finalLinks.join('\n'));
    }

    return new Response(content, {
        headers: {
            'Content-Type': contentType,
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        }
    });
}

// 支持 VLESS 的 Clash 配置生成 (适配 Meta/Mihomo 内核)
function generateClashConfig(links) {
    let yaml = 'port: 7890\nsocks-port: 7891\nallow-lan: false\nmode: rule\nlog-level: info\n\nproxies:\n';
    const proxyNames = [];
    links.forEach((link, index) => {
        try {
            if (link.startsWith('vless://')) {
                const url = new URL(link);
                const params = url.searchParams;
                const name = decodeURIComponent(url.hash.slice(1)) || `Node-${index}`;
                proxyNames.push(name);
                yaml += `  - name: ${name}\n    type: vless\n    server: ${url.hostname}\n    port: ${url.port}\n    uuid: ${url.username}\n    tls: ${params.get('security') === 'tls'}\n    network: ws\n    ws-opts:\n      path: ${params.get('path') || '/'}\n      headers:\n        Host: ${params.get('host') || url.hostname}\n`;
                if (params.get('sni')) yaml += `    servername: ${params.get('sni')}\n`;
                if (params.get('fp')) yaml += `    client-fingerprint: ${params.get('fp')}\n`;
            }
            // (Clash 原生支持 Trojan/VMess，如需也可在此扩展)
        } catch(e) {}
    });
    yaml += '\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n';
    proxyNames.forEach(name => yaml += `      - '${name}'\n`);
    yaml += '\nrules:\n  - MATCH,PROXY\n';
    return yaml;
}

// 修复后的 Surge 配置生成函数：支持 Trojan 和 VMess，跳过 VLESS
function generateSurgeConfig(links) {
    let config = '[Proxy]\n';
    const names = [];
    
    links.forEach((link, i) => {
        try {
            let name = decodeURIComponent(link.split('#')[1] || `Node-${i}`);
            let line = '';
            
            // 1. 处理 Trojan (Surge 原生支持)
            if (link.startsWith('trojan://')) {
                const url = new URL(link);
                const params = url.searchParams;
                line = `${name} = trojan, ${url.hostname}, ${url.port}, password=${url.username}`;
                if (params.get('sni')) line += `, sni=${params.get('sni')}`;
                if (params.get('allowInsecure') === '1') line += `, skip-cert-verify=true`;
            } 
            // 2. 处理 VMess (Surge 原生支持)
            else if (link.startsWith('vmess://')) {
                const b64 = link.slice(8);
                const jsonStr = new TextDecoder().decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0)));
                const v = JSON.parse(jsonStr);
                
                name = v.ps || name;
                line = `${name} = vmess, ${v.add}, ${v.port}, username=${v.id}`;
                if (v.tls === 'tls') line += `, tls=true`;
                if (v.sni) line += `, sni=${v.sni}`;
                if (v.net === 'ws') {
                    line += `, ws=true`;
                    if (v.path) line += `, ws-path=${v.path}`;
                    if (v.host) line += `, ws-headers=Host:${v.host}`;
                }
            }
            // 3. VLESS (Surge 不支持，直接跳过)
            
            if (line) {
                config += line + '\n';
                names.push(name);
            }
        } catch (e) { }
    });

    if (names.length === 0) {
        config += '# 警告: 未找到 Surge 支持的节点 (Surge 不支持 VLESS，请勾选 Trojan 或 VMess)\n';
    }

    config += '\n[Proxy Group]\nPROXY = select, ' + names.join(', ') + '\n';
    return config;
}

// --- 5. 前端界面 (最终版 - 含所有客户端协议监测) ---
function generateHomePage(scuValue) {
    const scu = scuValue || DEFAULT_SCU;
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>服务器优选工具</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(180deg, #f5f5f7 0%, #ffffff 50%, #fafafa 100%); color: #1d1d1f; min-height: 100vh; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { text-align: center; padding: 40px 0 30px; }
        .header h1 { font-size: 32px; font-weight: 700; color: #1d1d1f; margin-bottom: 8px; }
        .header p { color: #86868b; }
        .card { background: rgba(255, 255, 255, 0.8); backdrop-filter: blur(20px); border-radius: 20px; padding: 24px; box-shadow: 0 4px 24px rgba(0,0,0,0.05); border: 1px solid rgba(0,0,0,0.05); }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-size: 13px; font-weight: 600; color: #86868b; margin-bottom: 8px; text-transform: uppercase; }
        .form-group input { width: 100%; padding: 12px; font-size: 16px; background: rgba(142, 142, 147, 0.1); border: none; border-radius: 10px; color: #1d1d1f; outline: none; }
        .form-group input:focus { background: rgba(142, 142, 147, 0.15); box-shadow: 0 0 0 2px #007AFF; }
        .form-group small { display: block; margin-top: 6px; color: #86868b; font-size: 12px; }
        .list-item { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid rgba(0,0,0,0.05); cursor: pointer; }
        .list-item:last-child { border-bottom: none; }
        .switch { width: 50px; height: 30px; background: #e9e9ea; border-radius: 15px; position: relative; transition: 0.3s; }
        .switch.active { background: #34C759; }
        .switch::after { content: ''; width: 26px; height: 26px; background: white; border-radius: 50%; position: absolute; top: 2px; left: 2px; transition: 0.3s; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
        .switch.active::after { transform: translateX(20px); }
        .client-btn { padding: 10px 15px; font-size: 14px; color: #007AFF; background: rgba(0,122,255,0.1); border: none; border-radius: 8px; cursor: pointer; font-weight: 500; }
        .client-btn:active { background: rgba(0,122,255,0.2); }
        .result-url { margin-top: 15px; padding: 15px; background: rgba(0,122,255,0.05); border-radius: 10px; color: #007AFF; word-break: break-all; font-size: 13px; border: 1px dashed rgba(0,122,255,0.3); display: none; }
        .footer { text-align: center; margin-top: 30px; font-size: 13px; color: #86868b; }
        .footer a { color: #007AFF; text-decoration: none; }
        @media (prefers-color-scheme: dark) {
            body { background: #000; color: #fff; }
            .card { background: rgba(28,28,30,0.8); border-color: rgba(255,255,255,0.1); }
            .form-group input { background: rgba(255,255,255,0.1); color: #fff; }
            .header h1 { color: #fff; }
            .switch { background: #39393d; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>服务器优选工具</h1>
            <p>UI修复完整版</p>
        </div>
        <div class="card">
            <div class="form-group">
                <label>域名 (Domain)</label>
                <input type="text" id="domain" placeholder="请输入您的域名">
            </div>
            <div class="form-group">
                <label>UUID / Password</label>
                <input type="text" id="uuid" placeholder="请输入UUID或Password">
            </div>
            
            <div class="form-group">
                <label>WebSocket路径 (Path)</label>
                <input type="text" id="customPath" placeholder="默认为 /，可自定义如 /ws" value="/">
                <small>对应 path 参数</small>
            </div>
            <div class="form-group">
                <label>自定义端口 (Ports)</label>
                <input type="text" id="customPorts" placeholder="例如：2053 或 443,2053,2096">
                <small>留空则使用默认策略；多个端口用逗号分隔</small>
            </div>

            <div class="list-item" onclick="toggleSwitch('switchDomain')">
                <div>优选域名 (EPD)</div>
                <div class="switch active" id="switchDomain"></div>
            </div>
            <div class="list-item" onclick="toggleSwitch('switchIP')">
                <div>优选IP (EPI)</div>
                <div class="switch active" id="switchIP"></div>
            </div>
            <div class="list-item" onclick="toggleSwitch('switchGitHub')">
                <div>GitHub优选 (EGI)</div>
                <div class="switch active" id="switchGitHub"></div>
            </div>
            <div class="form-group" style="margin-top: 15px;">
                <label>GitHub优选URL (可选)</label>
                <input type="text" id="githubUrl" placeholder="输入自定义的优选IP文件地址">
            </div>

            <div class="form-group" style="margin-top: 25px;">
                <label>协议选择</label>
                <div style="display:flex; gap:15px; margin-top:10px;">
                    <div style="display:flex; align-items:center; gap:8px;" onclick="toggleSwitch('switchVL')">
                        <span>VLESS</span> <div class="switch active" id="switchVL" style="transform:scale(0.8)"></div>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;" onclick="toggleSwitch('switchTJ')">
                        <span>Trojan</span> <div class="switch" id="switchTJ" style="transform:scale(0.8)"></div>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;" onclick="toggleSwitch('switchVM')">
                        <span>VMess</span> <div class="switch" id="switchVM" style="transform:scale(0.8)"></div>
                    </div>
                </div>
            </div>

            <div class="form-group" style="margin-top: 25px;">
                <label>生成订阅</label>
                <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px;">
                    <button class="client-btn" onclick="generateClientLink('clash', 'CLASH')">Clash</button>
                    <button class="client-btn" onclick="generateClientLink('surge', 'SURGE')">Surge</button>
                    <button class="client-btn" onclick="generateClientLink('sing-box', 'Sing-Box')">Sing-Box</button>
                    <button class="client-btn" onclick="generateClientLink('v2ray', 'V2Ray')">V2Ray/Neko</button>
                    <button class="client-btn" onclick="generateClientLink('quanx', 'QuanX')">QuanX</button>
                </div>
                <div class="result-url" id="clientSubscriptionUrl"></div>
            </div>
            
            <div class="form-group" style="margin-top: 20px;">
                <label>高级选项</label>
                <div style="display:flex; gap:20px; flex-wrap:wrap; font-size:14px; color:#555;">
                    <label><input type="checkbox" id="ipv4Enabled" checked> IPv4</label>
                    <label><input type="checkbox" id="ipv6Enabled" checked> IPv6</label>
                    <label><input type="checkbox" id="ispMobile" checked> 移动</label>
                    <label><input type="checkbox" id="ispUnicom" checked> 联通</label>
                    <label><input type="checkbox" id="ispTelecom" checked> 电信</label>
                </div>
                <div class="list-item" onclick="toggleSwitch('switchTLS')" style="margin-top:10px;">
                    <div style="font-size:14px;">仅生成 TLS 端口</div>
                    <div class="switch" id="switchTLS" style="transform:scale(0.8)"></div>
                </div>
            </div>
        </div>
        <div class="footer">
            <a href="https://github.com/byJoey/yx-auto" target="_blank">GitHub Project</a>
        </div>
    </div>
    <script>
        let switches = { switchDomain: true, switchIP: true, switchGitHub: true, switchVL: true, switchTJ: false, switchVM: false, switchTLS: false };
        function toggleSwitch(id) {
            const switchEl = document.getElementById(id);
            switches[id] = !switches[id];
            switchEl.classList.toggle('active');
        }
        const SUB_CONVERTER_URL = "${scu}";
        
        function tryOpenApp(scheme, fallback) {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = scheme;
            document.body.appendChild(iframe);
            setTimeout(() => {
                document.body.removeChild(iframe);
                if (fallback) fallback();
            }, 2000);
        }

        function generateClientLink(type, name) {
            const domain = document.getElementById('domain').value.trim();
            const uuid = document.getElementById('uuid').value.trim();
            const customPath = document.getElementById('customPath').value.trim() || '/';
            const customPortsRaw = (document.getElementById('customPorts')?.value || '').trim();
            
            if (!domain || !uuid) { alert('请填写域名和UUID'); return; }
            if (!switches.switchVL && !switches.switchTJ && !switches.switchVM) { alert('请至少选择一个协议'); return; }

            // --- 客户端协议兼容性检查 ---
            
            // 1. Surge: 不支持 VLESS
            if (type === 'surge') {
                if (switches.switchVL) {
                     if (!switches.switchTJ && !switches.switchVM) {
                         alert('错误：Surge 客户端不支持 VLESS 协议！\\n\\n当前您只选择了 VLESS，生成的订阅将为空。\\n请勾选 Trojan 或 VMess。');
                         return;
                     }
                     if (!confirm('提示：Surge 客户端不支持 VLESS 协议。\\n\\n生成的订阅将自动忽略 VLESS 节点，仅包含 Trojan/VMess 节点。\\n是否继续？')) {
                         return;
                     }
                }
            }
            // 2. Clash: 现在默认支持 VLESS (Meta内核)，无警告
            // 3. QuanX: 现在版本支持 VLESS，无警告
            
            // ---------------------------

            const baseUrl = window.location.origin;
            let url = \`\${baseUrl}/\${uuid}/sub?domain=\${encodeURIComponent(domain)}\`;
            
            // 开关参数
            url += \`&epd=\${switches.switchDomain ? 'yes' : 'no'}\`;
            url += \`&epi=\${switches.switchIP ? 'yes' : 'no'}\`;
            url += \`&egi=\${switches.switchGitHub ? 'yes' : 'no'}\`;
            
            // 协议参数
            if (switches.switchVL) url += '&ev=yes';
            if (switches.switchTJ) url += '&et=yes';
            if (switches.switchVM) url += '&mess=yes';
            
            // 自定义参数
            if (customPath !== '/') url += \`&path=\${encodeURIComponent(customPath)}\`;
            if (customPortsRaw) url += \`&ports=\${encodeURIComponent(customPortsRaw)}\`;
            
            // 优选URL
            const ghUrl = document.getElementById('githubUrl').value.trim();
            if (ghUrl) url += \`&piu=\${encodeURIComponent(ghUrl)}\`;

            // 高级选项
            if (!document.getElementById('ipv4Enabled').checked) url += '&ipv4=no';
            if (!document.getElementById('ipv6Enabled').checked) url += '&ipv6=no';
            if (!document.getElementById('ispMobile').checked) url += '&ispMobile=no';
            if (!document.getElementById('ispUnicom').checked) url += '&ispUnicom=no';
            if (!document.getElementById('ispTelecom').checked) url += '&ispTelecom=no';
            if (switches.switchTLS) url += '&dkby=yes';

            const urlEl = document.getElementById('clientSubscriptionUrl');
            
            if (type === 'v2ray') {
                urlEl.textContent = url;
                urlEl.style.display = 'block';
                navigator.clipboard.writeText(url).then(() => alert('订阅链接已复制'));
            } else {
                const subUrl = \`\${SUB_CONVERTER_URL}?target=\${type}&url=\${encodeURIComponent(url)}&insert=false\`;
                urlEl.textContent = subUrl;
                urlEl.style.display = 'block';
                
                // 尝试唤起APP
                let scheme = '';
                if (type === 'clash') scheme = \`clash://install-config?url=\${encodeURIComponent(subUrl)}\`;
                else if (type === 'surge') scheme = \`surge:///install-config?url=\${encodeURIComponent(subUrl)}\`;
                
                if (scheme) {
                    tryOpenApp(scheme, () => {
                         navigator.clipboard.writeText(subUrl).then(() => alert('已尝试唤起APP，链接已复制'));
                    });
                } else {
                    navigator.clipboard.writeText(subUrl).then(() => alert('订阅链接已复制'));
                }
            }
        }
    </script>
</body>
</html>`;
}

// --- 6. Worker 入口 ---
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        
        if (path === '/' || path === '') {
            const scuValue = env?.scu || DEFAULT_SCU;
            return new Response(generateHomePage(scuValue), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }
        
        if (path === '/test-optimize-api') {
            const apiUrl = url.searchParams.get('url');
            if (!apiUrl) return new Response(JSON.stringify({ error: 'Missing url param' }), { headers: { 'Content-Type': 'application/json' } });
            try {
                const results = await fetchPreferredAPI([apiUrl]);
                return new Response(JSON.stringify({ success: true, count: results.length, results }), { headers: { 'Content-Type': 'application/json' } });
            } catch (e) {
                return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
            }
        }
        
        const pathMatch = path.match(/^\/([^\/]+)\/sub$/);
        if (pathMatch) {
            const uuid = pathMatch[1];
            const domain = url.searchParams.get('domain');
            
            if (!domain) return new Response('缺少域名参数', { status: 400 });

            const envParams = {
                user: uuid,
                domain: domain,
                workerDomain: url.hostname,
                scu: env?.scu || DEFAULT_SCU,
                epd: url.searchParams.get('epd') !== 'no',
                epi: url.searchParams.get('epi') !== 'no',
                egi: url.searchParams.get('egi') !== 'no',
                piu: url.searchParams.get('piu') || '',
                evEnabled: url.searchParams.get('ev') === 'yes' || (url.searchParams.get('ev') === null),
                etEnabled: url.searchParams.get('et') === 'yes',
                vmEnabled: url.searchParams.get('mess') === 'yes',
                ipv4Enabled: url.searchParams.get('ipv4') !== 'no',
                ipv6Enabled: url.searchParams.get('ipv6') !== 'no',
                ispMobile: url.searchParams.get('ispMobile') !== 'no',
                ispUnicom: url.searchParams.get('ispUnicom') !== 'no',
                ispTelecom: url.searchParams.get('ispTelecom') !== 'no',
                disableNonTLS: url.searchParams.get('dkby') === 'yes',
                customPath: url.searchParams.get('path') || '/',
                customPorts: (url.searchParams.get('ports') || '').split(',').map(s => parseInt((s || '').trim(), 10)).filter(n => Number.isFinite(n) && n > 0 && n < 65536)
            };
            return await handleSubscriptionRequest(request, envParams);
        }
        
        return new Response('Not Found', { status: 404 });
    }
};
