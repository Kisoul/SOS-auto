// Cloudflare Worker - 简化版优选工具 (完整修复版)
// 包含：并发修复、性能优化、以及完整的 UI 界面

// --- 常量定义 ---
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

// --- 辅助工具函数 ---

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
                    const ipIdx =
