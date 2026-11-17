// Cloudflare Worker - 简化版优选工具（支持 Clash 配置下拉选择 / 自定义远程远程配置文件）
// 逻辑：
// 1. 默认配置：使用 worker 自身的 Clash 生成逻辑
// 2. 内置配置：从 presetClashConfigMap 读取远程配置文件，交给订阅转换器 scu
// 3. 自定义配置：用户自行填写远程配置文件，交给订阅转换器 scu

let customPreferredIPs = [];
let customPreferredDomains = [];
let epd = true;
let epi = true;
let egi = true;
let ev = true;
let et = false;
let vm = false;
let scu = 'https://url.v1.mk/sub';

// 默认优选域名列表
const directDomains = [
  { domain: 'tel1.kisoul.org' },
  { domain: 'tel2.kisoul.org' },
  { domain: 'hkt1.kisoul.org' },
  { domain: 'hkt2.kisoul.org' },
  { domain: 'hku1.kisoul.org' }, 
  { domain: 'hku2.kisoul.org' },
  { domain: 'hkm1.kisoul.org' },
  { domain: 'hkm2.kisoul.org' },
  { domain: 'bn1.kisoul.org' },
  { domain: 'bn2.kisoul.org' },
  { domain: 'lgm1.kisoul.org' },
  { domain: 'lgm2.kisoul.org' },
  { domain: 'yg7.ygkkk.dpdns.org' },
  { domain: 'ys2046.cv' },
  { domain: 'cloudflare.182682.xyz' },
  { domain: 'freeyx.cloudflare88.eu.org' },
  { domain: 'bestcf.top' },
  { domain: 'cdn.2020111.xyz' },
  { domain: 'cf.0sm.com' },
  { domain: 'cf.090227.xyz' },
  { domain: 'cf.zhetengsha.eu.org' },
  { domain: 'cfip.1323123.xyz' },
  { domain: 'cloudflare-ip.mofashi.ltd' },
  { domain: 'cf.877771.xyz' },
  { domain: 'xn--b6gac.eu.org' },
  { domain: 'saas.sin.fan' },
  { domain: 'cfyx.aliyun.20237737.xyz' }
];

// 默认优选IP来源URL
const defaultIPURL = 'https://raw.githubusercontent.com/qwer-search/bestip/refs/heads/main/kejilandbestip.txt';

// 内置 远程配置文件 配置
const presetClashConfigMap = {
  acl_default: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini',
  acl_nospeed: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_NoSpeed.ini',
  acl_mini: 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Mini.ini',
  acl_Kisoul: 'https://raw.githubusercontent.com/Kisoul/Rulers/refs/heads/main/Kisoul.ini'
};

// UUID验证
function isValidUUID(str) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}

// 获取动态IP列表（支持IPv4/IPv6和运营商筛选）
async function fetchWetestIPs(ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
  const v4Url = 'https://www.wetest.vip/page/cloudflare/address_v4.html';
  const v6Url = 'https://www.wetest.vip/page/cloudflare/address_v6.html';
  let results = [];

  try {
    const fetchPromises = [];
    fetchPromises.push(ipv4Enabled ? fetchAndParseWetest(v4Url) : Promise.resolve([]));
    fetchPromises.push(ipv6Enabled ? fetchAndParseWetest(v6Url) : Promise.resolve([]));

    const [ipv4List, ipv6List] = await Promise.all(fetchPromises);
    results = [].concat(ipv4List, ipv6List);

    if (results.length > 0) {
      results = results.filter(item => {
        const isp = item.isp || '';
        if (isp.includes('移动') && !ispMobile) return false;
        if (isp.includes('联通') && !ispUnicom) return false;
        if (isp.includes('电信') && !ispTelecom) return false;
        return true;
      });
    }

    return results.length > 0 ? results : [];
  } catch (e) {
    return [];
  }
}

// 新动态 IP API 沿用上游签名协议；地址可覆盖，失败时保留 wetest 回退。
async function md5Hex(value) {
  const digest = await crypto.subtle.digest('MD5', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, params = new URLSearchParams()) {
  const options = [ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom];
  if (params.get('ipSource') === 'wetest') return fetchWetestIPs(...options);
  if (!ipv4Enabled && !ipv6Enabled) return [];
  try {
    const address = new URL(params.get('dynamicIPUrl') || 'https://api.uouin.com/index.php/index/Cloudflare');
    if (address.protocol !== 'https:') throw new Error('动态 IP API 必须使用 HTTPS');
    const time = String(Date.now());
    const inner = await md5Hex(atob('RGRsVHh0TjBzVU91'));
    address.searchParams.set('key', await md5Hex(inner + atob('NzBjbG91ZGZsYXJlYXBpa2V5') + time));
    address.searchParams.set('time', time);
    const response = await fetch(address.toString(), { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error('动态 IP API HTTP ' + response.status);
    const data = await response.json();
    if (!data.data || typeof data.data !== 'object') throw new Error('动态 IP API 格式无效');
    const groups = { ctcc: ['电信', ispTelecom], cucc: ['联通', ispUnicom], cmcc: ['移动', ispMobile],
      bgp: ['多线', ispMobile || ispUnicom || ispTelecom], ipv6: ['IPv6', ispMobile || ispUnicom || ispTelecom] };
    const results = [], seen = new Set();
    for (const [key, [isp, include]] of Object.entries(groups)) {
      if (!include || (key === 'ipv6' ? !ipv6Enabled : !ipv4Enabled)) continue;
      const entries = data.data[key]?.info;
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        const ip = String(entry?.ip || '').trim().replace(/^\[|\]$/g, '');
        if (!ip || !/^[0-9a-fA-F:.]+$/.test(ip)) continue;
        try { new URL('https://' + (ip.includes(':') ? '[' + ip + ']' : ip)); } catch { continue; }
        if (ip.includes(':') ? !ipv6Enabled : !ipv4Enabled) continue;
        if (seen.has(ip)) continue;
        seen.add(ip);
        results.push({ ip, isp, colo: String(results.length + 1).padStart(2, '0') });
      }
    }
    if (results.length) return results;
  } catch (error) { console.warn('动态 IP API 失败，将尝试 wetest:', error.message); }
  return params.get('ipFallback') === 'no' ? [] : fetchWetestIPs(...options);
}

function getECHOptions(params) {
  if (params.get('ech') !== 'yes') return null;
  const domain = params.get('customECHDomain') || 'cloudflare-ech.com';
  if (!/^(?=.{1,253}$)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$/.test(domain)) throw new Error('ECH 查询域名无效');
  const dns = new URL(params.get('customDNS') || 'https://dns.alidns.com/dns-query');
  if (dns.protocol !== 'https:' || dns.username || dns.password || dns.hash) throw new Error('ECH DNS 必须为不含凭据的 HTTPS DoH 地址');
  return { domain, dns: dns.toString() };
}

function addECHToLink(link, ech) {
  if (link.startsWith('vmess://')) {
    const data = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(link.slice(8)), c => c.charCodeAt(0))));
    data.ech = ech.domain + '+' + ech.dns;
    return 'vmess://' + btoa(Array.from(new TextEncoder().encode(JSON.stringify(data)), byte => String.fromCharCode(byte)).join(''));
  }
  const url = new URL(link);
  url.searchParams.set('ech', ech.domain + '+' + ech.dns);
  return url.toString();
}

// 解析 wetest 页面
async function fetchAndParseWetest(url) {
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(5000) });
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
  } catch (e) {
    return [];
  }
}

// 整理成数组
async function 整理成数组(content) {
  let s = content.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',');
  if (s.startsWith(',')) s = s.slice(1);
  if (s.endsWith(',')) s = s.slice(0, -1);
  return s.split(',');
}

// 请求优选API
async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000, reportFailure = false) {
  if (!urls || !urls.length) return [];
  const results = new Set();

  const outcomes = await Promise.allSettled(
    urls.map(async (url) => {
      try {
        const response = await fetch(url, { signal: AbortSignal.timeout(超时时间) });
        if (!response.ok) throw new Error('优选来源 HTTP ' + response.status);
        const buffer = await response.arrayBuffer();
        let text = '';
        {
          const contentType = (response.headers.get('content-type') || '').toLowerCase();
          const charset = (contentType.match(/charset=([^\s;]+)/i) || [])[1] || '';

          let decoders = ['utf-8', 'gb2312'];
          if (charset && /gb|gbk|gb2312/i.test(charset)) {
            decoders = ['gb2312', 'utf-8'];
          }

          let decodeSuccess = false;
          for (const decoder of decoders) {
            try {
              const decoded = new TextDecoder(decoder).decode(buffer);
              if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
                text = decoded;
                decodeSuccess = true;
                break;
              }
            } catch (e) {}
          }

          if (!decodeSuccess) text = new TextDecoder().decode(buffer);
        }
        if (!text.trim()) return;

        const lines = text.trim().split('\n').map(l => l.trim()).filter(Boolean);
        const isCSV = lines.length > 1 && lines[0].includes(',');
        const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;

        if (!isCSV) {
          lines.forEach(line => {
            const hashIndex = line.indexOf('#');
            const hostPart = hashIndex > -1 ? line.substring(0, hashIndex) : line;
            const remark = hashIndex > -1 ? line.substring(hashIndex) : '';

            let hasPort = false;
            if (hostPart.startsWith('[')) {
              hasPort = /\]:(\d+)$/.test(hostPart);
            } else {
              const colonIndex = hostPart.lastIndexOf(':');
              hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
            }

            const port = new URL(url).searchParams.get('port') || 默认端口;
            results.add(hasPort ? line : hostPart + ':' + port + remark);
          });
        } else {
          const headers = lines[0].split(',').map(h => h.trim());
          const dataLines = lines.slice(1);

          if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
            const ipIdx = headers.indexOf('IP地址');
            const portIdx = headers.indexOf('端口');
            const remarkIdx = headers.indexOf('国家') > -1
              ? headers.indexOf('国家')
              : headers.indexOf('城市') > -1
                ? headers.indexOf('城市')
                : headers.indexOf('数据中心');
            const tlsIdx = headers.indexOf('TLS');

            dataLines.forEach(line => {
              const cols = line.split(',').map(c => c.trim());
              if (tlsIdx !== -1 && cols[tlsIdx] && cols[tlsIdx].toLowerCase() !== 'true') return;
              const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? '[' + cols[ipIdx] + ']' : cols[ipIdx];
              results.add(wrappedIP + ':' + cols[portIdx] + '#' + cols[remarkIdx]);
            });
          } else if (
            headers.some(h => h.includes('IP')) &&
            headers.some(h => h.includes('延迟')) &&
            headers.some(h => h.includes('下载速度'))
          ) {
            const ipIdx = headers.findIndex(h => h.includes('IP'));
            const delayIdx = headers.findIndex(h => h.includes('延迟'));
            const speedIdx = headers.findIndex(h => h.includes('下载速度'));
            const port = new URL(url).searchParams.get('port') || 默认端口;

            dataLines.forEach(line => {
              const cols = line.split(',').map(c => c.trim());
              const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? '[' + cols[ipIdx] + ']' : cols[ipIdx];
              results.add(wrappedIP + ':' + port + '#CF优选 ' + cols[delayIdx] + 'ms ' + cols[speedIdx] + 'MB/s');
            });
          }
        }
      } catch (error) {
        if (reportFailure) throw error;
      }
    })
  );

  if (reportFailure) {
    const failure = outcomes.find(outcome => outcome.status === 'rejected');
    if (failure) throw failure.reason;
  }
  return Array.from(results);
}

// 解析单行优选记录
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
      const name = (cc && remark) ? (cc + '-' + remark) : (remark || cc || ipRaw);
      return { ip: ipRaw, port: port, name: name };
    }
  }

  const m = s.match(/^(\[[^\]]+\]|[^:#]+):(\d+)(?:#(.*))?$/);
  if (m) {
    const ipRaw = m[1].replace(/[\[\]]/g, '');
    const port = parseInt(m[2], 10);
    if (!Number.isFinite(port) || port <= 0 || port >= 65536) return null;
    const remark = (m[3] || '').trim();
    return { ip: ipRaw, port: port, name: remark || ipRaw };
  }

  return null;
}

// 从 GitHub 获取优选 IP
async function fetchAndParseNewIPs(piu) {
  const url = piu || defaultIPURL;

  function isIPv4(s) {
    const parts = s.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => {
      if (!/^\d+$/.test(p)) return false;
      const n = Number(p);
      return n >= 0 && n <= 255;
    });
  }

  function isIPv6(s) {
    const v = s.replace(/^\[|\]$/g, '');
    return v.includes(':') && /^[0-9a-fA-F:]+$/.test(v);
  }

  function makeDefaultItem(ip) {
    const clean = ip.replace(/^\[|\]$/g, '').trim();
    if (!clean) return null;

    if (isIPv4(clean) || isIPv6(clean)) {
      return {
        ip: clean,
        port: 443,
        name: clean
      };
    }

    return null;
  }

  try {
    const response = await fetch(url);
    if (!response.ok) return [];

    const text = await response.text();
    const lines = text
      .replace(/\r/g, '\n')
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    const results = [];

    for (const line of lines) {
      if (!line || line.startsWith('#') || line.startsWith('//')) continue;

      // 1. 先走原来的解析逻辑，保证继续支持：
      //    IP:端口#备注
      //    IP,端口,地区,备注
      const parsed = parsePreferredLine(line);
      if (parsed) {
        results.push(parsed);
        continue;
      }

      // 2. 原格式解析失败后，再兼容一整行裸 IP：
      //    IP1,IP2,IP3
      const parts = line
        .split(/[，,;\s]+/)
        .map(s => s.trim())
        .filter(Boolean);

      for (const part of parts) {
        const item = makeDefaultItem(part);
        if (item) results.push(item);
      }
    }

    return results;
  } catch (e) {
    return [];
  }
}

// 生成 VLESS 链接
function generateLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', customPorts = [], transport = 'ws') {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const defaultHttpsPorts = [443];
  const defaultHttpPorts = disableNonTLS ? [] : [80];
  const links = [];
  const wsPath = customPath || '/';
  const proto = 'vless';

  list.forEach(item => {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
    if (item.colo && item.colo.trim()) {
      nodeNameBase = nodeNameBase + '-' + item.colo.trim();
    }

    const safeIP = item.ip.includes(':') ? '[' + item.ip + ']' : item.ip;
    let portsToGenerate = [];
    const useCustom = Array.isArray(customPorts) && customPorts.length > 0;

    if (useCustom) {
      customPorts.forEach(port => {
        const isHttp = CF_HTTP_PORTS.includes(port);
        const isHttps = CF_HTTPS_PORTS.includes(port);
        if (disableNonTLS && isHttp) return;
        if (isHttps) portsToGenerate.push({ port: port, tls: true });
        else if (isHttp) portsToGenerate.push({ port: port, tls: false });
        else portsToGenerate.push({ port: port, tls: true });
      });
    } else if (item.port) {
      const port = item.port;
      const isHttp = CF_HTTP_PORTS.includes(port);
      const isHttps = CF_HTTPS_PORTS.includes(port);
      if (disableNonTLS && isHttp) return;
      if (isHttps) portsToGenerate.push({ port: port, tls: true });
      else if (isHttp) portsToGenerate.push({ port: port, tls: false });
      else portsToGenerate.push({ port: port, tls: true });
    } else {
      defaultHttpsPorts.forEach(port => portsToGenerate.push({ port: port, tls: true }));
      defaultHttpPorts.forEach(port => portsToGenerate.push({ port: port, tls: false }));
    }

    portsToGenerate.forEach(({ port, tls }) => {
      if (tls) {
        const wsNodeName = nodeNameBase + '-' + port + '-' + transport.toUpperCase() + '-TLS';
        const wsParams = new URLSearchParams({
          encryption: 'none',
          security: 'tls',
          sni: workerDomain,
          fp: 'chrome',
          type: transport,
          host: workerDomain,
          path: wsPath
        });
        if (transport === 'xhttp') wsParams.set('mode', 'packet-up');
        links.push(proto + '://' + user + '@' + safeIP + ':' + port + '?' + wsParams.toString() + '#' + encodeURIComponent(wsNodeName));
      } else {
        const wsNodeName = nodeNameBase + '-' + port + '-' + transport.toUpperCase();
        const wsParams = new URLSearchParams({
          encryption: 'none',
          security: 'none',
          type: transport,
          host: workerDomain,
          path: wsPath
        });
        if (transport === 'xhttp') wsParams.set('mode', 'packet-up');
        links.push(proto + '://' + user + '@' + safeIP + ':' + port + '?' + wsParams.toString() + '#' + encodeURIComponent(wsNodeName));
      }
    });
  });

  return links;
}

// 生成 Trojan 链接
async function generateTrojanLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', customPorts = []) {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const defaultHttpsPorts = [443];
  const defaultHttpPorts = disableNonTLS ? [] : [80];
  const links = [];
  const wsPath = customPath || '/';
  const password = user;

  list.forEach(item => {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
    if (item.colo && item.colo.trim()) {
      nodeNameBase = nodeNameBase + '-' + item.colo.trim();
    }

    const safeIP = item.ip.includes(':') ? '[' + item.ip + ']' : item.ip;
    let portsToGenerate = [];
    const useCustom = Array.isArray(customPorts) && customPorts.length > 0;

    if (useCustom) {
      customPorts.forEach(port => {
        const isHttp = CF_HTTP_PORTS.includes(port);
        const isHttps = CF_HTTPS_PORTS.includes(port);
        if (disableNonTLS && isHttp) return;
        if (isHttps) portsToGenerate.push({ port: port, tls: true });
        else if (isHttp) portsToGenerate.push({ port: port, tls: false });
        else portsToGenerate.push({ port: port, tls: true });
      });
    } else if (item.port) {
      const port = item.port;
      const isHttp = CF_HTTP_PORTS.includes(port);
      const isHttps = CF_HTTPS_PORTS.includes(port);
      if (disableNonTLS && isHttp) return;
      if (isHttps) portsToGenerate.push({ port: port, tls: true });
      else if (isHttp) portsToGenerate.push({ port: port, tls: false });
      else portsToGenerate.push({ port: port, tls: true });
    } else {
      defaultHttpsPorts.forEach(port => portsToGenerate.push({ port: port, tls: true }));
      defaultHttpPorts.forEach(port => portsToGenerate.push({ port: port, tls: false }));
    }

    portsToGenerate.forEach(({ port, tls }) => {
      if (tls) {
        const wsNodeName = nodeNameBase + '-' + port + '-Trojan-WS-TLS';
        const wsParams = new URLSearchParams({
          security: 'tls',
          sni: workerDomain,
          fp: 'chrome',
          type: 'ws',
          host: workerDomain,
          path: wsPath
        });
        links.push('trojan://' + password + '@' + safeIP + ':' + port + '?' + wsParams.toString() + '#' + encodeURIComponent(wsNodeName));
      } else {
        const wsNodeName = nodeNameBase + '-' + port + '-Trojan-WS';
        const wsParams = new URLSearchParams({
          security: 'none',
          type: 'ws',
          host: workerDomain,
          path: wsPath
        });
        links.push('trojan://' + password + '@' + safeIP + ':' + port + '?' + wsParams.toString() + '#' + encodeURIComponent(wsNodeName));
      }
    });
  });

  return links;
}

// 生成 VMess 链接
function generateVMessLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', customPorts = []) {
  const CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  const CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
  const defaultHttpsPorts = [443];
  const defaultHttpPorts = disableNonTLS ? [] : [80];
  const links = [];
  const wsPath = customPath || '/';

  list.forEach(item => {
    let nodeNameBase = item.isp ? item.isp.replace(/\s/g, '_') : (item.name || item.domain || item.ip);
    if (item.colo && item.colo.trim()) {
      nodeNameBase = nodeNameBase + '-' + item.colo.trim();
    }

    const safeIP = item.ip.includes(':') ? '[' + item.ip + ']' : item.ip;
    let portsToGenerate = [];
    const useCustom = Array.isArray(customPorts) && customPorts.length > 0;

    if (useCustom) {
      customPorts.forEach(port => {
        const isHttp = CF_HTTP_PORTS.includes(port);
        const isHttps = CF_HTTPS_PORTS.includes(port);
        if (disableNonTLS && isHttp) return;
        if (isHttps) portsToGenerate.push({ port: port, tls: true });
        else if (isHttp) portsToGenerate.push({ port: port, tls: false });
        else portsToGenerate.push({ port: port, tls: true });
      });
    } else if (item.port) {
      const port = item.port;
      const isHttp = CF_HTTP_PORTS.includes(port);
      const isHttps = CF_HTTPS_PORTS.includes(port);
      if (disableNonTLS && isHttp) return;
      if (isHttps) portsToGenerate.push({ port: port, tls: true });
      else if (isHttp) portsToGenerate.push({ port: port, tls: false });
      else portsToGenerate.push({ port: port, tls: true });
    } else {
      defaultHttpsPorts.forEach(port => portsToGenerate.push({ port: port, tls: true }));
      defaultHttpPorts.forEach(port => portsToGenerate.push({ port: port, tls: false }));
    }

    portsToGenerate.forEach(({ port, tls }) => {
      const vmessConfig = {
        v: '2',
        ps: tls ? (nodeNameBase + '-' + port + '-VMess-WS-TLS') : (nodeNameBase + '-' + port + '-VMess-WS'),
        add: safeIP,
        port: String(port),
        id: user,
        aid: '0',
        scy: 'auto',
        net: 'ws',
        type: 'none',
        host: workerDomain,
        path: wsPath,
        tls: tls ? 'tls' : 'none'
      };

      if (tls) {
        vmessConfig.sni = workerDomain;
        vmessConfig.fp = 'chrome';
      }

      const jsonStr = JSON.stringify(vmessConfig);
      const vmessBase64 = btoa(
        encodeURIComponent(jsonStr).replace(/%([0-9A-F]{2})/g, function (_, p1) {
          return String.fromCharCode('0x' + p1);
        })
      );
      links.push('vmess://' + vmessBase64);
    });
  });

  return links;
}

// Mihomo XHTTP treats Path as a URL path, unlike Xray's path/query split.
// Strip only the inherited numeric WS early-data option; reject other query/fragment input.
function normalizeMihomoXHTTPPath(value) {
  const path = String(value || '/');
  if (!path.startsWith('/') || path.includes('#')) throw new Error('Mihomo XHTTP 请使用以 / 开头且不含片段的纯路径');
  const q = path.indexOf('?');
  if (q < 0) return path;
  const params = new URLSearchParams(path.slice(q + 1));
  if ([...params].length && [...params].every(([key, value]) => key === 'ed' && /^\d+$/.test(value))) return path.slice(0, q) || '/';
  throw new Error('Mihomo XHTTP 不支持此路径查询参数，请填写纯路径，例如 / 或 /xhttp');
}

function getMihomoXHTTPOptions(params) {
  const mode = params.get('xhttpMode') || 'auto';
  const padding = params.get('xhttpPaddingBytes') || '100-1000';
  if (!['auto', 'stream-one', 'stream-up', 'packet-up'].includes(mode)) throw new Error('无效的 Mihomo XHTTP mode');
  const range = padding.split('-');
  if (range.length !== 2 || range.some(n => !/^\d+$/.test(n) || !Number.isSafeInteger(Number(n))) || Number(range[0]) > Number(range[1]) || Number(range[1]) > 1000000) throw new Error('无效的 XHTTP padding 范围');
  return { mode, padding };
}

// YAML 字符串转义
function escapeYamlString(str) {
  const s = String(str == null ? '' : str);
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function parseSubscriptionNode(link) {
  if (link.startsWith('vmess://')) {
    const bytes = Uint8Array.from(atob(link.slice(8)), character => character.charCodeAt(0));
    const vmess = JSON.parse(new TextDecoder().decode(bytes));
    return {
      type: 'vmess', name: vmess.ps, server: vmess.add.replace(/^\[|\]$/g, ''),
      port: Number(vmess.port), credential: vmess.id, tls: vmess.tls === 'tls',
      sni: vmess.sni, host: vmess.host, path: vmess.path || '/', ech: vmess.ech
    };
  }
  const url = new URL(link);
  const params = url.searchParams;
  return {
    type: url.protocol.slice(0, -1), name: decodeURIComponent(url.hash.slice(1)),
    server: url.hostname.replace(/^\[|\]$/g, ''), port: Number(url.port),
    credential: decodeURIComponent(url.username), tls: params.get('security') === 'tls',
    sni: params.get('sni'), host: params.get('host') || '', path: params.get('path') || '/',
    transport: params.get('type'), ech: params.get('ech')
  };
}

// 生成 Clash 配置（默认方案）
function generateClashConfig(links, params = new URLSearchParams()) {
  const enabled = (name, fallback) => params.has(name)
    ? ['true', 'yes', '1'].includes(params.get(name).toLowerCase()) : fallback;
  const nativeOptions = params.get('client') !== 'stash';
  // Current Mihomo forces XUDP for VLESS unless packetaddr is selected.
  // Do not silently replace it with another server-dependent UDP encoding.
  if (nativeOptions && links.some(link => link.startsWith('vless://'))
    && params.has('xudp') && !enabled('xudp', true) && enabled('udp', true)) {
    throw new Error('当前 Mihomo VLESS 实现不能单独关闭 XUDP；可关闭 UDP，或使用明确支持 packetaddr 的其他配置');
  }
  let yaml = 'port: 7890\n';
  yaml += 'socks-port: 7891\n';
  yaml += 'allow-lan: false\n';
  yaml += 'mode: rule\n';
  yaml += 'log-level: info\n\n';
  yaml += 'proxies:\n';

  const nodes = links.flatMap((link, index) => {
    const node = parseSubscriptionNode(link);
    if (node.type === 'trojan' && !node.tls) return [];
    node.name ||= '节点' + (index + 1);
    return [node];
  });
  const reservedNames = new Set(nodes.map(node => node.name));
  const nextSuffix = new Map();
  const proxyNames = [];

  nodes.forEach(({ type, server, port, credential, tls, path, host, sni, transport, ech, name: baseName }) => {
    let name = baseName;
    let suffix = nextSuffix.get(baseName) || 1;
    if (suffix > 1) {
      do {
        name = baseName + ' (' + suffix++ + ')';
      } while (reservedNames.has(name));
    }
    nextSuffix.set(baseName, Math.max(2, suffix));
    proxyNames.push(name);

    yaml += '  - name: ' + escapeYamlString(name) + '\n';
    yaml += '    type: ' + type + '\n';
    yaml += '    server: ' + (server.includes(':') ? escapeYamlString(server) : server) + '\n';
    yaml += '    port: ' + port + '\n';
    if (type === 'trojan') yaml += '    password: ' + escapeYamlString(credential) + '\n';
    else yaml += '    uuid: ' + credential + '\n';
    if (type === 'vmess') yaml += '    alterId: 0\n    cipher: auto\n';
    if (type !== 'trojan') yaml += '    tls: ' + tls + '\n';
    if (nativeOptions) {
      if (params.has('udp')) yaml += '    udp: ' + enabled('udp', true) + '\n';
      if (params.has('tfo')) yaml += '    tfo: ' + enabled('tfo', true) + '\n';
      if (tls && params.has('scv')) yaml += '    skip-cert-verify: ' + enabled('scv', false) + '\n';
      if (type === 'vless' && params.has('xudp') && enabled('udp', true)) yaml += '    packet-encoding: xudp\n';
    }
    if (type === 'vless' && transport === 'xhttp') {
      yaml += '    network: xhttp\n';
      yaml += '    xhttp-opts:\n';
      yaml += '      path: ' + escapeYamlString(normalizeMihomoXHTTPPath(path)) + '\n';
      yaml += '      host: ' + escapeYamlString(host) + '\n';
      if (nativeOptions) {
        const options = getMihomoXHTTPOptions(params);
        yaml += '      mode: ' + options.mode + '\n';
        yaml += '      x-padding-bytes: ' + JSON.stringify(options.padding) + '\n';
      } else yaml += '      mode: packet-up\n';
    } else {
      yaml += '    network: ws\n';
      yaml += '    ws-opts:\n';
      yaml += '      path: ' + escapeYamlString(path) + '\n';
      yaml += '      headers:\n';
      yaml += '        Host: ' + escapeYamlString(host) + '\n';
    }
    if (sni) yaml += '    ' + (type === 'trojan' ? 'sni' : 'servername') + ': ' + escapeYamlString(sni) + '\n';
    if (ech) {
      yaml += '    ech-opts:\n      enable: true\n      query-server-name: ' + escapeYamlString(ech.split('+')[0]) + '\n';
    }
  });

  yaml += '\nproxy-groups:\n';
  yaml += '  - name: PROXY\n';
  yaml += '    type: select\n';
  yaml += '    proxies: [' + proxyNames.map(name => "'" + name.replace(/'/g, "''") + "'").join(', ') + ']\n';

  yaml += '\nrules:\n';
  yaml += '  - DOMAIN-SUFFIX,local,DIRECT\n';
  yaml += '  - IP-CIDR,127.0.0.0/8,DIRECT\n';
  yaml += '  - GEOIP,CN,DIRECT\n';
  yaml += '  - MATCH,PROXY\n';

  if (!nodes.length) throw new Error('没有可用的 Clash 节点，Trojan 需要 TLS 端口');
  if (params.get('client') === 'stash') return yaml;
  const config = {};
  applyMihomoDNS(config, getECHOptions(params));
  return yaml + '\n' + clashYAML.dump(config);
}

// 生成 Surge 配置
function generateSurgeConfig(links) {
  const vlessLinks = links.filter(link => link.startsWith('vless://'));
  let config = '[Proxy]\n';

  vlessLinks.forEach((link, i) => {
    const { name, server, port, credential, tls, path, host } = parseSubscriptionNode(link);
    config += (name || '节点' + (i + 1)) + ' = vless, ' + server + ', ' + port + ', username=' + credential + ', tls=' + tls + ', ws=true, ws-path=' + path + ', ws-headers=Host:' + host + '\n';
  });

  config += '\n[Proxy Group]\nPROXY = select, ' + vlessLinks.map((link, i) => decodeURIComponent((link.split('#')[1]) || ('节点' + (i + 1)))).join(', ') + '\n';
  return config;
}

// 生成 Quantumult 配置
function generateQuantumultConfig(links) {
  return btoa(links.join('\n'));
}

// 原生 sing-box 1.14 配置；复用生成后的节点，避免两套节点参数逻辑。
function generateSingBoxConfig(links, params) {
  const ech = getECHOptions(params);
  const enabled = (name, fallback = true) => params.has(name)
    ? ['true', 'yes', '1'].includes(params.get(name).toLowerCase()) : fallback;
  const tags = new Set(['PROXY', 'AUTO', 'DIRECT']);
  const nodes = links.map(link => {
    let type, server, port, credential, name, tls, sni, fingerprint, host, path;
    if (link.startsWith('vmess://')) {
      const bytes = Uint8Array.from(atob(link.slice(8)), c => c.charCodeAt(0));
      const v = JSON.parse(new TextDecoder().decode(bytes));
      type = 'vmess'; server = v.add; port = Number(v.port); credential = v.id;
      name = v.ps; tls = v.tls === 'tls'; sni = v.sni || v.host;
      fingerprint = v.fp; host = v.host; path = v.path || '/';
    } else {
      const v = new URL(link);
      type = v.protocol.slice(0, -1); server = v.hostname; port = Number(v.port);
      credential = decodeURIComponent(v.username); name = decodeURIComponent(v.hash.slice(1));
      tls = v.searchParams.get('security') === 'tls';
      sni = v.searchParams.get('sni'); fingerprint = v.searchParams.get('fp');
      host = v.searchParams.get('host'); path = v.searchParams.get('path') || '/';
    }
    server = server.replace(/^\[|\]$/g, '');
    if (!['vless', 'trojan', 'vmess'].includes(type) || !server || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('无效的 sing-box 节点');
    }
    const baseTag = name || server + ':' + port;
    let tag = baseTag, suffix = 2;
    while (tags.has(tag)) tag = baseTag + ' (' + suffix++ + ')';
    tags.add(tag);
    const transport = { type: 'ws', path, headers: host ? { Host: host } : {} };
    // Xray 的 ?ed= 参数在 sing-box 中需要转换成独立的早期数据字段。
    const wsUrl = new URL(path, 'https://ws.invalid');
    const earlyData = wsUrl.searchParams.get('ed');
    if (earlyData !== null && /^\d+$/.test(earlyData) && Number(earlyData) > 0) {
      wsUrl.searchParams.delete('ed');
      transport.path = wsUrl.pathname + wsUrl.search + wsUrl.hash;
      transport.max_early_data = Number(earlyData);
      transport.early_data_header_name = 'Sec-WebSocket-Protocol';
    }
    const node = { type, tag, server, server_port: port, transport,
      tcp_fast_open: enabled('tfo'), domain_resolver: 'dns-direct' };
    if (type === 'trojan') node.password = credential;
    else node.uuid = credential;
    if (type === 'vmess') { node.security = 'auto'; node.alter_id = 0; }
    if (!enabled('udp')) node.network = 'tcp';
    if (type === 'vless') node.packet_encoding = enabled('udp') && enabled('xudp') ? 'xudp' : '';
    if (tls) {
      node.tls = { enabled: true, server_name: sni || host || server,
        insecure: enabled('scv', false) };
      if (fingerprint) node.tls.utls = { enabled: true, fingerprint };
      if (ech) node.tls.ech = { enabled: true, query_server_name: ech.domain };
    }
    return node;
  });
  if (!nodes.length) throw new Error('没有可用节点');
  const nodeTags = nodes.map(node => node.tag);
  const config = {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { type: 'local', tag: 'dns-direct' },
        { type: 'https', tag: 'dns-proxy', server: '1.1.1.1', path: '/dns-query', detour: 'PROXY' }
      ],
      final: 'dns-proxy', strategy: params.get('ipv6') === 'no' ? 'ipv4_only' : 'prefer_ipv4'
    },
    inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'],
      auto_route: true, strict_route: true, stack: 'mixed' }],
    outbounds: [
      { type: 'selector', tag: 'PROXY', outbounds: ['AUTO', ...nodeTags, 'DIRECT'], default: 'AUTO' },
      { type: 'urltest', tag: 'AUTO', outbounds: nodeTags,
        url: 'https://www.gstatic.com/generate_204', interval: '3m', tolerance: 50 },
      { type: 'direct', tag: 'DIRECT', domain_resolver: 'dns-direct' },
      ...nodes
    ],
    route: { auto_detect_interface: true, default_domain_resolver: 'dns-direct',
      rules: [
        { protocol: 'dns', action: 'hijack-dns' },
        { ip_is_private: true, action: 'route', outbound: 'DIRECT' }
      ], final: 'PROXY' }
  };
  if (ech) {
    const dns = new URL(ech.dns);
    config.dns.servers.push({ type: 'https', tag: 'dns-ech', server: dns.hostname,
      server_port: Number(dns.port || 443), path: dns.pathname + dns.search, domain_resolver: 'dns-direct' });
    // ECH 配置查询走直连 DoH，避免建立代理之前又依赖代理的循环。
    config.dns.rules = [{ domain: [ech.domain], query_type: ['HTTPS'], action: 'route', server: 'dns-ech' }];
  }
  return JSON.stringify(config, null, 2);
}

// 有限缓存远程模板/规则，避免每次刷新重复下载；失败不缓存。
const singBoxTemplateCache = new Map();
async function fetchSingBoxTemplateText(address) {
  if (new URL(address).protocol !== 'https:') throw new Error('模板和规则地址必须使用 HTTPS');
  const cached = singBoxTemplateCache.get(address);
  if (cached && cached.expires > Date.now()) return cached.text;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(address, { signal: controller.signal });
    if (!response.ok) throw new Error('远程文件 HTTP ' + response.status + ': ' + address);
    const text = await response.text();
    if (singBoxTemplateCache.size >= 64) singBoxTemplateCache.delete(singBoxTemplateCache.keys().next().value);
    singBoxTemplateCache.set(address, { text, expires: Date.now() + 300000 });
    return text;
  } finally { clearTimeout(timer); }
}

async function applySingBoxTemplate(config, params) {
  const mode = params.get('config_mode');
  if (mode && mode !== 'default' && !presetClashConfigMap[mode] && !params.get('config')) throw new Error('未知模板模式: ' + mode);
  const templateUrl = params.get('config') || presetClashConfigMap[params.get('config_mode')];
  if (!templateUrl) return { config, skipped: 0 };
  const ini = await fetchSingBoxTemplateText(templateUrl);
  const groupDefs = [], ruleDefs = [];
  let customSection = false;
  for (const raw of ini.split(/\r?\n/)) {
    const line = raw.trim().replace(/^\uFEFF/, '');
    if (!line || /^[;#]/.test(line)) continue;
    if (line.startsWith('[')) { customSection = line.toLowerCase() === '[custom]'; continue; }
    if (!customSection) continue;
    if (line.startsWith('custom_proxy_group=')) groupDefs.push(line.slice(19).split('`'));
    if (line.startsWith('ruleset=')) {
      const value = line.slice(8), comma = value.indexOf(',');
      if (comma < 0) throw new Error('无效 ruleset 定义');
      ruleDefs.push({ policy: value.slice(0, comma).trim(), source: value.slice(comma + 1).trim() });
    }
  }
  if (!groupDefs.length || !ruleDefs.length) throw new Error('模板缺少 [custom] 分组或 ruleset');
  const names = new Set(['DIRECT', 'REJECT']);
  for (const [name, type] of groupDefs) {
    if (!name || names.has(name)) throw new Error('重复或保留的分组名称: ' + name);
    if (!['select', 'url-test'].includes(type)) throw new Error('暂不支持分组类型: ' + type);
    names.add(name);
  }
  const nodes = config.outbounds.filter(node => ['vless', 'trojan', 'vmess'].includes(node.type));
  for (const node of nodes) {
    const base = node.tag; let suffix = 2;
    while (names.has(node.tag)) node.tag = base + ' (' + suffix++ + ')';
    names.add(node.tag);
  }
  const groups = groupDefs.map(parts => {
    const [tag, type] = parts;
    const filters = type === 'url-test' ? parts.slice(2, -2) : parts.slice(2);
    const choices = [];
    for (const filter of filters) {
      if (filter.startsWith('[]')) {
        const choice = filter.slice(2);
        if (!names.has(choice)) throw new Error('未知分组引用: ' + choice);
        choices.push(choice);
      } else {
        const regex = new RegExp(filter);
        choices.push(...nodes.filter(node => regex.test(node.tag)).map(node => node.tag));
      }
    }
    const outbounds = [...new Set(choices)];
    if (!outbounds.length) throw new Error('分组没有匹配节点: ' + tag);
    if (type === 'select') return { type: 'selector', tag, outbounds, default: outbounds[0] };
    const timing = parts[parts.length - 1].split(',');
    const seconds = Number(timing[0]), tolerance = Number(timing[2] || 50);
    if (!Number.isFinite(seconds) || seconds <= 0 || !Number.isFinite(tolerance) || tolerance < 0) throw new Error('无效测速参数');
    return { type: 'urltest', tag, outbounds, url: parts[parts.length - 2], interval: seconds + 's', tolerance };
  });
  const groupMap = new Map(groups.map(group => [group.tag, group]));
  function checkCycles(tag, path = new Set()) {
    if (!groupMap.has(tag)) return;
    if (path.has(tag)) throw new Error('分组循环引用: ' + tag);
    for (const child of groupMap.get(tag).outbounds) checkCycles(child, new Set([...path, tag]));
  }
  groups.forEach(group => checkCycles(group.tag));
  const sources = [...new Set(ruleDefs.map(rule => rule.source).filter(source => !source.startsWith('[]')))];
  if (sources.length > 40) throw new Error('远程规则来源不能超过 40 个');
  const texts = new Map();
  // 分批请求限制并发数，同时保持后续路由规则的模板顺序。
  for (let index = 0; index < sources.length; index += 4) {
    await Promise.all(sources.slice(index, index + 4).map(async source => {
      texts.set(source, await fetchSingBoxTemplateText(source));
    }));
  }
  const rules = [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' },
    { action: 'resolve', server: 'dns-proxy' }];
  const ruleSets = [];
  let final = groups[0].tag, skipped = 0;
  for (const definition of ruleDefs) {
    if (!names.has(definition.policy)) throw new Error('未知规则分组: ' + definition.policy);
    const buckets = {};
    const lines = definition.source.startsWith('[]') ? [definition.source.slice(2)] : texts.get(definition.source).split(/\r?\n/);
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || /^[#;]/.test(line)) continue;
      const [kind, value] = line.split(',').map(part => part.trim());
      if (kind === 'FINAL' || kind === 'MATCH') { final = definition.policy; continue; }
      // URL 路径是 HTTP 应用层信息，无法在 TUN 路由中等价匹配。
      if (kind === 'URL-REGEX') { skipped++; continue; }
      if (kind === 'GEOIP') {
        if (value === 'LAN' || value === 'private') buckets.ip_is_private = true;
        else {
          if (!/^[a-z]{2}$/i.test(value)) throw new Error('不支持 GEOIP: ' + value);
          const geo = JSON.parse(await fetchSingBoxTemplateText('https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/' + value.toLowerCase() + '.json'));
          for (const rule of geo.rules || []) if (rule.ip_cidr) (buckets.ip_cidr ||= []).push(...rule.ip_cidr);
        }
        continue;
      }
      const field = { 'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword',
        'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'PROCESS-NAME': 'process_name' }[kind];
      if (!field || !value) throw new Error('暂不支持规则: ' + line);
      (buckets[field] ||= []).push(field === 'domain_suffix' ? value.replace(/^\./, '') : value);
    }
    const headless = Object.entries(buckets).map(([field, values]) => ({ [field]: Array.isArray(values) ? [...new Set(values)] : values }));
    if (headless.length) {
      const tag = 'template-rule-' + ruleSets.length;
      ruleSets.push({ type: 'inline', tag, rules: headless });
      rules.push({ rule_set: tag, action: 'route', outbound: definition.policy });
    }
  }
  config.outbounds = [...groups, { type: 'direct', tag: 'DIRECT', domain_resolver: 'dns-direct' },
    { type: 'block', tag: 'REJECT' }, ...nodes];
  config.dns.servers.find(server => server.tag === 'dns-proxy').detour = groups[0].tag;
  config.route.rules = rules;
  config.route.rule_set = ruleSets;
  config.route.final = final;
  config.experimental = { cache_file: { enabled: true }, clash_api: {} };
  return { config, skipped };
}

// 生成订阅内容
async function handleSubscriptionRequest(request, user, customDomain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, customPorts = []) {
  const url = new URL(request.url);
  let ech;
  try { ech = getECHOptions(url.searchParams); } catch (error) {
    return new Response(error.message, { status: 400 });
  }
  if (ech) disableNonTLS = true;
  // 每次请求独立读取来源开关，避免并发订阅互相覆盖全局状态。
  const epd = url.searchParams.get('epd') !== 'no';
  const epi = url.searchParams.get('epi') !== 'no';
  const egi = url.searchParams.get('egi') !== 'no';
  const finalLinks = [];
  const workerDomain = url.hostname;
  const nodeDomain = customDomain || url.hostname;
  const target = (url.searchParams.get('target') || 'base64').toLowerCase();
  const wsPath = customPath || '/';
  // Unknown clients and every converter path use WS. Explicit capability confirmation is required.
  let transport = 'ws';
  const requestedXHTTP = url.searchParams.get('transport') === 'xhttp';
  const confirmedXHTTP = url.searchParams.get('xhttpReady') === 'yes';
  if (requestedXHTTP && confirmedXHTTP) {
    const client = url.searchParams.get('client');
    const rawCompatible = ['v2ray', 'v2rayng', 'shadowrocket'].includes(client);
    const yamlCompatible = ['mihomo', 'stash'].includes(client);
    if (target === 'base64' && rawCompatible) transport = 'xhttp';
    if (target === 'clash' && yamlCompatible) transport = 'xhttp';
  }

  async function addNodesFromList(list) {
    const useVL = evEnabled;

    if (useVL) finalLinks.push(...generateLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts, transport));
    if (etEnabled) finalLinks.push(...await generateTrojanLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts));
    if (vmEnabled) finalLinks.push(...generateVMessLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts));
  }

  if (!evEnabled && !etEnabled && !vmEnabled) return new Response('请至少选择一个协议', { status: 400 });

  await addNodesFromList([{ ip: workerDomain, isp: '原生地址' }]);

  if (epd) {
    const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
    await addNodesFromList(domainList);
  }

  if (epi) {
    try {
      const dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, url.searchParams);
      if (dynamicIPList.length > 0) await addNodesFromList(dynamicIPList);
    } catch (error) {
      console.error('获取动态IP失败:', error);
    }
  }

  if (egi) {
    try {
      if (piu && piu.toLowerCase().startsWith('https://')) {
        const newIPList = await fetchAndParseNewIPs(piu);
        if (newIPList.length > 0) {
          await addNodesFromList(newIPList);
        } else {
          const apiIPs = await 请求优选API([piu]);
          if (apiIPs && apiIPs.length > 0) {
            const ipList = apiIPs.map(parsePreferredLine).filter(Boolean);
            if (ipList.length > 0) await addNodesFromList(ipList);
          }
        }
      } else if (piu && piu.includes('\n')) {
        const fullList = await 整理成数组(piu);
        const apiUrls = [];
        const prefIPs = [];

        for (const item of fullList) {
          if (item.toLowerCase().startsWith('https://')) apiUrls.push(item);
          else if (!item.toLowerCase().includes('://')) prefIPs.push(item);
        }

        if (apiUrls.length > 0) {
          const apiIPs = await 请求优选API(apiUrls);
          prefIPs.push(...apiIPs);
        }

        if (prefIPs.length > 0) {
          const ipList = prefIPs.map(parsePreferredLine).filter(Boolean);
          if (ipList.length > 0) await addNodesFromList(ipList);
        }
      } else {
        const newIPList = await fetchAndParseNewIPs(piu);
        if (newIPList.length > 0) await addNodesFromList(newIPList);
      }
    } catch (error) {
      console.error('获取优选IP失败:', error);
    }
  }

  if (finalLinks.length === 0) {
    if (ech) return new Response('ECH 已开启，但所选端口没有 TLS 节点', { status: 400 });
    return new Response('没有可用节点，请检查协议、端口及仅 TLS 设置', { status: 400 });
  }

  let subscriptionContent;
  if (ech) for (let index = 0; index < finalLinks.length; index++) finalLinks[index] = addECHToLink(finalLinks[index], ech);
  let contentType = 'text/plain; charset=utf-8';

  switch (target) {
    case 'sing-box':
      try {
        const result = await applySingBoxTemplate(JSON.parse(generateSingBoxConfig(finalLinks, url.searchParams)), url.searchParams);
        subscriptionContent = JSON.stringify(result.config, null, 2);
        if (result.skipped) console.warn('sing-box 模板忽略 URL-REGEX 条目:', result.skipped);
      } catch (error) {
        return new Response('sing-box 模板转换失败: ' + error.message, { status: 422,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }
      contentType = 'application/json; charset=utf-8';
      break;
    case 'clash':
    case 'clashr':
      try { subscriptionContent = generateClashConfig(finalLinks, url.searchParams); }
      catch (error) { return new Response('Clash DNS 配置失败: ' + error.message, { status: 422 }); }
      contentType = 'text/yaml; charset=utf-8';
      break;
    case 'surge':
    case 'surge2':
    case 'surge3':
    case 'surge4':
      subscriptionContent = generateSurgeConfig(finalLinks);
      break;
    case 'quantumult':
    case 'quanx':
      subscriptionContent = generateQuantumultConfig(finalLinks);
      break;
    case 'base64':
      subscriptionContent = btoa(finalLinks.join('\n'));
      break;
    default:
      return new Response('不支持的订阅格式: ' + target, { status: 400 });
  }

  return new Response(subscriptionContent, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
    }
  });
}

// 生成主页
function generateHomePage(scuValue) {
  const realScu = scuValue || 'https://url.v1.mk/sub';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <title>服务器优选工具</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      -webkit-tap-highlight-color: transparent;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(180deg, #f5f5f7 0%, #ffffff 50%, #fafafa 100%);
      color: #1d1d1f;
      min-height: 100vh;
      padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
      overflow-x: hidden;
    }

    .container {
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }

    .header {
      text-align: center;
      padding: 48px 20px 32px;
    }

    .header h1 {
      font-size: 40px;
      font-weight: 700;
      letter-spacing: -0.3px;
      margin-bottom: 8px;
      line-height: 1.1;
    }

    .header p {
      font-size: 17px;
      color: #86868b;
    }

    .card {
      background: rgba(255,255,255,0.75);
      backdrop-filter: blur(30px) saturate(200%);
      -webkit-backdrop-filter: blur(30px) saturate(200%);
      border-radius: 24px;
      padding: 28px;
      margin-bottom: 20px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.06), 0 1px 3px rgba(0,0,0,0.05);
      border: 0.5px solid rgba(0,0,0,0.06);
    }

    .form-group {
      margin-bottom: 24px;
    }

    .form-group:last-child {
      margin-bottom: 0;
    }

    .form-group label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #86868b;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .form-group input,
    .form-group textarea,
    .form-group select {
      width: 100%;
      padding: 14px 16px;
      font-size: 17px;
      font-weight: 400;
      color: #1d1d1f;
      background: rgba(142,142,147,0.12);
      border: 2px solid transparent;
      border-radius: 12px;
      outline: none;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      -webkit-appearance: none;
      appearance: none;
    }

    .form-group input:focus,
    .form-group textarea:focus,
    .form-group select:focus {
      background: rgba(142,142,147,0.16);
      border-color: #007AFF;
      transform: scale(1.005);
    }

    .form-group input::placeholder,
    .form-group textarea::placeholder {
      color: #86868b;
    }

    .form-group small {
      display: block;
      margin-top: 8px;
      color: #86868b;
      font-size: 13px;
      line-height: 1.4;
    }

    .list-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 0;
      min-height: 52px;
      cursor: pointer;
      border-bottom: 0.5px solid rgba(0,0,0,0.08);
      transition: background-color 0.15s ease;
    }

    .list-item:last-child {
      border-bottom: none;
    }

    .list-item:active {
      background-color: rgba(142,142,147,0.08);
      margin: 0 -28px;
      padding-left: 28px;
      padding-right: 28px;
    }

    .list-item-label {
      font-size: 17px;
      font-weight: 400;
      color: #1d1d1f;
      flex: 1;
    }

    .list-item-description {
      font-size: 13px;
      color: #86868b;
      margin-top: 4px;
      line-height: 1.4;
    }

    .switch {
      position: relative;
      width: 51px;
      height: 31px;
      background: rgba(142,142,147,0.3);
      border-radius: 16px;
      transition: background 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      cursor: pointer;
      flex-shrink: 0;
    }

    .switch.active {
      background: #34C759;
    }

    .switch::after {
      content: '';
      position: absolute;
      top: 2px;
      left: 2px;
      width: 27px;
      height: 27px;
      background: #ffffff;
      border-radius: 50%;
      transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 2px 6px rgba(0,0,0,0.15), 0 1px 2px rgba(0,0,0,0.1);
    }

    .switch.active::after {
      transform: translateX(20px);
    }

    .result-url {
      display: none;
      margin-top: 12px;
      padding: 12px;
      background: rgba(0,122,255,0.1);
      border-radius: 8px;
      font-size: 13px;
      color: #007aff;
      word-break: break-all;
    }

    .client-btn {
      padding: 12px 16px;
      font-size: 14px;
      font-weight: 500;
      color: #007AFF;
      background: rgba(0,122,255,0.1);
      border: 1px solid rgba(0,122,255,0.2);
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      min-width: 0;
    }

    .client-btn:active {
      transform: scale(0.97);
      background: rgba(0,122,255,0.2);
    }

    .checkbox-label {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
      font-size: 17px;
      user-select: none;
      -webkit-user-select: none;
      padding: 8px 0;
    }

    .checkbox-label input[type="checkbox"] {
      width: 22px;
      height: 22px;
      margin: 0;
      cursor: pointer;
      appearance: auto;
      -webkit-appearance: checkbox;
      accent-color: #007AFF;
      flex-shrink: 0;
    }

    .checkbox-label span {
      cursor: pointer;
      color: #1d1d1f;
    }

    .footer {
      text-align: center;
      padding: 32px 20px;
      color: #86868b;
      font-size: 13px;
    }

    @media (prefers-color-scheme: dark) {
      body {
        background: linear-gradient(180deg, #000000 0%, #1c1c1e 50%, #2c2c2e 100%);
        color: #f5f5f7;
      }

      .card {
        background: rgba(28,28,30,0.75);
        border: 0.5px solid rgba(255,255,255,0.12);
      }

      .form-group input,
      .form-group textarea,
      .form-group select {
        background: rgba(142,142,147,0.2);
        color: #f5f5f7;
      }

      .form-group input:focus,
      .form-group textarea:focus,
      .form-group select:focus {
        background: rgba(142,142,147,0.25);
        border-color: #5ac8fa;
      }

      .list-item {
        border-bottom-color: rgba(255,255,255,0.1);
      }

      .list-item-label,
      .checkbox-label span {
        color: #f5f5f7;
      }

      .client-btn {
        background: rgba(0,122,255,0.15) !important;
        border-color: rgba(0,122,255,0.3) !important;
        color: #5ac8fa !important;
      }
    }
    :root { --accent:#2563eb; --ink:#17243b; --muted:#64748b; --panel:#fff; --field:#f3f6fb; --line:#e5ebf3; }
    body { background:radial-gradient(ellipse at top left,#e6f1ff 0,transparent 48%),#f5f7fb; color:var(--ink); }
    .container { max-width:780px; padding:24px 20px; }
    .header { text-align:left; padding:28px 4px 32px; }
    .header h1 { font-size:34px; letter-spacing:-1px; color:var(--ink); }
    .header p { color:var(--muted); line-height:1.7; }
    .eyebrow { color:var(--accent); font-size:12px; font-weight:700; letter-spacing:2px; margin-bottom:12px; }
    .card { background:var(--panel); border:1px solid var(--line); box-shadow:0 12px 40px rgba(28,54,90,.05); border-radius:24px; padding:28px; }
    .section-title { display:flex; align-items:center; gap:10px; margin:24px 0 16px; padding-top:20px; border-top:1px solid var(--line); font-size:17px; font-weight:650; color:var(--ink); }
    .section-title:first-child { margin-top:0; padding-top:0; border:0; }
    .section-title span { display:grid; place-items:center; width:26px; height:26px; border-radius:8px; background:#eaf1ff; color:var(--accent); font-size:12px; }
    .form-group label { color:var(--ink); font-size:14px; font-weight:600; }
    .form-group input,.form-group select,.form-group textarea { background:var(--field); border:1px solid var(--line); border-radius:12px; color:var(--ink); font-size:15px; }
    .form-group input:focus,.form-group select:focus,.form-group textarea:focus { outline:2px solid #bfdbfe; border-color:var(--accent); }
    .form-group small,.list-item-description { color:var(--muted); line-height:1.6; }
    .list-item { gap:20px; border-color:var(--line); }
    .list-item-label { color:var(--ink); font-size:15px; font-weight:550; }
    .list-item:active { margin:0; padding:16px 0; }
    .switch.active { background:var(--accent); }
    .switch:focus-visible { outline:3px solid #93c5fd; outline-offset:4px; }
    .list-item.is-disabled { opacity:.48; cursor:not-allowed; }
    .option-reason { color:var(--muted); font-size:12px; margin-top:5px; line-height:1.5; }
    .form-group input:disabled,.form-group select:disabled { opacity:.5; cursor:not-allowed; }
    .client-btn { background:#eff5ff; color:var(--accent); border-color:#d8e5ff; border-radius:12px; min-height:44px; }
    .client-btn:hover,.client-btn.selected { color:white!important; background:var(--accent)!important; border-color:var(--accent)!important; }
    .result-url { background:#edf8f5; color:#146b52; border:1px solid #cce9df; padding:16px; line-height:1.6; }
    .context-note { background:var(--field); border:1px solid var(--line); border-radius:12px; padding:12px 14px; color:var(--muted); font-size:13px; line-height:1.6; margin:12px 0; }
    .card { padding:0; overflow:hidden; }
    .settings-section { padding:26px 28px; border-bottom:1px solid var(--line); }
    .settings-section:last-child { border-bottom:0; }
    .settings-section h2 { margin:0 0 6px; font-size:18px; color:var(--ink); }
    .section-caption { margin:0 0 20px; font-size:13px; color:var(--muted); line-height:1.7; }
    .settings-section .form-group { margin-bottom:18px; }
    .settings-section .form-group:last-child { margin-bottom:0; }
    .settings-section .form-group>label { display:block; margin-bottom:8px; text-transform:none; letter-spacing:0; }
    .settings-section .list-item { padding:14px 0; }
    .linked-panel { padding:18px; margin:14px 0; background:var(--field); border:1px solid var(--line); border-radius:14px; }
    .linked-panel .form-group input,.linked-panel select { background:var(--panel); }
    .linked-panel input+label { margin-top:16px; }
    .linked-panel .checkbox-label { display:flex; font-size:13px; gap:9px; padding:10px 0 0; }
    .linked-panel .checkbox-label input { width:18px; height:18px; }
    .settings-section .form-group>label.fallback-option { display:flex; align-items:center; gap:9px; }
    .settings-section .form-group>label.fallback-option input { margin:0; flex-shrink:0; }
    .advanced-field { margin:14px 0 8px; }
    .advanced-field summary { color:var(--muted); font-size:13px; cursor:pointer; padding:5px 0; }
    .advanced-field input { margin-top:10px; }
    .state-badge { display:inline-flex; align-items:center; gap:6px; padding:5px 9px; border-radius:7px; background:#e9f3ff; color:var(--accent); font-size:12px; font-weight:600; margin-top:8px; }
    .state-badge:empty { display:none; }
    .generate-button { width:100%; padding:15px 20px; border:0; border-radius:12px; color:white; background:var(--accent); font-size:16px; font-weight:650; cursor:pointer; margin:12px 0 0; }
    .generate-button:hover { background:#1d4ed8; }
    .converter-panel { margin-top:22px; }
    .converter-panel>summary { font-size:14px; color:var(--muted); cursor:pointer; padding:12px 0; }
    .source-note { font-size:12px; color:var(--muted); margin-top:10px; line-height:1.6; }
    [hidden] { display:none!important; }
    @media(max-width:520px) { .card { padding:0; } .settings-section { padding:22px 20px; } .linked-panel { padding:15px; } }
    @media(max-width:520px) { .container { padding:12px; } .card { padding:20px; } .header h1 { font-size:28px; } .header { padding:20px 6px; } }
    @media(prefers-color-scheme:dark) { :root { --ink:#e5edf9; --muted:#9cabc0; --panel:#172237; --field:#202e45; --line:#2c3b53; } body { background:radial-gradient(ellipse at top left,#1a345a 0,transparent 48%),#101a2b; } .section-title span { background:#243c60; } .result-url { background:#163b35; color:#93ddc4; border-color:#27554a; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="eyebrow">SOS · SUBSCRIPTION STUDIO</div>
      <h1>连接，从这里开始</h1>
      <p>选择节点来源与分流方案，为你的客户端生成订阅。</p>
    </div>

    <div class="card">
      <div class="section-title"><span>01</span>连接信息</div>
      <div class="form-group">
        <label>域名</label>
        <input type="text" id="domain" placeholder="请输入您的域名">
      </div>

      <div class="form-group">
        <label>UUID/Password</label>
        <input type="text" id="uuid" placeholder="请输入UUID或Password">
      </div>

      <div class="form-group">
        <label>Path路径（可选）</label>
        <input type="text" id="customPath" placeholder="留空则使用默认路径 /" value="/">
        <small>自定义 Path 路径，例如：/v2ray 或 /。XHTTP 协议下 ?ed=2560 参数无效；该参数仅用于 WS Early Data。</small>
      </div>

      <div class="form-group">
        <label>自定义端口（可选）</label>
        <input type="text" id="customPorts" placeholder="例如：443,2053" oninput="syncOptionState()">
        <small>留空按来源端口生成；无来源端口时生成 443 和 80。开启仅 TLS 后过滤已知非 TLS 端口。</small>
      </div>

      <div class="section-title"><span>02</span>节点来源</div>
      <div class="list-item" onclick="toggleSwitch('switchDomain')">
        <div><div class="list-item-label">启用优选域名</div></div>
        <div class="switch active" id="switchDomain"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchIP')">
        <div><div class="list-item-label">启用优选IP</div></div>
        <div class="switch active" id="switchIP"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchGitHub')">
        <div><div class="list-item-label">启用GitHub优选</div></div>
        <div class="switch active" id="switchGitHub"></div>
      </div>

      <div class="form-group" id="githubUrlGroup" style="margin-top:12px;">
        <label>GitHub优选URL（可选）</label>
        <input type="text" id="githubUrl" placeholder="留空则使用默认地址" style="font-size:15px;">
        <small>自定义优选IP列表来源URL，留空则使用默认地址</small>
      </div>

      <div class="form-group" id="clashConfigModeGroup" style="margin-top:12px;">
        <label>分组与分流模板（Clash / sing-box）</label>
        <select id="clashConfigMode">
          <option value="default">默认配置</option>
          <option value="acl_default">内置：ACL4SSR 默认版</option>
          <option value="acl_nospeed">内置：ACL4SSR 无测速版</option>
          <option value="acl_mini">内置：ACL4SSR Mini</option>
          <option value="acl_Kisoul">内置：ACL4SSR Kisoul</option>
          <option value="custom">自定义远程配置文件</option>
        </select>
        <small>sing-box 原生读取所选模板；Clash 的远程模板交给订阅转换器。</small>
      </div>

      <div class="form-group" id="customClashConfigGroup" style="display:none; margin-top:12px;">
        <label>自定义远程配置文件地址</label>
        <input type="text" id="clashConfigUrl" placeholder="例如：https://example.com/ACL4SSR_Online.ini" style="font-size:15px;">
        <small>仅在选择“自定义远程配置文件”时生效</small>
      </div>

      <div class="form-group" style="margin-top:24px;">
        <div class="section-title"><span>03</span>节点协议</div>
        <div style="margin-top:8px;">
          <div class="list-item" onclick="toggleSwitch('switchVL')">
            <div><div class="list-item-label">VLESS (vl)</div></div>
            <div class="switch active" id="switchVL"></div>
          </div>
          <div class="list-item" onclick="toggleSwitch('switchTJ')">
            <div><div class="list-item-label">Trojan (tj)</div></div>
            <div class="switch" id="switchTJ"></div>
          </div>
          <div class="list-item" onclick="toggleSwitch('switchVM')">
            <div><div class="list-item-label">VMess (vm)</div></div>
            <div class="switch" id="switchVM"></div>
          </div>
        </div>
      </div>

      <div class="form-group" style="margin-top:24px;">
        <label>客户端选择</label>
        <select id="clientProfile" onchange="selectClientProfile()">
          <option value="sing-box">SING-BOX</option><option value="clash">CLASH</option><option value="stash">STASH</option>
          <option value="surge">SURGE</option><option value="loon">LOON</option><option value="quanx">QUANTUMULT X</option>
          <option value="v2ray">V2RAY</option><option value="v2rayng">V2RAYNG</option><option value="nekoray">NEKORAY</option><option value="shadowrocket">Shadowrocket</option>
        </select>
        <button type="button" class="generate-button" id="generateSubscription" onclick="generateSelectedClient()">生成 SING-BOX 订阅</button>
        <div class="context-note" id="clientScopeNote">点击客户端生成订阅。下方选项会显示该客户端的支持范围。</div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px; margin-top:8px;">
          <button type="button" class="client-btn" onclick="generateClientLink('clash', 'CLASH')">CLASH</button>
          <button type="button" class="client-btn" onclick="generateClientLink('clash', 'STASH')">STASH</button>
          <button type="button" class="client-btn" onclick="generateClientLink('surge', 'SURGE')">SURGE</button>
          <button type="button" class="client-btn" onclick="generateClientLink('sing-box', 'SING-BOX')">SING-BOX</button>
          <button type="button" class="client-btn" onclick="generateClientLink('loon', 'LOON')">LOON</button>
          <button type="button" class="client-btn" onclick="generateClientLink('quanx', 'QUANTUMULT X')" style="font-size:13px;">QUANTUMULT X</button>
          <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAY')">V2RAY</button>
          <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'V2RAYNG')">V2RAYNG</button>
          <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'NEKORAY')">NEKORAY</button>
          <button type="button" class="client-btn" onclick="generateClientLink('v2ray', 'Shadowrocket')" style="font-size:13px;">Shadowrocket</button>
        </div>
        <div class="result-url" id="clientSubscriptionUrl"></div>
      <p style="font-size:12px;color:#86868b;">SING-BOX 使用原生 JSON（1.14），支持 UDP/XUDP/TFO/证书校验及上方选中的远程 INI 模板分组、分流。规则会写入配置；URL-REGEX 无法转换，Android 不支持按进程名分流。Emoji/Expand/New Name/FDN 仍用于其他客户端的订阅转换器。</p>
      </div>

      <div class="form-group">
        <div class="section-title"><span>04</span>动态优选筛选</div>
        <label>IP 版本（仅筛选动态优选来源）</label>
        <div style="display:flex; gap:16px; margin-top:8px; flex-wrap:wrap;">
          <label class="checkbox-label">
            <input type="checkbox" id="ipv4Enabled" checked>
            <span>IPv4</span>
          </label>
          <label class="checkbox-label">
            <input type="checkbox" id="ipv6Enabled" checked>
            <span>IPv6</span>
          </label>
        </div>
      </div>

      <div class="form-group">
        <label>运营商（仅筛选动态优选来源）</label>
        <div style="display:flex; gap:16px; flex-wrap:wrap; margin-top:8px;">
          <label class="checkbox-label">
            <input type="checkbox" id="ispMobile" checked>
            <span>移动</span>
          </label>
          <label class="checkbox-label">
            <input type="checkbox" id="ispUnicom" checked>
            <span>联通</span>
          </label>
          <label class="checkbox-label">
            <input type="checkbox" id="ispTelecom" checked>
            <span>电信</span>
          </label>
        </div>
      </div>

      <div class="section-title"><span>05</span>连接选项</div>
      <div class="list-item" onclick="toggleSwitch('switchTLS')" style="margin-top:8px;">
        <div>
          <div class="list-item-label">仅TLS节点</div>
          <div class="list-item-description">启用后只生成带TLS的节点，不生成非TLS节点（如80端口）</div>
        </div>
        <div class="switch" id="switchTLS"></div>
      </div>

      <div class="form-group">
        <label>动态优选 IP 来源</label>
        <select id="ipSource"><option value="uouin">api.uouin.com（默认）</option><option value="wetest">wetest（原来源）</option></select>
        <details class="advanced-field" id="customAPIField"><summary>自定义兼容 API 地址（可选）</summary><input type="text" id="dynamicIPUrl" placeholder="https://example.com/api"></details>
        <label class="checkbox-label fallback-option"><input type="checkbox" id="ipFallback" checked><span>新 API 失败时回退 wetest</span></label>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchXHTTP')">
        <div><div class="list-item-label">VLESS XHTTP（实验性）</div><div class="list-item-description">支持原始 V2RAY / V2RAYNG（Xray）、Shadowrocket（2.2.67+）及 CLASH（支持 XHTTP 的 Mihomo，含远程 INI 模板）、默认模板 STASH（iOS/tvOS 3.6+、macOS 4.3+）；旧版 Clash 不支持。请确认客户端内核及已部署的 XHTTP 服务端均支持。开启即确认两端支持。当前订阅生成器不实现 Workers XHTTP 转发；普通 WS Worker 不能直接使用。Clash 远程模板由 Worker 在转换后补回 XHTTP；Stash 远程模板、其他客户端及未确认路径回退 WS。Trojan / VMess 继续 WS，路径沿用上方自定义路径；Mihomo 输出会移除遗留的 WS ?ed=数字，其他查询参数请改为纯路径；Mihomo 模式 auto，padding 100-1000（订阅参数 xhttpMode / xhttpPaddingBytes 可调整）；其他客户端保持原模式。</div><div class="context-note" id="xhttpCompatibilityNote"></div></div>
        <div class="switch" id="switchXHTTP"></div>
      </div>
      <div class="form-group linked-panel" id="xhttpOptionsPanel" hidden>
        <label for="xhttpMode">Mihomo XHTTP 模式</label>
        <select id="xhttpMode">
          <option value="auto" selected>auto（自动，默认）</option>
          <option value="stream-one">stream-one</option>
          <option value="stream-up">stream-up</option>
          <option value="packet-up">packet-up</option>
        </select>
        <label for="xhttpPaddingBytes">Padding 字节范围</label>
        <input type="text" id="xhttpPaddingBytes" value="100-1000" placeholder="100-1000">
        <small>仅 Clash/Mihomo 生效，默认模板与远程 INI 均支持。模式需要服务端支持；路径沿用上方自定义路径。</small>
      </div>
      <div class="list-item" onclick="toggleSwitch('switchECH')">
        <div><div class="list-item-label">ECH（加密 ClientHello）</div><div class="list-item-description">默认关闭；开启后仅生成 TLS 节点，需要客户端和服务端支持</div></div>
        <div class="switch" id="switchECH"></div>
      </div>
      <div class="form-group">
        <label>ECH 查询域名（可选）</label>
        <input type="text" id="customECHDomain" placeholder="默认：cloudflare-ech.com">
        <label>ECH 查询 DNS（HTTPS DoH，可选）</label>
        <input type="text" id="customDNS" placeholder="默认：https://dns.alidns.com/dns-query">
        <small id="echDNSNote">可自定义 HTTPS DoH，留空使用 https://dns.alidns.com/dns-query；ECH 查询域名留空使用 cloudflare-ech.com。sing-box 与 Clash/Mihomo 应用查询 DNS；Stash 保留原逻辑，其他客户端取决于转换器及内核支持。</small>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchXUDP')">
        <div>
          <div class="list-item-label">XUDP（UDP流量的优化扩展技术）</div>
          <div class="list-item-description">启用后开启“UDP流量的优化扩展技术”</div>
        </div>
        <div class="switch active" id="switchXUDP"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchUDP')">
        <div>
          <div class="list-item-label">UDP（UDP流量转发）</div>
          <div class="list-item-description">启用后开启“UDP流量转发”功能</div>
        </div>
        <div class="switch active" id="switchUDP"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchTFO')">
        <div>
          <div class="list-item-label">TFO（TCP快速打开）</div>
          <div class="list-item-description">启用后开启“TCP快速打开”功能</div>
        </div>
        <div class="switch active" id="switchTFO"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchEmoji')">
        <div>
          <div class="list-item-label">Emoji（显示国家/地区或平台图标）</div>
          <div class="list-item-description">启用后开启“显示国家/地区或平台图标”功能</div>
        </div>
        <div class="switch active" id="switchEmoji"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchExpand')">
        <div>
          <div class="list-item-label">Expand（本地化远程规则）</div>
          <div class="list-item-description">启用后开启“将远程规则展开并写入本地配置文件”功能</div>
        </div>
        <div class="switch active" id="switchExpand"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchNewName')">
        <div>
          <div class="list-item-label">New Name（启用 Clash 新版本的字段格式）</div>
          <div class="list-item-description">启用后订阅转换链接使用 Clash 新版本的字段格式</div>
        </div>
        <div class="switch active" id="switchNewName"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchSCV')">
        <div>
          <div class="list-item-label">SCV（跳过证书验证）</div>
          <div class="list-item-description">启用后开启“跳过证书验证”功能</div>
        </div>
        <div class="switch active" id="switchSCV"></div>
      </div>

      <div class="list-item" onclick="toggleSwitch('switchFDN')">
        <div>
          <div class="list-item-label">FDN（过滤废弃/失效节点）</div>
          <div class="list-item-description">启用后开启“过滤废弃/失效节点”功能</div>
        </div>
        <div class="switch active" id="switchFDN"></div>
      </div>
    </div>

    <div class="footer">
      <p>简化版优选工具 • 默认配置走原生配置文件，内置/自定义走远程配置文件</p>
    </div>
  </div>

  <script>
    let switches = {
      switchDomain: true,
      switchIP: true,
      switchGitHub: true,
      switchVL: true,
      switchTJ: false,
      switchVM: false,
      switchTLS: false,
      switchECH: false,
      switchXHTTP: false,
      switchXUDP: true,
      switchUDP: true,
      switchTFO: true,
      switchEmoji: true,
      switchExpand: true,
      switchNewName: true,
      switchSCV: true,
      switchFDN: true
    };

    const SUB_CONVERTER_URL = "${realScu}";
    const PRESET_CONFIG_MAP = ${JSON.stringify(presetClashConfigMap)};

    let activeClient = '';
    let activeClientName = ''; 
    let tlsBeforeECH = false;
    const disabledSwitches = new Set();

    const clientProfiles = {
      'sing-box': ['sing-box', 'SING-BOX'], clash: ['clash', 'CLASH'], stash: ['clash', 'STASH'],
      surge: ['surge', 'SURGE'], loon: ['loon', 'LOON'], quanx: ['quanx', 'QUANTUMULT X'],
      v2ray: ['v2ray', 'V2RAY'], v2rayng: ['v2ray', 'V2RAYNG'], nekoray: ['v2ray', 'NEKORAY'], shadowrocket: ['v2ray', 'Shadowrocket']
    };
    function selectClientProfile() {
      const profile = clientProfiles[document.getElementById('clientProfile').value] || clientProfiles['sing-box'];
      activeClient = profile[0];
      activeClientName = profile[1];
      document.getElementById('generateSubscription').textContent = '生成 ' + profile[1] + ' 订阅';
      syncOptionState();
    }
    function generateSelectedClient() {
      const profile = clientProfiles[document.getElementById('clientProfile').value] || clientProfiles['sing-box'];
      generateClientLink(profile[0], profile[1]);
    }
    function arrangeSettings() {
      if (!document.querySelector) return;
      const card = document.querySelector('.card');
      document.querySelectorAll('.section-title').forEach(function (heading) { heading.remove(); });
      const field = function (id) { return document.getElementById(id).closest('.form-group'); };
      const row = function (id) { return document.getElementById(id).closest('.list-item'); };
      const connection = ['domain','uuid','customPath','customPorts'].map(field);
      const sources = ['switchDomain','switchIP','switchGitHub'].map(row);
      const dynamic = field('ipSource'), versions = field('ipv4Enabled'), carriers = field('ispMobile');
      const ech = field('customECHDomain');
      const protocol = field('switchVL');
      const client = field('clientProfile');
      document.querySelector('.client-btn').parentElement.hidden = true;
      const oldNote = client.querySelector('p'); if (oldNote) oldNote.remove();
      dynamic.classList.add('linked-panel'); dynamic.id = 'dynamicSourcePanel';
      dynamic.appendChild(versions); dynamic.appendChild(carriers);
      const sourceCaption = document.createElement('div'); sourceCaption.className = 'source-note';
      sourceCaption.textContent = '这些筛选仅影响动态优选 IP。原生地址、优选域名与自定义列表不受影响。';
      dynamic.appendChild(sourceCaption);
      ech.classList.add('linked-panel'); ech.id = 'echOptionsPanel';
      const echBadge = document.createElement('div'); echBadge.className = 'state-badge'; echBadge.id = 'echStateBadge'; row('switchECH').firstElementChild.appendChild(echBadge);
      const sourceBadge = document.createElement('div'); sourceBadge.className = 'state-badge'; sourceBadge.id = 'ipStateBadge'; row('switchIP').firstElementChild.appendChild(sourceBadge);
      const converter = document.createElement('details'); converter.className = 'converter-panel'; converter.id = 'converterOptionsPanel';
      converter.innerHTML = '<summary>订阅转换器选项</summary><p class="source-note">仅在使用订阅转换器时生效。</p>';
      ['switchEmoji','switchExpand','switchNewName','switchFDN'].forEach(function (id) { converter.appendChild(row(id)); });
      const sections = [
        ['连接信息','填写代理域名与身份信息，端口和路径可按需调整。',connection],
        ['节点来源','可组合多个来源；原生地址始终保留。',[sources[0],sources[1],dynamic,sources[2],field('githubUrl')]],
        ['协议与连接','选择至少一种协议，再配置加密与传输选项。',[protocol,row('switchXHTTP'),document.getElementById('xhttpOptionsPanel'),row('switchECH'),ech,row('switchTLS'),row('switchUDP'),row('switchXUDP'),row('switchTFO'),row('switchSCV')]],
        ['分组与分流','从远程模板读取策略；默认模式使用基础分组。',[field('clashConfigMode'),field('clashConfigUrl')]],
        ['生成订阅','先选客户端，选项会同步显示对应的支持范围。',[client,converter]]
      ];
      sections.forEach(function (definition) {
        const section = document.createElement('section'); section.className = 'settings-section';
        const title = document.createElement('h2'); title.textContent = definition[0]; section.appendChild(title);
        const caption = document.createElement('p'); caption.className = 'section-caption'; caption.textContent = definition[1]; section.appendChild(caption);
        definition[2].forEach(function (element) { element.style.marginTop = ''; section.appendChild(element); });
        card.appendChild(section);
      });
    }

    function syncOptionState() {
      if (!document.querySelectorAll) return;
      disabledSwitches.clear();
      const nativeClashOptions = activeClient === 'clash' && activeClientName === 'CLASH'
        && document.getElementById('clashConfigMode').value === 'default';
      if (nativeClashOptions) switches.switchXUDP = !!switches.switchUDP && !!switches.switchVL;
      const xhttpAllowed = switches.switchVL && ((activeClient === 'v2ray' && ['V2RAY','V2RAYNG','Shadowrocket'].includes(activeClientName))
        || (activeClient === 'clash' && (activeClientName === 'CLASH' || (activeClientName === 'STASH' && document.getElementById('clashConfigMode').value === 'default'))));
      if (!xhttpAllowed) switches.switchXHTTP = false;
      const mihomoXHTTP = switches.switchXHTTP && activeClient === 'clash' && activeClientName === 'CLASH';
      document.getElementById('xhttpOptionsPanel').hidden = !mihomoXHTTP;
      ['xhttpMode','xhttpPaddingBytes'].forEach(function (id) { document.getElementById(id).disabled = !mihomoXHTTP; });
      function availability(id, reason) {
        const element = document.getElementById(id);
        if (!element) return;
        const row = element.closest('.list-item');
        row.classList.toggle('is-disabled', !!reason);
        element.setAttribute('aria-disabled', reason ? 'true' : 'false');
        let note = row.querySelector('.option-reason');
        if (!note) { note = document.createElement('div'); note.className = 'option-reason'; row.firstElementChild.appendChild(note); }
        note.textContent = reason || '';
        note.hidden = !reason;
        if (reason) disabledSwitches.add(id);
      }
      Object.keys(switches).forEach(function (id) {
        const element = document.getElementById(id);
        element.classList.toggle('active', switches[id]);
        element.setAttribute('aria-checked', String(switches[id]));
        availability(id, '');
      });
      if (!xhttpAllowed) availability('switchXHTTP', '当前客户端或转换路径不支持本脚本的 XHTTP 输出，自动使用 WS');
      const xhttpNote = document.getElementById('xhttpCompatibilityNote');
      if (xhttpNote) xhttpNote.textContent = activeClient === 'sing-box' ? '官方 sing-box 未列出 XHTTP 传输；第三方分支不在本配置支持范围内。'
        : activeClientName === 'NEKORAY' ? '原版 NEKORAY 4.x 已移除 Xray；按其 sing-box 内核回退 WS。'
        : activeClient === 'surge' ? 'Surge 官方协议列表未列出 VLESS / XHTTP；回退 WS 不会使 VLESS 自动兼容 Surge。'
        : activeClient === 'loon' || activeClient === 'quanx' ? '未确认官方 XHTTP 支持，且当前走转换器；回退 WS。'
        : activeClient === 'clash' && activeClientName === 'CLASH' && document.getElementById('clashConfigMode').value !== 'default' ? 'Mihomo 支持 XHTTP；保留远程 INI 和转换参数，Worker 在转换器输出中补回 XHTTP。需可用 XHTTP 服务端与转发。'
        : activeClientName === 'STASH' && document.getElementById('clashConfigMode').value !== 'default' ? 'Stash 的远程模板保留原转换流程，此路径仍回退 WS。'
        : xhttpAllowed ? '请核对上方最低版本与实际内核；开启表示已确认两端支持。脚本无法自动检测客户端版本。' : '请先选择客户端并开启 VLESS。';
      const mode = document.getElementById('clashConfigMode').value;
      const converter = activeClient && activeClient !== 'sing-box' && activeClient !== 'v2ray'
        && (activeClient !== 'clash' || mode !== 'default');
      if (switches.switchECH) availability('switchTLS', 'ECH 已开启，必须保留 TLS');
      if (!switches.switchUDP || !switches.switchVL) availability('switchXUDP', '仅在 UDP 和 VLESS 都开启时生效');
      else if (nativeClashOptions) availability('switchXUDP', '当前 Mihomo VLESS 内核默认启用 XUDP，不能单独关闭；关闭 UDP 后不生效');
      if (activeClient && activeClient !== 'sing-box' && !nativeClashOptions && !converter) {
        ['switchUDP','switchXUDP','switchTFO','switchSCV'].forEach(function (id) {
          availability(id, '当前原生或原始订阅未应用此选项');
        });
      }
      if (activeClient && !converter) {
        ['switchEmoji','switchExpand','switchNewName','switchFDN'].forEach(function (id) {
          availability(id, activeClient === 'sing-box' && id === 'switchExpand'
            ? 'sing-box 模板规则始终内嵌' : '仅订阅转换器使用此选项');
        });
      }
      ['githubUrl'].forEach(function (id) { document.getElementById(id).disabled = !switches.switchGitHub; });
      const source = document.getElementById('ipSource');
      source.disabled = !switches.switchIP;
      document.getElementById('dynamicIPUrl').disabled = !switches.switchIP || source.value === 'wetest';
      document.getElementById('ipFallback').disabled = !switches.switchIP || source.value === 'wetest';
      ['ipv4Enabled','ipv6Enabled','ispMobile','ispUnicom','ispTelecom'].forEach(function (id) {
        document.getElementById(id).disabled = !switches.switchIP;
      });
      ['customECHDomain','customDNS'].forEach(function (id) { document.getElementById(id).disabled = !switches.switchECH; });
      document.getElementById('customDNS').placeholder = '默认：https://dns.alidns.com/dns-query';
      const dnsNote = document.getElementById('echDNSNote');
      if (dnsNote) dnsNote.textContent = activeClient === 'sing-box' ? '可自定义 HTTPS DoH，留空使用默认值；仅 ECH 域名的 HTTPS 记录查询使用它，其余 DNS 保持原设置。'
        : activeClient === 'clash' && activeClientName === 'CLASH' ? '可自定义 HTTPS DoH，留空使用 https://dns.alidns.com/dns-query；ECH 查询域名留空使用 cloudflare-ech.com。仅为 ECH 域名添加 DNS 策略（含节点解析策略），其余模板 DNS 保留；不兼容的 YAML 明确报错。'
        : activeClientName === 'STASH' ? 'Stash 保留原有 ECH 转换逻辑；此 DoH 值仅随原始节点参数传递，本脚本不改写 Stash DNS，是否采用取决于客户端与转换器。'
        : activeClient === 'v2ray' ? '可填写 HTTPS DoH；会写入原始节点 ech 参数，实际采用取决于客户端及内核，未进行导入实测。'
        : 'DoH 值仅随原始节点传给转换器，尚未确认当前客户端是否采用；不能保证转换后 ECH / DNS 生效。';
      document.getElementById('clashConfigMode').disabled = activeClient === 'v2ray';
      document.getElementById('clashConfigUrl').disabled = activeClient === 'v2ray';
      const echPanel = document.getElementById('echOptionsPanel'); if (echPanel) echPanel.hidden = !switches.switchECH;
      const dynamicPanel = document.getElementById('dynamicSourcePanel'); if (dynamicPanel) dynamicPanel.hidden = !switches.switchIP;
      const customAPI = document.getElementById('customAPIField'); if (customAPI) customAPI.hidden = !switches.switchIP || source.value === 'wetest';
      const fallbackRow = document.getElementById('ipFallback').closest('label'); if (fallbackRow) fallbackRow.hidden = source.value === 'wetest';
      const echBadge = document.getElementById('echStateBadge'); if (echBadge) echBadge.textContent = switches.switchECH ? '已联动 · 仅 TLS 节点' : '';
      const ipBadge = document.getElementById('ipStateBadge'); if (ipBadge) ipBadge.textContent = switches.switchIP ? source.value === 'wetest' ? '来源 · wetest' : '来源 · uouin API' : '';
      const ports = document.getElementById('customPorts').value.trim();
      const onlyHTTP = ports && ports.split(',').every(function (port) { return [80,8080,8880,2052,2082,2086,2095].includes(Number(port.trim())); });
      if (onlyHTTP && !switches.switchTLS && !switches.switchECH) availability('switchSCV', '当前端口仅生成非 TLS 节点，无证书校验');
      const converterPanel = document.getElementById('converterOptionsPanel'); if (converterPanel) converterPanel.hidden = !converter;
      document.getElementById('clientScopeNote').textContent = !activeClient ? '点击客户端生成订阅。下方选项会显示该客户端的支持范围。'
        : activeClient === 'sing-box' ? 'sing-box：原生 JSON，支持分组模板和连接选项；转换器专属选项不生效。'
        : activeClient === 'v2ray' ? '原始节点订阅：不应用分组模板及转换器选项。'
        : converter ? '当前使用订阅转换器；选项是否生效取决于转换器与客户端支持。' : nativeClashOptions ? 'Clash/Mihomo 原生配置：UDP、TFO、SCV 已应用到节点；VLESS 的 XUDP 由内核默认启用。转换器专属选项不生效。' : '当前使用原生基础配置；转换器专属选项不生效。';
      document.querySelectorAll('.client-btn').forEach(function (button) {
        button.classList.toggle('selected', !!activeClient && button.getAttribute('onclick').includes("'" + activeClient + "'"));
      });
    }

    function invalidateSubscriptionLink() {
      const result = document.getElementById('clientSubscriptionUrl');
      if (!result || !result.textContent) return;
      result.textContent = '设置已修改，请重新生成订阅，并在客户端替换旧订阅地址；刷新旧地址不会应用页面上的新设置。';
      result.style.display = 'block';
      result.setAttribute('aria-live', 'polite');
    }

    function toggleSwitch(id) {
      if (disabledSwitches.has(id)) return;
      if (['switchVL','switchTJ','switchVM'].includes(id) && switches[id]
        && ['switchVL','switchTJ','switchVM'].filter(function (key) { return switches[key]; }).length === 1) {
        alert('请至少保留一个节点协议'); return;
      }
      switches[id] = !switches[id];
      if (id === 'switchECH') {
        if (switches.switchECH) { tlsBeforeECH = switches.switchTLS; switches.switchTLS = true; }
        else switches.switchTLS = tlsBeforeECH;
      }
      if (!switches.switchUDP || !switches.switchVL) switches.switchXUDP = false;
      syncOptionState();
      invalidateSubscriptionLink();
    }

    function toggleClashConfigInput() {
      const mode = document.getElementById('clashConfigMode').value;
      const customGroup = document.getElementById('customClashConfigGroup');
      customGroup.style.display = mode === 'custom' ? 'block' : 'none';
      syncOptionState();
    }

    function tryOpenApp(schemeUrl, fallbackCallback, timeout) {
      timeout = timeout || 2500;
      let appOpened = false;
      let callbackExecuted = false;
      const startTime = Date.now();

      const blurHandler = function () {
        const elapsed = Date.now() - startTime;
        if (elapsed < 3000 && !callbackExecuted) appOpened = true;
      };

      const hiddenHandler = function () {
        const elapsed = Date.now() - startTime;
        if (elapsed < 3000 && !callbackExecuted) appOpened = true;
      };

      window.addEventListener('blur', blurHandler);
      document.addEventListener('visibilitychange', hiddenHandler);

      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.src = schemeUrl;
      document.body.appendChild(iframe);

      setTimeout(function () {
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
        window.removeEventListener('blur', blurHandler);
        document.removeEventListener('visibilitychange', hiddenHandler);

        if (!callbackExecuted) {
          callbackExecuted = true;
          if (!appOpened && fallbackCallback) fallbackCallback();
        }
      }, timeout);
    }

    function generateClientLink(clientType, clientName) {
      activeClient = clientType;
      activeClientName = clientName;
      syncOptionState();
      const domain = document.getElementById('domain').value.trim();
      const uuid = document.getElementById('uuid').value.trim();
      const customPath = (document.getElementById('customPath').value || '').trim() || '/';
      const customPortsRaw = ((document.getElementById('customPorts') || {}).value || '').trim();
      if (customPortsRaw && customPortsRaw.split(',').some(function (port) { return !/^\\d+$/.test(port.trim()) || Number(port.trim()) < 1 || Number(port.trim()) > 65535; })) {
        alert('端口需为 1–65535 的整数，多个端口用英文逗号分隔'); return;
      }
      if ((switches.switchECH || switches.switchTLS) && customPortsRaw && customPortsRaw.split(',').every(function (port) { return [80,8080,8880,2052,2082,2086,2095].includes(Number(port.trim())); })) {
        alert('ECH / 仅 TLS 已开启，请保留至少一个 TLS 端口，例如 443'); return;
      }
      const githubUrl = document.getElementById('githubUrl').value.trim();
      const clashConfigMode = (document.getElementById('clashConfigMode') || {}).value || 'default';
      const clashConfigUrlInput = ((document.getElementById('clashConfigUrl') || {}).value || '').trim();

      if (!domain || !uuid) {
        alert('请先填写域名和UUID/Password');
        return;
      }

      if (!switches.switchVL && !switches.switchTJ && !switches.switchVM) {
        alert('请至少选择一个协议（VLESS、Trojan或VMess）');
        return;
      }

      const ipv4Enabled = document.getElementById('ipv4Enabled').checked;
      const ipv6Enabled = document.getElementById('ipv6Enabled').checked;
      const ispMobile = document.getElementById('ispMobile').checked;
      const ispUnicom = document.getElementById('ispUnicom').checked;
      const ispTelecom = document.getElementById('ispTelecom').checked;
      const xudpEnabled = switches.switchXUDP;
      const udpEnabled = switches.switchUDP;
      const tfoEnabled = switches.switchTFO;
      const emojiEnabled = switches.switchEmoji;
      const expandEnabled = switches.switchExpand;
      const newNameEnabled = switches.switchNewName;
      const scvEnabled = switches.switchSCV;
      const fdnEnabled = switches.switchFDN;

      const currentUrl = new URL(window.location.href);
      const baseUrl = currentUrl.origin;

      let subscriptionUrl = baseUrl + '/' + uuid + '/sub?domain=' + encodeURIComponent(domain)
        + '&epd=' + (switches.switchDomain ? 'yes' : 'no')
        + '&epi=' + (switches.switchIP ? 'yes' : 'no')
        + '&egi=' + (switches.switchGitHub ? 'yes' : 'no');

      if (githubUrl) subscriptionUrl += '&piu=' + encodeURIComponent(githubUrl);
      subscriptionUrl += '&ev=' + (switches.switchVL ? 'yes' : 'no');
      if (switches.switchTJ) subscriptionUrl += '&et=yes';
      if (switches.switchVM) subscriptionUrl += '&mess=yes';
      if (!ipv4Enabled) subscriptionUrl += '&ipv4=no';
      if (!ipv6Enabled) subscriptionUrl += '&ipv6=no';
      if (!ispMobile) subscriptionUrl += '&ispMobile=no';
      if (!ispUnicom) subscriptionUrl += '&ispUnicom=no';
      if (!ispTelecom) subscriptionUrl += '&ispTelecom=no';
      if (switches.switchTLS) subscriptionUrl += '&dkby=yes';
      const ipSource = ((document.getElementById('ipSource') || {}).value || 'uouin');
      if (ipSource !== 'uouin') subscriptionUrl += '&ipSource=' + encodeURIComponent(ipSource);
      const dynamicIPUrl = (((document.getElementById('dynamicIPUrl') || {}).value || '')).trim();
      if (dynamicIPUrl) subscriptionUrl += '&dynamicIPUrl=' + encodeURIComponent(dynamicIPUrl);
      const ipFallback = document.getElementById('ipFallback');
      if (ipFallback && !ipFallback.checked) subscriptionUrl += '&ipFallback=no';
      if (switches.switchECH) {
        subscriptionUrl += '&ech=yes';
        const echDomain = (((document.getElementById('customECHDomain') || {}).value || '')).trim();
        const echDNS = (((document.getElementById('customDNS') || {}).value || '')).trim();
        if (echDomain) subscriptionUrl += '&customECHDomain=' + encodeURIComponent(echDomain);
        if (echDNS) subscriptionUrl += '&customDNS=' + encodeURIComponent(echDNS);
      }
      if (switches.switchXHTTP) subscriptionUrl += '&transport=xhttp&xhttpReady=yes&client=' + (clientType === 'clash' ? (clientName === 'STASH' ? 'stash' : 'mihomo') : clientName === 'Shadowrocket' ? 'shadowrocket' : clientName === 'V2RAYNG' ? 'v2rayng' : 'v2ray');
      else if (clientType === 'clash') subscriptionUrl += '&transport=ws';
      if (switches.switchXHTTP && clientType === 'clash' && clientName !== 'STASH') {
        const xhttpMode = document.getElementById('xhttpMode').value || 'auto';
        const padding = document.getElementById('xhttpPaddingBytes').value.trim() || '100-1000';
        const range = padding.split('-');
        if (!['auto','stream-one','stream-up','packet-up'].includes(xhttpMode) || range.length !== 2 || range.some(function (n) { return !/^[0-9]+$/.test(n) || !Number.isSafeInteger(Number(n)); }) || Number(range[0]) > Number(range[1]) || Number(range[1]) > 1000000) {
          alert('请检查 XHTTP 模式与 Padding 范围，例如 100-1000'); return;
        }
        subscriptionUrl += '&xhttpMode=' + encodeURIComponent(xhttpMode) + '&xhttpPaddingBytes=' + encodeURIComponent(padding);
      }
      if (customPath && customPath !== '/') subscriptionUrl += '&path=' + encodeURIComponent(customPath);
      if (customPortsRaw) subscriptionUrl += '&ports=' + encodeURIComponent(customPortsRaw);

      let finalClashConfigUrl = '';
      if (clashConfigMode === 'custom') {
        finalClashConfigUrl = clashConfigUrlInput;
      } else if (PRESET_CONFIG_MAP[clashConfigMode]) {
        finalClashConfigUrl = PRESET_CONFIG_MAP[clashConfigMode];
      }

      let finalUrl = subscriptionUrl;
      let schemeUrl = '';
      let displayName = clientName || '';
      const urlElement = document.getElementById('clientSubscriptionUrl');

      // V2Ray类客户端直接使用原始订阅
      if (clientType === 'v2ray') {
        urlElement.textContent = finalUrl;
        urlElement.style.display = 'block';

        if (clientName === 'V2RAY') {
          navigator.clipboard.writeText(finalUrl).then(function () {
            alert(displayName + ' 订阅链接已复制');
          });
        } else if (clientName === 'Shadowrocket') {
          schemeUrl = 'shadowrocket://add/' + encodeURIComponent(finalUrl);
          tryOpenApp(schemeUrl, function () {
            navigator.clipboard.writeText(finalUrl).then(function () {
              alert(displayName + ' 订阅链接已复制');
            });
          });
        } else if (clientName === 'V2RAYNG') {
          schemeUrl = 'v2rayng://install?url=' + encodeURIComponent(finalUrl);
          tryOpenApp(schemeUrl, function () {
            navigator.clipboard.writeText(finalUrl).then(function () {
              alert(displayName + ' 订阅链接已复制');
            });
          });
        } else if (clientName === 'NEKORAY') {
          schemeUrl = 'nekoray://install-config?url=' + encodeURIComponent(finalUrl);
          tryOpenApp(schemeUrl, function () {
            navigator.clipboard.writeText(finalUrl).then(function () {
              alert(displayName + ' 订阅链接已复制');
            });
          });
        }
        return;
      }

      // Clash / Stash 特殊逻辑
      if (clientType === 'clash') {
        if (!finalClashConfigUrl) {
          finalUrl = subscriptionUrl + '&target=clash';
          if (clientName === 'STASH' && !switches.switchXHTTP) finalUrl += '&client=stash';
          if (clientName !== 'STASH') finalUrl += '&udp=' + udpEnabled + '&xudp=' + xudpEnabled + '&tfo=' + tfoEnabled + '&scv=' + scvEnabled;
        } else {
          const encodedUrl = encodeURIComponent(subscriptionUrl);
          finalUrl = SUB_CONVERTER_URL
            + '?target=clash'
            + '&url=' + encodedUrl
            + '&config=' + encodeURIComponent(finalClashConfigUrl)
            + '&insert=false'
            + '&emoji=' + (emojiEnabled ? 'true' : 'false')
            + '&list=false'
            + '&xudp=' + (xudpEnabled ? 'true' : 'false')
            + '&udp=' + (udpEnabled ? 'true' : 'false')
            + '&tfo=' + (tfoEnabled ? 'true' : 'false')
            + '&expand=' + (expandEnabled ? 'true' : 'false')
            + '&scv=' + (scvEnabled ? 'true' : 'false')
            + '&fdn=' + (fdnEnabled ? 'true' : 'false')
            + '&new_name=' + (newNameEnabled ? 'true' : 'false');
        }

        if (finalClashConfigUrl && clientName !== 'STASH') {
          const converterLink = new URL(finalUrl);
          const defaults = {insert:'false',emoji:'true',list:'false',xudp:'true',udp:'true',tfo:'true',expand:'true',scv:'false',fdn:'true',new_name:'true'};
          const overrides = new URLSearchParams();
          Object.keys(defaults).forEach(function (key) {
            const value = converterLink.searchParams.get(key);
            if (value !== null && value !== defaults[key]) overrides.set(key,value);
          });
          const preset = Object.keys(PRESET_CONFIG_MAP).find(function (key) { return PRESET_CONFIG_MAP[key] === finalClashConfigUrl; });
          finalUrl = subscriptionUrl + '&target=' + (switches.switchXHTTP ? 'clash-compat' : switches.switchECH ? 'clash-ech' : 'clash-template')
            + '&template=' + encodeURIComponent(preset || finalClashConfigUrl)
            + (overrides.size ? '&cv=' + encodeURIComponent(overrides.toString()) : '');
        }
        urlElement.textContent = finalUrl;
        urlElement.style.display = 'block';

        if (clientName === 'STASH') {
          schemeUrl = 'stash://install?url=' + encodeURIComponent(finalUrl);
          displayName = 'STASH';
        } else {
          schemeUrl = 'clash://install-config?url=' + encodeURIComponent(finalUrl);
          displayName = 'CLASH';
        }

        tryOpenApp(schemeUrl, function () {
          navigator.clipboard.writeText(finalUrl).then(function () {
            alert(displayName + ' 订阅链接已复制');
          });
        });
        return;
      }

      // sing-box 原生输出；不改变其他客户端的订阅转换器及远程模板流程。
      if (clientType === 'sing-box') {
        if (clashConfigMode === 'custom' && !finalClashConfigUrl) {
          alert('请填写自定义远程配置文件地址');
          return;
        }
        finalUrl = subscriptionUrl + '&target=sing-box'
          + '&xudp=' + xudpEnabled
          + '&udp=' + udpEnabled
          + '&tfo=' + tfoEnabled
          + '&scv=' + scvEnabled;
        if (finalClashConfigUrl) finalUrl += '&config=' + encodeURIComponent(finalClashConfigUrl);
        urlElement.textContent = finalUrl;
        urlElement.style.display = 'block';
        schemeUrl = 'sing-box://install-config?url=' + encodeURIComponent(finalUrl);
        tryOpenApp(schemeUrl, function () {
          navigator.clipboard.writeText(finalUrl).then(function () {
            alert('SING-BOX 订阅链接已复制');
          });
        });
        return;
      }

      // 其他客户端仍走订阅转换器
      const encodedUrl = encodeURIComponent(subscriptionUrl);
      finalUrl = SUB_CONVERTER_URL
        + '?target=' + clientType
        + '&url=' + encodedUrl
        + '&insert=false'
        + '&emoji=' + (emojiEnabled ? 'true' : 'false')
        + '&list=false'
        + '&xudp=' + (xudpEnabled ? 'true' : 'false')
        + '&udp=' + (udpEnabled ? 'true' : 'false')
        + '&tfo=' + (tfoEnabled ? 'true' : 'false')
        + '&expand=' + (expandEnabled ? 'true' : 'false')
        + '&scv=' + (scvEnabled ? 'true' : 'false')
        + '&fdn=' + (fdnEnabled ? 'true' : 'false')
        + '&new_name=' + (newNameEnabled ? 'true' : 'false');

      urlElement.textContent = finalUrl;
      urlElement.style.display = 'block';

      if (clientType === 'surge') {
        schemeUrl = 'surge:///install-config?url=' + encodeURIComponent(finalUrl);
        displayName = 'SURGE';
      } else if (clientType === 'sing-box') {
        schemeUrl = 'sing-box://install-config?url=' + encodeURIComponent(finalUrl);
        displayName = 'SING-BOX';
      } else if (clientType === 'loon') {
        schemeUrl = 'loon://install?url=' + encodeURIComponent(finalUrl);
        displayName = 'LOON';
      } else if (clientType === 'quanx') {
        schemeUrl = 'quantumult-x://install-config?url=' + encodeURIComponent(finalUrl);
        displayName = 'QUANTUMULT X';
      }

      if (schemeUrl) {
        tryOpenApp(schemeUrl, function () {
          navigator.clipboard.writeText(finalUrl).then(function () {
            alert(displayName + ' 订阅链接已复制');
          });
        });
      } else {
        navigator.clipboard.writeText(finalUrl).then(function () {
          alert(displayName + ' 订阅链接已复制');
        });
      }
    }

    document.addEventListener('DOMContentLoaded', function () {
      arrangeSettings();
      const modeSelect = document.getElementById('clashConfigMode');
      if (modeSelect) {
        modeSelect.addEventListener('change', toggleClashConfigInput);
        toggleClashConfigInput();
      }
      document.getElementById('ipSource').addEventListener('change', syncOptionState);
      document.querySelectorAll('.switch').forEach(function (element) {
        element.setAttribute('role', 'switch');
        element.setAttribute('aria-label', element.closest('.list-item').querySelector('.list-item-label')?.textContent || element.id);
        element.setAttribute('tabindex', '0');
        element.addEventListener('keydown', function (event) {
          if (event.key === ' ' || event.key === 'Enter') { event.preventDefault(); toggleSwitch(element.id); }
        });
      });
      selectClientProfile();
      document.addEventListener('input', invalidateSubscriptionLink);
      document.addEventListener('change', invalidateSubscriptionLink);
    });
  </script>
</body>
</html>`;
}




function isClashMapping(value) {
  return value !== null && typeof value === 'object'
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function parseClashConfig(text) {
  const config = clashYAML.load(text);
  const nodes = config?.proxies;
  const validNodes = Array.isArray(nodes) && nodes.every(isClashMapping);
  const providers = isClashMapping(config?.['proxy-providers']) && Object.keys(config['proxy-providers']).length > 0;
  if (!isClashMapping(config) || (!nodes?.length && !providers) || (nodes != null && !validNodes)) {
    throw new Error('转换器未返回包含节点或代理提供者的 Clash YAML');
  }
  return config;
}

// Retain untouched sections verbatim for the usual block-style converter output.
function renderClashSections(text, config, keys) {
  const dump = value => clashYAML.dump(value, { lineWidth: -1, quotingType: '"' });
  const lines = text.split(/\r?\n/);
  const sections = new Map();
  for (let i = 0; i < lines.length; i++) {
    if (/^(?:\.\.\.|%|\{)/.test(lines[i]) || /(?:^|[ \t,:[{])[&*][A-Za-z0-9_]/.test(lines[i])) return dump(config);
    if (/^[^\s#]/.test(lines[i]) && !/^(?:---(?:\s|$)|- )/.test(lines[i])) {
      const match = lines[i].match(/^([A-Za-z0-9_-]+)[ \t]*:/);
      if (!match) return dump(config);
      sections.set(match[1], i);
    }
  }
  const boundaries = [...sections.values(), lines.length];
  const patches = keys.map(key => {
    const start = sections.get(key);
    const end = start === undefined ? lines.length : boundaries[boundaries.indexOf(start) + 1];
    return { start: start ?? lines.length, end, replacement: dump({ [key]: config[key] }).trimEnd() };
  });
  for (const { start, end, replacement } of patches.sort((a, b) => b.start - a.start)) {
    lines.splice(start, end - start, replacement);
  }
  return lines.join('\n').trimEnd() + '\n';
}

function applyMihomoDNS(config, ech) {
  const nameservers = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];
  const defaultServers = ['223.5.5.5', '119.29.29.29'];
  const original = config.dns ?? { enable: true, 'default-nameserver': defaultServers };
  if (!isClashMapping(original)) throw new Error('Mihomo DNS 必须是 YAML 映射');
  const dns = config.dns = { ...original, nameserver: nameservers };
  if (!ech) return;
  dns.enable = true;
  dns['default-nameserver'] ??= defaultServers;
  if (!Array.isArray(dns['proxy-server-nameserver']) || !dns['proxy-server-nameserver'].length) {
    dns['proxy-server-nameserver'] = nameservers;
  }
  for (const key of ['nameserver-policy', 'proxy-server-nameserver-policy']) {
    const policy = dns[key] ?? {};
    if (!isClashMapping(policy)) throw new Error('无效的 DNS 策略: ' + key);
    const otherEntries = Object.entries(policy).filter(([domain]) => domain.toLowerCase() !== ech.domain.toLowerCase());
    dns[key] = Object.fromEntries([[ech.domain, [ech.dns]], ...otherEntries]);
  }
}

function isGeneratedClashProxy(node, options) {
  const trojan = node.type === 'trojan';
  const credential = trojan ? node.password : node.uuid;
  const host = trojan ? (node.sni || node.servername) : (node.servername || node.sni);
  return typeof credential === 'string'
    && (trojan ? credential === options.uuid : credential.toLowerCase() === options.uuid.toLowerCase())
    && typeof host === 'string' && host.toLowerCase() === options.host.toLowerCase();
}

function restoreRemoteClashOptions(config, ech, xhttp, options) {
  if (!ech && !xhttp) return;
  let echCount = 0;
  let xhttpCount = 0;
  config.proxies = (config.proxies || []).map(original => {
    if (!isClashMapping(original) || !isGeneratedClashProxy(original, options)) return original;
    const node = { ...original };
    if (xhttp && node.type === 'vless') {
      if (node.network !== 'ws') throw new Error('转换后的生成节点不是 WS，无法安全补回 XHTTP');
      node.network = 'xhttp';
      delete node['ws-opts'];
      delete node['ws-headers'];
      node['xhttp-opts'] = { path: normalizeMihomoXHTTPPath(options.path), host: options.host, mode: options.mode, 'x-padding-bytes': options.padding };
      xhttpCount++;
    }
    const tls = node.type === 'trojan' ? node.tls !== false : node.tls === true;
    if (ech && tls && ['vless', 'trojan', 'vmess'].includes(node.type)) {
      if (Object.hasOwn(node, 'ech-opts')) throw new Error('远程节点已含 ECH，拒绝覆盖未知结构');
      node['ech-opts'] = { enable: true, 'query-server-name': ech.domain };
      echCount++;
    }
    return node;
  });
  if ((ech && !echCount) || (xhttp && !xhttpCount)) throw new Error('未找到可进行兼容处理的节点');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (env && env.scu) {
      scu = env.scu;
    }

    if (path === '/' || path === '') {
      return new Response(generateHomePage(scu), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    if (path === '/test-optimize-api') {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
          }
        });
      }

      const apiUrl = url.searchParams.get('url');
      const port = url.searchParams.get('port') || '443';
      const timeout = parseInt(url.searchParams.get('timeout') || '3000', 10);

      if (!apiUrl) {
        return new Response(JSON.stringify({ success: false, error: '缺少url参数' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      try {
        const results = await 请求优选API([apiUrl], port, timeout, true);
        return new Response(JSON.stringify({
          success: true,
          results: results,
          total: results.length,
          message: '成功获取 ' + results.length + ' 个优选IP'
        }, null, 2), {
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
          status: error.name === 'TimeoutError' || error.name === 'AbortError' ? 504 : 502,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    }

    // Apply the Mihomo DNS settings after the converter applies the remote template.
    const target = url.searchParams.get('target')?.toLowerCase();
    if (['clash-template', 'clash-ech', 'clash-compat'].includes(target) && /^\/[^/]+\/sub$/.test(path)) {
      try {
        const ech = getECHOptions(url.searchParams);
        const xhttp = url.searchParams.get('transport') === 'xhttp' && url.searchParams.get('xhttpReady') === 'yes' && url.searchParams.get('client') === 'mihomo';
        if (target !== 'clash-template' && !ech && !xhttp) throw new Error('缺少 ECH 或已确认的 Mihomo XHTTP 设置');
        const query = new URLSearchParams(url.searchParams.get('converterQuery') || '');
        if (!url.searchParams.has('converterQuery')) {
          const template = url.searchParams.get('template');
          const config = presetClashConfigMap[template] || template;
          const configURL = new URL(config);
          if (!['https:', 'http:'].includes(configURL.protocol)) throw new Error('无效的模板 URL');
          const sourceURL = new URL(url);
          ['target','template','cv','converterQuery'].forEach(key => sourceURL.searchParams.delete(key));
          query.set('target','clash'); query.set('url',sourceURL.toString()); query.set('config',configURL.toString());
          const defaults = {insert:'false',emoji:'true',list:'false',xudp:'true',udp:'true',tfo:'true',expand:'true',scv:'false',fdn:'true',new_name:'true'};
          const overrides = new URLSearchParams(url.searchParams.get('cv') || '');
          if (target === 'clash-template') {
            for (const key of Object.keys(defaults)) {
              if (!overrides.has(key) && url.searchParams.has(key)) overrides.set(key, url.searchParams.get(key));
              sourceURL.searchParams.delete(key);
            }
            query.set('url', sourceURL.toString());
          }
          for (const [key,value] of overrides) {
            if (!Object.hasOwn(defaults,key) || !['true','false'].includes(value)) throw new Error('无效的转换选项');
            defaults[key] = value;
          }
          for (const [key,value] of Object.entries(defaults)) query.set(key,value);
        }
        const source = new URL(query.get('url'));
        if (query.get('target') !== 'clash' || source.origin !== url.origin || source.pathname !== path
          || source.searchParams.has('target')) throw new Error('转换器来源无效');
        // Sanitize at the request boundary, including saved converterQuery URLs.
        // The outer URL retains the user's ECH settings for restoration.
        if (source.searchParams.get('domain') !== url.searchParams.get('domain') || (source.searchParams.get('path') || '/') !== (url.searchParams.get('path') || '/')) throw new Error('兼容来源参数不一致');
        const options = { uuid: decodeURIComponent(path.split('/')[1]), host: url.searchParams.get('domain'), path: url.searchParams.get('path') || '/' };
        if (!options.host || !isValidUUID(options.uuid)) throw new Error('无效的兼容节点身份');
        if (xhttp) {
          Object.assign(options, getMihomoXHTTPOptions(url.searchParams));
          normalizeMihomoXHTTPPath(options.path);
          source.searchParams.delete('transport');
          source.searchParams.delete('xhttpReady');
        }
        if (ech) {
          source.searchParams.delete('ech');
          source.searchParams.delete('customECHDomain');
          source.searchParams.delete('customDNS');
          // Removing ECH must retain the TLS-only node selection it implied.
          source.searchParams.set('dkby', 'yes');
        }
        query.set('url', source.toString());
        const converter = new URL(scu);
        converter.search = query.toString();
        const result = await fetch(converter, { signal: AbortSignal.timeout(15000) });
        if (!result.ok) return new Response('Clash 转换器 HTTP ' + result.status, { status: 502 });
        const text = await result.text();
        let config;
        try { config = parseClashConfig(text); }
        catch { return new Response('Clash 转换器返回无效的订阅 YAML', { status: 502 }); }
        restoreRemoteClashOptions(config, ech, xhttp, options);
        applyMihomoDNS(config, ech);
        const sections = ech || xhttp ? ['proxies', 'dns'] : ['dns'];
        return new Response(renderClashSections(text, config, sections), { headers: { 'Content-Type': 'text/yaml; charset=utf-8' } });
      } catch (error) { return new Response('Clash 兼容处理失败: ' + error.message, { status: 422 }); }
    }
    const pathMatch = path.match(/^\/([^\/]+)\/sub$/);
    if (pathMatch) {
      const uuid = pathMatch[1];
      const domain = url.searchParams.get('domain');

      if (!domain) {
        return new Response('缺少域名参数', { status: 400 });
      }

      epd = url.searchParams.get('epd') !== 'no';
      epi = url.searchParams.get('epi') !== 'no';
      egi = url.searchParams.get('egi') !== 'no';
      const piu = url.searchParams.get('piu') || defaultIPURL;

      const evEnabled = url.searchParams.get('ev') === 'yes' || (url.searchParams.get('ev') === null && ev);
      const etEnabled = url.searchParams.get('et') === 'yes';
      const vmEnabled = url.searchParams.get('mess') === 'yes';

      const ipv4Enabled = url.searchParams.get('ipv4') !== 'no';
      const ipv6Enabled = url.searchParams.get('ipv6') !== 'no';

      const ispMobile = url.searchParams.get('ispMobile') !== 'no';
      const ispUnicom = url.searchParams.get('ispUnicom') !== 'no';
      const ispTelecom = url.searchParams.get('ispTelecom') !== 'no';

      const disableNonTLS = url.searchParams.get('dkby') === 'yes';
      const customPath = url.searchParams.get('path') || '/';

      const portsParam = url.searchParams.get('ports') || '';
      const customPorts = [...new Set(portsParam
        .split(',')
        .map(s => parseInt(s.trim(), 10))
        .filter(n => Number.isFinite(n) && n > 0 && n < 65536))];

      return await handleSubscriptionRequest(
        request,
        uuid,
        domain,
        piu,
        ipv4Enabled,
        ipv6Enabled,
        ispMobile,
        ispUnicom,
        ispTelecom,
        evEnabled,
        etEnabled,
        vmEnabled,
        disableNonTLS,
        customPath,
        customPorts
      );
    }

    return new Response('Not Found', { status: 404 });
  }
};


// Bundled js-yaml 4.2.0 (MIT), https://github.com/nodeca/js-yaml/tree/4.2.0
// Included here to keep the Cloudflare Worker deployable as a single file.
/*
(The MIT License)

Copyright (C) 2011-2015 by Vitaly Puzrin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
const clashYAML = (() => {
  const modules = {
    "lib/common"(module, exports, require) {
'use strict'

function isNothing (subject) {
  return (typeof subject === 'undefined') || (subject === null)
}

function isObject (subject) {
  return (typeof subject === 'object') && (subject !== null)
}

function toArray (sequence) {
  if (Array.isArray(sequence)) return sequence
  else if (isNothing(sequence)) return []

  return [sequence]
}

function extend (target, source) {
  if (source) {
    const sourceKeys = Object.keys(source)

    for (let index = 0, length = sourceKeys.length; index < length; index += 1) {
      const key = sourceKeys[index]
      target[key] = source[key]
    }
  }

  return target
}

function repeat (string, count) {
  let result = ''

  for (let cycle = 0; cycle < count; cycle += 1) {
    result += string
  }

  return result
}

function isNegativeZero (number) {
  return (number === 0) && (Number.NEGATIVE_INFINITY === 1 / number)
}

module.exports.isNothing = isNothing
module.exports.isObject = isObject
module.exports.toArray = toArray
module.exports.repeat = repeat
module.exports.isNegativeZero = isNegativeZero
module.exports.extend = extend
    },
    "lib/dumper"(module, exports, require) {
'use strict'

const common = require('./common')
const YAMLException = require('./exception')
const DEFAULT_SCHEMA = require('./schema/default')

const _toString = Object.prototype.toString
const _hasOwnProperty = Object.prototype.hasOwnProperty

const CHAR_BOM = 0xFEFF
const CHAR_TAB = 0x09 /* Tab */
const CHAR_LINE_FEED = 0x0A /* LF */
const CHAR_CARRIAGE_RETURN = 0x0D /* CR */
const CHAR_SPACE = 0x20 /* Space */
const CHAR_EXCLAMATION = 0x21 /* ! */
const CHAR_DOUBLE_QUOTE = 0x22 /* " */
const CHAR_SHARP = 0x23 /* # */
const CHAR_PERCENT = 0x25 /* % */
const CHAR_AMPERSAND = 0x26 /* & */
const CHAR_SINGLE_QUOTE = 0x27 /* ' */
const CHAR_ASTERISK = 0x2A /* * */
const CHAR_COMMA = 0x2C /* , */
const CHAR_MINUS = 0x2D /* - */
const CHAR_COLON = 0x3A /* : */
const CHAR_EQUALS = 0x3D /* = */
const CHAR_GREATER_THAN = 0x3E /* > */
const CHAR_QUESTION = 0x3F /* ? */
const CHAR_COMMERCIAL_AT = 0x40 /* @ */
const CHAR_LEFT_SQUARE_BRACKET = 0x5B /* [ */
const CHAR_RIGHT_SQUARE_BRACKET = 0x5D /* ] */
const CHAR_GRAVE_ACCENT = 0x60 /* ` */
const CHAR_LEFT_CURLY_BRACKET = 0x7B /* { */
const CHAR_VERTICAL_LINE = 0x7C /* | */
const CHAR_RIGHT_CURLY_BRACKET = 0x7D /* } */

const ESCAPE_SEQUENCES = {}

ESCAPE_SEQUENCES[0x00] = '\\0'
ESCAPE_SEQUENCES[0x07] = '\\a'
ESCAPE_SEQUENCES[0x08] = '\\b'
ESCAPE_SEQUENCES[0x09] = '\\t'
ESCAPE_SEQUENCES[0x0A] = '\\n'
ESCAPE_SEQUENCES[0x0B] = '\\v'
ESCAPE_SEQUENCES[0x0C] = '\\f'
ESCAPE_SEQUENCES[0x0D] = '\\r'
ESCAPE_SEQUENCES[0x1B] = '\\e'
ESCAPE_SEQUENCES[0x22] = '\\"'
ESCAPE_SEQUENCES[0x5C] = '\\\\'
ESCAPE_SEQUENCES[0x85] = '\\N'
ESCAPE_SEQUENCES[0xA0] = '\\_'
ESCAPE_SEQUENCES[0x2028] = '\\L'
ESCAPE_SEQUENCES[0x2029] = '\\P'

const DEPRECATED_BOOLEANS_SYNTAX = [
  'y', 'Y', 'yes', 'Yes', 'YES', 'on', 'On', 'ON',
  'n', 'N', 'no', 'No', 'NO', 'off', 'Off', 'OFF'
]

const DEPRECATED_BASE60_SYNTAX = /^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/

function compileStyleMap (schema, map) {
  if (map === null) return {}

  const result = {}
  const keys = Object.keys(map)

  for (let index = 0, length = keys.length; index < length; index += 1) {
    let tag = keys[index]
    let style = String(map[tag])

    if (tag.slice(0, 2) === '!!') {
      tag = 'tag:yaml.org,2002:' + tag.slice(2)
    }
    const type = schema.compiledTypeMap['fallback'][tag]

    if (type && _hasOwnProperty.call(type.styleAliases, style)) {
      style = type.styleAliases[style]
    }

    result[tag] = style
  }

  return result
}

function encodeHex (character) {
  let handle
  let length

  const string = character.toString(16).toUpperCase()

  if (character <= 0xFF) {
    handle = 'x'
    length = 2
  } else if (character <= 0xFFFF) {
    handle = 'u'
    length = 4
  } else if (character <= 0xFFFFFFFF) {
    handle = 'U'
    length = 8
  } else {
    throw new YAMLException('code point within a string may not be greater than 0xFFFFFFFF')
  }

  return '\\' + handle + common.repeat('0', length - string.length) + string
}

const QUOTING_TYPE_SINGLE = 1
const QUOTING_TYPE_DOUBLE = 2

function State (options) {
  this.schema = options['schema'] || DEFAULT_SCHEMA
  this.indent = Math.max(1, (options['indent'] || 2))
  this.noArrayIndent = options['noArrayIndent'] || false
  this.skipInvalid = options['skipInvalid'] || false
  this.flowLevel = (common.isNothing(options['flowLevel']) ? -1 : options['flowLevel'])
  this.styleMap = compileStyleMap(this.schema, options['styles'] || null)
  this.sortKeys = options['sortKeys'] || false
  this.lineWidth = options['lineWidth'] || 80
  this.noRefs = options['noRefs'] || false
  this.noCompatMode = options['noCompatMode'] || false
  this.condenseFlow = options['condenseFlow'] || false
  this.quotingType = options['quotingType'] === '"' ? QUOTING_TYPE_DOUBLE : QUOTING_TYPE_SINGLE
  this.forceQuotes = options['forceQuotes'] || false
  this.replacer = typeof options['replacer'] === 'function' ? options['replacer'] : null

  this.implicitTypes = this.schema.compiledImplicit
  this.explicitTypes = this.schema.compiledExplicit

  this.tag = null
  this.result = ''

  this.duplicates = []
  this.usedDuplicates = null
}

// Indents every line in a string. Empty lines (\n only) are not indented.
function indentString (string, spaces) {
  const ind = common.repeat(' ', spaces)
  let position = 0
  let result = ''
  const length = string.length

  while (position < length) {
    let line
    const next = string.indexOf('\n', position)
    if (next === -1) {
      line = string.slice(position)
      position = length
    } else {
      line = string.slice(position, next + 1)
      position = next + 1
    }

    if (line.length && line !== '\n') result += ind

    result += line
  }

  return result
}

function generateNextLine (state, level) {
  return '\n' + common.repeat(' ', state.indent * level)
}

function testImplicitResolving (state, str) {
  for (let index = 0, length = state.implicitTypes.length; index < length; index += 1) {
    const type = state.implicitTypes[index]

    if (type.resolve(str)) {
      return true
    }
  }

  return false
}

// [33] s-white ::= s-space | s-tab
function isWhitespace (c) {
  return c === CHAR_SPACE || c === CHAR_TAB
}

// Returns true if the character can be printed without escaping.
// From YAML 1.2: "any allowed characters known to be non-printable
// should also be escaped. [However,] This isn’t mandatory"
// Derived from nb-char - \t - #x85 - #xA0 - #x2028 - #x2029.
function isPrintable (c) {
  return (c >= 0x00020 && c <= 0x00007E) ||
    ((c >= 0x000A1 && c <= 0x00D7FF) && c !== 0x2028 && c !== 0x2029) ||
    ((c >= 0x0E000 && c <= 0x00FFFD) && c !== CHAR_BOM) ||
    (c >= 0x10000 && c <= 0x10FFFF)
}

// [34] ns-char ::= nb-char - s-white
// [27] nb-char ::= c-printable - b-char - c-byte-order-mark
// [26] b-char  ::= b-line-feed | b-carriage-return
// Including s-white (for some reason, examples doesn't match specs in this aspect)
// ns-char ::= c-printable - b-line-feed - b-carriage-return - c-byte-order-mark
function isNsCharOrWhitespace (c) {
  return isPrintable(c) &&
    c !== CHAR_BOM &&
    // - b-char
    c !== CHAR_CARRIAGE_RETURN &&
    c !== CHAR_LINE_FEED
}

// [127]  ns-plain-safe(c) ::= c = flow-out  ⇒ ns-plain-safe-out
//                             c = flow-in   ⇒ ns-plain-safe-in
//                             c = block-key ⇒ ns-plain-safe-out
//                             c = flow-key  ⇒ ns-plain-safe-in
// [128] ns-plain-safe-out ::= ns-char
// [129]  ns-plain-safe-in ::= ns-char - c-flow-indicator
// [130]  ns-plain-char(c) ::=  ( ns-plain-safe(c) - “:” - “#” )
//                            | ( /* An ns-char preceding */ “#” )
//                            | ( “:” /* Followed by an ns-plain-safe(c) */ )
function isPlainSafe (c, prev, inblock) {
  const cIsNsCharOrWhitespace = isNsCharOrWhitespace(c)
  const cIsNsChar = cIsNsCharOrWhitespace && !isWhitespace(c)
  return (
    (
      // ns-plain-safe
      inblock // c = flow-in
        ? cIsNsCharOrWhitespace
        : cIsNsCharOrWhitespace &&
          // - c-flow-indicator
          c !== CHAR_COMMA &&
          c !== CHAR_LEFT_SQUARE_BRACKET &&
          c !== CHAR_RIGHT_SQUARE_BRACKET &&
          c !== CHAR_LEFT_CURLY_BRACKET &&
          c !== CHAR_RIGHT_CURLY_BRACKET
    ) &&
    // ns-plain-char
    c !== CHAR_SHARP && // false on '#'
    !(prev === CHAR_COLON && !cIsNsChar)
  ) || // false on ': '
  (isNsCharOrWhitespace(prev) && !isWhitespace(prev) && c === CHAR_SHARP) || // change to true on '[^ ]#'
  (prev === CHAR_COLON && cIsNsChar) // change to true on ':[^ ]'
}

// Simplified test for values allowed as the first character in plain style.
function isPlainSafeFirst (c) {
  // Uses a subset of ns-char - c-indicator
  // where ns-char = nb-char - s-white.
  // No support of ( ( “?” | “:” | “-” ) /* Followed by an ns-plain-safe(c)) */ ) part
  return isPrintable(c) &&
    c !== CHAR_BOM &&
    !isWhitespace(c) && // - s-white
    // - (c-indicator ::=
    // “-” | “?” | “:” | “,” | “[” | “]” | “{” | “}”
    c !== CHAR_MINUS &&
    c !== CHAR_QUESTION &&
    c !== CHAR_COLON &&
    c !== CHAR_COMMA &&
    c !== CHAR_LEFT_SQUARE_BRACKET &&
    c !== CHAR_RIGHT_SQUARE_BRACKET &&
    c !== CHAR_LEFT_CURLY_BRACKET &&
    c !== CHAR_RIGHT_CURLY_BRACKET &&
    // | “#” | “&” | “*” | “!” | “|” | “=” | “>” | “'” | “"”
    c !== CHAR_SHARP &&
    c !== CHAR_AMPERSAND &&
    c !== CHAR_ASTERISK &&
    c !== CHAR_EXCLAMATION &&
    c !== CHAR_VERTICAL_LINE &&
    c !== CHAR_EQUALS &&
    c !== CHAR_GREATER_THAN &&
    c !== CHAR_SINGLE_QUOTE &&
    c !== CHAR_DOUBLE_QUOTE &&
    // | “%” | “@” | “`”)
    c !== CHAR_PERCENT &&
    c !== CHAR_COMMERCIAL_AT &&
    c !== CHAR_GRAVE_ACCENT
}

// Simplified test for values allowed as the last character in plain style.
function isPlainSafeLast (c) {
  // just not whitespace or colon, it will be checked to be plain character later
  return !isWhitespace(c) && c !== CHAR_COLON
}

// Same as 'string'.codePointAt(pos), but works in older browsers.
function codePointAt (string, pos) {
  const first = string.charCodeAt(pos)
  let second

  if (first >= 0xD800 && first <= 0xDBFF && pos + 1 < string.length) {
    second = string.charCodeAt(pos + 1)
    if (second >= 0xDC00 && second <= 0xDFFF) {
      // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
      return (first - 0xD800) * 0x400 + second - 0xDC00 + 0x10000
    }
  }
  return first
}

// Determines whether block indentation indicator is required.
function needIndentIndicator (string) {
  const leadingSpaceRe = /^\n* /
  return leadingSpaceRe.test(string)
}

const STYLE_PLAIN = 1
const STYLE_SINGLE = 2
const STYLE_LITERAL = 3
const STYLE_FOLDED = 4
const STYLE_DOUBLE = 5

// Determines which scalar styles are possible and returns the preferred style.
// lineWidth = -1 => no limit.
// Pre-conditions: str.length > 0.
// Post-conditions:
//    STYLE_PLAIN or STYLE_SINGLE => no \n are in the string.
//    STYLE_LITERAL => no lines are suitable for folding (or lineWidth is -1).
//    STYLE_FOLDED => a line > lineWidth and can be folded (and lineWidth != -1).
function chooseScalarStyle (string, singleLineOnly, indentPerLevel, lineWidth,
  testAmbiguousType, quotingType, forceQuotes, inblock) {
  let i
  let char = 0
  let prevChar = null
  let hasLineBreak = false
  let hasFoldableLine = false // only checked if shouldTrackWidth
  const shouldTrackWidth = lineWidth !== -1
  let previousLineBreak = -1 // count the first line correctly
  let plain = isPlainSafeFirst(codePointAt(string, 0)) &&
    isPlainSafeLast(codePointAt(string, string.length - 1))

  if (singleLineOnly || forceQuotes) {
    // Case: no block styles.
    // Check for disallowed characters to rule out plain and single.
    for (i = 0; i < string.length; char >= 0x10000 ? i += 2 : i++) {
      char = codePointAt(string, i)
      if (!isPrintable(char)) {
        return STYLE_DOUBLE
      }
      plain = plain && isPlainSafe(char, prevChar, inblock)
      prevChar = char
    }
  } else {
    // Case: block styles permitted.
    for (i = 0; i < string.length; char >= 0x10000 ? i += 2 : i++) {
      char = codePointAt(string, i)
      if (char === CHAR_LINE_FEED) {
        hasLineBreak = true
        // Check if any line can be folded.
        if (shouldTrackWidth) {
          hasFoldableLine = hasFoldableLine ||
            // Foldable line = too long, and not more-indented.
            (i - previousLineBreak - 1 > lineWidth &&
             string[previousLineBreak + 1] !== ' ')
          previousLineBreak = i
        }
      } else if (!isPrintable(char)) {
        return STYLE_DOUBLE
      }
      plain = plain && isPlainSafe(char, prevChar, inblock)
      prevChar = char
    }
    // in case the end is missing a \n
    hasFoldableLine = hasFoldableLine || (shouldTrackWidth &&
      (i - previousLineBreak - 1 > lineWidth &&
       string[previousLineBreak + 1] !== ' '))
  }
  // Although every style can represent \n without escaping, prefer block styles
  // for multiline, since they're more readable and they don't add empty lines.
  // Also prefer folding a super-long line.
  if (!hasLineBreak && !hasFoldableLine) {
    // Strings interpretable as another type have to be quoted;
    // e.g. the string 'true' vs. the boolean true.
    if (plain && !forceQuotes && !testAmbiguousType(string)) {
      return STYLE_PLAIN
    }
    return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE
  }
  // Edge case: block indentation indicator can only have one digit.
  if (indentPerLevel > 9 && needIndentIndicator(string)) {
    return STYLE_DOUBLE
  }
  // At this point we know block styles are valid.
  // Prefer literal style unless we want to fold.
  if (!forceQuotes) {
    return hasFoldableLine ? STYLE_FOLDED : STYLE_LITERAL
  }
  return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE
}

// Note: line breaking/folding is implemented for only the folded style.
// NB. We drop the last trailing newline (if any) of a returned block scalar
//  since the dumper adds its own newline. This always works:
//    • No ending newline => unaffected; already using strip "-" chomping.
//    • Ending newline    => removed then restored.
//  Importantly, this keeps the "+" chomp indicator from gaining an extra line.
function writeScalar (state, string, level, iskey, inblock) {
  state.dump = (function () {
    if (string.length === 0) {
      return state.quotingType === QUOTING_TYPE_DOUBLE ? '""' : "''"
    }
    if (!state.noCompatMode) {
      if (DEPRECATED_BOOLEANS_SYNTAX.indexOf(string) !== -1 || DEPRECATED_BASE60_SYNTAX.test(string)) {
        return state.quotingType === QUOTING_TYPE_DOUBLE ? ('"' + string + '"') : ("'" + string + "'")
      }
    }

    const indent = state.indent * Math.max(1, level) // no 0-indent scalars
    // As indentation gets deeper, let the width decrease monotonically
    // to the lower bound min(state.lineWidth, 40).
    // Note that this implies
    //  state.lineWidth ≤ 40 + state.indent: width is fixed at the lower bound.
    //  state.lineWidth > 40 + state.indent: width decreases until the lower bound.
    // This behaves better than a constant minimum width which disallows narrower options,
    // or an indent threshold which causes the width to suddenly increase.
    const lineWidth = (state.lineWidth === -1)
      ? -1
      : Math.max(Math.min(state.lineWidth, 40), state.lineWidth - indent)

    // Without knowing if keys are implicit/explicit, assume implicit for safety.
    const singleLineOnly = iskey ||
      // No block styles in flow mode.
      (state.flowLevel > -1 && level >= state.flowLevel)
    function testAmbiguity (string) {
      return testImplicitResolving(state, string)
    }

    switch (chooseScalarStyle(string, singleLineOnly, state.indent, lineWidth,
      testAmbiguity, state.quotingType, state.forceQuotes && !iskey, inblock)) {
      case STYLE_PLAIN:
        return string
      case STYLE_SINGLE:
        return "'" + string.replace(/'/g, "''") + "'"
      case STYLE_LITERAL:
        return '|' + blockHeader(string, state.indent) +
          dropEndingNewline(indentString(string, indent))
      case STYLE_FOLDED:
        return '>' + blockHeader(string, state.indent) +
          dropEndingNewline(indentString(foldString(string, lineWidth), indent))
      case STYLE_DOUBLE:
        return '"' + escapeString(string, lineWidth) + '"'
      default:
        throw new YAMLException('impossible error: invalid scalar style')
    }
  }())
}

// Pre-conditions: string is valid for a block scalar, 1 <= indentPerLevel <= 9.
function blockHeader (string, indentPerLevel) {
  const indentIndicator = needIndentIndicator(string) ? String(indentPerLevel) : ''

  // note the special case: the string '\n' counts as a "trailing" empty line.
  const clip = string[string.length - 1] === '\n'
  const keep = clip && (string[string.length - 2] === '\n' || string === '\n')
  const chomp = keep ? '+' : (clip ? '' : '-')

  return indentIndicator + chomp + '\n'
}

// (See the note for writeScalar.)
function dropEndingNewline (string) {
  return string[string.length - 1] === '\n' ? string.slice(0, -1) : string
}

// Note: a long line without a suitable break point will exceed the width limit.
// Pre-conditions: every char in str isPrintable, str.length > 0, width > 0.
function foldString (string, width) {
  // In folded style, $k$ consecutive newlines output as $k+1$ newlines—
  // unless they're before or after a more-indented line, or at the very
  // beginning or end, in which case $k$ maps to $k$.
  // Therefore, parse each chunk as newline(s) followed by a content line.
  const lineRe = /(\n+)([^\n]*)/g

  // first line (possibly an empty line)
  let result = (function () {
    let nextLF = string.indexOf('\n')
    nextLF = nextLF !== -1 ? nextLF : string.length
    lineRe.lastIndex = nextLF
    return foldLine(string.slice(0, nextLF), width)
  }())
  // If we haven't reached the first content line yet, don't add an extra \n.
  let prevMoreIndented = string[0] === '\n' || string[0] === ' '
  let moreIndented

  // rest of the lines
  let match
  while ((match = lineRe.exec(string))) {
    const prefix = match[1]
    const line = match[2]

    moreIndented = (line[0] === ' ')
    result += prefix +
      ((!prevMoreIndented && !moreIndented && line !== '') ? '\n' : '') +
      foldLine(line, width)
    prevMoreIndented = moreIndented
  }

  return result
}

// Greedy line breaking.
// Picks the longest line under the limit each time,
// otherwise settles for the shortest line over the limit.
// NB. More-indented lines *cannot* be folded, as that would add an extra \n.
function foldLine (line, width) {
  if (line === '' || line[0] === ' ') return line

  // Since a more-indented line adds a \n, breaks can't be followed by a space.
  const breakRe = / [^ ]/g // note: the match index will always be <= length-2.
  let match
  // start is an inclusive index. end, curr, and next are exclusive.
  let start = 0
  let end
  let curr = 0
  let next = 0
  let result = ''

  // Invariants: 0 <= start <= length-1.
  //   0 <= curr <= next <= max(0, length-2). curr - start <= width.
  // Inside the loop:
  //   A match implies length >= 2, so curr and next are <= length-2.
  while ((match = breakRe.exec(line))) {
    next = match.index
    // maintain invariant: curr - start <= width
    if (next - start > width) {
      end = (curr > start) ? curr : next // derive end <= length-2
      result += '\n' + line.slice(start, end)
      // skip the space that was output as \n
      start = end + 1                    // derive start <= length-1
    }
    curr = next
  }

  // By the invariants, start <= length-1, so there is something left over.
  // It is either the whole string or a part starting from non-whitespace.
  result += '\n'
  // Insert a break if the remainder is too long and there is a break available.
  if (line.length - start > width && curr > start) {
    result += line.slice(start, curr) + '\n' + line.slice(curr + 1)
  } else {
    result += line.slice(start)
  }

  return result.slice(1) // drop extra \n joiner
}

// Escapes a double-quoted string.
function escapeString (string) {
  let result = ''
  let char = 0

  for (let i = 0; i < string.length; char >= 0x10000 ? i += 2 : i++) {
    char = codePointAt(string, i)
    const escapeSeq = ESCAPE_SEQUENCES[char]

    if (!escapeSeq && isPrintable(char)) {
      result += string[i]
      if (char >= 0x10000) result += string[i + 1]
    } else {
      result += escapeSeq || encodeHex(char)
    }
  }

  return result
}

function writeFlowSequence (state, level, object) {
  let _result = ''
  const _tag = state.tag

  for (let index = 0, length = object.length; index < length; index += 1) {
    let value = object[index]

    if (state.replacer) {
      value = state.replacer.call(object, String(index), value)
    }

    // Write only valid elements, put null instead of invalid elements.
    if (writeNode(state, level, value, false, false) ||
        (typeof value === 'undefined' &&
         writeNode(state, level, null, false, false))) {
      if (_result !== '') _result += ',' + (!state.condenseFlow ? ' ' : '')
      _result += state.dump
    }
  }

  state.tag = _tag
  state.dump = '[' + _result + ']'
}

function writeBlockSequence (state, level, object, compact) {
  let _result = ''
  const _tag = state.tag

  for (let index = 0, length = object.length; index < length; index += 1) {
    let value = object[index]

    if (state.replacer) {
      value = state.replacer.call(object, String(index), value)
    }

    // Write only valid elements, put null instead of invalid elements.
    if (writeNode(state, level + 1, value, true, true, false, true) ||
        (typeof value === 'undefined' &&
         writeNode(state, level + 1, null, true, true, false, true))) {
      if (!compact || _result !== '') {
        _result += generateNextLine(state, level)
      }

      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        _result += '-'
      } else {
        _result += '- '
      }

      _result += state.dump
    }
  }

  state.tag = _tag
  state.dump = _result || '[]' // Empty sequence if no valid values.
}

function writeFlowMapping (state, level, object) {
  let _result = ''
  const _tag = state.tag
  const objectKeyList = Object.keys(object)

  for (let index = 0, length = objectKeyList.length; index < length; index += 1) {
    let pairBuffer = ''
    if (_result !== '') pairBuffer += ', '

    if (state.condenseFlow) pairBuffer += '"'

    const objectKey = objectKeyList[index]
    let objectValue = object[objectKey]

    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue)
    }

    if (!writeNode(state, level, objectKey, false, false)) {
      continue // Skip this pair because of invalid key;
    }

    if (state.dump.length > 1024) pairBuffer += '? '

    pairBuffer += state.dump + (state.condenseFlow ? '"' : '') + ':' + (state.condenseFlow ? '' : ' ')

    if (!writeNode(state, level, objectValue, false, false)) {
      continue // Skip this pair because of invalid value.
    }

    pairBuffer += state.dump

    // Both key and value are valid.
    _result += pairBuffer
  }

  state.tag = _tag
  state.dump = '{' + _result + '}'
}

function writeBlockMapping (state, level, object, compact) {
  let _result = ''
  const _tag = state.tag
  const objectKeyList = Object.keys(object)

  // Allow sorting keys so that the output file is deterministic
  if (state.sortKeys === true) {
    // Default sorting
    objectKeyList.sort()
  } else if (typeof state.sortKeys === 'function') {
    // Custom sort function
    objectKeyList.sort(state.sortKeys)
  } else if (state.sortKeys) {
    // Something is wrong
    throw new YAMLException('sortKeys must be a boolean or a function')
  }

  for (let index = 0, length = objectKeyList.length; index < length; index += 1) {
    let pairBuffer = ''

    if (!compact || _result !== '') {
      pairBuffer += generateNextLine(state, level)
    }

    const objectKey = objectKeyList[index]
    let objectValue = object[objectKey]

    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue)
    }

    if (!writeNode(state, level + 1, objectKey, true, true, true)) {
      continue // Skip this pair because of invalid key.
    }

    const explicitPair = (state.tag !== null && state.tag !== '?') ||
                   (state.dump && state.dump.length > 1024)

    if (explicitPair) {
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        pairBuffer += '?'
      } else {
        pairBuffer += '? '
      }
    }

    pairBuffer += state.dump

    if (explicitPair) {
      pairBuffer += generateNextLine(state, level)
    }

    if (!writeNode(state, level + 1, objectValue, true, explicitPair)) {
      continue // Skip this pair because of invalid value.
    }

    if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
      pairBuffer += ':'
    } else {
      pairBuffer += ': '
    }

    pairBuffer += state.dump

    // Both key and value are valid.
    _result += pairBuffer
  }

  state.tag = _tag
  state.dump = _result || '{}' // Empty mapping if no valid pairs.
}

function detectType (state, object, explicit) {
  const typeList = explicit ? state.explicitTypes : state.implicitTypes

  for (let index = 0, length = typeList.length; index < length; index += 1) {
    const type = typeList[index]

    if ((type.instanceOf || type.predicate) &&
        (!type.instanceOf || ((typeof object === 'object') && (object instanceof type.instanceOf))) &&
        (!type.predicate || type.predicate(object))) {
      if (explicit) {
        if (type.multi && type.representName) {
          state.tag = type.representName(object)
        } else {
          state.tag = type.tag
        }
      } else {
        state.tag = '?'
      }

      if (type.represent) {
        const style = state.styleMap[type.tag] || type.defaultStyle

        let _result
        if (_toString.call(type.represent) === '[object Function]') {
          _result = type.represent(object, style)
        } else if (_hasOwnProperty.call(type.represent, style)) {
          _result = type.represent[style](object, style)
        } else {
          throw new YAMLException('!<' + type.tag + '> tag resolver accepts not "' + style + '" style')
        }

        state.dump = _result
      }

      return true
    }
  }

  return false
}

// Serializes `object` and writes it to global `result`.
// Returns true on success, or false on invalid object.
//
function writeNode (state, level, object, block, compact, iskey, isblockseq) {
  state.tag = null
  state.dump = object

  if (!detectType(state, object, false)) {
    detectType(state, object, true)
  }

  const type = _toString.call(state.dump)
  const inblock = block

  if (block) {
    block = (state.flowLevel < 0 || state.flowLevel > level)
  }

  const objectOrArray = type === '[object Object]' || type === '[object Array]'
  let duplicateIndex
  let duplicate

  if (objectOrArray) {
    duplicateIndex = state.duplicates.indexOf(object)
    duplicate = duplicateIndex !== -1
  }

  if ((state.tag !== null && state.tag !== '?') || duplicate || (state.indent !== 2 && level > 0)) {
    compact = false
  }

  if (duplicate && state.usedDuplicates[duplicateIndex]) {
    state.dump = '*ref_' + duplicateIndex
  } else {
    if (objectOrArray && duplicate && !state.usedDuplicates[duplicateIndex]) {
      state.usedDuplicates[duplicateIndex] = true
    }
    if (type === '[object Object]') {
      if (block && (Object.keys(state.dump).length !== 0)) {
        writeBlockMapping(state, level, state.dump, compact)
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + state.dump
        }
      } else {
        writeFlowMapping(state, level, state.dump)
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + ' ' + state.dump
        }
      }
    } else if (type === '[object Array]') {
      if (block && (state.dump.length !== 0)) {
        if (state.noArrayIndent && !isblockseq && level > 0) {
          writeBlockSequence(state, level - 1, state.dump, compact)
        } else {
          writeBlockSequence(state, level, state.dump, compact)
        }
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + state.dump
        }
      } else {
        writeFlowSequence(state, level, state.dump)
        if (duplicate) {
          state.dump = '&ref_' + duplicateIndex + ' ' + state.dump
        }
      }
    } else if (type === '[object String]') {
      if (state.tag !== '?') {
        writeScalar(state, state.dump, level, iskey, inblock)
      }
    } else if (type === '[object Undefined]') {
      return false
    } else {
      if (state.skipInvalid) return false
      throw new YAMLException('unacceptable kind of an object to dump ' + type)
    }

    if (state.tag !== null && state.tag !== '?') {
      // Need to encode all characters except those allowed by the spec:
      //
      // [35] ns-dec-digit    ::=  [#x30-#x39] /* 0-9 */
      // [36] ns-hex-digit    ::=  ns-dec-digit
      //                         | [#x41-#x46] /* A-F */ | [#x61-#x66] /* a-f */
      // [37] ns-ascii-letter ::=  [#x41-#x5A] /* A-Z */ | [#x61-#x7A] /* a-z */
      // [38] ns-word-char    ::=  ns-dec-digit | ns-ascii-letter | “-”
      // [39] ns-uri-char     ::=  “%” ns-hex-digit ns-hex-digit | ns-word-char | “#”
      //                         | “;” | “/” | “?” | “:” | “@” | “&” | “=” | “+” | “$” | “,”
      //                         | “_” | “.” | “!” | “~” | “*” | “'” | “(” | “)” | “[” | “]”
      //
      // Also need to encode '!' because it has special meaning (end of tag prefix).
      //
      let tagStr = encodeURI(
        state.tag[0] === '!' ? state.tag.slice(1) : state.tag
      ).replace(/!/g, '%21')

      if (state.tag[0] === '!') {
        tagStr = '!' + tagStr
      } else if (tagStr.slice(0, 18) === 'tag:yaml.org,2002:') {
        tagStr = '!!' + tagStr.slice(18)
      } else {
        tagStr = '!<' + tagStr + '>'
      }

      state.dump = tagStr + ' ' + state.dump
    }
  }

  return true
}

function getDuplicateReferences (object, state) {
  const objects = []
  const duplicatesIndexes = []

  inspectNode(object, objects, duplicatesIndexes)

  const length = duplicatesIndexes.length
  for (let index = 0; index < length; index += 1) {
    state.duplicates.push(objects[duplicatesIndexes[index]])
  }
  state.usedDuplicates = new Array(length)
}

function inspectNode (object, objects, duplicatesIndexes) {
  if (object !== null && typeof object === 'object') {
    const index = objects.indexOf(object)
    if (index !== -1) {
      if (duplicatesIndexes.indexOf(index) === -1) {
        duplicatesIndexes.push(index)
      }
    } else {
      objects.push(object)

      if (Array.isArray(object)) {
        for (let i = 0, length = object.length; i < length; i += 1) {
          inspectNode(object[i], objects, duplicatesIndexes)
        }
      } else {
        const objectKeyList = Object.keys(object)

        for (let i = 0, length = objectKeyList.length; i < length; i += 1) {
          inspectNode(object[objectKeyList[i]], objects, duplicatesIndexes)
        }
      }
    }
  }
}

function dump (input, options) {
  options = options || {}

  const state = new State(options)

  if (!state.noRefs) getDuplicateReferences(input, state)

  let value = input

  if (state.replacer) {
    value = state.replacer.call({ '': value }, '', value)
  }

  if (writeNode(state, 0, value, true, true)) return state.dump + '\n'

  return ''
}

module.exports.dump = dump
    },
    "lib/exception"(module, exports, require) {
// YAML error class. http://stackoverflow.com/questions/8458984
//
'use strict'

function formatError (exception, compact) {
  let where = ''
  const message = exception.reason || '(unknown reason)'

  if (!exception.mark) return message

  if (exception.mark.name) {
    where += 'in "' + exception.mark.name + '" '
  }

  where += '(' + (exception.mark.line + 1) + ':' + (exception.mark.column + 1) + ')'

  if (!compact && exception.mark.snippet) {
    where += '\n\n' + exception.mark.snippet
  }

  return message + ' ' + where
}

function YAMLException (reason, mark) {
  // Super constructor
  Error.call(this)

  this.name = 'YAMLException'
  this.reason = reason
  this.mark = mark
  this.message = formatError(this, false)

  // Include stack trace in error object
  if (Error.captureStackTrace) {
    // Chrome and NodeJS
    Error.captureStackTrace(this, this.constructor)
  } else {
    // FF, IE 10+ and Safari 6+. Fallback for others
    this.stack = (new Error()).stack || ''
  }
}

// Inherit from Error
YAMLException.prototype = Object.create(Error.prototype)
YAMLException.prototype.constructor = YAMLException

YAMLException.prototype.toString = function toString (compact) {
  return this.name + ': ' + formatError(this, compact)
}

module.exports = YAMLException
    },
    "lib/loader"(module, exports, require) {
'use strict'

const common = require('./common')
const YAMLException = require('./exception')
const makeSnippet = require('./snippet')
const DEFAULT_SCHEMA = require('./schema/default')

const _hasOwnProperty = Object.prototype.hasOwnProperty

const CONTEXT_FLOW_IN = 1
const CONTEXT_FLOW_OUT = 2
const CONTEXT_BLOCK_IN = 3
const CONTEXT_BLOCK_OUT = 4

const CHOMPING_CLIP = 1
const CHOMPING_STRIP = 2
const CHOMPING_KEEP = 3

// eslint-disable-next-line no-control-regex
const PATTERN_NON_PRINTABLE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/
const PATTERN_NON_ASCII_LINE_BREAKS = /[\x85\u2028\u2029]/
// eslint-disable-next-line no-useless-escape
const PATTERN_FLOW_INDICATORS = /[,\[\]{}]/
// eslint-disable-next-line no-useless-escape
const PATTERN_TAG_HANDLE = /^(?:!|!!|![0-9A-Za-z-]+!)$/
// eslint-disable-next-line no-useless-escape
const PATTERN_TAG_URI = /^(?:!|[^,\[\]{}])(?:%[0-9a-f]{2}|[0-9a-z\-#;/?:@&=+$,_.!~*'()\[\]])*$/i

function _class (obj) { return Object.prototype.toString.call(obj) }

function isEol (c) {
  return (c === 0x0A/* LF */) || (c === 0x0D/* CR */)
}

function isWhiteSpace (c) {
  return (c === 0x09/* Tab */) || (c === 0x20/* Space */)
}

function isWsOrEol (c) {
  return (c === 0x09/* Tab */) ||
         (c === 0x20/* Space */) ||
         (c === 0x0A/* LF */) ||
         (c === 0x0D/* CR */)
}

function isFlowIndicator (c) {
  return c === 0x2C/* , */ ||
         c === 0x5B/* [ */ ||
         c === 0x5D/* ] */ ||
         c === 0x7B/* { */ ||
         c === 0x7D/* } */
}

function fromHexCode (c) {
  if ((c >= 0x30/* 0 */) && (c <= 0x39/* 9 */)) {
    return c - 0x30
  }

  const lc = c | 0x20

  if ((lc >= 0x61/* a */) && (lc <= 0x66/* f */)) {
    return lc - 0x61 + 10
  }

  return -1
}

function escapedHexLen (c) {
  if (c === 0x78/* x */) { return 2 }
  if (c === 0x75/* u */) { return 4 }
  if (c === 0x55/* U */) { return 8 }
  return 0
}

function fromDecimalCode (c) {
  if ((c >= 0x30/* 0 */) && (c <= 0x39/* 9 */)) {
    return c - 0x30
  }

  return -1
}

function simpleEscapeSequence (c) {
  switch (c) {
    case 0x30/* 0 */: return '\x00'
    case 0x61/* a */: return '\x07'
    case 0x62/* b */: return '\x08'
    case 0x74/* t */: return '\x09'
    case 0x09/* Tab */: return '\x09'
    case 0x6E/* n */: return '\x0A'
    case 0x76/* v */: return '\x0B'
    case 0x66/* f */: return '\x0C'
    case 0x72/* r */: return '\x0D'
    case 0x65/* e */: return '\x1B'
    case 0x20/* Space */: return ' '
    case 0x22/* " */: return '\x22'
    case 0x2F/* / */: return '/'
    case 0x5C/* \ */: return '\x5C'
    case 0x4E/* N */: return '\x85'
    case 0x5F/* _ */: return '\xA0'
    case 0x4C/* L */: return '\u2028'
    case 0x50/* P */: return '\u2029'
    default: return ''
  }
}

function charFromCodepoint (c) {
  if (c <= 0xFFFF) {
    return String.fromCharCode(c)
  }
  // Encode UTF-16 surrogate pair
  // https://en.wikipedia.org/wiki/UTF-16#Code_points_U.2B010000_to_U.2B10FFFF
  return String.fromCharCode(
    ((c - 0x010000) >> 10) + 0xD800,
    ((c - 0x010000) & 0x03FF) + 0xDC00
  )
}

// set a property of a literal object, while protecting against prototype pollution,
// see https://github.com/nodeca/js-yaml/issues/164 for more details
function setProperty (object, key, value) {
  // used for this specific key only because Object.defineProperty is slow
  if (key === '__proto__') {
    Object.defineProperty(object, key, {
      configurable: true,
      enumerable: true,
      writable: true,
      value: value
    })
  } else {
    object[key] = value
  }
}

const simpleEscapeCheck = new Array(256) // integer, for fast access
const simpleEscapeMap = new Array(256)
for (let i = 0; i < 256; i++) {
  simpleEscapeCheck[i] = simpleEscapeSequence(i) ? 1 : 0
  simpleEscapeMap[i] = simpleEscapeSequence(i)
}

function State (input, options) {
  this.input = input

  this.filename = options['filename'] || null
  this.schema = options['schema'] || DEFAULT_SCHEMA
  this.onWarning = options['onWarning'] || null
  // (Hidden) Remove? makes the loader to expect YAML 1.1 documents
  // if such documents have no explicit %YAML directive
  this.legacy = options['legacy'] || false

  this.json = options['json'] || false
  this.listener = options['listener'] || null
  this.maxDepth = typeof options['maxDepth'] === 'number' ? options['maxDepth'] : 100
  this.maxMergeSeqLength = typeof options['maxMergeSeqLength'] === 'number' ? options['maxMergeSeqLength'] : 20

  this.implicitTypes = this.schema.compiledImplicit
  this.typeMap = this.schema.compiledTypeMap

  this.length = input.length
  this.position = 0
  this.line = 0
  this.lineStart = 0
  this.lineIndent = 0
  this.depth = 0

  // position of first leading tab in the current line,
  // used to make sure there are no tabs in the indentation
  this.firstTabInLine = -1

  this.documents = []
  this.anchorMapTransactions = []

  /*
  this.version;
  this.checkLineBreaks;
  this.tagMap;
  this.anchorMap;
  this.tag;
  this.anchor;
  this.kind;
  this.result; */
}

function generateError (state, message) {
  const mark = {
    name: state.filename,
    buffer: state.input.slice(0, -1), // omit trailing \0
    position: state.position,
    line: state.line,
    column: state.position - state.lineStart
  }

  mark.snippet = makeSnippet(mark)

  return new YAMLException(message, mark)
}

function throwError (state, message) {
  throw generateError(state, message)
}

function throwWarning (state, message) {
  if (state.onWarning) {
    state.onWarning.call(null, generateError(state, message))
  }
}

function storeAnchor (state, name, value) {
  const transactions = state.anchorMapTransactions

  if (transactions.length !== 0) {
    const transaction = transactions[transactions.length - 1]

    if (!_hasOwnProperty.call(transaction, name)) {
      transaction[name] = {
        existed: _hasOwnProperty.call(state.anchorMap, name),
        value: state.anchorMap[name]
      }
    }
  }

  state.anchorMap[name] = value
}

function beginAnchorTransaction (state) {
  state.anchorMapTransactions.push(Object.create(null))
}

function commitAnchorTransaction (state) {
  const transaction = state.anchorMapTransactions.pop()
  const transactions = state.anchorMapTransactions

  if (transactions.length === 0) return

  const parent = transactions[transactions.length - 1]
  const names = Object.keys(transaction)

  for (let index = 0, length = names.length; index < length; index += 1) {
    const name = names[index]

    if (!_hasOwnProperty.call(parent, name)) {
      parent[name] = transaction[name]
    }
  }
}

function rollbackAnchorTransaction (state) {
  const transaction = state.anchorMapTransactions.pop()
  const names = Object.keys(transaction)

  for (let index = names.length - 1; index >= 0; index -= 1) {
    const entry = transaction[names[index]]

    if (entry.existed) {
      state.anchorMap[names[index]] = entry.value
    } else {
      delete state.anchorMap[names[index]]
    }
  }
}

function snapshotState (state) {
  return {
    position: state.position,
    line: state.line,
    lineStart: state.lineStart,
    lineIndent: state.lineIndent,
    firstTabInLine: state.firstTabInLine,
    tag: state.tag,
    anchor: state.anchor,
    kind: state.kind,
    result: state.result
  }
}

function restoreState (state, snapshot) {
  state.position = snapshot.position
  state.line = snapshot.line
  state.lineStart = snapshot.lineStart
  state.lineIndent = snapshot.lineIndent
  state.firstTabInLine = snapshot.firstTabInLine
  state.tag = snapshot.tag
  state.anchor = snapshot.anchor
  state.kind = snapshot.kind
  state.result = snapshot.result
}

const directiveHandlers = {

  YAML: function handleYamlDirective (state, name, args) {
    if (state.version !== null) {
      throwError(state, 'duplication of %YAML directive')
    }

    if (args.length !== 1) {
      throwError(state, 'YAML directive accepts exactly one argument')
    }

    const match = /^([0-9]+)\.([0-9]+)$/.exec(args[0])

    if (match === null) {
      throwError(state, 'ill-formed argument of the YAML directive')
    }

    const major = parseInt(match[1], 10)
    const minor = parseInt(match[2], 10)

    if (major !== 1) {
      throwError(state, 'unacceptable YAML version of the document')
    }

    state.version = args[0]
    state.checkLineBreaks = (minor < 2)

    if (minor !== 1 && minor !== 2) {
      throwWarning(state, 'unsupported YAML version of the document')
    }
  },

  TAG: function handleTagDirective (state, name, args) {
    let prefix

    if (args.length !== 2) {
      throwError(state, 'TAG directive accepts exactly two arguments')
    }

    const handle = args[0]
    prefix = args[1]

    if (!PATTERN_TAG_HANDLE.test(handle)) {
      throwError(state, 'ill-formed tag handle (first argument) of the TAG directive')
    }

    if (_hasOwnProperty.call(state.tagMap, handle)) {
      throwError(state, 'there is a previously declared suffix for "' + handle + '" tag handle')
    }

    if (!PATTERN_TAG_URI.test(prefix)) {
      throwError(state, 'ill-formed tag prefix (second argument) of the TAG directive')
    }

    try {
      prefix = decodeURIComponent(prefix)
    } catch (err) {
      throwError(state, 'tag prefix is malformed: ' + prefix)
    }

    state.tagMap[handle] = prefix
  }
}

function captureSegment (state, start, end, checkJson) {
  if (start < end) {
    const _result = state.input.slice(start, end)

    if (checkJson) {
      for (let _position = 0, _length = _result.length; _position < _length; _position += 1) {
        const _character = _result.charCodeAt(_position)
        if (!(_character === 0x09 ||
              (_character >= 0x20 && _character <= 0x10FFFF))) {
          throwError(state, 'expected valid JSON character')
        }
      }
    } else if (PATTERN_NON_PRINTABLE.test(_result)) {
      throwError(state, 'the stream contains non-printable characters')
    }

    state.result += _result
  }
}

function mergeMappings (state, destination, source, overridableKeys) {
  if (!common.isObject(source)) {
    throwError(state, 'cannot merge mappings; the provided source object is unacceptable')
  }

  const sourceKeys = Object.keys(source)

  for (let index = 0, quantity = sourceKeys.length; index < quantity; index += 1) {
    const key = sourceKeys[index]

    if (!_hasOwnProperty.call(destination, key)) {
      setProperty(destination, key, source[key])
      overridableKeys[key] = true
    }
  }
}

function storeMappingPair (state, _result, overridableKeys, keyTag, keyNode, valueNode,
  startLine, startLineStart, startPos) {
  // The output is a plain object here, so keys can only be strings.
  // We need to convert keyNode to a string, but doing so can hang the process
  // (deeply nested arrays that explode exponentially using aliases).
  if (Array.isArray(keyNode)) {
    keyNode = Array.prototype.slice.call(keyNode)

    for (let index = 0, quantity = keyNode.length; index < quantity; index += 1) {
      if (Array.isArray(keyNode[index])) {
        throwError(state, 'nested arrays are not supported inside keys')
      }

      if (typeof keyNode === 'object' && _class(keyNode[index]) === '[object Object]') {
        keyNode[index] = '[object Object]'
      }
    }
  }

  // Avoid code execution in load() via toString property
  // (still use its own toString for arrays, timestamps,
  // and whatever user schema extensions happen to have @@toStringTag)
  if (typeof keyNode === 'object' && _class(keyNode) === '[object Object]') {
    keyNode = '[object Object]'
  }

  keyNode = String(keyNode)

  if (_result === null) {
    _result = {}
  }

  if (keyTag === 'tag:yaml.org,2002:merge') {
    if (Array.isArray(valueNode)) {
      if (valueNode.length > state.maxMergeSeqLength) {
        throwError(state, 'merge sequence length exceeded maxMergeSeqLength (' + state.maxMergeSeqLength + ')')
      }
      const seen = new Set()
      for (let index = 0, quantity = valueNode.length; index < quantity; index += 1) {
        const src = valueNode[index]
        // Existing keys are not overridden on merge, so dedupe sources to
        // avoid redundant work on repeated aliases.
        if (seen.has(src)) continue
        seen.add(src)
        mergeMappings(state, _result, src, overridableKeys)
      }
    } else {
      mergeMappings(state, _result, valueNode, overridableKeys)
    }
  } else {
    if (!state.json &&
        !_hasOwnProperty.call(overridableKeys, keyNode) &&
        _hasOwnProperty.call(_result, keyNode)) {
      state.line = startLine || state.line
      state.lineStart = startLineStart || state.lineStart
      state.position = startPos || state.position
      throwError(state, 'duplicated mapping key')
    }

    setProperty(_result, keyNode, valueNode)
    delete overridableKeys[keyNode]
  }

  return _result
}

function readLineBreak (state) {
  const ch = state.input.charCodeAt(state.position)

  if (ch === 0x0A/* LF */) {
    state.position++
  } else if (ch === 0x0D/* CR */) {
    state.position++
    if (state.input.charCodeAt(state.position) === 0x0A/* LF */) {
      state.position++
    }
  } else {
    throwError(state, 'a line break is expected')
  }

  state.line += 1
  state.lineStart = state.position
  state.firstTabInLine = -1
}

function skipSeparationSpace (state, allowComments, checkIndent) {
  let lineBreaks = 0
  let ch = state.input.charCodeAt(state.position)

  while (ch !== 0) {
    while (isWhiteSpace(ch)) {
      if (ch === 0x09/* Tab */ && state.firstTabInLine === -1) {
        state.firstTabInLine = state.position
      }
      ch = state.input.charCodeAt(++state.position)
    }

    if (allowComments && ch === 0x23/* # */) {
      do {
        ch = state.input.charCodeAt(++state.position)
      } while (ch !== 0x0A/* LF */ && ch !== 0x0D/* CR */ && ch !== 0)
    }

    if (isEol(ch)) {
      readLineBreak(state)

      ch = state.input.charCodeAt(state.position)
      lineBreaks++
      state.lineIndent = 0

      while (ch === 0x20/* Space */) {
        state.lineIndent++
        ch = state.input.charCodeAt(++state.position)
      }
    } else {
      break
    }
  }

  if (checkIndent !== -1 && lineBreaks !== 0 && state.lineIndent < checkIndent) {
    throwWarning(state, 'deficient indentation')
  }

  return lineBreaks
}

function testDocumentSeparator (state) {
  let _position = state.position
  let ch = state.input.charCodeAt(_position)

  // Condition state.position === state.lineStart is tested
  // in parent on each call, for efficiency. No needs to test here again.
  if ((ch === 0x2D/* - */ || ch === 0x2E/* . */) &&
      ch === state.input.charCodeAt(_position + 1) &&
      ch === state.input.charCodeAt(_position + 2)) {
    _position += 3

    ch = state.input.charCodeAt(_position)

    if (ch === 0 || isWsOrEol(ch)) {
      return true
    }
  }

  return false
}

function writeFoldedLines (state, count) {
  if (count === 1) {
    state.result += ' '
  } else if (count > 1) {
    state.result += common.repeat('\n', count - 1)
  }
}

function readPlainScalar (state, nodeIndent, withinFlowCollection) {
  let captureStart
  let captureEnd
  let hasPendingContent
  let _line
  let _lineStart
  let _lineIndent
  const _kind = state.kind
  const _result = state.result

  let ch = state.input.charCodeAt(state.position)

  if (isWsOrEol(ch) ||
      isFlowIndicator(ch) ||
      ch === 0x23/* # */ ||
      ch === 0x26/* & */ ||
      ch === 0x2A/* * */ ||
      ch === 0x21/* ! */ ||
      ch === 0x7C/* | */ ||
      ch === 0x3E/* > */ ||
      ch === 0x27/* ' */ ||
      ch === 0x22/* " */ ||
      ch === 0x25/* % */ ||
      ch === 0x40/* @ */ ||
      ch === 0x60/* ` */) {
    return false
  }

  if (ch === 0x3F/* ? */ || ch === 0x2D/* - */) {
    const following = state.input.charCodeAt(state.position + 1)

    if (isWsOrEol(following) ||
        (withinFlowCollection && isFlowIndicator(following))) {
      return false
    }
  }

  state.kind = 'scalar'
  state.result = ''
  captureStart = captureEnd = state.position
  hasPendingContent = false

  while (ch !== 0) {
    if (ch === 0x3A/* : */) {
      const following = state.input.charCodeAt(state.position + 1)

      if (isWsOrEol(following) ||
          (withinFlowCollection && isFlowIndicator(following))) {
        break
      }
    } else if (ch === 0x23/* # */) {
      const preceding = state.input.charCodeAt(state.position - 1)

      if (isWsOrEol(preceding)) {
        break
      }
    } else if ((state.position === state.lineStart && testDocumentSeparator(state)) ||
               (withinFlowCollection && isFlowIndicator(ch))) {
      break
    } else if (isEol(ch)) {
      _line = state.line
      _lineStart = state.lineStart
      _lineIndent = state.lineIndent
      skipSeparationSpace(state, false, -1)

      if (state.lineIndent >= nodeIndent) {
        hasPendingContent = true
        ch = state.input.charCodeAt(state.position)
        continue
      } else {
        state.position = captureEnd
        state.line = _line
        state.lineStart = _lineStart
        state.lineIndent = _lineIndent
        break
      }
    }

    if (hasPendingContent) {
      captureSegment(state, captureStart, captureEnd, false)
      writeFoldedLines(state, state.line - _line)
      captureStart = captureEnd = state.position
      hasPendingContent = false
    }

    if (!isWhiteSpace(ch)) {
      captureEnd = state.position + 1
    }

    ch = state.input.charCodeAt(++state.position)
  }

  captureSegment(state, captureStart, captureEnd, false)

  if (state.result) {
    return true
  }

  state.kind = _kind
  state.result = _result
  return false
}

function readSingleQuotedScalar (state, nodeIndent) {
  let captureStart
  let captureEnd

  let ch = state.input.charCodeAt(state.position)

  if (ch !== 0x27/* ' */) {
    return false
  }

  state.kind = 'scalar'
  state.result = ''
  state.position++
  captureStart = captureEnd = state.position

  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 0x27/* ' */) {
      captureSegment(state, captureStart, state.position, true)
      ch = state.input.charCodeAt(++state.position)

      if (ch === 0x27/* ' */) {
        captureStart = state.position
        state.position++
        captureEnd = state.position
      } else {
        return true
      }
    } else if (isEol(ch)) {
      captureSegment(state, captureStart, captureEnd, true)
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent))
      captureStart = captureEnd = state.position
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, 'unexpected end of the document within a single quoted scalar')
    } else {
      state.position++
      if (!isWhiteSpace(ch)) {
        captureEnd = state.position
      }
    }
  }

  throwError(state, 'unexpected end of the stream within a single quoted scalar')
}

function readDoubleQuotedScalar (state, nodeIndent) {
  let captureStart
  let captureEnd
  let tmp

  let ch = state.input.charCodeAt(state.position)

  if (ch !== 0x22/* " */) {
    return false
  }

  state.kind = 'scalar'
  state.result = ''
  state.position++
  captureStart = captureEnd = state.position

  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 0x22/* " */) {
      captureSegment(state, captureStart, state.position, true)
      state.position++
      return true
    } else if (ch === 0x5C/* \ */) {
      captureSegment(state, captureStart, state.position, true)
      ch = state.input.charCodeAt(++state.position)

      if (isEol(ch)) {
        skipSeparationSpace(state, false, nodeIndent)

        // TODO: rework to inline fn with no type cast?
      } else if (ch < 256 && simpleEscapeCheck[ch]) {
        state.result += simpleEscapeMap[ch]
        state.position++
      } else if ((tmp = escapedHexLen(ch)) > 0) {
        let hexLength = tmp
        let hexResult = 0

        for (; hexLength > 0; hexLength--) {
          ch = state.input.charCodeAt(++state.position)

          if ((tmp = fromHexCode(ch)) >= 0) {
            hexResult = (hexResult << 4) + tmp
          } else {
            throwError(state, 'expected hexadecimal character')
          }
        }

        state.result += charFromCodepoint(hexResult)

        state.position++
      } else {
        throwError(state, 'unknown escape sequence')
      }

      captureStart = captureEnd = state.position
    } else if (isEol(ch)) {
      captureSegment(state, captureStart, captureEnd, true)
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent))
      captureStart = captureEnd = state.position
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, 'unexpected end of the document within a double quoted scalar')
    } else {
      state.position++
      if (!isWhiteSpace(ch)) {
        captureEnd = state.position
      }
    }
  }

  throwError(state, 'unexpected end of the stream within a double quoted scalar')
}

function readFlowCollection (state, nodeIndent) {
  let readNext = true
  let _line
  let _lineStart
  let _pos
  const _tag = state.tag
  let _result
  const _anchor = state.anchor
  let terminator
  let isPair
  let isExplicitPair
  let isMapping
  const overridableKeys = Object.create(null)
  let keyNode
  let keyTag
  let valueNode

  let ch = state.input.charCodeAt(state.position)

  if (ch === 0x5B/* [ */) {
    terminator = 0x5D/* ] */
    isMapping = false
    _result = []
  } else if (ch === 0x7B/* { */) {
    terminator = 0x7D/* } */
    isMapping = true
    _result = {}
  } else {
    return false
  }

  if (state.anchor !== null) {
    storeAnchor(state, state.anchor, _result)
  }

  ch = state.input.charCodeAt(++state.position)

  while (ch !== 0) {
    skipSeparationSpace(state, true, nodeIndent)

    ch = state.input.charCodeAt(state.position)

    if (ch === terminator) {
      state.position++
      state.tag = _tag
      state.anchor = _anchor
      state.kind = isMapping ? 'mapping' : 'sequence'
      state.result = _result
      return true
    } else if (!readNext) {
      throwError(state, 'missed comma between flow collection entries')
    } else if (ch === 0x2C/* , */) {
      // "flow collection entries can never be completely empty", as per YAML 1.2, section 7.4
      throwError(state, "expected the node content, but found ','")
    }

    keyTag = keyNode = valueNode = null
    isPair = isExplicitPair = false

    if (ch === 0x3F/* ? */) {
      const following = state.input.charCodeAt(state.position + 1)

      if (isWsOrEol(following)) {
        isPair = isExplicitPair = true
        state.position++
        skipSeparationSpace(state, true, nodeIndent)
      }
    }

    _line = state.line // Save the current line.
    _lineStart = state.lineStart
    _pos = state.position
    composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true)
    keyTag = state.tag
    keyNode = state.result
    skipSeparationSpace(state, true, nodeIndent)

    ch = state.input.charCodeAt(state.position)

    if ((isExplicitPair || state.line === _line) && ch === 0x3A/* : */) {
      isPair = true
      ch = state.input.charCodeAt(++state.position)
      skipSeparationSpace(state, true, nodeIndent)
      composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true)
      valueNode = state.result
    }

    if (isMapping) {
      storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos)
    } else if (isPair) {
      _result.push(storeMappingPair(state, null, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos))
    } else {
      _result.push(keyNode)
    }

    skipSeparationSpace(state, true, nodeIndent)

    ch = state.input.charCodeAt(state.position)

    if (ch === 0x2C/* , */) {
      readNext = true
      ch = state.input.charCodeAt(++state.position)
    } else {
      readNext = false
    }
  }

  throwError(state, 'unexpected end of the stream within a flow collection')
}

function readBlockScalar (state, nodeIndent) {
  let folding
  let chomping = CHOMPING_CLIP
  let didReadContent = false
  let detectedIndent = false
  let textIndent = nodeIndent
  let emptyLines = 0
  let atMoreIndented = false
  let tmp

  let ch = state.input.charCodeAt(state.position)

  if (ch === 0x7C/* | */) {
    folding = false
  } else if (ch === 0x3E/* > */) {
    folding = true
  } else {
    return false
  }

  state.kind = 'scalar'
  state.result = ''

  while (ch !== 0) {
    ch = state.input.charCodeAt(++state.position)

    if (ch === 0x2B/* + */ || ch === 0x2D/* - */) {
      if (CHOMPING_CLIP === chomping) {
        chomping = (ch === 0x2B/* + */) ? CHOMPING_KEEP : CHOMPING_STRIP
      } else {
        throwError(state, 'repeat of a chomping mode identifier')
      }
    } else if ((tmp = fromDecimalCode(ch)) >= 0) {
      if (tmp === 0) {
        throwError(state, 'bad explicit indentation width of a block scalar; it cannot be less than one')
      } else if (!detectedIndent) {
        textIndent = nodeIndent + tmp - 1
        detectedIndent = true
      } else {
        throwError(state, 'repeat of an indentation width identifier')
      }
    } else {
      break
    }
  }

  if (isWhiteSpace(ch)) {
    do { ch = state.input.charCodeAt(++state.position) }
    while (isWhiteSpace(ch))

    if (ch === 0x23/* # */) {
      do { ch = state.input.charCodeAt(++state.position) }
      while (!isEol(ch) && (ch !== 0))
    }
  }

  while (ch !== 0) {
    readLineBreak(state)
    state.lineIndent = 0

    ch = state.input.charCodeAt(state.position)

    // eslint-disable-next-line no-unmodified-loop-condition
    while ((!detectedIndent || state.lineIndent < textIndent) &&
           (ch === 0x20/* Space */)) {
      state.lineIndent++
      ch = state.input.charCodeAt(++state.position)
    }

    if (!detectedIndent && state.lineIndent > textIndent) {
      textIndent = state.lineIndent
    }

    if (isEol(ch)) {
      emptyLines++
      continue
    }

    if (!detectedIndent && textIndent === 0) {
      throwError(state, 'missing indentation for block scalar')
    }

    // End of the scalar.
    if (state.lineIndent < textIndent) {
      // Perform the chomping.
      if (chomping === CHOMPING_KEEP) {
        state.result += common.repeat('\n', didReadContent ? 1 + emptyLines : emptyLines)
      } else if (chomping === CHOMPING_CLIP) {
        if (didReadContent) { // i.e. only if the scalar is not empty.
          state.result += '\n'
        }
      }

      // Break this `while` cycle and go to the funciton's epilogue.
      break
    }

    // Folded style: use fancy rules to handle line breaks.
    if (folding) {
      // Lines starting with white space characters (more-indented lines) are not folded.
      if (isWhiteSpace(ch)) {
        atMoreIndented = true
        // except for the first content line (cf. Example 8.1)
        state.result += common.repeat('\n', didReadContent ? 1 + emptyLines : emptyLines)

      // End of more-indented block.
      } else if (atMoreIndented) {
        atMoreIndented = false
        state.result += common.repeat('\n', emptyLines + 1)

      // Just one line break - perceive as the same line.
      } else if (emptyLines === 0) {
        if (didReadContent) { // i.e. only if we have already read some scalar content.
          state.result += ' '
        }

      // Several line breaks - perceive as different lines.
      } else {
        state.result += common.repeat('\n', emptyLines)
      }

    // Literal style: just add exact number of line breaks between content lines.
    } else {
      // Keep all line breaks except the header line break.
      state.result += common.repeat('\n', didReadContent ? 1 + emptyLines : emptyLines)
    }

    didReadContent = true
    detectedIndent = true
    emptyLines = 0
    const captureStart = state.position

    while (!isEol(ch) && (ch !== 0)) {
      ch = state.input.charCodeAt(++state.position)
    }

    captureSegment(state, captureStart, state.position, false)
  }

  return true
}

function readBlockSequence (state, nodeIndent) {
  const _tag = state.tag
  const _anchor = state.anchor
  const _result = []
  let detected = false

  // there is a leading tab before this token, so it can't be a block sequence/mapping;
  // it can still be flow sequence/mapping or a scalar
  if (state.firstTabInLine !== -1) return false

  if (state.anchor !== null) {
    storeAnchor(state, state.anchor, _result)
  }

  let ch = state.input.charCodeAt(state.position)

  while (ch !== 0) {
    if (state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine
      throwError(state, 'tab characters must not be used in indentation')
    }

    if (ch !== 0x2D/* - */) {
      break
    }

    const following = state.input.charCodeAt(state.position + 1)

    if (!isWsOrEol(following)) {
      break
    }

    detected = true
    state.position++

    if (skipSeparationSpace(state, true, -1)) {
      if (state.lineIndent <= nodeIndent) {
        _result.push(null)
        ch = state.input.charCodeAt(state.position)
        continue
      }
    }

    const _line = state.line
    composeNode(state, nodeIndent, CONTEXT_BLOCK_IN, false, true)
    _result.push(state.result)
    skipSeparationSpace(state, true, -1)

    ch = state.input.charCodeAt(state.position)

    if ((state.line === _line || state.lineIndent > nodeIndent) && (ch !== 0)) {
      throwError(state, 'bad indentation of a sequence entry')
    } else if (state.lineIndent < nodeIndent) {
      break
    }
  }

  if (detected) {
    state.tag = _tag
    state.anchor = _anchor
    state.kind = 'sequence'
    state.result = _result
    return true
  }
  return false
}

function readBlockMapping (state, nodeIndent, flowIndent) {
  let allowCompact
  let _keyLine
  let _keyLineStart
  let _keyPos
  const _tag = state.tag
  const _anchor = state.anchor
  const _result = {}
  const overridableKeys = Object.create(null)
  let keyTag = null
  let keyNode = null
  let valueNode = null
  let atExplicitKey = false
  let detected = false

  // there is a leading tab before this token, so it can't be a block sequence/mapping;
  // it can still be flow sequence/mapping or a scalar
  if (state.firstTabInLine !== -1) return false

  if (state.anchor !== null) {
    storeAnchor(state, state.anchor, _result)
  }

  let ch = state.input.charCodeAt(state.position)

  while (ch !== 0) {
    if (!atExplicitKey && state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine
      throwError(state, 'tab characters must not be used in indentation')
    }

    const following = state.input.charCodeAt(state.position + 1)
    const _line = state.line // Save the current line.

    //
    // Explicit notation case. There are two separate blocks:
    // first for the key (denoted by "?") and second for the value (denoted by ":")
    //
    if ((ch === 0x3F/* ? */ || ch === 0x3A/* : */) && isWsOrEol(following)) {
      if (ch === 0x3F/* ? */) {
        if (atExplicitKey) {
          storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos)
          keyTag = keyNode = valueNode = null
        }

        detected = true
        atExplicitKey = true
        allowCompact = true
      } else if (atExplicitKey) {
        // i.e. 0x3A/* : */ === character after the explicit key.
        atExplicitKey = false
        allowCompact = true
      } else {
        throwError(state, 'incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line')
      }

      state.position += 1
      ch = following

    //
    // Implicit notation case. Flow-style node as the key first, then ":", and the value.
    //
    } else {
      _keyLine = state.line
      _keyLineStart = state.lineStart
      _keyPos = state.position

      if (!composeNode(state, flowIndent, CONTEXT_FLOW_OUT, false, true)) {
        // Neither implicit nor explicit notation.
        // Reading is done. Go to the epilogue.
        break
      }

      if (state.line === _line) {
        ch = state.input.charCodeAt(state.position)

        while (isWhiteSpace(ch)) {
          ch = state.input.charCodeAt(++state.position)
        }

        if (ch === 0x3A/* : */) {
          ch = state.input.charCodeAt(++state.position)

          if (!isWsOrEol(ch)) {
            throwError(state, 'a whitespace character is expected after the key-value separator within a block mapping')
          }

          if (atExplicitKey) {
            storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos)
            keyTag = keyNode = valueNode = null
          }

          detected = true
          atExplicitKey = false
          allowCompact = false
          keyTag = state.tag
          keyNode = state.result
        } else if (detected) {
          throwError(state, 'can not read an implicit mapping pair; a colon is missed')
        } else {
          state.tag = _tag
          state.anchor = _anchor
          return true // Keep the result of `composeNode`.
        }
      } else if (detected) {
        throwError(state, 'can not read a block mapping entry; a multiline key may not be an implicit key')
      } else {
        state.tag = _tag
        state.anchor = _anchor
        return true // Keep the result of `composeNode`.
      }
    }

    //
    // Common reading code for both explicit and implicit notations.
    //
    if (state.line === _line || state.lineIndent > nodeIndent) {
      if (atExplicitKey) {
        _keyLine = state.line
        _keyLineStart = state.lineStart
        _keyPos = state.position
      }

      if (composeNode(state, nodeIndent, CONTEXT_BLOCK_OUT, true, allowCompact)) {
        if (atExplicitKey) {
          keyNode = state.result
        } else {
          valueNode = state.result
        }
      }

      if (!atExplicitKey) {
        storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _keyLine, _keyLineStart, _keyPos)
        keyTag = keyNode = valueNode = null
      }

      skipSeparationSpace(state, true, -1)
      ch = state.input.charCodeAt(state.position)
    }

    if ((state.line === _line || state.lineIndent > nodeIndent) && (ch !== 0)) {
      throwError(state, 'bad indentation of a mapping entry')
    } else if (state.lineIndent < nodeIndent) {
      break
    }
  }

  //
  // Epilogue.
  //

  // Special case: last mapping's node contains only the key in explicit notation.
  if (atExplicitKey) {
    storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos)
  }

  // Expose the resulting mapping.
  if (detected) {
    state.tag = _tag
    state.anchor = _anchor
    state.kind = 'mapping'
    state.result = _result
  }

  return detected
}

function readTagProperty (state) {
  let isVerbatim = false
  let isNamed = false
  let tagHandle
  let tagName

  let ch = state.input.charCodeAt(state.position)

  if (ch !== 0x21/* ! */) return false

  if (state.tag !== null) {
    throwError(state, 'duplication of a tag property')
  }

  ch = state.input.charCodeAt(++state.position)

  if (ch === 0x3C/* < */) {
    isVerbatim = true
    ch = state.input.charCodeAt(++state.position)
  } else if (ch === 0x21/* ! */) {
    isNamed = true
    tagHandle = '!!'
    ch = state.input.charCodeAt(++state.position)
  } else {
    tagHandle = '!'
  }

  let _position = state.position

  if (isVerbatim) {
    do { ch = state.input.charCodeAt(++state.position) }
    while (ch !== 0 && ch !== 0x3E/* > */)

    if (state.position < state.length) {
      tagName = state.input.slice(_position, state.position)
      ch = state.input.charCodeAt(++state.position)
    } else {
      throwError(state, 'unexpected end of the stream within a verbatim tag')
    }
  } else {
    while (ch !== 0 && !isWsOrEol(ch)) {
      if (ch === 0x21/* ! */) {
        if (!isNamed) {
          tagHandle = state.input.slice(_position - 1, state.position + 1)

          if (!PATTERN_TAG_HANDLE.test(tagHandle)) {
            throwError(state, 'named tag handle cannot contain such characters')
          }

          isNamed = true
          _position = state.position + 1
        } else {
          throwError(state, 'tag suffix cannot contain exclamation marks')
        }
      }

      ch = state.input.charCodeAt(++state.position)
    }

    tagName = state.input.slice(_position, state.position)

    if (PATTERN_FLOW_INDICATORS.test(tagName)) {
      throwError(state, 'tag suffix cannot contain flow indicator characters')
    }
  }

  if (tagName && !PATTERN_TAG_URI.test(tagName)) {
    throwError(state, 'tag name cannot contain such characters: ' + tagName)
  }

  try {
    tagName = decodeURIComponent(tagName)
  } catch (err) {
    throwError(state, 'tag name is malformed: ' + tagName)
  }

  if (isVerbatim) {
    state.tag = tagName
  } else if (_hasOwnProperty.call(state.tagMap, tagHandle)) {
    state.tag = state.tagMap[tagHandle] + tagName
  } else if (tagHandle === '!') {
    state.tag = '!' + tagName
  } else if (tagHandle === '!!') {
    state.tag = 'tag:yaml.org,2002:' + tagName
  } else {
    throwError(state, 'undeclared tag handle "' + tagHandle + '"')
  }

  return true
}

function readAnchorProperty (state) {
  let ch = state.input.charCodeAt(state.position)

  if (ch !== 0x26/* & */) return false

  if (state.anchor !== null) {
    throwError(state, 'duplication of an anchor property')
  }

  ch = state.input.charCodeAt(++state.position)
  const _position = state.position

  while (ch !== 0 && !isWsOrEol(ch) && !isFlowIndicator(ch)) {
    ch = state.input.charCodeAt(++state.position)
  }

  if (state.position === _position) {
    throwError(state, 'name of an anchor node must contain at least one character')
  }

  state.anchor = state.input.slice(_position, state.position)
  return true
}

function readAlias (state) {
  let ch = state.input.charCodeAt(state.position)

  if (ch !== 0x2A/* * */) return false

  ch = state.input.charCodeAt(++state.position)
  const _position = state.position

  while (ch !== 0 && !isWsOrEol(ch) && !isFlowIndicator(ch)) {
    ch = state.input.charCodeAt(++state.position)
  }

  if (state.position === _position) {
    throwError(state, 'name of an alias node must contain at least one character')
  }

  const alias = state.input.slice(_position, state.position)

  if (!_hasOwnProperty.call(state.anchorMap, alias)) {
    throwError(state, 'unidentified alias "' + alias + '"')
  }

  state.result = state.anchorMap[alias]
  skipSeparationSpace(state, true, -1)
  return true
}

function tryReadBlockMappingFromProperty (state, propertyStart, nodeIndent, flowIndent) {
  const fallbackState = snapshotState(state)

  beginAnchorTransaction(state)
  restoreState(state, propertyStart)

  // Re-read the leading properties as part of the first implicit key, not as
  // properties of the current node.
  state.tag = null
  state.anchor = null
  state.kind = null
  state.result = null

  if (readBlockMapping(state, nodeIndent, flowIndent) && state.kind === 'mapping') {
    commitAnchorTransaction(state)
    return true
  }

  rollbackAnchorTransaction(state)
  restoreState(state, fallbackState)
  return false
}

function composeNode (state, parentIndent, nodeContext, allowToSeek, allowCompact) {
  let allowBlockScalars
  let allowBlockCollections
  let indentStatus = 1 // 1: this>parent, 0: this=parent, -1: this<parent
  let atNewLine = false
  let hasContent = false
  let propertyStart = null
  let type
  let flowIndent
  let blockIndent

  if (state.depth >= state.maxDepth) {
    throwError(state, 'nesting exceeded maxDepth (' + state.maxDepth + ')')
  }

  state.depth += 1

  if (state.listener !== null) {
    state.listener('open', state)
  }

  state.tag = null
  state.anchor = null
  state.kind = null
  state.result = null

  const allowBlockStyles = allowBlockScalars = allowBlockCollections =
    CONTEXT_BLOCK_OUT === nodeContext ||
    CONTEXT_BLOCK_IN === nodeContext

  if (allowToSeek) {
    if (skipSeparationSpace(state, true, -1)) {
      atNewLine = true

      if (state.lineIndent > parentIndent) {
        indentStatus = 1
      } else if (state.lineIndent === parentIndent) {
        indentStatus = 0
      } else if (state.lineIndent < parentIndent) {
        indentStatus = -1
      }
    }
  }

  if (indentStatus === 1) {
    while (true) {
      const ch = state.input.charCodeAt(state.position)
      const propertyState = snapshotState(state)

      // A duplicate property token after a line break can be the first key of
      // a nested block mapping, e.g. `!!map\n  !!str key: value`.
      if (atNewLine &&
          ((ch === 0x21/* ! */ && state.tag !== null) ||
           (ch === 0x26/* & */ && state.anchor !== null))) {
        break
      }

      if (!readTagProperty(state) && !readAnchorProperty(state)) {
        break
      }

      if (propertyStart === null) {
        propertyStart = propertyState
      }

      if (skipSeparationSpace(state, true, -1)) {
        atNewLine = true
        allowBlockCollections = allowBlockStyles

        if (state.lineIndent > parentIndent) {
          indentStatus = 1
        } else if (state.lineIndent === parentIndent) {
          indentStatus = 0
        } else if (state.lineIndent < parentIndent) {
          indentStatus = -1
        }
      } else {
        allowBlockCollections = false
      }
    }
  }

  if (allowBlockCollections) {
    allowBlockCollections = atNewLine || allowCompact
  }

  if (indentStatus === 1 || CONTEXT_BLOCK_OUT === nodeContext) {
    if (CONTEXT_FLOW_IN === nodeContext || CONTEXT_FLOW_OUT === nodeContext) {
      flowIndent = parentIndent
    } else {
      flowIndent = parentIndent + 1
    }

    blockIndent = state.position - state.lineStart

    if (indentStatus === 1) {
      if ((allowBlockCollections &&
          (readBlockSequence(state, blockIndent) || readBlockMapping(state, blockIndent, flowIndent))) ||
          readFlowCollection(state, flowIndent)) {
        hasContent = true
      } else {
        const ch = state.input.charCodeAt(state.position)

        if (propertyStart !== null && allowBlockStyles && !allowBlockCollections &&
            ch !== 0x7C/* | */ && ch !== 0x3E/* > */ &&
            tryReadBlockMappingFromProperty(
              state,
              propertyStart,
              propertyStart.position - propertyStart.lineStart,
              flowIndent
            )) {
          hasContent = true
        } else if ((allowBlockScalars && readBlockScalar(state, flowIndent)) ||
            readSingleQuotedScalar(state, flowIndent) ||
            readDoubleQuotedScalar(state, flowIndent)) {
          hasContent = true
        } else if (readAlias(state)) {
          hasContent = true

          if (state.tag !== null || state.anchor !== null) {
            throwError(state, 'alias node should not have any properties')
          }
        } else if (readPlainScalar(state, flowIndent, CONTEXT_FLOW_IN === nodeContext)) {
          hasContent = true

          if (state.tag === null) {
            state.tag = '?'
          }
        }

        if (state.anchor !== null) {
          storeAnchor(state, state.anchor, state.result)
        }
      }
    } else if (indentStatus === 0) {
      // Special case: block sequences are allowed to have same indentation level as the parent.
      // http://www.yaml.org/spec/1.2/spec.html#id2799784
      hasContent = allowBlockCollections && readBlockSequence(state, blockIndent)
    }
  }

  if (state.tag === null) {
    if (state.anchor !== null) {
      storeAnchor(state, state.anchor, state.result)
    }
  } else if (state.tag === '?') {
    // Implicit resolving is not allowed for non-scalar types, and '?'
    // non-specific tag is only automatically assigned to plain scalars.
    //
    // We only need to check kind conformity in case user explicitly assigns '?'
    // tag, for example like this: "!<?> [0]"
    //
    if (state.result !== null && state.kind !== 'scalar') {
      throwError(state, 'unacceptable node kind for !<?> tag; it should be "scalar", not "' + state.kind + '"')
    }

    for (let typeIndex = 0, typeQuantity = state.implicitTypes.length; typeIndex < typeQuantity; typeIndex += 1) {
      type = state.implicitTypes[typeIndex]

      if (type.resolve(state.result)) { // `state.result` updated in resolver if matched
        state.result = type.construct(state.result)
        state.tag = type.tag
        if (state.anchor !== null) {
          storeAnchor(state, state.anchor, state.result)
        }
        break
      }
    }
  } else if (state.tag !== '!') {
    if (_hasOwnProperty.call(state.typeMap[state.kind || 'fallback'], state.tag)) {
      type = state.typeMap[state.kind || 'fallback'][state.tag]
    } else {
      // looking for multi type
      type = null
      const typeList = state.typeMap.multi[state.kind || 'fallback']

      for (let typeIndex = 0, typeQuantity = typeList.length; typeIndex < typeQuantity; typeIndex += 1) {
        if (state.tag.slice(0, typeList[typeIndex].tag.length) === typeList[typeIndex].tag) {
          type = typeList[typeIndex]
          break
        }
      }
    }

    if (!type) {
      throwError(state, 'unknown tag !<' + state.tag + '>')
    }

    if (state.result !== null && type.kind !== state.kind) {
      throwError(state, 'unacceptable node kind for !<' + state.tag + '> tag; it should be "' + type.kind + '", not "' + state.kind + '"')
    }

    if (!type.resolve(state.result, state.tag)) { // `state.result` updated in resolver if matched
      throwError(state, 'cannot resolve a node with !<' + state.tag + '> explicit tag')
    } else {
      state.result = type.construct(state.result, state.tag)
      if (state.anchor !== null) {
        storeAnchor(state, state.anchor, state.result)
      }
    }
  }

  if (state.listener !== null) {
    state.listener('close', state)
  }

  state.depth -= 1
  return state.tag !== null || state.anchor !== null || hasContent
}

function readDocument (state) {
  const documentStart = state.position
  let hasDirectives = false
  let ch

  state.version = null
  state.checkLineBreaks = state.legacy
  state.tagMap = Object.create(null)
  state.anchorMap = Object.create(null)

  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    skipSeparationSpace(state, true, -1)

    ch = state.input.charCodeAt(state.position)

    if (state.lineIndent > 0 || ch !== 0x25/* % */) {
      break
    }

    hasDirectives = true
    ch = state.input.charCodeAt(++state.position)
    let _position = state.position

    while (ch !== 0 && !isWsOrEol(ch)) {
      ch = state.input.charCodeAt(++state.position)
    }

    const directiveName = state.input.slice(_position, state.position)
    const directiveArgs = []

    if (directiveName.length < 1) {
      throwError(state, 'directive name must not be less than one character in length')
    }

    while (ch !== 0) {
      while (isWhiteSpace(ch)) {
        ch = state.input.charCodeAt(++state.position)
      }

      if (ch === 0x23/* # */) {
        do { ch = state.input.charCodeAt(++state.position) }
        while (ch !== 0 && !isEol(ch))
        break
      }

      if (isEol(ch)) break

      _position = state.position

      while (ch !== 0 && !isWsOrEol(ch)) {
        ch = state.input.charCodeAt(++state.position)
      }

      directiveArgs.push(state.input.slice(_position, state.position))
    }

    if (ch !== 0) readLineBreak(state)

    if (_hasOwnProperty.call(directiveHandlers, directiveName)) {
      directiveHandlers[directiveName](state, directiveName, directiveArgs)
    } else {
      throwWarning(state, 'unknown document directive "' + directiveName + '"')
    }
  }

  skipSeparationSpace(state, true, -1)

  if (state.lineIndent === 0 &&
      state.input.charCodeAt(state.position) === 0x2D/* - */ &&
      state.input.charCodeAt(state.position + 1) === 0x2D/* - */ &&
      state.input.charCodeAt(state.position + 2) === 0x2D/* - */) {
    state.position += 3
    skipSeparationSpace(state, true, -1)
  } else if (hasDirectives) {
    throwError(state, 'directives end mark is expected')
  }

  composeNode(state, state.lineIndent - 1, CONTEXT_BLOCK_OUT, false, true)
  skipSeparationSpace(state, true, -1)

  if (state.checkLineBreaks &&
      PATTERN_NON_ASCII_LINE_BREAKS.test(state.input.slice(documentStart, state.position))) {
    throwWarning(state, 'non-ASCII line breaks are interpreted as content')
  }

  state.documents.push(state.result)

  if (state.position === state.lineStart && testDocumentSeparator(state)) {
    if (state.input.charCodeAt(state.position) === 0x2E/* . */) {
      state.position += 3
      skipSeparationSpace(state, true, -1)
    }
    return
  }

  if (state.position < (state.length - 1)) {
    throwError(state, 'end of the stream or a document separator is expected')
  }
}

function loadDocuments (input, options) {
  input = String(input)
  options = options || {}

  if (input.length !== 0) {
    // Add tailing `\n` if not exists
    if (input.charCodeAt(input.length - 1) !== 0x0A/* LF */ &&
        input.charCodeAt(input.length - 1) !== 0x0D/* CR */) {
      input += '\n'
    }

    // Strip BOM
    if (input.charCodeAt(0) === 0xFEFF) {
      input = input.slice(1)
    }
  }

  const state = new State(input, options)

  const nullpos = input.indexOf('\0')

  if (nullpos !== -1) {
    state.position = nullpos
    throwError(state, 'null byte is not allowed in input')
  }

  // Use 0 as string terminator. That significantly simplifies bounds check.
  state.input += '\0'

  while (state.input.charCodeAt(state.position) === 0x20/* Space */) {
    state.lineIndent += 1
    state.position += 1
  }

  while (state.position < (state.length - 1)) {
    readDocument(state)
  }

  return state.documents
}

function loadAll (input, iterator, options) {
  if (iterator !== null && typeof iterator === 'object' && typeof options === 'undefined') {
    options = iterator
    iterator = null
  }

  const documents = loadDocuments(input, options)

  if (typeof iterator !== 'function') {
    return documents
  }

  for (let index = 0, length = documents.length; index < length; index += 1) {
    iterator(documents[index])
  }
}

function load (input, options) {
  const documents = loadDocuments(input, options)

  if (documents.length === 0) {
    return undefined
  } else if (documents.length === 1) {
    return documents[0]
  }
  throw new YAMLException('expected a single document in the stream, but found more')
}

module.exports.loadAll = loadAll
module.exports.load = load
    },
    "lib/schema"(module, exports, require) {
'use strict'

const YAMLException = require('./exception')
const Type = require('./type')

function compileList (schema, name) {
  const result = []

  schema[name].forEach(function (currentType) {
    let newIndex = result.length

    result.forEach(function (previousType, previousIndex) {
      if (previousType.tag === currentType.tag &&
          previousType.kind === currentType.kind &&
          previousType.multi === currentType.multi) {
        newIndex = previousIndex
      }
    })

    result[newIndex] = currentType
  })

  return result
}

function compileMap (/* lists... */) {
  const result = {
    scalar: {},
    sequence: {},
    mapping: {},
    fallback: {},
    multi: {
      scalar: [],
      sequence: [],
      mapping: [],
      fallback: []
    }
  }
  function collectType (type) {
    if (type.multi) {
      result.multi[type.kind].push(type)
      result.multi['fallback'].push(type)
    } else {
      result[type.kind][type.tag] = result['fallback'][type.tag] = type
    }
  }

  for (let index = 0, length = arguments.length; index < length; index += 1) {
    arguments[index].forEach(collectType)
  }
  return result
}

function Schema (definition) {
  return this.extend(definition)
}

Schema.prototype.extend = function extend (definition) {
  let implicit = []
  let explicit = []

  if (definition instanceof Type) {
    // Schema.extend(type)
    explicit.push(definition)
  } else if (Array.isArray(definition)) {
    // Schema.extend([ type1, type2, ... ])
    explicit = explicit.concat(definition)
  } else if (definition && (Array.isArray(definition.implicit) || Array.isArray(definition.explicit))) {
    // Schema.extend({ explicit: [ type1, type2, ... ], implicit: [ type1, type2, ... ] })
    if (definition.implicit) implicit = implicit.concat(definition.implicit)
    if (definition.explicit) explicit = explicit.concat(definition.explicit)
  } else {
    throw new YAMLException('Schema.extend argument should be a Type, [ Type ], ' +
      'or a schema definition ({ implicit: [...], explicit: [...] })')
  }

  implicit.forEach(function (type) {
    if (!(type instanceof Type)) {
      throw new YAMLException('Specified list of YAML types (or a single Type object) contains a non-Type object.')
    }

    if (type.loadKind && type.loadKind !== 'scalar') {
      throw new YAMLException('There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.')
    }

    if (type.multi) {
      throw new YAMLException('There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.')
    }
  })

  explicit.forEach(function (type) {
    if (!(type instanceof Type)) {
      throw new YAMLException('Specified list of YAML types (or a single Type object) contains a non-Type object.')
    }
  })

  const result = Object.create(Schema.prototype)

  result.implicit = (this.implicit || []).concat(implicit)
  result.explicit = (this.explicit || []).concat(explicit)

  result.compiledImplicit = compileList(result, 'implicit')
  result.compiledExplicit = compileList(result, 'explicit')
  result.compiledTypeMap = compileMap(result.compiledImplicit, result.compiledExplicit)

  return result
}

module.exports = Schema
    },
    "lib/schema/core"(module, exports, require) {
// Standard YAML's Core schema.
// http://www.yaml.org/spec/1.2/spec.html#id2804923
//
// NOTE: JS-YAML does not support schema-specific tag resolution restrictions.
// So, Core schema has no distinctions from JSON schema is JS-YAML.

'use strict'

module.exports = require('./json')
    },
    "lib/schema/default"(module, exports, require) {
// JS-YAML's default schema for `safeLoad` function.
// It is not described in the YAML specification.
//
// This schema is based on standard YAML's Core schema and includes most of
// extra types described at YAML tag repository. (http://yaml.org/type/)

'use strict'

module.exports = require('./core').extend({
  implicit: [
    require('../type/timestamp'),
    require('../type/merge')
  ],
  explicit: [
    require('../type/binary'),
    require('../type/omap'),
    require('../type/pairs'),
    require('../type/set')
  ]
})
    },
    "lib/schema/failsafe"(module, exports, require) {
// Standard YAML's Failsafe schema.
// http://www.yaml.org/spec/1.2/spec.html#id2802346

'use strict'

const Schema = require('../schema')

module.exports = new Schema({
  explicit: [
    require('../type/str'),
    require('../type/seq'),
    require('../type/map')
  ]
})
    },
    "lib/schema/json"(module, exports, require) {
// Standard YAML's JSON schema.
// http://www.yaml.org/spec/1.2/spec.html#id2803231
//
// NOTE: JS-YAML does not support schema-specific tag resolution restrictions.
// So, this schema is not such strict as defined in the YAML specification.
// It allows numbers in binary notaion, use `Null` and `NULL` as `null`, etc.

'use strict'

module.exports = require('./failsafe').extend({
  implicit: [
    require('../type/null'),
    require('../type/bool'),
    require('../type/int'),
    require('../type/float')
  ]
})
    },
    "lib/snippet"(module, exports, require) {
'use strict'

const common = require('./common')

// get snippet for a single line, respecting maxLength
function getLine (buffer, lineStart, lineEnd, position, maxLineLength) {
  let head = ''
  let tail = ''
  const maxHalfLength = Math.floor(maxLineLength / 2) - 1

  if (position - lineStart > maxHalfLength) {
    head = ' ... '
    lineStart = position - maxHalfLength + head.length
  }

  if (lineEnd - position > maxHalfLength) {
    tail = ' ...'
    lineEnd = position + maxHalfLength - tail.length
  }

  return {
    str: head + buffer.slice(lineStart, lineEnd).replace(/\t/g, '→') + tail,
    pos: position - lineStart + head.length // relative position
  }
}

function padStart (string, max) {
  return common.repeat(' ', max - string.length) + string
}

function makeSnippet (mark, options) {
  options = Object.create(options || null)

  if (!mark.buffer) return null

  if (!options.maxLength) options.maxLength = 79
  if (typeof options.indent !== 'number') options.indent = 1
  if (typeof options.linesBefore !== 'number') options.linesBefore = 3
  if (typeof options.linesAfter !== 'number') options.linesAfter = 2

  const re = /\r?\n|\r|\0/g
  const lineStarts = [0]
  const lineEnds = []
  let match
  let foundLineNo = -1

  while ((match = re.exec(mark.buffer))) {
    lineEnds.push(match.index)
    lineStarts.push(match.index + match[0].length)

    if (mark.position <= match.index && foundLineNo < 0) {
      foundLineNo = lineStarts.length - 2
    }
  }

  if (foundLineNo < 0) foundLineNo = lineStarts.length - 1

  let result = ''
  const lineNoLength = Math.min(mark.line + options.linesAfter, lineEnds.length).toString().length
  const maxLineLength = options.maxLength - (options.indent + lineNoLength + 3)

  for (let i = 1; i <= options.linesBefore; i++) {
    if (foundLineNo - i < 0) break
    const line = getLine(
      mark.buffer,
      lineStarts[foundLineNo - i],
      lineEnds[foundLineNo - i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo - i]),
      maxLineLength
    )
    result = common.repeat(' ', options.indent) + padStart((mark.line - i + 1).toString(), lineNoLength) +
      ' | ' + line.str + '\n' + result
  }

  const line = getLine(mark.buffer, lineStarts[foundLineNo], lineEnds[foundLineNo], mark.position, maxLineLength)
  result += common.repeat(' ', options.indent) + padStart((mark.line + 1).toString(), lineNoLength) +
    ' | ' + line.str + '\n'
  result += common.repeat('-', options.indent + lineNoLength + 3 + line.pos) + '^' + '\n'

  for (let i = 1; i <= options.linesAfter; i++) {
    if (foundLineNo + i >= lineEnds.length) break
    const line = getLine(
      mark.buffer,
      lineStarts[foundLineNo + i],
      lineEnds[foundLineNo + i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo + i]),
      maxLineLength
    )
    result += common.repeat(' ', options.indent) + padStart((mark.line + i + 1).toString(), lineNoLength) +
      ' | ' + line.str + '\n'
  }

  return result.replace(/\n$/, '')
}

module.exports = makeSnippet
    },
    "lib/type"(module, exports, require) {
'use strict'

const YAMLException = require('./exception')

const TYPE_CONSTRUCTOR_OPTIONS = [
  'kind',
  'multi',
  'resolve',
  'construct',
  'instanceOf',
  'predicate',
  'represent',
  'representName',
  'defaultStyle',
  'styleAliases'
]

const YAML_NODE_KINDS = [
  'scalar',
  'sequence',
  'mapping'
]

function compileStyleAliases (map) {
  const result = {}

  if (map !== null) {
    Object.keys(map).forEach(function (style) {
      map[style].forEach(function (alias) {
        result[String(alias)] = style
      })
    })
  }

  return result
}

function Type (tag, options) {
  options = options || {}

  Object.keys(options).forEach(function (name) {
    if (TYPE_CONSTRUCTOR_OPTIONS.indexOf(name) === -1) {
      throw new YAMLException('Unknown option "' + name + '" is met in definition of "' + tag + '" YAML type.')
    }
  })

  // TODO: Add tag format check.
  this.options = options // keep original options in case user wants to extend this type later
  this.tag = tag
  this.kind = options['kind'] || null
  this.resolve = options['resolve'] || function () { return true }
  this.construct = options['construct'] || function (data) { return data }
  this.instanceOf = options['instanceOf'] || null
  this.predicate = options['predicate'] || null
  this.represent = options['represent'] || null
  this.representName = options['representName'] || null
  this.defaultStyle = options['defaultStyle'] || null
  this.multi = options['multi'] || false
  this.styleAliases = compileStyleAliases(options['styleAliases'] || null)

  if (YAML_NODE_KINDS.indexOf(this.kind) === -1) {
    throw new YAMLException('Unknown kind "' + this.kind + '" is specified for "' + tag + '" YAML type.')
  }
}

module.exports = Type
    },
    "lib/type/binary"(module, exports, require) {
'use strict'

const Type = require('../type')

// [ 64, 65, 66 ] -> [ padding, CR, LF ]
const BASE64_MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r'

function resolveYamlBinary (data) {
  if (data === null) return false

  let bitlen = 0
  const max = data.length
  const map = BASE64_MAP

  // Convert one by one.
  for (let idx = 0; idx < max; idx++) {
    const code = map.indexOf(data.charAt(idx))

    // Skip CR/LF
    if (code > 64) continue

    // Fail on illegal characters
    if (code < 0) return false

    bitlen += 6
  }

  // If there are any bits left, source was corrupted
  return (bitlen % 8) === 0
}

function constructYamlBinary (data) {
  const input = data.replace(/[\r\n=]/g, '') // remove CR/LF & padding to simplify scan
  const max = input.length
  const map = BASE64_MAP
  let bits = 0
  const result = []

  // Collect by 6*4 bits (3 bytes)

  for (let idx = 0; idx < max; idx++) {
    if ((idx % 4 === 0) && idx) {
      result.push((bits >> 16) & 0xFF)
      result.push((bits >> 8) & 0xFF)
      result.push(bits & 0xFF)
    }

    bits = (bits << 6) | map.indexOf(input.charAt(idx))
  }

  // Dump tail

  const tailbits = (max % 4) * 6

  if (tailbits === 0) {
    result.push((bits >> 16) & 0xFF)
    result.push((bits >> 8) & 0xFF)
    result.push(bits & 0xFF)
  } else if (tailbits === 18) {
    result.push((bits >> 10) & 0xFF)
    result.push((bits >> 2) & 0xFF)
  } else if (tailbits === 12) {
    result.push((bits >> 4) & 0xFF)
  }

  return new Uint8Array(result)
}

function representYamlBinary (object /*, style */) {
  let result = ''
  let bits = 0
  const max = object.length
  const map = BASE64_MAP

  // Convert every three bytes to 4 ASCII characters.

  for (let idx = 0; idx < max; idx++) {
    if ((idx % 3 === 0) && idx) {
      result += map[(bits >> 18) & 0x3F]
      result += map[(bits >> 12) & 0x3F]
      result += map[(bits >> 6) & 0x3F]
      result += map[bits & 0x3F]
    }

    bits = (bits << 8) + object[idx]
  }

  // Dump tail

  const tail = max % 3

  if (tail === 0) {
    result += map[(bits >> 18) & 0x3F]
    result += map[(bits >> 12) & 0x3F]
    result += map[(bits >> 6) & 0x3F]
    result += map[bits & 0x3F]
  } else if (tail === 2) {
    result += map[(bits >> 10) & 0x3F]
    result += map[(bits >> 4) & 0x3F]
    result += map[(bits << 2) & 0x3F]
    result += map[64]
  } else if (tail === 1) {
    result += map[(bits >> 2) & 0x3F]
    result += map[(bits << 4) & 0x3F]
    result += map[64]
    result += map[64]
  }

  return result
}

function isBinary (obj) {
  return Object.prototype.toString.call(obj) === '[object Uint8Array]'
}

module.exports = new Type('tag:yaml.org,2002:binary', {
  kind: 'scalar',
  resolve: resolveYamlBinary,
  construct: constructYamlBinary,
  predicate: isBinary,
  represent: representYamlBinary
})
    },
    "lib/type/bool"(module, exports, require) {
'use strict'

const Type = require('../type')

function resolveYamlBoolean (data) {
  if (data === null) return false

  const max = data.length

  return (max === 4 && (data === 'true' || data === 'True' || data === 'TRUE')) ||
         (max === 5 && (data === 'false' || data === 'False' || data === 'FALSE'))
}

function constructYamlBoolean (data) {
  return data === 'true' ||
         data === 'True' ||
         data === 'TRUE'
}

function isBoolean (object) {
  return Object.prototype.toString.call(object) === '[object Boolean]'
}

module.exports = new Type('tag:yaml.org,2002:bool', {
  kind: 'scalar',
  resolve: resolveYamlBoolean,
  construct: constructYamlBoolean,
  predicate: isBoolean,
  represent: {
    lowercase: function (object) { return object ? 'true' : 'false' },
    uppercase: function (object) { return object ? 'TRUE' : 'FALSE' },
    camelcase: function (object) { return object ? 'True' : 'False' }
  },
  defaultStyle: 'lowercase'
})
    },
    "lib/type/float"(module, exports, require) {
'use strict'

const common = require('../common')
const Type = require('../type')

const YAML_FLOAT_PATTERN = new RegExp(
  // 2.5e4, 2.5 and integers
  '^(?:[-+]?(?:[0-9]+)(?:\\.[0-9]*)?(?:[eE][-+]?[0-9]+)?' +
  // .2e4, .2
  // special case, seems not from spec
  '|\\.[0-9]+(?:[eE][-+]?[0-9]+)?' +
  // .inf
  '|[-+]?\\.(?:inf|Inf|INF)' +
  // .nan
  '|\\.(?:nan|NaN|NAN))$')

const YAML_FLOAT_SPECIAL_PATTERN = new RegExp(
  '^(?:' +
  // .inf
  '[-+]?\\.(?:inf|Inf|INF)' +
  // .nan
  '|\\.(?:nan|NaN|NAN))$')

function resolveYamlFloat (data) {
  if (data === null) return false

  if (!YAML_FLOAT_PATTERN.test(data)) {
    return false
  }

  if (Number.isFinite(parseFloat(data, 10))) {
    return true
  }

  return YAML_FLOAT_SPECIAL_PATTERN.test(data)
}

function constructYamlFloat (data) {
  let value = data.toLowerCase()
  const sign = value[0] === '-' ? -1 : 1

  if ('+-'.indexOf(value[0]) >= 0) {
    value = value.slice(1)
  }

  if (value === '.inf') {
    return (sign === 1) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY
  } else if (value === '.nan') {
    return NaN
  }
  return sign * parseFloat(value, 10)
}

const SCIENTIFIC_WITHOUT_DOT = /^[-+]?[0-9]+e/

function representYamlFloat (object, style) {
  if (isNaN(object)) {
    switch (style) {
      case 'lowercase': return '.nan'
      case 'uppercase': return '.NAN'
      case 'camelcase': return '.NaN'
    }
  } else if (Number.POSITIVE_INFINITY === object) {
    switch (style) {
      case 'lowercase': return '.inf'
      case 'uppercase': return '.INF'
      case 'camelcase': return '.Inf'
    }
  } else if (Number.NEGATIVE_INFINITY === object) {
    switch (style) {
      case 'lowercase': return '-.inf'
      case 'uppercase': return '-.INF'
      case 'camelcase': return '-.Inf'
    }
  } else if (common.isNegativeZero(object)) {
    return '-0.0'
  }

  const res = object.toString(10)

  // JS stringifier can build scientific format without dots: 5e-100,
  // while YAML requres dot: 5.e-100. Fix it with simple hack

  return SCIENTIFIC_WITHOUT_DOT.test(res) ? res.replace('e', '.e') : res
}

function isFloat (object) {
  return (Object.prototype.toString.call(object) === '[object Number]') &&
         (object % 1 !== 0 || common.isNegativeZero(object))
}

module.exports = new Type('tag:yaml.org,2002:float', {
  kind: 'scalar',
  resolve: resolveYamlFloat,
  construct: constructYamlFloat,
  predicate: isFloat,
  represent: representYamlFloat,
  defaultStyle: 'lowercase'
})
    },
    "lib/type/int"(module, exports, require) {
'use strict'

const common = require('../common')
const Type = require('../type')

function isHexCode (c) {
  return ((c >= 0x30/* 0 */) && (c <= 0x39/* 9 */)) ||
         ((c >= 0x41/* A */) && (c <= 0x46/* F */)) ||
         ((c >= 0x61/* a */) && (c <= 0x66/* f */))
}

function isOctCode (c) {
  return ((c >= 0x30/* 0 */) && (c <= 0x37/* 7 */))
}

function isDecCode (c) {
  return ((c >= 0x30/* 0 */) && (c <= 0x39/* 9 */))
}

function resolveYamlInteger (data) {
  if (data === null) return false

  const max = data.length
  let index = 0
  let hasDigits = false

  if (!max) return false

  let ch = data[index]

  // sign
  if (ch === '-' || ch === '+') {
    ch = data[++index]
  }

  if (ch === '0') {
    // 0
    if (index + 1 === max) return true
    ch = data[++index]

    // base 2, base 8, base 16

    if (ch === 'b') {
      // base 2
      index++

      for (; index < max; index++) {
        ch = data[index]
        if (ch !== '0' && ch !== '1') return false
        hasDigits = true
      }
      return hasDigits && Number.isFinite(parseYamlInteger(data))
    }

    if (ch === 'x') {
      // base 16
      index++

      for (; index < max; index++) {
        if (!isHexCode(data.charCodeAt(index))) return false
        hasDigits = true
      }
      return hasDigits && Number.isFinite(parseYamlInteger(data))
    }

    if (ch === 'o') {
      // base 8
      index++

      for (; index < max; index++) {
        if (!isOctCode(data.charCodeAt(index))) return false
        hasDigits = true
      }
      return hasDigits && Number.isFinite(parseYamlInteger(data))
    }
  }

  // base 10 (except 0)

  for (; index < max; index++) {
    if (!isDecCode(data.charCodeAt(index))) {
      return false
    }
    hasDigits = true
  }

  if (!hasDigits) return false

  return Number.isFinite(parseYamlInteger(data))
}

function parseYamlInteger (data) {
  let value = data
  let sign = 1

  let ch = value[0]

  if (ch === '-' || ch === '+') {
    if (ch === '-') sign = -1
    value = value.slice(1)
    ch = value[0]
  }

  if (value === '0') return 0

  if (ch === '0') {
    if (value[1] === 'b') return sign * parseInt(value.slice(2), 2)
    if (value[1] === 'x') return sign * parseInt(value.slice(2), 16)
    if (value[1] === 'o') return sign * parseInt(value.slice(2), 8)
  }

  return sign * parseInt(value, 10)
}

function constructYamlInteger (data) {
  return parseYamlInteger(data)
}

function isInteger (object) {
  return (Object.prototype.toString.call(object)) === '[object Number]' &&
         (object % 1 === 0 && !common.isNegativeZero(object))
}

module.exports = new Type('tag:yaml.org,2002:int', {
  kind: 'scalar',
  resolve: resolveYamlInteger,
  construct: constructYamlInteger,
  predicate: isInteger,
  represent: {
    binary: function (obj) { return obj >= 0 ? '0b' + obj.toString(2) : '-0b' + obj.toString(2).slice(1) },
    octal: function (obj) { return obj >= 0 ? '0o' + obj.toString(8) : '-0o' + obj.toString(8).slice(1) },
    decimal: function (obj) { return obj.toString(10) },
    hexadecimal: function (obj) { return obj >= 0 ? '0x' + obj.toString(16).toUpperCase() : '-0x' + obj.toString(16).toUpperCase().slice(1) }
  },
  defaultStyle: 'decimal',
  styleAliases: {
    binary: [2, 'bin'],
    octal: [8, 'oct'],
    decimal: [10, 'dec'],
    hexadecimal: [16, 'hex']
  }
})
    },
    "lib/type/map"(module, exports, require) {
'use strict'

const Type = require('../type')

module.exports = new Type('tag:yaml.org,2002:map', {
  kind: 'mapping',
  construct: function (data) { return data !== null ? data : {} }
})
    },
    "lib/type/merge"(module, exports, require) {
'use strict'

const Type = require('../type')

function resolveYamlMerge (data) {
  return data === '<<' || data === null
}

module.exports = new Type('tag:yaml.org,2002:merge', {
  kind: 'scalar',
  resolve: resolveYamlMerge
})
    },
    "lib/type/null"(module, exports, require) {
'use strict'

const Type = require('../type')

function resolveYamlNull (data) {
  if (data === null) return true

  const max = data.length

  return (max === 1 && data === '~') ||
         (max === 4 && (data === 'null' || data === 'Null' || data === 'NULL'))
}

function constructYamlNull () {
  return null
}

function isNull (object) {
  return object === null
}

module.exports = new Type('tag:yaml.org,2002:null', {
  kind: 'scalar',
  resolve: resolveYamlNull,
  construct: constructYamlNull,
  predicate: isNull,
  represent: {
    canonical: function () { return '~' },
    lowercase: function () { return 'null' },
    uppercase: function () { return 'NULL' },
    camelcase: function () { return 'Null' },
    empty: function () { return '' }
  },
  defaultStyle: 'lowercase'
})
    },
    "lib/type/omap"(module, exports, require) {
'use strict'

const Type = require('../type')

const _hasOwnProperty = Object.prototype.hasOwnProperty
const _toString = Object.prototype.toString

function resolveYamlOmap (data) {
  if (data === null) return true

  const objectKeys = []
  const object = data

  for (let index = 0, length = object.length; index < length; index += 1) {
    const pair = object[index]
    let pairHasKey = false

    if (_toString.call(pair) !== '[object Object]') return false

    let pairKey
    for (pairKey in pair) {
      if (_hasOwnProperty.call(pair, pairKey)) {
        if (!pairHasKey) pairHasKey = true
        else return false
      }
    }

    if (!pairHasKey) return false

    if (objectKeys.indexOf(pairKey) === -1) objectKeys.push(pairKey)
    else return false
  }

  return true
}

function constructYamlOmap (data) {
  return data !== null ? data : []
}

module.exports = new Type('tag:yaml.org,2002:omap', {
  kind: 'sequence',
  resolve: resolveYamlOmap,
  construct: constructYamlOmap
})
    },
    "lib/type/pairs"(module, exports, require) {
'use strict'

const Type = require('../type')

const _toString = Object.prototype.toString

function resolveYamlPairs (data) {
  if (data === null) return true

  const object = data

  const result = new Array(object.length)

  for (let index = 0, length = object.length; index < length; index += 1) {
    const pair = object[index]

    if (_toString.call(pair) !== '[object Object]') return false

    const keys = Object.keys(pair)

    if (keys.length !== 1) return false

    result[index] = [keys[0], pair[keys[0]]]
  }

  return true
}

function constructYamlPairs (data) {
  if (data === null) return []

  const object = data
  const result = new Array(object.length)

  for (let index = 0, length = object.length; index < length; index += 1) {
    const pair = object[index]

    const keys = Object.keys(pair)

    result[index] = [keys[0], pair[keys[0]]]
  }

  return result
}

module.exports = new Type('tag:yaml.org,2002:pairs', {
  kind: 'sequence',
  resolve: resolveYamlPairs,
  construct: constructYamlPairs
})
    },
    "lib/type/seq"(module, exports, require) {
'use strict'

const Type = require('../type')

module.exports = new Type('tag:yaml.org,2002:seq', {
  kind: 'sequence',
  construct: function (data) { return data !== null ? data : [] }
})
    },
    "lib/type/set"(module, exports, require) {
'use strict'

const Type = require('../type')

const _hasOwnProperty = Object.prototype.hasOwnProperty

function resolveYamlSet (data) {
  if (data === null) return true

  const object = data

  for (const key in object) {
    if (_hasOwnProperty.call(object, key)) {
      if (object[key] !== null) return false
    }
  }

  return true
}

function constructYamlSet (data) {
  return data !== null ? data : {}
}

module.exports = new Type('tag:yaml.org,2002:set', {
  kind: 'mapping',
  resolve: resolveYamlSet,
  construct: constructYamlSet
})
    },
    "lib/type/str"(module, exports, require) {
'use strict'

const Type = require('../type')

module.exports = new Type('tag:yaml.org,2002:str', {
  kind: 'scalar',
  construct: function (data) { return data !== null ? data : '' }
})
    },
    "lib/type/timestamp"(module, exports, require) {
'use strict'

const Type = require('../type')

const YAML_DATE_REGEXP = new RegExp(
  '^([0-9][0-9][0-9][0-9])' + // [1] year
  '-([0-9][0-9])' + // [2] month
  '-([0-9][0-9])$')                   // [3] day

const YAML_TIMESTAMP_REGEXP = new RegExp(
  '^([0-9][0-9][0-9][0-9])' + // [1] year
  '-([0-9][0-9]?)' + // [2] month
  '-([0-9][0-9]?)' + // [3] day
  '(?:[Tt]|[ \\t]+)' + // ...
  '([0-9][0-9]?)' + // [4] hour
  ':([0-9][0-9])' + // [5] minute
  ':([0-9][0-9])' + // [6] second
  '(?:\\.([0-9]*))?' + // [7] fraction
  '(?:[ \\t]*(Z|([-+])([0-9][0-9]?)' + // [8] tz [9] tz_sign [10] tzHour
  '(?::([0-9][0-9]))?))?$')           // [11] tzMinute

function resolveYamlTimestamp (data) {
  if (data === null) return false
  if (YAML_DATE_REGEXP.exec(data) !== null) return true
  if (YAML_TIMESTAMP_REGEXP.exec(data) !== null) return true
  return false
}

function constructYamlTimestamp (data) {
  let fraction = 0
  let delta = null

  let match = YAML_DATE_REGEXP.exec(data)
  if (match === null) match = YAML_TIMESTAMP_REGEXP.exec(data)

  if (match === null) throw new Error('Date resolve error')

  // match: [1] year [2] month [3] day

  const year = +(match[1])
  const month = +(match[2]) - 1 // JS month starts with 0
  const day = +(match[3])

  if (!match[4]) { // no hour
    return new Date(Date.UTC(year, month, day))
  }

  // match: [4] hour [5] minute [6] second [7] fraction

  const hour = +(match[4])
  const minute = +(match[5])
  const second = +(match[6])

  if (match[7]) {
    fraction = match[7].slice(0, 3)
    while (fraction.length < 3) { // milli-seconds
      fraction += '0'
    }
    fraction = +fraction
  }

  // match: [8] tz [9] tz_sign [10] tzHour [11] tzMinute

  if (match[9]) {
    const tzHour = +(match[10])
    const tzMinute = +(match[11] || 0)
    delta = (tzHour * 60 + tzMinute) * 60000 // delta in mili-seconds
    if (match[9] === '-') delta = -delta
  }

  const date = new Date(Date.UTC(year, month, day, hour, minute, second, fraction))

  if (delta) date.setTime(date.getTime() - delta)

  return date
}

function representYamlTimestamp (object /*, style */) {
  return object.toISOString()
}

module.exports = new Type('tag:yaml.org,2002:timestamp', {
  kind: 'scalar',
  resolve: resolveYamlTimestamp,
  construct: constructYamlTimestamp,
  instanceOf: Date,
  represent: representYamlTimestamp
})
    },
  };
  const cache = Object.create(null);
  function load(id) {
    if (Object.hasOwn(cache, id)) return cache[id].exports;
    const module = { exports: {} };
    cache[id] = module;
    modules[id](module, module.exports, path => {
      const parts = id.split('/').slice(0, -1);
      for (const component of path.split('/')) {
        if (component === '..') parts.pop();
        else if (component !== '.') parts.push(component);
      }
      return load(parts.join('/'));
    });
    return module.exports;
  }
  return { load: load('lib/loader').load, dump: load('lib/dumper').dump };
})();
