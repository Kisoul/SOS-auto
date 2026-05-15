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
  { domain: 'top1.kisoul.org' },
  { domain: 'top2.kisoul.org' },
  { domain: 'telecom1.kisoul.org' },
  { domain: 'telecom2.kisoul.org' },
  { domain: 'hkt1.kisoul.org' },
  { domain: 'hkt2.kisoul.org' },
  { domain: 'hku1.kisoul.org' }, 
  { domain: 'hku2.kisoul.org' },
  { domain: 'hkm1.kisoul.org' },
  { domain: 'hkm2.kisoul.org' },
  { domain: 'unicom1.kisoul.org' },
  { domain: 'unicom2.kisoul.org' },
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
async function fetchDynamicIPs(ipv4Enabled = true, ipv6Enabled = true, ispMobile = true, ispUnicom = true, ispTelecom = true) {
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

// 解析 wetest 页面
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
async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
  if (!urls || !urls.length) return [];
  const results = new Set();

  await Promise.allSettled(
    urls.map(async (url) => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 超时时间);
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);

        let text = '';
        try {
          const buffer = await response.arrayBuffer();
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

          if (!decodeSuccess) {
            text = await response.text();
          }

          if (!text || text.trim().length === 0) return;
        } catch (e) {
          return;
        }

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
      } catch (e) {}
    })
  );

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
function generateLinksFromSource(list, user, workerDomain, disableNonTLS = false, customPath = '/', customPorts = []) {
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
        const wsNodeName = nodeNameBase + '-' + port + '-WS-TLS';
        const wsParams = new URLSearchParams({
          encryption: 'none',
          security: 'tls',
          sni: workerDomain,
          fp: 'chrome',
          type: 'ws',
          host: workerDomain,
          path: wsPath
        });
        links.push(proto + '://' + user + '@' + safeIP + ':' + port + '?' + wsParams.toString() + '#' + encodeURIComponent(wsNodeName));
      } else {
        const wsNodeName = nodeNameBase + '-' + port + '-WS';
        const wsParams = new URLSearchParams({
          encryption: 'none',
          security: 'none',
          type: 'ws',
          host: workerDomain,
          path: wsPath
        });
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

// YAML 字符串转义
function escapeYamlString(str) {
  const s = String(str == null ? '' : str);
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// 生成 Clash 配置（默认方案）
function generateClashConfig(links) {
  let yaml = 'port: 7890\n';
  yaml += 'socks-port: 7891\n';
  yaml += 'allow-lan: false\n';
  yaml += 'mode: rule\n';
  yaml += 'log-level: info\n\n';
  yaml += 'proxies:\n';

  const proxyNames = [];

  links.forEach((link, index) => {
    if (!link.startsWith('vless://')) return;

    const name = decodeURIComponent((link.split('#')[1]) || ('节点' + (index + 1)));
    proxyNames.push(name);

    const server = (link.match(/@([^:]+):(\d+)/) || [])[1] || '';
    const port = (link.match(/@[^:]+:(\d+)/) || [])[1] || '443';
    const uuid = (link.match(/vless:\/\/([^@]+)@/) || [])[1] || '';
    const tls = link.includes('security=tls');
    const path = decodeURIComponent(((link.match(/path=([^&#]+)/) || [])[1]) || '/');
    const host = decodeURIComponent(((link.match(/host=([^&#]+)/) || [])[1]) || '');
    const sni = decodeURIComponent(((link.match(/sni=([^&#]+)/) || [])[1]) || '');

    yaml += '  - name: ' + escapeYamlString(name) + '\n';
    yaml += '    type: vless\n';
    yaml += '    server: ' + server + '\n';
    yaml += '    port: ' + port + '\n';
    yaml += '    uuid: ' + uuid + '\n';
    yaml += '    tls: ' + tls + '\n';
    yaml += '    network: ws\n';
    yaml += '    ws-opts:\n';
    yaml += '      path: ' + escapeYamlString(path) + '\n';
    yaml += '      headers:\n';
    yaml += '        Host: ' + escapeYamlString(host) + '\n';
    if (sni) yaml += '    servername: ' + escapeYamlString(sni) + '\n';
  });

  yaml += '\nproxy-groups:\n';
  yaml += '  - name: PROXY\n';
  yaml += '    type: select\n';
  yaml += '    proxies: [' + proxyNames.map(n => "'" + n + "'").join(', ') + ']\n';

  yaml += '\nrules:\n';
  yaml += '  - DOMAIN-SUFFIX,local,DIRECT\n';
  yaml += '  - IP-CIDR,127.0.0.0/8,DIRECT\n';
  yaml += '  - GEOIP,CN,DIRECT\n';
  yaml += '  - MATCH,PROXY\n';

  return yaml;
}

// 生成 Surge 配置
function generateSurgeConfig(links) {
  const vlessLinks = links.filter(link => link.startsWith('vless://'));
  let config = '[Proxy]\n';

  vlessLinks.forEach((link, i) => {
    const name = decodeURIComponent((link.split('#')[1]) || ('节点' + (i + 1)));
    const server = (link.match(/@([^:]+):(\d+)/) || [])[1] || '';
    const port = (link.match(/@[^:]+:(\d+)/) || [])[1] || '443';
    const username = (link.match(/vless:\/\/([^@]+)@/) || [])[1] || '';
    const tls = link.includes('security=tls');
    const path = decodeURIComponent(((link.match(/path=([^&#]+)/) || [])[1]) || '/');
    const host = decodeURIComponent(((link.match(/host=([^&#]+)/) || [])[1]) || '');
    config += name + ' = vless, ' + server + ', ' + port + ', username=' + username + ', tls=' + tls + ', ws=true, ws-path=' + path + ', ws-headers=Host:' + host + '\n';
  });

  config += '\n[Proxy Group]\nPROXY = select, ' + vlessLinks.map((link, i) => decodeURIComponent((link.split('#')[1]) || ('节点' + (i + 1)))).join(', ') + '\n';
  return config;
}

// 生成 Quantumult 配置
function generateQuantumultConfig(links) {
  return btoa(links.join('\n'));
}

// 生成订阅内容
async function handleSubscriptionRequest(request, user, customDomain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, customPorts = []) {
  const url = new URL(request.url);
  const finalLinks = [];
  const workerDomain = url.hostname;
  const nodeDomain = customDomain || url.hostname;
  const target = url.searchParams.get('target') || 'base64';
  const wsPath = customPath || '/';

  async function addNodesFromList(list) {
    const hasProtocol = evEnabled || etEnabled || vmEnabled;
    const useVL = hasProtocol ? evEnabled : true;

    if (useVL) finalLinks.push(...generateLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts));
    if (etEnabled) finalLinks.push(...await generateTrojanLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts));
    if (vmEnabled) finalLinks.push(...generateVMessLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts));
  }

  await addNodesFromList([{ ip: workerDomain, isp: '原生地址' }]);

  if (epd) {
    const domainList = directDomains.map(d => ({ ip: d.domain, isp: d.name || d.domain }));
    await addNodesFromList(domainList);
  }

  if (epi) {
    try {
      const dynamicIPList = await fetchDynamicIPs(ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom);
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
    const errorRemark = '所有节点获取失败';
    finalLinks.push('vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=ws&host=error.com&path=%2F#' + encodeURIComponent(errorRemark));
  }

  let subscriptionContent;
  let contentType = 'text/plain; charset=utf-8';

  switch ((target || '').toLowerCase()) {
    case 'clash':
    case 'clashr':
      subscriptionContent = generateClashConfig(finalLinks);
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
    default:
      subscriptionContent = btoa(finalLinks.join('\n'));
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
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>服务器优选工具</h1>
      <p>智能优选 • 一键生成</p>
    </div>

    <div class="card">
      <div class="form-group">
        <label>域名</label>
        <input type="text" id="domain" placeholder="请输入您的域名">
      </div>

      <div class="form-group">
        <label>UUID/Password</label>
        <input type="text" id="uuid" placeholder="请输入UUID或Password">
      </div>

      <div class="form-group">
        <label>WebSocket路径（可选）</label>
        <input type="text" id="customPath" placeholder="留空则使用默认路径 /" value="/">
        <small>自定义WebSocket路径，例如：/v2ray 或 /</small>
      </div>

      <div class="form-group">
        <label>自定义端口（可选）</label>
        <input type="text" id="customPorts" placeholder="留空则使用443端口">
        <small>支持英文逗号分隔；例如：TLS端口：443,2053,2083,2087,2096,8443非TLS端口：80,8080,8880,2052,2082,2086,2095</small>
      </div>

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
        <label>Clash 配置方式</label>
        <select id="clashConfigMode">
          <option value="default">默认配置</option>
          <option value="acl_default">内置：ACL4SSR 默认版</option>
          <option value="acl_nospeed">内置：ACL4SSR 无测速版</option>
          <option value="acl_mini">内置：ACL4SSR Mini</option>
          <option value="acl_Kisoul">内置：ACL4SSR Kisoul</option>
          <option value="custom">自定义远程配置文件</option>
        </select>
        <small>默认配置走 worker 原生方案；内置 / 自定义会交给订阅转换器处理</small>
      </div>

      <div class="form-group" id="customClashConfigGroup" style="display:none; margin-top:12px;">
        <label>自定义远程配置文件地址</label>
        <input type="text" id="clashConfigUrl" placeholder="例如：https://example.com/ACL4SSR_Online.ini" style="font-size:15px;">
        <small>仅在选择“自定义远程配置文件”时生效</small>
      </div>

      <div class="form-group" style="margin-top:24px;">
        <label>协议选择</label>
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
      </div>

      <div class="form-group">
        <label>IP版本选择</label>
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
        <label>运营商选择</label>
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

      <div class="list-item" onclick="toggleSwitch('switchTLS')" style="margin-top:8px;">
        <div>
          <div class="list-item-label">仅TLS节点</div>
          <div class="list-item-description">启用后只生成带TLS的节点，不生成非TLS节点（如80端口）</div>
        </div>
        <div class="switch" id="switchTLS"></div>
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
      switchTLS: false
    };

    const SUB_CONVERTER_URL = "${realScu}";
    const PRESET_CONFIG_MAP = ${JSON.stringify(presetClashConfigMap)};

    function toggleSwitch(id) {
      const switchEl = document.getElementById(id);
      switches[id] = !switches[id];
      switchEl.classList.toggle('active');
    }

    function toggleClashConfigInput() {
      const mode = document.getElementById('clashConfigMode').value;
      const customGroup = document.getElementById('customClashConfigGroup');
      customGroup.style.display = mode === 'custom' ? 'block' : 'none';
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
      const domain = document.getElementById('domain').value.trim();
      const uuid = document.getElementById('uuid').value.trim();
      const customPath = (document.getElementById('customPath').value || '').trim() || '/';
      const customPortsRaw = ((document.getElementById('customPorts') || {}).value || '').trim();
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

      const currentUrl = new URL(window.location.href);
      const baseUrl = currentUrl.origin;

      let subscriptionUrl = baseUrl + '/' + uuid + '/sub?domain=' + encodeURIComponent(domain)
        + '&epd=' + (switches.switchDomain ? 'yes' : 'no')
        + '&epi=' + (switches.switchIP ? 'yes' : 'no')
        + '&egi=' + (switches.switchGitHub ? 'yes' : 'no');

      if (githubUrl) subscriptionUrl += '&piu=' + encodeURIComponent(githubUrl);
      if (switches.switchVL) subscriptionUrl += '&ev=yes';
      if (switches.switchTJ) subscriptionUrl += '&et=yes';
      if (switches.switchVM) subscriptionUrl += '&mess=yes';
      if (!ipv4Enabled) subscriptionUrl += '&ipv4=no';
      if (!ipv6Enabled) subscriptionUrl += '&ipv6=no';
      if (!ispMobile) subscriptionUrl += '&ispMobile=no';
      if (!ispUnicom) subscriptionUrl += '&ispUnicom=no';
      if (!ispTelecom) subscriptionUrl += '&ispTelecom=no';
      if (switches.switchTLS) subscriptionUrl += '&dkby=yes';
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
        } else {
          const encodedUrl = encodeURIComponent(subscriptionUrl);
          finalUrl = SUB_CONVERTER_URL
            + '?target=clash'
            + '&url=' + encodedUrl
            + '&config=' + encodeURIComponent(finalClashConfigUrl)
            + '&insert=false'
            + '&emoji=true'
            + '&list=false'
            + '&xudp=false'
            + '&udp=false'
            + '&tfo=false'
            + '&expand=true'
            + '&scv=false'
            + '&fdn=false'
            + '&new_name=true';
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

      // 其他客户端仍走订阅转换器
      const encodedUrl = encodeURIComponent(subscriptionUrl);
      finalUrl = SUB_CONVERTER_URL
        + '?target=' + clientType
        + '&url=' + encodedUrl
        + '&insert=false'
        + '&emoji=true'
        + '&list=false'
        + '&xudp=false'
        + '&udp=false'
        + '&tfo=false'
        + '&expand=true'
        + '&scv=false'
        + '&fdn=false'
        + '&new_name=true';

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
      const modeSelect = document.getElementById('clashConfigMode');
      if (modeSelect) {
        modeSelect.addEventListener('change', toggleClashConfigInput);
        toggleClashConfigInput();
      }
    });
  </script>
</body>
</html>`;
}

// 主处理函数
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
        const results = await 请求优选API([apiUrl], port, timeout);
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
          status: 500,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
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
      const customPorts = portsParam
        .split(',')
        .map(s => parseInt((s || '').trim(), 10))
        .filter(n => Number.isFinite(n) && n > 0 && n < 65536);

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
