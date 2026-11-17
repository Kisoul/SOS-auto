import assert from 'node:assert/strict';
import fs from 'node:fs';

const source = fs.readFileSync(new URL('../_worker.js', import.meta.url), 'utf8');
const { default: worker, clashYAML } = await import(
  'data:text/javascript;base64,' + Buffer.from(source + '\nexport { clashYAML };').toString('base64')
);
const uuid = '00000000-0000-4000-8000-000000000001';
const base = 'https://worker.example/' + uuid + '/sub?domain=example.com&epd=no&epi=no&egi=no';
const request = (url, options) => worker.fetch(new Request(url, options), {});
async function yamlResponse(url) {
  const response = await request(url);
  const text = await response.text();
  assert.equal(response.status, 200, text);
  return clashYAML.load(text);
}

const sourceUrl = base.replace('egi=no', 'egi=yes') + '&piu=https%3A%2F%2Ffixtures.example%2Fips';
globalThis.fetch = async () => new Response('[2001:db8::1]:2053#test\n');
const withIPv6 = await yamlResponse(sourceUrl + '&target=clash');
assert.equal(withIPv6.proxies.at(-1).server, '2001:db8::1');
assert.equal(withIPv6.proxies.at(-1).port, 2053);
assert.match(await (await request(sourceUrl + '&target=surge')).text(), /2001:db8::1, 2053,/);

const native = base + '&target=clash';
const trojan = await yamlResponse(native + '&ev=no&et=yes&udp=true&xudp=false');
assert.deepEqual(trojan.proxies.map(node => [node.type, node.password, node.sni, node.port]),
  [['trojan', uuid, 'example.com', 443]]);
const mixed = await yamlResponse(native + '&et=yes&mess=yes&ports=443,443&path=%2Fa%20b%2Bc');
assert.deepEqual(mixed.proxies.map(node => node.type), ['vless', 'trojan', 'vmess']);
const vmess = mixed.proxies.find(node => node.type === 'vmess');
assert.equal(vmess.alterId, 0);
assert.equal(vmess.cipher, 'auto');
assert.ok(mixed.proxies.every(node => node['ws-opts'].path === '/a b+c'));
assert.deepEqual(mixed['proxy-groups'][0].proxies, mixed.proxies.map(node => node.name));
assert.deepEqual(mixed.dns['default-nameserver'], ['223.5.5.5', '119.29.29.29']);
assert.equal((await request(base + '&target=calsh')).status, 400);
const regular = await request(base);
assert.equal(atob(await regular.text()).split('\n').length, 2);

const proxy = 'proxies:\n  - {name: Demo, type: vless, server: 192.0.2.4, port: 443, uuid: ' + uuid + ', tls: true, network: ws, servername: example.com} # keepable YAML\n';
const rules = 'rules:\n  - MATCH,DIRECT\n';
const template = base + '&target=clash-template&template=acl_Kisoul';
for (const dns of ['dns: {enable: true, nameserver: [9.9.9.9]}\n',
  'dns:\n    enable: true\n    nameserver: [9.9.9.9]\n',
  'dns:\n  enable: true\n  nameserver-policy: {}\n']) {
  globalThis.fetch = async () => new Response(dns + proxy + rules);
  for (const ech of [false, true]) {
    const config = await yamlResponse(template + (ech ? '&ech=yes' : ''));
    assert.deepEqual(config.rules, ['MATCH,DIRECT']);
    assert.deepEqual(config.dns.nameserver, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
    if (ech) assert.deepEqual(config.dns['nameserver-policy']['cloudflare-ech.com'], ['https://dns.alidns.com/dns-query']);
  }
}

globalThis.fetch = async () => new Response('proxies:\n  - {name: Demo, type: trojan, server: 192.0.2.4, port: 443, password: ' + uuid + ', sni: example.com, network: ws}\n');
const remoteTrojan = await yamlResponse(template + '&ech=yes&ev=no&et=yes');
assert.deepEqual(remoteTrojan.proxies[0]['ech-opts'], { enable: true, 'query-server-name': 'cloudflare-ech.com' });
for (const wrong of ['converter error', 'proxies: [', '<!doctype html>']) {
  globalThis.fetch = async () => new Response(wrong);
  assert.equal((await request(template)).status, 502);
}

const diagnostics = 'https://worker.example/test-optimize-api?url=https%3A%2F%2Ffixtures.example%2Fips';
globalThis.fetch = async () => new Response('192.0.2.1\n', { status: 503 });
const failed = await request(diagnostics);
assert.equal(failed.status, 502);
assert.equal((await failed.json()).success, false);
globalThis.fetch = async () => new Response('192.0.2.1\n');
assert.deepEqual((await (await request(diagnostics)).json()).results, ['192.0.2.1:443']);
globalThis.fetch = async (_url, { signal }) => new Response(new ReadableStream({
  start(controller) { signal.addEventListener('abort', () => controller.error(signal.reason), { once: true }); }
}));
const keepEventLoop = setTimeout(() => {}, 1000);
try {
  assert.equal((await request(diagnostics + '&timeout=20')).status, 504);
} finally {
  clearTimeout(keepEventLoop);
}
console.log('PASS: seven review regressions, normal RAW output, existing DNS, and body-read timeout');
