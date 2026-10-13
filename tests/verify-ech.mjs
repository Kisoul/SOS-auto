import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const { default: worker } = await import('data:text/javascript;base64,' + fs.readFileSync(new URL('../_worker.js', import.meta.url)).toString('base64'));
const base = 'https://worker.example/00000000-0000-4000-8000-000000000001/sub?domain=proxy.example&epd=no&epi=no&egi=no';
const extra = '&ech=yes&customECHDomain=ech.example&customDNS=https%3A%2F%2Fdns.example%3A8443%2Fquery%3Ftoken%3Dtest&ev=yes&et=yes&mess=yes&ports=80,443';
const response = await worker.fetch(new Request(base + extra + '&target=sing-box'),{});
assert.equal(response.status,200);
const config = await response.json();
const nodes = config.outbounds.filter(x=>['vless','trojan','vmess'].includes(x.type));
assert.equal(nodes.length,3);
for(const node of nodes) { assert.equal(node.server_port,443); assert.equal(node.tls.ech.query_server_name,'ech.example'); }
const dns = config.dns.servers.find(x=>x.tag==='dns-ech');
assert.equal(dns.server,'dns.example'); assert.equal(dns.server_port,8443); assert.equal(dns.path,'/query?token=test');
assert.equal(dns.detour,undefined); assert.equal(dns.domain_resolver,'dns-direct');
assert.equal(config.dns.rules[0].server,'dns-ech');
fs.writeFileSync(new URL('./check-ech.json',import.meta.url),JSON.stringify(config));
const raw = atob(await (await worker.fetch(new Request(base+extra),{})).text()).split('\n');
assert.equal(raw.length,3);
for(const link of raw.filter(x=>!x.startsWith('vmess:'))) assert.equal(new URL(link).searchParams.get('ech'),'ech.example+https://dns.example:8443/query?token=test');
assert.ok(JSON.parse(Buffer.from(raw.find(x=>x.startsWith('vmess:')).slice(8),'base64').toString()).ech);
assert.equal((await worker.fetch(new Request(base+'&ech=yes&ports=80'),{})).status,400);
assert.equal((await worker.fetch(new Request(base+'&ech=yes&customDNS=http://example.com'),{})).status,400);
const calls=[];
Object.defineProperty(globalThis,'crypto',{value:{subtle:{digest:async (algorithm,input)=>createHash(algorithm.toLowerCase()).update(input).digest()}}});
globalThis.fetch=async url=>{
  calls.push(String(url));
  const address=new URL(url);
  if(address.hostname==='api.uouin.com') {
    const inner=createHash('md5').update(atob('RGRsVHh0TjBzVU91')).digest('hex');
    assert.equal(address.searchParams.get('key'),createHash('md5').update(inner+atob('NzBjbG91ZGZsYXJlYXBpa2V5')+address.searchParams.get('time')).digest('hex'));
    return Response.json({data:{ctcc:{info:[{ip:'192.0.2.1'}]},cmcc:{info:[{ip:'192.0.2.2'}]},ipv6:{info:[{ip:'2001:db8::1'}]}}});
  }
  return new Response('<tr><td data-label="线路名称">电信</td><td data-label="优选地址">192.0.2.3</td><td data-label="数据中心">HKG</td></tr>');
};
const api=await (await worker.fetch(new Request(base.replace('epi=no','epi=yes')+'&ipv6=no&ispMobile=no&target=sing-box'),{})).json();
assert.ok(api.outbounds.some(x=>x.server==='192.0.2.1'));
assert.ok(!api.outbounds.some(x=>x.server==='192.0.2.2'||x.server==='2001:db8::1'));
assert.ok(!calls.some(x=>x.includes('wetest')));
globalThis.fetch=async url=>{calls.push(String(url));if(String(url).includes('api.uouin'))return new Response('',{status:503});return new Response('<tr><td data-label="线路名称">电信</td><td data-label="优选地址">192.0.2.3</td><td data-label="数据中心">HKG</td></tr>');};
const fallback=await (await worker.fetch(new Request(base.replace('epi=no','epi=yes')+'&ipv6=no&target=sing-box'),{})).json();
assert.ok(fallback.outbounds.some(x=>x.server==='192.0.2.3'));
calls.length=0;
await worker.fetch(new Request(base.replace('epi=no','epi=yes')+'&ipFallback=no'),{});
assert.ok(!calls.some(x=>x.includes('wetest')));
calls.length=0;
await worker.fetch(new Request(base.replace('epi=no','epi=yes')+'&ipSource=wetest&ipv6=no'),{});
assert.ok(calls.every(x=>x.includes('wetest')));
console.log('PASS: ECH protocols/custom DNS/TLS filtering; signed API, filters, fallback, legacy source');
