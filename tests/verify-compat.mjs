import assert from 'node:assert/strict';
import fs from 'node:fs';
const {default: worker}=await import('data:text/javascript;base64,'+fs.readFileSync(new URL('../_worker.js',import.meta.url)).toString('base64'));
const uuid='00000000-0000-4000-8000-000000000001';
const base=`https://worker.example/${uuid}/sub?domain=proxy.example&epd=no&epi=no&egi=no&ports=80,443&path=${encodeURIComponent('/244341896@qq.com')}&ev=yes&et=yes&mess=yes`;
let calls=0;
for (const flow of [true,false]) for (const ech of [false,true]) for (const xhttp of [false,true]) {
  const outer=new URL(base+(ech?'&ech=yes&customECHDomain=custom.example&customDNS='+encodeURIComponent('https://dns.example/query?token=a+b'):'')+(xhttp?'&transport=xhttp&xhttpReady=yes&client=mihomo':''));
  const source=new URL(outer); // deliberately retains legacy ECH/XHTTP params
  const query=new URLSearchParams({target:'clash',url:source.toString(),config:'https://raw.githubusercontent.com/Kisoul/Rulers/refs/heads/main/Kisoul.ini',emoji:'true',insert:'false'});
  const tail='proxy-groups:\n  - name: Kisoul\n    type: select\n    proxies: [generated]\nrules:\n  - MATCH,Kisoul\n';
  const fields=type=>({name:'generated',type,server:'worker.example',port:'443',tls:'true',servername:'proxy.example',[type==='trojan'?'password':'uuid']:uuid,network:'ws','ws-opts':'{path: "/244341896@qq.com", headers: {Host: proxy.example}}'});
  const nodes=[fields('vless'),fields('trojan'),fields('vmess'),{...fields('vless'),uuid:'unrelated'}, {...fields('vless'),servername:'other.example'}];
  const yaml='proxies:\n'+nodes.map(n=>flow?'  - {'+Object.entries(n).map(([k,v])=>k+': '+v).join(', ')+'}\n':Object.entries(n).map(([k,v],i)=>(i?'    ':'  - ')+k+': '+v+'\n').join('')).join('')+tail;
  globalThis.fetch=async address=>{
    calls++;
    const q=new URL(address).searchParams;
    assert.equal(q.get('config'),query.get('config')); assert.equal(q.get('emoji'),'true');
    const src=new URL(q.get('url'));
    assert.equal(src.searchParams.has('ech'),false);
    if(xhttp) assert.equal(src.searchParams.has('transport'),false);
    if(ech) { assert.equal(src.searchParams.get('dkby'),'yes'); assert.equal(src.searchParams.has('customDNS'),false); }
    // Actually execute the URL the converter would fetch: nodes must contain neither ECH nor XHTTP.
    const raw=atob(await (await worker.fetch(new Request(src),{})).text()).split('\n');
    for(const link of raw) {
      if(link.startsWith('vmess:')) { const n=JSON.parse(Buffer.from(link.slice(8),'base64')); assert.equal(n.ech,undefined); }
      else { const n=new URL(link); assert.equal(n.searchParams.has('ech'),false); assert.equal(n.searchParams.get('type'),'ws'); if(ech) assert.equal(n.port,'443'); }
    }
    return new Response(yaml);
  };
  if(!ech&&!xhttp) continue; // ordinary remote conversion is a direct converter URL
  outer.searchParams.set('target',xhttp?'clash-compat':'clash-ech');
  outer.searchParams.set('converterQuery',query.toString());
  const response=await worker.fetch(new Request(outer),{}); const result=await response.text();
  assert.equal(response.status,200,result); assert.ok(result.includes(tail));
  const compact = new URL(outer);
  compact.searchParams.delete('converterQuery'); compact.searchParams.set('template','acl_Kisoul');
  assert.equal(await (await worker.fetch(new Request(compact),{})).text(),result);
  assert.equal((result.match(/query-server-name/g)||[]).length,ech?3:0);
  assert.equal((result.match(/network: xhttp/g)||[]).length,xhttp?1:0);
  if(xhttp) { assert.ok(result.includes('mode: auto')); assert.ok(result.includes('x-padding-bytes: "100-1000"')); assert.ok(result.includes('/244341896@qq.com')); }
  if(ech) {assert.ok(result.includes('custom.example')); assert.ok(result.includes('https://dns.example/query?token=a+b'));}
  if(xhttp) {
    for (const mode of ['auto','stream-one','stream-up','packet-up']) {
    outer.searchParams.set('xhttpMode',mode); outer.searchParams.set('xhttpPaddingBytes','200-300');
    const custom=await (await worker.fetch(new Request(outer),{})).text();
    assert.ok(custom.includes('mode: '+mode)); assert.ok(custom.includes('"200-300"'));
    }
    outer.searchParams.set('xhttpMode','invalid'); const before=calls;
    assert.equal((await worker.fetch(new Request(outer),{})).status,422); assert.equal(calls,before);
  }
}
globalThis.fetch=()=>{throw new Error('unexpected network');};
for(const client of ['mihomo','stash']) {
  const result=await (await worker.fetch(new Request(base+'&target=clash&transport=xhttp&xhttpReady=yes&client='+client),{})).text();
  assert.ok(result.includes(client==='mihomo'?'mode: auto':'mode: packet-up'));
  assert.equal(result.includes('x-padding-bytes'),client==='mihomo');
}
const custom=await (await worker.fetch(new Request(base+'&target=clash&transport=xhttp&xhttpReady=yes&client=mihomo&xhttpMode=stream-up&xhttpPaddingBytes=200-300'),{})).text();
assert.ok(custom.includes('mode: stream-up')); assert.ok(custom.includes('"200-300"'));
console.log('PASS: remote WS/ECH/XHTTP combinations, flow/block YAML, nested raw-source execution, custom ECH/DoH, identity scope, template preservation, invalid mode before fetch, native Mihomo/Stash defaults and custom options');
