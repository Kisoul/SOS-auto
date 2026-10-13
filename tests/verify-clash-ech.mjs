import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const workerCode=fs.readFileSync(new URL('../_worker.js',import.meta.url),'utf8');
const {default:worker}=await import('data:text/javascript;base64,'+Buffer.from(workerCode).toString('base64'));
const start=workerCode.indexOf('const clashYamlCodec');
const end=workerCode.indexOf('\n})();',start)+6;
const yaml=vm.runInNewContext(workerCode.slice(start,end)+'\nclashYamlCodec',{});
const uuid='00000000-0000-4000-8000-000000000001';
const fixture={dns:{enable:true,nameserver:['119.29.29.29'],'nameserver-policy':{'geosite:cn':['223.5.5.5']}},
 proxies:[{name:'renamed',type:'vless',server:'worker.example',port:443,uuid,tls:true,network:'ws','ws-opts':{path:'/?ed=2560',headers:{Host:'proxy.example'}}},
 {name:'other',type:'vless',server:'other.example',port:443,uuid:'different',tls:true}],
 'proxy-groups':[{name:'Video',type:'select',proxies:['renamed','DIRECT']}],rules:['DOMAIN-SUFFIX,youtube.com,Video','MATCH,DIRECT']};
let called;
globalThis.fetch=async address=>{called=new URL(address);return new Response(yaml.dump(fixture));};
const base='https://worker.example/'+uuid+'/sub?domain=proxy.example&epd=no&epi=no&egi=no&ports=443&target=clash';
const options='&ech=yes&config=https%3A%2F%2Ftemplate.example%2FKisoul.ini&customDNS=https%3A%2F%2Fdns.alidns.com%2Fdns-query&scv=false&xudp=false';
let response=await worker.fetch(new Request(base+options),{scu:'https://converter.example/sub'});
assert.equal(response.status,200,await response.clone().text());
const output=JSON.parse(JSON.stringify(yaml.load(await response.text())));
assert.equal(called.hostname,'converter.example');assert.equal(called.searchParams.get('scv'),'false');assert.equal(called.searchParams.get('xudp'),'false');
const raw=new URL(called.searchParams.get('url'));assert.equal(raw.searchParams.get('target'),'base64');assert.equal(raw.searchParams.get('config'),null);
assert.equal(output.proxies[0]['ech-opts'].enable,true);assert.equal(output.proxies[0]['ech-opts']['query-server-name'],'cloudflare-ech.com');
assert.equal(output.proxies[1]['ech-opts'],undefined);
assert.deepEqual(output['proxy-groups'],fixture['proxy-groups']);assert.deepEqual(output.rules,fixture.rules);
assert.deepEqual(output.proxies[0]['ws-opts'],fixture.proxies[0]['ws-opts']);
assert.deepEqual(output.dns.nameserver,fixture.dns.nameserver);
assert.equal(output.dns['nameserver-policy']['cloudflare-ech.com'][0],'https://dns.alidns.com/dns-query');
for(const text of [JSON.stringify(fixture),yaml.dump(fixture,{flowLevel:0})]){
 globalThis.fetch=async()=>new Response(text);
 const response=await worker.fetch(new Request(base+options),{});assert.equal(response.status,200);
}
globalThis.fetch=async()=>new Response('Invalid target!');
response=await worker.fetch(new Request(base+options),{});assert.equal(response.status,502);
globalThis.fetch=async()=>new Response('',{status:503});
response=await worker.fetch(new Request(base+options),{});assert.equal(response.status,502);
const html=await (await worker.fetch(new Request('https://worker.example/'),{})).text();
const values={domain:{value:'proxy.example'},uuid:{value:uuid},customPath:{value:'/'},customPorts:{value:'443'},githubUrl:{value:''},clashConfigMode:{value:'acl_Kisoul'},clashConfigUrl:{value:''},clientSubscriptionUrl:{style:{}}};
const ctx=vm.createContext({URL,encodeURIComponent,Set,document:{getElementById:id=>values[id]||{checked:true},addEventListener(){}},window:{location:{href:'https://worker.example/'}},navigator:{clipboard:{writeText:()=>Promise.resolve()}},alert(){}});
vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1],ctx);
vm.runInContext("tryOpenApp=function(){};switches.switchECH=true;generateClientLink('clash','CLASH')",ctx);
assert.equal(new URL(values.clientSubscriptionUrl.textContent).hostname,'worker.example');
vm.runInContext("switches.switchECH=false;generateClientLink('clash','CLASH')",ctx);
assert.equal(new URL(values.clientSubscriptionUrl.textContent).hostname,'converter.example');
console.log('PASS: structural ECH patch, node matching, groups/rules preserved, flow/JSON YAML, errors, frontend routing');
