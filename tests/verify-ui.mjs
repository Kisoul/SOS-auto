import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const {default:worker}=await import('data:text/javascript;base64,'+fs.readFileSync(new URL('../_worker.js',import.meta.url)).toString('base64'));
const html=await (await worker.fetch(new Request('https://worker.example/'),{})).text();
const elements=new Map();
function element(id) {
 if(elements.has(id))return elements.get(id);
 const classes=new Set(), attrs={}, children={};
 const row={classList:{toggle:(key,on)=>on?classes.add(key):classes.delete(key)},querySelector:()=>row.note||null,
 firstElementChild:{appendChild:note=>row.note=note}};
 const value={id,checked:true,style:{},value:'',attrs,classes,disabled:false,
 classList:row.classList,closest:()=>row,setAttribute:(key,value)=>attrs[key]=value,
 addEventListener:(name,callback)=>children[name]=callback, events:children};
 elements.set(id,value);return value;
}
for(const match of html.matchAll(/id="([^"]+)"/g)) element(match[1]);
element('domain').value='proxy.example';element('uuid').value='00000000-0000-4000-8000-000000000001';
element('ipSource').value='uouin';element('clashConfigMode').value='default';
let loaded;let alerts=0;
const context=vm.createContext({URL,encodeURIComponent,Set,document:{
 getElementById:element,createElement:()=>({}),
 querySelectorAll:selector=>selector==='.switch'?[...elements.values()].filter(x=>x.id.startsWith('switch')):[],
 addEventListener:(name,callback)=>loaded=callback},window:{location:{href:'https://worker.example/'}},
 navigator:{clipboard:{writeText:()=>Promise.resolve()}},alert:()=>alerts++});
vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1],context);
loaded();vm.runInContext('tryOpenApp=function(){};',context);
const run=code=>vm.runInContext(code,context);
assert.equal(element('customDNS').disabled,true);
run("toggleSwitch('switchECH')");
assert.equal(run('switches.switchTLS'),true);
assert.equal(element('switchTLS').attrs['aria-disabled'],'true');
run("toggleSwitch('switchTLS')");assert.equal(run('switches.switchTLS'),true);
assert.equal(element('customDNS').disabled,false);
run("toggleSwitch('switchECH')");assert.equal(run('switches.switchTLS'),false);
run("toggleSwitch('switchUDP')");assert.equal(run('switches.switchXUDP'),false);
assert.equal(element('switchXUDP').attrs['aria-disabled'],'true');
run("toggleSwitch('switchXUDP')");assert.equal(run('switches.switchXUDP'),false);
run("toggleSwitch('switchVL')");assert.equal(run('switches.switchVL'),true);assert.equal(alerts,1);
run("toggleSwitch('switchTJ');toggleSwitch('switchVL');generateClientLink('sing-box','SING-BOX')");
let url=new URL(element('clientSubscriptionUrl').textContent);assert.equal(url.searchParams.get('ev'),'no');
assert.equal(element('switchEmoji').attrs['aria-disabled'],'true');
run("toggleSwitch('switchIP')");assert.equal(element('ipv6Enabled').disabled,true);
run("toggleSwitch('switchIP')");element('ipSource').value='wetest';run('syncOptionState()');
assert.equal(element('dynamicIPUrl').disabled,true);assert.equal(element('ipFallback').disabled,true);
run("generateClientLink('v2ray','V2RAY')");assert.equal(element('clashConfigMode').disabled,true);
const base='https://worker.example/00000000-0000-4000-8000-000000000001/sub?domain=proxy.example&epd=no&epi=no&egi=no';
assert.equal((await worker.fetch(new Request(base+'&ev=no'),{})).status,400);
assert.equal((await worker.fetch(new Request(base+'&ports=80&dkby=yes'),{})).status,400);
const config=await (await worker.fetch(new Request(base+'&ports=443&target=sing-box&udp=false&xudp=true'),{})).json();
const node=config.outbounds.find(x=>x.type==='vless');assert.equal(node.network,'tcp');assert.equal(node.packet_encoding,'');
const trojan=atob(await (await worker.fetch(new Request(base+'&ev=no&et=yes&ports=443'),{})).text());
assert.ok(!trojan.includes('vless://'));
console.log('PASS: UI ECH/TLS, UDP/XUDP, protocol selection, source/client scope, backend empty-node rejection');
