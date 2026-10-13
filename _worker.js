// Cloudflare Worker - 简化版优选工具（支持 Clash 配置下拉选择 / 自定义远程远程配置文件）
// 逻辑：
// 1. 默认配置：使用 worker 自身的 Clash 生成逻辑
// 2. 内置配置：从 presetClashConfigMap 读取远程配置文件，交给订阅转换器 scu
// 3. 自定义配置：用户自行填写远程配置文件，交给订阅转换器 scu

/* Third-party license for bundled js-yaml 4.1.1:
+(The MIT License)

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
// Bundled js-yaml 4.1.1 (MIT), for structural edits of converter YAML.
const clashYamlCodec = (() => {
  const exports = {};
  const module = { exports };
+/*! js-yaml 4.1.1 https://github.com/nodeca/js-yaml @license MIT */
!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):"function"==typeof define&&define.amd?define(["exports"],t):t((e="undefined"!=typeof globalThis?globalThis:e||self).jsyaml={})}(this,function(e){"use strict";function t(e){return null==e}var n={isNothing:t,isObject:function(e){return"object"==typeof e&&null!==e},toArray:function(e){return Array.isArray(e)?e:t(e)?[]:[e]},repeat:function(e,t){var n,i="";for(n=0;n<t;n+=1)i+=e;return i},isNegativeZero:function(e){return 0===e&&Number.NEGATIVE_INFINITY===1/e},extend:function(e,t){var n,i,r,o;if(t)for(n=0,i=(o=Object.keys(t)).length;n<i;n+=1)e[r=o[n]]=t[r];return e}};function i(e,t){var n="",i=e.reason||"(unknown reason)";return e.mark?(e.mark.name&&(n+='in "'+e.mark.name+'" '),n+="("+(e.mark.line+1)+":"+(e.mark.column+1)+")",!t&&e.mark.snippet&&(n+="\n\n"+e.mark.snippet),i+" "+n):i}function r(e,t){Error.call(this),this.name="YAMLException",this.reason=e,this.mark=t,this.message=i(this,!1),Error.captureStackTrace?Error.captureStackTrace(this,this.constructor):this.stack=(new Error).stack||""}r.prototype=Object.create(Error.prototype),r.prototype.constructor=r,r.prototype.toString=function(e){return this.name+": "+i(this,e)};var o=r;function a(e,t,n,i,r){var o="",a="",l=Math.floor(r/2)-1;return i-t>l&&(t=i-l+(o=" ... ").length),n-i>l&&(n=i+l-(a=" ...").length),{str:o+e.slice(t,n).replace(/\t/g,"→")+a,pos:i-t+o.length}}function l(e,t){return n.repeat(" ",t-e.length)+e}var c=function(e,t){if(t=Object.create(t||null),!e.buffer)return null;t.maxLength||(t.maxLength=79),"number"!=typeof t.indent&&(t.indent=1),"number"!=typeof t.linesBefore&&(t.linesBefore=3),"number"!=typeof t.linesAfter&&(t.linesAfter=2);for(var i,r=/\r?\n|\r|\0/g,o=[0],c=[],s=-1;i=r.exec(e.buffer);)c.push(i.index),o.push(i.index+i[0].length),e.position<=i.index&&s<0&&(s=o.length-2);s<0&&(s=o.length-1);var u,p,f="",d=Math.min(e.line+t.linesAfter,c.length).toString().length,h=t.maxLength-(t.indent+d+3);for(u=1;u<=t.linesBefore&&!(s-u<0);u++)p=a(e.buffer,o[s-u],c[s-u],e.position-(o[s]-o[s-u]),h),f=n.repeat(" ",t.indent)+l((e.line-u+1).toString(),d)+" | "+p.str+"\n"+f;for(p=a(e.buffer,o[s],c[s],e.position,h),f+=n.repeat(" ",t.indent)+l((e.line+1).toString(),d)+" | "+p.str+"\n",f+=n.repeat("-",t.indent+d+3+p.pos)+"^\n",u=1;u<=t.linesAfter&&!(s+u>=c.length);u++)p=a(e.buffer,o[s+u],c[s+u],e.position-(o[s]-o[s+u]),h),f+=n.repeat(" ",t.indent)+l((e.line+u+1).toString(),d)+" | "+p.str+"\n";return f.replace(/\n$/,"")},s=["kind","multi","resolve","construct","instanceOf","predicate","represent","representName","defaultStyle","styleAliases"],u=["scalar","sequence","mapping"];var p=function(e,t){if(t=t||{},Object.keys(t).forEach(function(t){if(-1===s.indexOf(t))throw new o('Unknown option "'+t+'" is met in definition of "'+e+'" YAML type.')}),this.options=t,this.tag=e,this.kind=t.kind||null,this.resolve=t.resolve||function(){return!0},this.construct=t.construct||function(e){return e},this.instanceOf=t.instanceOf||null,this.predicate=t.predicate||null,this.represent=t.represent||null,this.representName=t.representName||null,this.defaultStyle=t.defaultStyle||null,this.multi=t.multi||!1,this.styleAliases=function(e){var t={};return null!==e&&Object.keys(e).forEach(function(n){e[n].forEach(function(e){t[String(e)]=n})}),t}(t.styleAliases||null),-1===u.indexOf(this.kind))throw new o('Unknown kind "'+this.kind+'" is specified for "'+e+'" YAML type.')};function f(e,t){var n=[];return e[t].forEach(function(e){var t=n.length;n.forEach(function(n,i){n.tag===e.tag&&n.kind===e.kind&&n.multi===e.multi&&(t=i)}),n[t]=e}),n}function d(e){return this.extend(e)}d.prototype.extend=function(e){var t=[],n=[];if(e instanceof p)n.push(e);else if(Array.isArray(e))n=n.concat(e);else{if(!e||!Array.isArray(e.implicit)&&!Array.isArray(e.explicit))throw new o("Schema.extend argument should be a Type, [ Type ], or a schema definition ({ implicit: [...], explicit: [...] })");e.implicit&&(t=t.concat(e.implicit)),e.explicit&&(n=n.concat(e.explicit))}t.forEach(function(e){if(!(e instanceof p))throw new o("Specified list of YAML types (or a single Type object) contains a non-Type object.");if(e.loadKind&&"scalar"!==e.loadKind)throw new o("There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.");if(e.multi)throw new o("There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.")}),n.forEach(function(e){if(!(e instanceof p))throw new o("Specified list of YAML types (or a single Type object) contains a non-Type object.")});var i=Object.create(d.prototype);return i.implicit=(this.implicit||[]).concat(t),i.explicit=(this.explicit||[]).concat(n),i.compiledImplicit=f(i,"implicit"),i.compiledExplicit=f(i,"explicit"),i.compiledTypeMap=function(){var e,t,n={scalar:{},sequence:{},mapping:{},fallback:{},multi:{scalar:[],sequence:[],mapping:[],fallback:[]}};function i(e){e.multi?(n.multi[e.kind].push(e),n.multi.fallback.push(e)):n[e.kind][e.tag]=n.fallback[e.tag]=e}for(e=0,t=arguments.length;e<t;e+=1)arguments[e].forEach(i);return n}(i.compiledImplicit,i.compiledExplicit),i};var h=d,g=new p("tag:yaml.org,2002:str",{kind:"scalar",construct:function(e){return null!==e?e:""}}),m=new p("tag:yaml.org,2002:seq",{kind:"sequence",construct:function(e){return null!==e?e:[]}}),y=new p("tag:yaml.org,2002:map",{kind:"mapping",construct:function(e){return null!==e?e:{}}}),b=new h({explicit:[g,m,y]});var A=new p("tag:yaml.org,2002:null",{kind:"scalar",resolve:function(e){if(null===e)return!0;var t=e.length;return 1===t&&"~"===e||4===t&&("null"===e||"Null"===e||"NULL"===e)},construct:function(){return null},predicate:function(e){return null===e},represent:{canonical:function(){return"~"},lowercase:function(){return"null"},uppercase:function(){return"NULL"},camelcase:function(){return"Null"},empty:function(){return""}},defaultStyle:"lowercase"});var v=new p("tag:yaml.org,2002:bool",{kind:"scalar",resolve:function(e){if(null===e)return!1;var t=e.length;return 4===t&&("true"===e||"True"===e||"TRUE"===e)||5===t&&("false"===e||"False"===e||"FALSE"===e)},construct:function(e){return"true"===e||"True"===e||"TRUE"===e},predicate:function(e){return"[object Boolean]"===Object.prototype.toString.call(e)},represent:{lowercase:function(e){return e?"true":"false"},uppercase:function(e){return e?"TRUE":"FALSE"},camelcase:function(e){return e?"True":"False"}},defaultStyle:"lowercase"});function w(e){return 48<=e&&e<=57||65<=e&&e<=70||97<=e&&e<=102}function k(e){return 48<=e&&e<=55}function C(e){return 48<=e&&e<=57}var x=new p("tag:yaml.org,2002:int",{kind:"scalar",resolve:function(e){if(null===e)return!1;var t,n=e.length,i=0,r=!1;if(!n)return!1;if("-"!==(t=e[i])&&"+"!==t||(t=e[++i]),"0"===t){if(i+1===n)return!0;if("b"===(t=e[++i])){for(i++;i<n;i++)if("_"!==(t=e[i])){if("0"!==t&&"1"!==t)return!1;r=!0}return r&&"_"!==t}if("x"===t){for(i++;i<n;i++)if("_"!==(t=e[i])){if(!w(e.charCodeAt(i)))return!1;r=!0}return r&&"_"!==t}if("o"===t){for(i++;i<n;i++)if("_"!==(t=e[i])){if(!k(e.charCodeAt(i)))return!1;r=!0}return r&&"_"!==t}}if("_"===t)return!1;for(;i<n;i++)if("_"!==(t=e[i])){if(!C(e.charCodeAt(i)))return!1;r=!0}return!(!r||"_"===t)},construct:function(e){var t,n=e,i=1;if(-1!==n.indexOf("_")&&(n=n.replace(/_/g,"")),"-"!==(t=n[0])&&"+"!==t||("-"===t&&(i=-1),t=(n=n.slice(1))[0]),"0"===n)return 0;if("0"===t){if("b"===n[1])return i*parseInt(n.slice(2),2);if("x"===n[1])return i*parseInt(n.slice(2),16);if("o"===n[1])return i*parseInt(n.slice(2),8)}return i*parseInt(n,10)},predicate:function(e){return"[object Number]"===Object.prototype.toString.call(e)&&e%1==0&&!n.isNegativeZero(e)},represent:{binary:function(e){return e>=0?"0b"+e.toString(2):"-0b"+e.toString(2).slice(1)},octal:function(e){return e>=0?"0o"+e.toString(8):"-0o"+e.toString(8).slice(1)},decimal:function(e){return e.toString(10)},hexadecimal:function(e){return e>=0?"0x"+e.toString(16).toUpperCase():"-0x"+e.toString(16).toUpperCase().slice(1)}},defaultStyle:"decimal",styleAliases:{binary:[2,"bin"],octal:[8,"oct"],decimal:[10,"dec"],hexadecimal:[16,"hex"]}}),I=new RegExp("^(?:[-+]?(?:[0-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN))$");var S=/^[-+]?[0-9]+e/;var O=new p("tag:yaml.org,2002:float",{kind:"scalar",resolve:function(e){return null!==e&&!(!I.test(e)||"_"===e[e.length-1])},construct:function(e){var t,n;return n="-"===(t=e.replace(/_/g,"").toLowerCase())[0]?-1:1,"+-".indexOf(t[0])>=0&&(t=t.slice(1)),".inf"===t?1===n?Number.POSITIVE_INFINITY:Number.NEGATIVE_INFINITY:".nan"===t?NaN:n*parseFloat(t,10)},predicate:function(e){return"[object Number]"===Object.prototype.toString.call(e)&&(e%1!=0||n.isNegativeZero(e))},represent:function(e,t){var i;if(isNaN(e))switch(t){case"lowercase":return".nan";case"uppercase":return".NAN";case"camelcase":return".NaN"}else if(Number.POSITIVE_INFINITY===e)switch(t){case"lowercase":return".inf";case"uppercase":return".INF";case"camelcase":return".Inf"}else if(Number.NEGATIVE_INFINITY===e)switch(t){case"lowercase":return"-.inf";case"uppercase":return"-.INF";case"camelcase":return"-.Inf"}else if(n.isNegativeZero(e))return"-0.0";return i=e.toString(10),S.test(i)?i.replace("e",".e"):i},defaultStyle:"lowercase"}),j=b.extend({implicit:[A,v,x,O]}),T=j,N=new RegExp("^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$"),F=new RegExp("^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:[Tt]|[ \\t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\\.([0-9]*))?(?:[ \\t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?$");var E=new p("tag:yaml.org,2002:timestamp",{kind:"scalar",resolve:function(e){return null!==e&&(null!==N.exec(e)||null!==F.exec(e))},construct:function(e){var t,n,i,r,o,a,l,c,s=0,u=null;if(null===(t=N.exec(e))&&(t=F.exec(e)),null===t)throw new Error("Date resolve error");if(n=+t[1],i=+t[2]-1,r=+t[3],!t[4])return new Date(Date.UTC(n,i,r));if(o=+t[4],a=+t[5],l=+t[6],t[7]){for(s=t[7].slice(0,3);s.length<3;)s+="0";s=+s}return t[9]&&(u=6e4*(60*+t[10]+ +(t[11]||0)),"-"===t[9]&&(u=-u)),c=new Date(Date.UTC(n,i,r,o,a,l,s)),u&&c.setTime(c.getTime()-u),c},instanceOf:Date,represent:function(e){return e.toISOString()}});var M=new p("tag:yaml.org,2002:merge",{kind:"scalar",resolve:function(e){return"<<"===e||null===e}}),L="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r";var _=new p("tag:yaml.org,2002:binary",{kind:"scalar",resolve:function(e){if(null===e)return!1;var t,n,i=0,r=e.length,o=L;for(n=0;n<r;n++)if(!((t=o.indexOf(e.charAt(n)))>64)){if(t<0)return!1;i+=6}return i%8==0},construct:function(e){var t,n,i=e.replace(/[\r\n=]/g,""),r=i.length,o=L,a=0,l=[];for(t=0;t<r;t++)t%4==0&&t&&(l.push(a>>16&255),l.push(a>>8&255),l.push(255&a)),a=a<<6|o.indexOf(i.charAt(t));return 0===(n=r%4*6)?(l.push(a>>16&255),l.push(a>>8&255),l.push(255&a)):18===n?(l.push(a>>10&255),l.push(a>>2&255)):12===n&&l.push(a>>4&255),new Uint8Array(l)},predicate:function(e){return"[object Uint8Array]"===Object.prototype.toString.call(e)},represent:function(e){var t,n,i="",r=0,o=e.length,a=L;for(t=0;t<o;t++)t%3==0&&t&&(i+=a[r>>18&63],i+=a[r>>12&63],i+=a[r>>6&63],i+=a[63&r]),r=(r<<8)+e[t];return 0===(n=o%3)?(i+=a[r>>18&63],i+=a[r>>12&63],i+=a[r>>6&63],i+=a[63&r]):2===n?(i+=a[r>>10&63],i+=a[r>>4&63],i+=a[r<<2&63],i+=a[64]):1===n&&(i+=a[r>>2&63],i+=a[r<<4&63],i+=a[64],i+=a[64]),i}}),D=Object.prototype.hasOwnProperty,U=Object.prototype.toString;var q=new p("tag:yaml.org,2002:omap",{kind:"sequence",resolve:function(e){if(null===e)return!0;var t,n,i,r,o,a=[],l=e;for(t=0,n=l.length;t<n;t+=1){if(i=l[t],o=!1,"[object Object]"!==U.call(i))return!1;for(r in i)if(D.call(i,r)){if(o)return!1;o=!0}if(!o)return!1;if(-1!==a.indexOf(r))return!1;a.push(r)}return!0},construct:function(e){return null!==e?e:[]}}),Y=Object.prototype.toString;var R=new p("tag:yaml.org,2002:pairs",{kind:"sequence",resolve:function(e){if(null===e)return!0;var t,n,i,r,o,a=e;for(o=new Array(a.length),t=0,n=a.length;t<n;t+=1){if(i=a[t],"[object Object]"!==Y.call(i))return!1;if(1!==(r=Object.keys(i)).length)return!1;o[t]=[r[0],i[r[0]]]}return!0},construct:function(e){if(null===e)return[];var t,n,i,r,o,a=e;for(o=new Array(a.length),t=0,n=a.length;t<n;t+=1)i=a[t],r=Object.keys(i),o[t]=[r[0],i[r[0]]];return o}}),B=Object.prototype.hasOwnProperty;var K=new p("tag:yaml.org,2002:set",{kind:"mapping",resolve:function(e){if(null===e)return!0;var t,n=e;for(t in n)if(B.call(n,t)&&null!==n[t])return!1;return!0},construct:function(e){return null!==e?e:{}}}),P=T.extend({implicit:[E,M],explicit:[_,q,R,K]}),W=Object.prototype.hasOwnProperty,H=/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/,$=/[\x85\u2028\u2029]/,G=/[,\[\]\{\}]/,V=/^(?:!|!!|![a-z\-]+!)$/i,Z=/^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;function J(e){return Object.prototype.toString.call(e)}function Q(e){return 10===e||13===e}function z(e){return 9===e||32===e}function X(e){return 9===e||32===e||10===e||13===e}function ee(e){return 44===e||91===e||93===e||123===e||125===e}function te(e){var t;return 48<=e&&e<=57?e-48:97<=(t=32|e)&&t<=102?t-97+10:-1}function ne(e){return 120===e?2:117===e?4:85===e?8:0}function ie(e){return 48<=e&&e<=57?e-48:-1}function re(e){return 48===e?"\0":97===e?"":98===e?"\b":116===e||9===e?"\t":110===e?"\n":118===e?"\v":102===e?"\f":114===e?"\r":101===e?"":32===e?" ":34===e?'"':47===e?"/":92===e?"\\":78===e?"":95===e?" ":76===e?"\u2028":80===e?"\u2029":""}function oe(e){return e<=65535?String.fromCharCode(e):String.fromCharCode(55296+(e-65536>>10),56320+(e-65536&1023))}function ae(e,t,n){"__proto__"===t?Object.defineProperty(e,t,{configurable:!0,enumerable:!0,writable:!0,value:n}):e[t]=n}for(var le=new Array(256),ce=new Array(256),se=0;se<256;se++)le[se]=re(se)?1:0,ce[se]=re(se);function ue(e,t){this.input=e,this.filename=t.filename||null,this.schema=t.schema||P,this.onWarning=t.onWarning||null,this.legacy=t.legacy||!1,this.json=t.json||!1,this.listener=t.listener||null,this.implicitTypes=this.schema.compiledImplicit,this.typeMap=this.schema.compiledTypeMap,this.length=e.length,this.position=0,this.line=0,this.lineStart=0,this.lineIndent=0,this.firstTabInLine=-1,this.documents=[]}function pe(e,t){var n={name:e.filename,buffer:e.input.slice(0,-1),position:e.position,line:e.line,column:e.position-e.lineStart};return n.snippet=c(n),new o(t,n)}function fe(e,t){throw pe(e,t)}function de(e,t){e.onWarning&&e.onWarning.call(null,pe(e,t))}var he={YAML:function(e,t,n){var i,r,o;null!==e.version&&fe(e,"duplication of %YAML directive"),1!==n.length&&fe(e,"YAML directive accepts exactly one argument"),null===(i=/^([0-9]+)\.([0-9]+)$/.exec(n[0]))&&fe(e,"ill-formed argument of the YAML directive"),r=parseInt(i[1],10),o=parseInt(i[2],10),1!==r&&fe(e,"unacceptable YAML version of the document"),e.version=n[0],e.checkLineBreaks=o<2,1!==o&&2!==o&&de(e,"unsupported YAML version of the document")},TAG:function(e,t,n){var i,r;2!==n.length&&fe(e,"TAG directive accepts exactly two arguments"),i=n[0],r=n[1],V.test(i)||fe(e,"ill-formed tag handle (first argument) of the TAG directive"),W.call(e.tagMap,i)&&fe(e,'there is a previously declared suffix for "'+i+'" tag handle'),Z.test(r)||fe(e,"ill-formed tag prefix (second argument) of the TAG directive");try{r=decodeURIComponent(r)}catch(t){fe(e,"tag prefix is malformed: "+r)}e.tagMap[i]=r}};function ge(e,t,n,i){var r,o,a,l;if(t<n){if(l=e.input.slice(t,n),i)for(r=0,o=l.length;r<o;r+=1)9===(a=l.charCodeAt(r))||32<=a&&a<=1114111||fe(e,"expected valid JSON character");else H.test(l)&&fe(e,"the stream contains non-printable characters");e.result+=l}}function me(e,t,i,r){var o,a,l,c;for(n.isObject(i)||fe(e,"cannot merge mappings; the provided source object is unacceptable"),l=0,c=(o=Object.keys(i)).length;l<c;l+=1)a=o[l],W.call(t,a)||(ae(t,a,i[a]),r[a]=!0)}function ye(e,t,n,i,r,o,a,l,c){var s,u;if(Array.isArray(r))for(s=0,u=(r=Array.prototype.slice.call(r)).length;s<u;s+=1)Array.isArray(r[s])&&fe(e,"nested arrays are not supported inside keys"),"object"==typeof r&&"[object Object]"===J(r[s])&&(r[s]="[object Object]");if("object"==typeof r&&"[object Object]"===J(r)&&(r="[object Object]"),r=String(r),null===t&&(t={}),"tag:yaml.org,2002:merge"===i)if(Array.isArray(o))for(s=0,u=o.length;s<u;s+=1)me(e,t,o[s],n);else me(e,t,o,n);else e.json||W.call(n,r)||!W.call(t,r)||(e.line=a||e.line,e.lineStart=l||e.lineStart,e.position=c||e.position,fe(e,"duplicated mapping key")),ae(t,r,o),delete n[r];return t}function be(e){var t;10===(t=e.input.charCodeAt(e.position))?e.position++:13===t?(e.position++,10===e.input.charCodeAt(e.position)&&e.position++):fe(e,"a line break is expected"),e.line+=1,e.lineStart=e.position,e.firstTabInLine=-1}function Ae(e,t,n){for(var i=0,r=e.input.charCodeAt(e.position);0!==r;){for(;z(r);)9===r&&-1===e.firstTabInLine&&(e.firstTabInLine=e.position),r=e.input.charCodeAt(++e.position);if(t&&35===r)do{r=e.input.charCodeAt(++e.position)}while(10!==r&&13!==r&&0!==r);if(!Q(r))break;for(be(e),r=e.input.charCodeAt(e.position),i++,e.lineIndent=0;32===r;)e.lineIndent++,r=e.input.charCodeAt(++e.position)}return-1!==n&&0!==i&&e.lineIndent<n&&de(e,"deficient indentation"),i}function ve(e){var t,n=e.position;return!(45!==(t=e.input.charCodeAt(n))&&46!==t||t!==e.input.charCodeAt(n+1)||t!==e.input.charCodeAt(n+2)||(n+=3,0!==(t=e.input.charCodeAt(n))&&!X(t)))}function we(e,t){1===t?e.result+=" ":t>1&&(e.result+=n.repeat("\n",t-1))}function ke(e,t){var n,i,r=e.tag,o=e.anchor,a=[],l=!1;if(-1!==e.firstTabInLine)return!1;for(null!==e.anchor&&(e.anchorMap[e.anchor]=a),i=e.input.charCodeAt(e.position);0!==i&&(-1!==e.firstTabInLine&&(e.position=e.firstTabInLine,fe(e,"tab characters must not be used in indentation")),45===i)&&X(e.input.charCodeAt(e.position+1));)if(l=!0,e.position++,Ae(e,!0,-1)&&e.lineIndent<=t)a.push(null),i=e.input.charCodeAt(e.position);else if(n=e.line,Ie(e,t,3,!1,!0),a.push(e.result),Ae(e,!0,-1),i=e.input.charCodeAt(e.position),(e.line===n||e.lineIndent>t)&&0!==i)fe(e,"bad indentation of a sequence entry");else if(e.lineIndent<t)break;return!!l&&(e.tag=r,e.anchor=o,e.kind="sequence",e.result=a,!0)}function Ce(e){var t,n,i,r,o=!1,a=!1;if(33!==(r=e.input.charCodeAt(e.position)))return!1;if(null!==e.tag&&fe(e,"duplication of a tag property"),60===(r=e.input.charCodeAt(++e.position))?(o=!0,r=e.input.charCodeAt(++e.position)):33===r?(a=!0,n="!!",r=e.input.charCodeAt(++e.position)):n="!",t=e.position,o){do{r=e.input.charCodeAt(++e.position)}while(0!==r&&62!==r);e.position<e.length?(i=e.input.slice(t,e.position),r=e.input.charCodeAt(++e.position)):fe(e,"unexpected end of the stream within a verbatim tag")}else{for(;0!==r&&!X(r);)33===r&&(a?fe(e,"tag suffix cannot contain exclamation marks"):(n=e.input.slice(t-1,e.position+1),V.test(n)||fe(e,"named tag handle cannot contain such characters"),a=!0,t=e.position+1)),r=e.input.charCodeAt(++e.position);i=e.input.slice(t,e.position),G.test(i)&&fe(e,"tag suffix cannot contain flow indicator characters")}i&&!Z.test(i)&&fe(e,"tag name cannot contain such characters: "+i);try{i=decodeURIComponent(i)}catch(t){fe(e,"tag name is malformed: "+i)}return o?e.tag=i:W.call(e.tagMap,n)?e.tag=e.tagMap[n]+i:"!"===n?e.tag="!"+i:"!!"===n?e.tag="tag:yaml.org,2002:"+i:fe(e,'undeclared tag handle "'+n+'"'),!0}function xe(e){var t,n;if(38!==(n=e.input.charCodeAt(e.position)))return!1;for(null!==e.anchor&&fe(e,"duplication of an anchor property"),n=e.input.charCodeAt(++e.position),t=e.position;0!==n&&!X(n)&&!ee(n);)n=e.input.charCodeAt(++e.position);return e.position===t&&fe(e,"name of an anchor node must contain at least one character"),e.anchor=e.input.slice(t,e.position),!0}function Ie(e,t,i,r,o){var a,l,c,s,u,p,f,d,h,g=1,m=!1,y=!1;if(null!==e.listener&&e.listener("open",e),e.tag=null,e.anchor=null,e.kind=null,e.result=null,a=l=c=4===i||3===i,r&&Ae(e,!0,-1)&&(m=!0,e.lineIndent>t?g=1:e.lineIndent===t?g=0:e.lineIndent<t&&(g=-1)),1===g)for(;Ce(e)||xe(e);)Ae(e,!0,-1)?(m=!0,c=a,e.lineIndent>t?g=1:e.lineIndent===t?g=0:e.lineIndent<t&&(g=-1)):c=!1;if(c&&(c=m||o),1!==g&&4!==i||(d=1===i||2===i?t:t+1,h=e.position-e.lineStart,1===g?c&&(ke(e,h)||function(e,t,n){var i,r,o,a,l,c,s,u=e.tag,p=e.anchor,f={},d=Object.create(null),h=null,g=null,m=null,y=!1,b=!1;if(-1!==e.firstTabInLine)return!1;for(null!==e.anchor&&(e.anchorMap[e.anchor]=f),s=e.input.charCodeAt(e.position);0!==s;){if(y||-1===e.firstTabInLine||(e.position=e.firstTabInLine,fe(e,"tab characters must not be used in indentation")),i=e.input.charCodeAt(e.position+1),o=e.line,63!==s&&58!==s||!X(i)){if(a=e.line,l=e.lineStart,c=e.position,!Ie(e,n,2,!1,!0))break;if(e.line===o){for(s=e.input.charCodeAt(e.position);z(s);)s=e.input.charCodeAt(++e.position);if(58===s)X(s=e.input.charCodeAt(++e.position))||fe(e,"a whitespace character is expected after the key-value separator within a block mapping"),y&&(ye(e,f,d,h,g,null,a,l,c),h=g=m=null),b=!0,y=!1,r=!1,h=e.tag,g=e.result;else{if(!b)return e.tag=u,e.anchor=p,!0;fe(e,"can not read an implicit mapping pair; a colon is missed")}}else{if(!b)return e.tag=u,e.anchor=p,!0;fe(e,"can not read a block mapping entry; a multiline key may not be an implicit key")}}else 63===s?(y&&(ye(e,f,d,h,g,null,a,l,c),h=g=m=null),b=!0,y=!0,r=!0):y?(y=!1,r=!0):fe(e,"incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line"),e.position+=1,s=i;if((e.line===o||e.lineIndent>t)&&(y&&(a=e.line,l=e.lineStart,c=e.position),Ie(e,t,4,!0,r)&&(y?g=e.result:m=e.result),y||(ye(e,f,d,h,g,m,a,l,c),h=g=m=null),Ae(e,!0,-1),s=e.input.charCodeAt(e.position)),(e.line===o||e.lineIndent>t)&&0!==s)fe(e,"bad indentation of a mapping entry");else if(e.lineIndent<t)break}return y&&ye(e,f,d,h,g,null,a,l,c),b&&(e.tag=u,e.anchor=p,e.kind="mapping",e.result=f),b}(e,h,d))||function(e,t){var n,i,r,o,a,l,c,s,u,p,f,d,h=!0,g=e.tag,m=e.anchor,y=Object.create(null);if(91===(d=e.input.charCodeAt(e.position)))a=93,s=!1,o=[];else{if(123!==d)return!1;a=125,s=!0,o={}}for(null!==e.anchor&&(e.anchorMap[e.anchor]=o),d=e.input.charCodeAt(++e.position);0!==d;){if(Ae(e,!0,t),(d=e.input.charCodeAt(e.position))===a)return e.position++,e.tag=g,e.anchor=m,e.kind=s?"mapping":"sequence",e.result=o,!0;h?44===d&&fe(e,"expected the node content, but found ','"):fe(e,"missed comma between flow collection entries"),f=null,l=c=!1,63===d&&X(e.input.charCodeAt(e.position+1))&&(l=c=!0,e.position++,Ae(e,!0,t)),n=e.line,i=e.lineStart,r=e.position,Ie(e,t,1,!1,!0),p=e.tag,u=e.result,Ae(e,!0,t),d=e.input.charCodeAt(e.position),!c&&e.line!==n||58!==d||(l=!0,d=e.input.charCodeAt(++e.position),Ae(e,!0,t),Ie(e,t,1,!1,!0),f=e.result),s?ye(e,o,y,p,u,f,n,i,r):l?o.push(ye(e,null,y,p,u,f,n,i,r)):o.push(u),Ae(e,!0,t),44===(d=e.input.charCodeAt(e.position))?(h=!0,d=e.input.charCodeAt(++e.position)):h=!1}fe(e,"unexpected end of the stream within a flow collection")}(e,d)?y=!0:(l&&function(e,t){var i,r,o,a,l=1,c=!1,s=!1,u=t,p=0,f=!1;if(124===(a=e.input.charCodeAt(e.position)))r=!1;else{if(62!==a)return!1;r=!0}for(e.kind="scalar",e.result="";0!==a;)if(43===(a=e.input.charCodeAt(++e.position))||45===a)1===l?l=43===a?3:2:fe(e,"repeat of a chomping mode identifier");else{if(!((o=ie(a))>=0))break;0===o?fe(e,"bad explicit indentation width of a block scalar; it cannot be less than one"):s?fe(e,"repeat of an indentation width identifier"):(u=t+o-1,s=!0)}if(z(a)){do{a=e.input.charCodeAt(++e.position)}while(z(a));if(35===a)do{a=e.input.charCodeAt(++e.position)}while(!Q(a)&&0!==a)}for(;0!==a;){for(be(e),e.lineIndent=0,a=e.input.charCodeAt(e.position);(!s||e.lineIndent<u)&&32===a;)e.lineIndent++,a=e.input.charCodeAt(++e.position);if(!s&&e.lineIndent>u&&(u=e.lineIndent),Q(a))p++;else{if(e.lineIndent<u){3===l?e.result+=n.repeat("\n",c?1+p:p):1===l&&c&&(e.result+="\n");break}for(r?z(a)?(f=!0,e.result+=n.repeat("\n",c?1+p:p)):f?(f=!1,e.result+=n.repeat("\n",p+1)):0===p?c&&(e.result+=" "):e.result+=n.repeat("\n",p):e.result+=n.repeat("\n",c?1+p:p),c=!0,s=!0,p=0,i=e.position;!Q(a)&&0!==a;)a=e.input.charCodeAt(++e.position);ge(e,i,e.position,!1)}}return!0}(e,d)||function(e,t){var n,i,r;if(39!==(n=e.input.charCodeAt(e.position)))return!1;for(e.kind="scalar",e.result="",e.position++,i=r=e.position;0!==(n=e.input.charCodeAt(e.position));)if(39===n){if(ge(e,i,e.position,!0),39!==(n=e.input.charCodeAt(++e.position)))return!0;i=e.position,e.position++,r=e.position}else Q(n)?(ge(e,i,r,!0),we(e,Ae(e,!1,t)),i=r=e.position):e.position===e.lineStart&&ve(e)?fe(e,"unexpected end of the document within a single quoted scalar"):(e.position++,r=e.position);fe(e,"unexpected end of the stream within a single quoted scalar")}(e,d)||function(e,t){var n,i,r,o,a,l;if(34!==(l=e.input.charCodeAt(e.position)))return!1;for(e.kind="scalar",e.result="",e.position++,n=i=e.position;0!==(l=e.input.charCodeAt(e.position));){if(34===l)return ge(e,n,e.position,!0),e.position++,!0;if(92===l){if(ge(e,n,e.position,!0),Q(l=e.input.charCodeAt(++e.position)))Ae(e,!1,t);else if(l<256&&le[l])e.result+=ce[l],e.position++;else if((a=ne(l))>0){for(r=a,o=0;r>0;r--)(a=te(l=e.input.charCodeAt(++e.position)))>=0?o=(o<<4)+a:fe(e,"expected hexadecimal character");e.result+=oe(o),e.position++}else fe(e,"unknown escape sequence");n=i=e.position}else Q(l)?(ge(e,n,i,!0),we(e,Ae(e,!1,t)),n=i=e.position):e.position===e.lineStart&&ve(e)?fe(e,"unexpected end of the document within a double quoted scalar"):(e.position++,i=e.position)}fe(e,"unexpected end of the stream within a double quoted scalar")}(e,d)?y=!0:!function(e){var t,n,i;if(42!==(i=e.input.charCodeAt(e.position)))return!1;for(i=e.input.charCodeAt(++e.position),t=e.position;0!==i&&!X(i)&&!ee(i);)i=e.input.charCodeAt(++e.position);return e.position===t&&fe(e,"name of an alias node must contain at least one character"),n=e.input.slice(t,e.position),W.call(e.anchorMap,n)||fe(e,'unidentified alias "'+n+'"'),e.result=e.anchorMap[n],Ae(e,!0,-1),!0}(e)?function(e,t,n){var i,r,o,a,l,c,s,u,p=e.kind,f=e.result;if(X(u=e.input.charCodeAt(e.position))||ee(u)||35===u||38===u||42===u||33===u||124===u||62===u||39===u||34===u||37===u||64===u||96===u)return!1;if((63===u||45===u)&&(X(i=e.input.charCodeAt(e.position+1))||n&&ee(i)))return!1;for(e.kind="scalar",e.result="",r=o=e.position,a=!1;0!==u;){if(58===u){if(X(i=e.input.charCodeAt(e.position+1))||n&&ee(i))break}else if(35===u){if(X(e.input.charCodeAt(e.position-1)))break}else{if(e.position===e.lineStart&&ve(e)||n&&ee(u))break;if(Q(u)){if(l=e.line,c=e.lineStart,s=e.lineIndent,Ae(e,!1,-1),e.lineIndent>=t){a=!0,u=e.input.charCodeAt(e.position);continue}e.position=o,e.line=l,e.lineStart=c,e.lineIndent=s;break}}a&&(ge(e,r,o,!1),we(e,e.line-l),r=o=e.position,a=!1),z(u)||(o=e.position+1),u=e.input.charCodeAt(++e.position)}return ge(e,r,o,!1),!!e.result||(e.kind=p,e.result=f,!1)}(e,d,1===i)&&(y=!0,null===e.tag&&(e.tag="?")):(y=!0,null===e.tag&&null===e.anchor||fe(e,"alias node should not have any properties")),null!==e.anchor&&(e.anchorMap[e.anchor]=e.result)):0===g&&(y=c&&ke(e,h))),null===e.tag)null!==e.anchor&&(e.anchorMap[e.anchor]=e.result);else if("?"===e.tag){for(null!==e.result&&"scalar"!==e.kind&&fe(e,'unacceptable node kind for !<?> tag; it should be "scalar", not "'+e.kind+'"'),s=0,u=e.implicitTypes.length;s<u;s+=1)if((f=e.implicitTypes[s]).resolve(e.result)){e.result=f.construct(e.result),e.tag=f.tag,null!==e.anchor&&(e.anchorMap[e.anchor]=e.result);break}}else if("!"!==e.tag){if(W.call(e.typeMap[e.kind||"fallback"],e.tag))f=e.typeMap[e.kind||"fallback"][e.tag];else for(f=null,s=0,u=(p=e.typeMap.multi[e.kind||"fallback"]).length;s<u;s+=1)if(e.tag.slice(0,p[s].tag.length)===p[s].tag){f=p[s];break}f||fe(e,"unknown tag !<"+e.tag+">"),null!==e.result&&f.kind!==e.kind&&fe(e,"unacceptable node kind for !<"+e.tag+'> tag; it should be "'+f.kind+'", not "'+e.kind+'"'),f.resolve(e.result,e.tag)?(e.result=f.construct(e.result,e.tag),null!==e.anchor&&(e.anchorMap[e.anchor]=e.result)):fe(e,"cannot resolve a node with !<"+e.tag+"> explicit tag")}return null!==e.listener&&e.listener("close",e),null!==e.tag||null!==e.anchor||y}function Se(e){var t,n,i,r,o=e.position,a=!1;for(e.version=null,e.checkLineBreaks=e.legacy,e.tagMap=Object.create(null),e.anchorMap=Object.create(null);0!==(r=e.input.charCodeAt(e.position))&&(Ae(e,!0,-1),r=e.input.charCodeAt(e.position),!(e.lineIndent>0||37!==r));){for(a=!0,r=e.input.charCodeAt(++e.position),t=e.position;0!==r&&!X(r);)r=e.input.charCodeAt(++e.position);for(i=[],(n=e.input.slice(t,e.position)).length<1&&fe(e,"directive name must not be less than one character in length");0!==r;){for(;z(r);)r=e.input.charCodeAt(++e.position);if(35===r){do{r=e.input.charCodeAt(++e.position)}while(0!==r&&!Q(r));break}if(Q(r))break;for(t=e.position;0!==r&&!X(r);)r=e.input.charCodeAt(++e.position);i.push(e.input.slice(t,e.position))}0!==r&&be(e),W.call(he,n)?he[n](e,n,i):de(e,'unknown document directive "'+n+'"')}Ae(e,!0,-1),0===e.lineIndent&&45===e.input.charCodeAt(e.position)&&45===e.input.charCodeAt(e.position+1)&&45===e.input.charCodeAt(e.position+2)?(e.position+=3,Ae(e,!0,-1)):a&&fe(e,"directives end mark is expected"),Ie(e,e.lineIndent-1,4,!1,!0),Ae(e,!0,-1),e.checkLineBreaks&&$.test(e.input.slice(o,e.position))&&de(e,"non-ASCII line breaks are interpreted as content"),e.documents.push(e.result),e.position===e.lineStart&&ve(e)?46===e.input.charCodeAt(e.position)&&(e.position+=3,Ae(e,!0,-1)):e.position<e.length-1&&fe(e,"end of the stream or a document separator is expected")}function Oe(e,t){t=t||{},0!==(e=String(e)).length&&(10!==e.charCodeAt(e.length-1)&&13!==e.charCodeAt(e.length-1)&&(e+="\n"),65279===e.charCodeAt(0)&&(e=e.slice(1)));var n=new ue(e,t),i=e.indexOf("\0");for(-1!==i&&(n.position=i,fe(n,"null byte is not allowed in input")),n.input+="\0";32===n.input.charCodeAt(n.position);)n.lineIndent+=1,n.position+=1;for(;n.position<n.length-1;)Se(n);return n.documents}var je={loadAll:function(e,t,n){null!==t&&"object"==typeof t&&void 0===n&&(n=t,t=null);var i=Oe(e,n);if("function"!=typeof t)return i;for(var r=0,o=i.length;r<o;r+=1)t(i[r])},load:function(e,t){var n=Oe(e,t);if(0!==n.length){if(1===n.length)return n[0];throw new o("expected a single document in the stream, but found more")}}},Te=Object.prototype.toString,Ne=Object.prototype.hasOwnProperty,Fe=65279,Ee={0:"\\0",7:"\\a",8:"\\b",9:"\\t",10:"\\n",11:"\\v",12:"\\f",13:"\\r",27:"\\e",34:'\\"',92:"\\\\",133:"\\N",160:"\\_",8232:"\\L",8233:"\\P"},Me=["y","Y","yes","Yes","YES","on","On","ON","n","N","no","No","NO","off","Off","OFF"],Le=/^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/;function _e(e){var t,i,r;if(t=e.toString(16).toUpperCase(),e<=255)i="x",r=2;else if(e<=65535)i="u",r=4;else{if(!(e<=4294967295))throw new o("code point within a string may not be greater than 0xFFFFFFFF");i="U",r=8}return"\\"+i+n.repeat("0",r-t.length)+t}function De(e){this.schema=e.schema||P,this.indent=Math.max(1,e.indent||2),this.noArrayIndent=e.noArrayIndent||!1,this.skipInvalid=e.skipInvalid||!1,this.flowLevel=n.isNothing(e.flowLevel)?-1:e.flowLevel,this.styleMap=function(e,t){var n,i,r,o,a,l,c;if(null===t)return{};for(n={},r=0,o=(i=Object.keys(t)).length;r<o;r+=1)a=i[r],l=String(t[a]),"!!"===a.slice(0,2)&&(a="tag:yaml.org,2002:"+a.slice(2)),(c=e.compiledTypeMap.fallback[a])&&Ne.call(c.styleAliases,l)&&(l=c.styleAliases[l]),n[a]=l;return n}(this.schema,e.styles||null),this.sortKeys=e.sortKeys||!1,this.lineWidth=e.lineWidth||80,this.noRefs=e.noRefs||!1,this.noCompatMode=e.noCompatMode||!1,this.condenseFlow=e.condenseFlow||!1,this.quotingType='"'===e.quotingType?2:1,this.forceQuotes=e.forceQuotes||!1,this.replacer="function"==typeof e.replacer?e.replacer:null,this.implicitTypes=this.schema.compiledImplicit,this.explicitTypes=this.schema.compiledExplicit,this.tag=null,this.result="",this.duplicates=[],this.usedDuplicates=null}function Ue(e,t){for(var i,r=n.repeat(" ",t),o=0,a=-1,l="",c=e.length;o<c;)-1===(a=e.indexOf("\n",o))?(i=e.slice(o),o=c):(i=e.slice(o,a+1),o=a+1),i.length&&"\n"!==i&&(l+=r),l+=i;return l}function qe(e,t){return"\n"+n.repeat(" ",e.indent*t)}function Ye(e){return 32===e||9===e}function Re(e){return 32<=e&&e<=126||161<=e&&e<=55295&&8232!==e&&8233!==e||57344<=e&&e<=65533&&e!==Fe||65536<=e&&e<=1114111}function Be(e){return Re(e)&&e!==Fe&&13!==e&&10!==e}function Ke(e,t,n){var i=Be(e),r=i&&!Ye(e);return(n?i:i&&44!==e&&91!==e&&93!==e&&123!==e&&125!==e)&&35!==e&&!(58===t&&!r)||Be(t)&&!Ye(t)&&35===e||58===t&&r}function Pe(e,t){var n,i=e.charCodeAt(t);return i>=55296&&i<=56319&&t+1<e.length&&(n=e.charCodeAt(t+1))>=56320&&n<=57343?1024*(i-55296)+n-56320+65536:i}function We(e){return/^\n* /.test(e)}function He(e,t,n,i,r,o,a,l){var c,s,u=0,p=null,f=!1,d=!1,h=-1!==i,g=-1,m=Re(s=Pe(e,0))&&s!==Fe&&!Ye(s)&&45!==s&&63!==s&&58!==s&&44!==s&&91!==s&&93!==s&&123!==s&&125!==s&&35!==s&&38!==s&&42!==s&&33!==s&&124!==s&&61!==s&&62!==s&&39!==s&&34!==s&&37!==s&&64!==s&&96!==s&&function(e){return!Ye(e)&&58!==e}(Pe(e,e.length-1));if(t||a)for(c=0;c<e.length;u>=65536?c+=2:c++){if(!Re(u=Pe(e,c)))return 5;m=m&&Ke(u,p,l),p=u}else{for(c=0;c<e.length;u>=65536?c+=2:c++){if(10===(u=Pe(e,c)))f=!0,h&&(d=d||c-g-1>i&&" "!==e[g+1],g=c);else if(!Re(u))return 5;m=m&&Ke(u,p,l),p=u}d=d||h&&c-g-1>i&&" "!==e[g+1]}return f||d?n>9&&We(e)?5:a?2===o?5:2:d?4:3:!m||a||r(e)?2===o?5:2:1}function $e(e,t,n,i,r){e.dump=function(){if(0===t.length)return 2===e.quotingType?'""':"''";if(!e.noCompatMode&&(-1!==Me.indexOf(t)||Le.test(t)))return 2===e.quotingType?'"'+t+'"':"'"+t+"'";var a=e.indent*Math.max(1,n),l=-1===e.lineWidth?-1:Math.max(Math.min(e.lineWidth,40),e.lineWidth-a),c=i||e.flowLevel>-1&&n>=e.flowLevel;switch(He(t,c,e.indent,l,function(t){return function(e,t){var n,i;for(n=0,i=e.implicitTypes.length;n<i;n+=1)if(e.implicitTypes[n].resolve(t))return!0;return!1}(e,t)},e.quotingType,e.forceQuotes&&!i,r)){case 1:return t;case 2:return"'"+t.replace(/'/g,"''")+"'";case 3:return"|"+Ge(t,e.indent)+Ve(Ue(t,a));case 4:return">"+Ge(t,e.indent)+Ve(Ue(function(e,t){var n,i,r=/(\n+)([^\n]*)/g,o=(l=e.indexOf("\n"),l=-1!==l?l:e.length,r.lastIndex=l,Ze(e.slice(0,l),t)),a="\n"===e[0]||" "===e[0];var l;for(;i=r.exec(e);){var c=i[1],s=i[2];n=" "===s[0],o+=c+(a||n||""===s?"":"\n")+Ze(s,t),a=n}return o}(t,l),a));case 5:return'"'+function(e){for(var t,n="",i=0,r=0;r<e.length;i>=65536?r+=2:r++)i=Pe(e,r),!(t=Ee[i])&&Re(i)?(n+=e[r],i>=65536&&(n+=e[r+1])):n+=t||_e(i);return n}(t)+'"';default:throw new o("impossible error: invalid scalar style")}}()}function Ge(e,t){var n=We(e)?String(t):"",i="\n"===e[e.length-1];return n+(i&&("\n"===e[e.length-2]||"\n"===e)?"+":i?"":"-")+"\n"}function Ve(e){return"\n"===e[e.length-1]?e.slice(0,-1):e}function Ze(e,t){if(""===e||" "===e[0])return e;for(var n,i,r=/ [^ ]/g,o=0,a=0,l=0,c="";n=r.exec(e);)(l=n.index)-o>t&&(i=a>o?a:l,c+="\n"+e.slice(o,i),o=i+1),a=l;return c+="\n",e.length-o>t&&a>o?c+=e.slice(o,a)+"\n"+e.slice(a+1):c+=e.slice(o),c.slice(1)}function Je(e,t,n,i){var r,o,a,l="",c=e.tag;for(r=0,o=n.length;r<o;r+=1)a=n[r],e.replacer&&(a=e.replacer.call(n,String(r),a)),(ze(e,t+1,a,!0,!0,!1,!0)||void 0===a&&ze(e,t+1,null,!0,!0,!1,!0))&&(i&&""===l||(l+=qe(e,t)),e.dump&&10===e.dump.charCodeAt(0)?l+="-":l+="- ",l+=e.dump);e.tag=c,e.dump=l||"[]"}function Qe(e,t,n){var i,r,a,l,c,s;for(a=0,l=(r=n?e.explicitTypes:e.implicitTypes).length;a<l;a+=1)if(((c=r[a]).instanceOf||c.predicate)&&(!c.instanceOf||"object"==typeof t&&t instanceof c.instanceOf)&&(!c.predicate||c.predicate(t))){if(n?c.multi&&c.representName?e.tag=c.representName(t):e.tag=c.tag:e.tag="?",c.represent){if(s=e.styleMap[c.tag]||c.defaultStyle,"[object Function]"===Te.call(c.represent))i=c.represent(t,s);else{if(!Ne.call(c.represent,s))throw new o("!<"+c.tag+'> tag resolver accepts not "'+s+'" style');i=c.represent[s](t,s)}e.dump=i}return!0}return!1}function ze(e,t,n,i,r,a,l){e.tag=null,e.dump=n,Qe(e,n,!1)||Qe(e,n,!0);var c,s=Te.call(e.dump),u=i;i&&(i=e.flowLevel<0||e.flowLevel>t);var p,f,d="[object Object]"===s||"[object Array]"===s;if(d&&(f=-1!==(p=e.duplicates.indexOf(n))),(null!==e.tag&&"?"!==e.tag||f||2!==e.indent&&t>0)&&(r=!1),f&&e.usedDuplicates[p])e.dump="*ref_"+p;else{if(d&&f&&!e.usedDuplicates[p]&&(e.usedDuplicates[p]=!0),"[object Object]"===s)i&&0!==Object.keys(e.dump).length?(!function(e,t,n,i){var r,a,l,c,s,u,p="",f=e.tag,d=Object.keys(n);if(!0===e.sortKeys)d.sort();else if("function"==typeof e.sortKeys)d.sort(e.sortKeys);else if(e.sortKeys)throw new o("sortKeys must be a boolean or a function");for(r=0,a=d.length;r<a;r+=1)u="",i&&""===p||(u+=qe(e,t)),c=n[l=d[r]],e.replacer&&(c=e.replacer.call(n,l,c)),ze(e,t+1,l,!0,!0,!0)&&((s=null!==e.tag&&"?"!==e.tag||e.dump&&e.dump.length>1024)&&(e.dump&&10===e.dump.charCodeAt(0)?u+="?":u+="? "),u+=e.dump,s&&(u+=qe(e,t)),ze(e,t+1,c,!0,s)&&(e.dump&&10===e.dump.charCodeAt(0)?u+=":":u+=": ",p+=u+=e.dump));e.tag=f,e.dump=p||"{}"}(e,t,e.dump,r),f&&(e.dump="&ref_"+p+e.dump)):(!function(e,t,n){var i,r,o,a,l,c="",s=e.tag,u=Object.keys(n);for(i=0,r=u.length;i<r;i+=1)l="",""!==c&&(l+=", "),e.condenseFlow&&(l+='"'),a=n[o=u[i]],e.replacer&&(a=e.replacer.call(n,o,a)),ze(e,t,o,!1,!1)&&(e.dump.length>1024&&(l+="? "),l+=e.dump+(e.condenseFlow?'"':"")+":"+(e.condenseFlow?"":" "),ze(e,t,a,!1,!1)&&(c+=l+=e.dump));e.tag=s,e.dump="{"+c+"}"}(e,t,e.dump),f&&(e.dump="&ref_"+p+" "+e.dump));else if("[object Array]"===s)i&&0!==e.dump.length?(e.noArrayIndent&&!l&&t>0?Je(e,t-1,e.dump,r):Je(e,t,e.dump,r),f&&(e.dump="&ref_"+p+e.dump)):(!function(e,t,n){var i,r,o,a="",l=e.tag;for(i=0,r=n.length;i<r;i+=1)o=n[i],e.replacer&&(o=e.replacer.call(n,String(i),o)),(ze(e,t,o,!1,!1)||void 0===o&&ze(e,t,null,!1,!1))&&(""!==a&&(a+=","+(e.condenseFlow?"":" ")),a+=e.dump);e.tag=l,e.dump="["+a+"]"}(e,t,e.dump),f&&(e.dump="&ref_"+p+" "+e.dump));else{if("[object String]"!==s){if("[object Undefined]"===s)return!1;if(e.skipInvalid)return!1;throw new o("unacceptable kind of an object to dump "+s)}"?"!==e.tag&&$e(e,e.dump,t,a,u)}null!==e.tag&&"?"!==e.tag&&(c=encodeURI("!"===e.tag[0]?e.tag.slice(1):e.tag).replace(/!/g,"%21"),c="!"===e.tag[0]?"!"+c:"tag:yaml.org,2002:"===c.slice(0,18)?"!!"+c.slice(18):"!<"+c+">",e.dump=c+" "+e.dump)}return!0}function Xe(e,t){var n,i,r=[],o=[];for(et(e,r,o),n=0,i=o.length;n<i;n+=1)t.duplicates.push(r[o[n]]);t.usedDuplicates=new Array(i)}function et(e,t,n){var i,r,o;if(null!==e&&"object"==typeof e)if(-1!==(r=t.indexOf(e)))-1===n.indexOf(r)&&n.push(r);else if(t.push(e),Array.isArray(e))for(r=0,o=e.length;r<o;r+=1)et(e[r],t,n);else for(r=0,o=(i=Object.keys(e)).length;r<o;r+=1)et(e[i[r]],t,n)}function tt(e,t){return function(){throw new Error("Function yaml."+e+" is removed in js-yaml 4. Use yaml."+t+" instead, which is now safe by default.")}}var nt=p,it=h,rt=b,ot=j,at=T,lt=P,ct=je.load,st=je.loadAll,ut={dump:function(e,t){var n=new De(t=t||{});n.noRefs||Xe(e,n);var i=e;return n.replacer&&(i=n.replacer.call({"":i},"",i)),ze(n,0,i,!0,!0)?n.dump+"\n":""}}.dump,pt=o,ft={binary:_,float:O,map:y,null:A,pairs:R,set:K,timestamp:E,bool:v,int:x,merge:M,omap:q,seq:m,str:g},dt=tt("safeLoad","load"),ht=tt("safeLoadAll","loadAll"),gt=tt("safeDump","dump"),mt={Type:nt,Schema:it,FAILSAFE_SCHEMA:rt,JSON_SCHEMA:ot,CORE_SCHEMA:at,DEFAULT_SCHEMA:lt,load:ct,loadAll:st,dump:ut,YAMLException:pt,types:ft,safeLoad:dt,safeLoadAll:ht,safeDump:gt};e.CORE_SCHEMA=at,e.DEFAULT_SCHEMA=lt,e.FAILSAFE_SCHEMA=rt,e.JSON_SCHEMA=ot,e.Schema=it,e.Type=nt,e.YAMLException=pt,e.default=mt,e.dump=ut,e.load=ct,e.loadAll=st,e.safeDump=gt,e.safeLoad=dt,e.safeLoadAll=ht,e.types=ft,Object.defineProperty(e,"__esModule",{value:!0})});


  return module.exports;
})();

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
  { domain: 'hkt1.kisoul.org' },
  { domain: 'hkt2.kisoul.org' },
  { domain: 'hku1.kisoul.org' }, 
  { domain: 'hku2.kisoul.org' },
  { domain: 'hkm1.kisoul.org' },
  { domain: 'hkm2.kisoul.org' },
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
    const ech = (link.match(/[?&]ech=([^&#]+)/) || [])[1];
    if (ech) {
      yaml += '    ech-opts:\n      enable: true\n      query-server-name: ' + escapeYamlString(decodeURIComponent(ech).split('+')[0]) + '\n';
    }
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

function patchClashECH(yaml, links, params) {
  const ech = getECHOptions(params);
  const config = clashYamlCodec.load(yaml, { schema: clashYamlCodec.JSON_SCHEMA });
  if (!ech || !config || typeof config !== 'object' || !Array.isArray(config.proxies)) throw new Error('转换器没有返回有效的 Clash proxies 配置');
  const key = node => JSON.stringify([node.type, String(node.server).replace(/^\[|\]$/g, ''), Number(node.server_port || node.port), node.uuid || node.password]);
  const source = JSON.parse(generateSingBoxConfig(links, params));
  const identities = new Set(source.outbounds.filter(node => node.tls?.enabled).map(key));
  let patched = 0;
  for (const node of config.proxies) {
    if (!node || !identities.has(key(node)) || !(node.tls === true || node.type === 'trojan')) continue;
    node['ech-opts'] = { enable: true, 'query-server-name': ech.domain };
    patched++;
  }
  if (!patched) throw new Error('转换结果中没有匹配的 TLS 节点，无法补入 ECH');
  // 精确域名策略仅用于 ECH 查询，不替换模板的普通 DNS 策略。
  config.dns ||= {};
  config.dns['nameserver-policy'] ||= {};
  if (typeof config.dns !== 'object' || Array.isArray(config.dns) || typeof config.dns['nameserver-policy'] !== 'object' || Array.isArray(config.dns['nameserver-policy'])) throw new Error('转换器 DNS 配置格式无效');
  config.dns.enable = true;
  config.dns['nameserver-policy'][ech.domain] = [ech.dns];
  return clashYamlCodec.dump(config, { schema: clashYamlCodec.JSON_SCHEMA, noRefs: true, lineWidth: -1 });
}

async function generateConvertedClashWithECH(request, links, converterAddress) {
  const sourceUrl = new URL(request.url);
  const params = sourceUrl.searchParams;
  const config = params.get('config') || presetClashConfigMap[params.get('config_mode')];
  if (!config || new URL(config).protocol !== 'https:') throw new Error('远程模板必须使用 HTTPS');
  const rawUrl = new URL(sourceUrl);
  rawUrl.searchParams.set('target', 'base64');
  rawUrl.searchParams.delete('config'); rawUrl.searchParams.delete('config_mode');
  const converter = new URL(converterAddress);
  if (converter.protocol !== 'https:') throw new Error('订阅转换器必须使用 HTTPS');
  converter.searchParams.set('target', 'clash');
  converter.searchParams.set('url', rawUrl.toString());
  converter.searchParams.set('config', config);
  converter.searchParams.set('insert', 'false'); converter.searchParams.set('list', 'false');
  for (const name of ['emoji','xudp','udp','tfo','expand','scv','fdn','new_name']) converter.searchParams.set(name, params.get(name) || 'true');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(converter.toString(), { signal: controller.signal });
    if (!response.ok) throw new Error('订阅转换器 HTTP ' + response.status);
    return patchClashECH(await response.text(), links, params);
  } finally { clearTimeout(timeout); }
}

// 生成订阅内容
async function handleSubscriptionRequest(request, user, customDomain, piu, ipv4Enabled, ipv6Enabled, ispMobile, ispUnicom, ispTelecom, evEnabled, etEnabled, vmEnabled, disableNonTLS, customPath, customPorts = [], converterAddress = scu) {
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
  const target = url.searchParams.get('target') || 'base64';
  const wsPath = customPath || '/';

  async function addNodesFromList(list) {
    const useVL = evEnabled;

    if (useVL) finalLinks.push(...generateLinksFromSource(list, user, nodeDomain, disableNonTLS, wsPath, customPorts));
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

  switch ((target || '').toLowerCase()) {
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
      if (ech && (url.searchParams.get('config') || presetClashConfigMap[url.searchParams.get('config_mode')])) {
        try { subscriptionContent = await generateConvertedClashWithECH(request, finalLinks, converterAddress); }
        catch (error) { return new Response('Clash ECH 转换失败: ' + error.message, { status: 502,
          headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } }); }
      } else subscriptionContent = generateClashConfig(finalLinks);
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
        <label>WebSocket路径（可选）</label>
        <input type="text" id="customPath" placeholder="留空则使用默认路径 /" value="/">
        <small>自定义WebSocket路径，例如：/v2ray 或 /</small>
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
        <label class="checkbox-label"><input type="checkbox" id="ipFallback" checked><span>新 API 失败时回退 wetest</span></label>
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
        <small>sing-box 原生应用 ECH 和查询 DNS；其他客户端转换后是否保留 ECH，取决于转换器和客户端。原生 Clash 使用其自身 DNS 查询 ECH。</small>
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
        ['协议与连接','选择至少一种协议，再配置加密与传输选项。',[protocol,row('switchECH'),ech,row('switchTLS'),row('switchUDP'),row('switchXUDP'),row('switchTFO'),row('switchSCV')]],
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
      const mode = document.getElementById('clashConfigMode').value;
      const converter = activeClient && activeClient !== 'sing-box' && activeClient !== 'v2ray'
        && (activeClient !== 'clash' || mode !== 'default');
      if (switches.switchECH) availability('switchTLS', 'ECH 已开启，必须保留 TLS');
      if (!switches.switchUDP || !switches.switchVL) availability('switchXUDP', '仅在 UDP 和 VLESS 都开启时生效');
      if (activeClient && activeClient !== 'sing-box' && !converter) {
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
        : converter ? '当前使用订阅转换器；选项是否生效取决于转换器与客户端支持。' : '当前使用原生基础配置；转换器专属选项不生效。';
      document.querySelectorAll('.client-btn').forEach(function (button) {
        button.classList.toggle('selected', !!activeClient && button.getAttribute('onclick').includes("'" + activeClient + "'"));
      });
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
        } else if (switches.switchECH && clientName !== 'STASH') {
          finalUrl = subscriptionUrl + '&target=clash&config=' + encodeURIComponent(finalClashConfigUrl)
            + '&emoji=' + emojiEnabled + '&xudp=' + xudpEnabled + '&udp=' + udpEnabled
            + '&tfo=' + tfoEnabled + '&expand=' + expandEnabled + '&scv=' + scvEnabled
            + '&fdn=' + fdnEnabled + '&new_name=' + newNameEnabled;
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
        customPorts,
        (env && env.scu) || scu
      );
    }

    return new Response('Not Found', { status: 404 });
  }
};


