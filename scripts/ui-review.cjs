// DOM behavior checks in Node: no claim of browser rendering verification.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; this.className = ''; this.value = ''; }
  append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); } }
  prepend(node) { node.parent = this; this.children.unshift(node); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(node => node !== this); }
  get lastChild() { return this.children.at(-1); }
  click() {}
}
const html = fs.readFileSync('web/index.html', 'utf8');
const elements = new Map();
const controls = [];
for (const match of html.matchAll(/<(\w+)\b([^>]*)>/g)) {
  const [,tag, attrs] = match;
  const id = /\bid="([^"]+)"/.exec(attrs)?.[1];
  const el = new Element(tag);
  if (id) { assert(!elements.has(id), `duplicate ID ${id}`); el.id = id; elements.set(id, el); }
  el.value = /\bvalue="([^"]*)"/.exec(attrs)?.[1] || '';
  const event = /\bdata-event="([^"]+)"/.exec(attrs)?.[1];
  if (event) el.dataset = {event};
  if (['button','input','select'].includes(tag)) controls.push(el);
}
elements.get('runtime').value = 'native';
const visit = (el,id) => el.id === id ? el : el.children.map(child=>visit(child,id)).find(Boolean);
const document = {
  createElement: tag=>new Element(tag),
  getElementById: id=>elements.get(id) || [...elements.values()].map(el=>visit(el,id)).find(Boolean),
  querySelectorAll: selector=>selector === '.authority' ? elements.get('authorities').children : selector === '[data-event]' ? controls.filter(el=>el.dataset) : controls
};
const config = {members:[{id:'ca-1'},{id:'ca-2'},{id:'ca-3'},{id:'ca-4'},{id:'ca-5'}],approvalQuorum:3,finalityQuorum:4,maxByzantine:1};
class Source { constructor() { Source.current=this; } close() { this.closed=true; } }
const context = vm.createContext({document, EventSource:Source, fetch:async()=>({ok:true,json:async()=>config}), setTimeout,clearTimeout,URL,Blob,console});
vm.runInContext(fs.readFileSync('web/app.js','utf8'),context);
(async()=>{
  // Allow asynchronous initial configuration fetch/connect to finish.
  await new Promise(resolve=>setImmediate(resolve));
  const evaluate = code=>vm.runInContext(code,context);
  assert.equal(elements.get('authorities').children.length,5);
  evaluate(`event({kind:'proposed',subject:'example.com',message:'issue'})`);
  evaluate(`event({kind:'committed',subject:'example.com',head:{size:1,root:'real-root'}})`);
  evaluate(`event({kind:'verified'})`);
  assert.equal(elements.get('ledger').children.length,1);
  evaluate(`event({kind:'scenario/committed',subject:'attacker.example',head:{size:99,root:'isolated-root'}})`);
  evaluate(`event({kind:'scenario/error',message:'expected forgery rejection'})`);
  assert.equal(elements.get('root').textContent,'real-root');
  assert.equal(elements.get('status').textContent,'VERIFIED');
  assert.equal(elements.get('ledger').children.length,1);
  evaluate(`event({kind:'committed',subject:'example.com',head:{size:1,root:'real-root'}})`);
  assert.equal(elements.get('ledger').children.length,1,'SSE replay duplicated entry');
  elements.get('proof').textContent='old proof';
  evaluate(`clearView()`);
  assert.equal(elements.get('ledger').children.length,0);
  assert.equal(elements.get('proof').textContent,'—');
  assert.equal(elements.get('approval').textContent,'0 / 3');
  assert.equal(elements.get('final').textContent,'0 / 4');
  await evaluate(`run(async()=>{throw Error('intentional failure')})`);
  assert.equal(elements.get('status').textContent,'FAILED');
  assert(controls.every(el=>!el.disabled),'failure left controls locked');
  elements.get('runtime').value='wasm';
  await assert.rejects(evaluate(`request('submit',{event:'issue'})`), /WASM worker is unavailable/);
  assert(html.includes('lang="en"'));
  assert(!/[éèêàô]/i.test(html),'French UI string remains');
  assert(!/#(?:254a38|315e43|326747|a23d34)/.test(fs.readFileSync('web/style.css','utf8')));
  console.log('PASS UI review: isolated scenarios, SSE deduplication, reset state, error recovery, no silent WASM fallback, English and monochrome styling');
})().catch(error=>{console.error(error);process.exit(1)});
