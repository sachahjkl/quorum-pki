// Execute the same browser Go WASM module in a Node Worker. No browser required.
const {Worker}=require('node:worker_threads');
const fs=require('node:fs');const path=require('node:path');
const web=path.resolve('web');let events=0;
const worker=new Worker(`const {parentPort}=require('node:worker_threads');const fs=require('node:fs');globalThis.crypto=require('node:crypto').webcrypto;globalThis.postMessage=m=>parentPort.postMessage(m);require(${JSON.stringify(path.join(web,'wasm_exec.js'))});parentPort.on('message',m=>globalThis.onmessage({data:m}));const go=new Go();WebAssembly.instantiate(fs.readFileSync(${JSON.stringify(path.join(web,'simulator.wasm'))}),go.importObject).then(x=>go.run(x.instance));`,{eval:true});
let phase=0;const timeout=setTimeout(()=>{console.error('WASM timed out');worker.terminate();process.exit(1)},30000);
worker.on('error',err=>{console.error(err);process.exit(1)});
worker.on('message',m=>{if(m.type==='event'){events++;return}if(m.error){console.error(m.error);process.exit(1)}if(m.type==='ready'){worker.postMessage(JSON.stringify({action:'scenarios'}));return}if(m.type==='result'){const rs=JSON.parse(m.data);if(!rs.every(r=>r.passed)){console.error(rs);process.exit(1)}console.log(`PASS WASM: ${rs.length} cryptographic scenarios, ${events} worker events`);clearTimeout(timeout);worker.terminate()}});
