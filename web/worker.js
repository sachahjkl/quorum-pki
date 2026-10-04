importScripts('wasm_exec.js');
const go = new Go();
WebAssembly.instantiateStreaming(fetch('simulator.wasm'),go.importObject).then(x=>go.run(x.instance)).catch(e=>postMessage({type:'result',error:e.message}));
