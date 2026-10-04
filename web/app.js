const $ = id => document.getElementById(id);
let worker, source, waiting, lastEvent = 'issue';
let busy = false;
let connectionEpoch = 0;

function text(tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}

function options() {
  const list = id => $(id).value.split(',').map(value => value.trim()).filter(Boolean);
  return {
    validators: +$('members').value,
    quorum: +$('quorum').value,
    finality: +$('finality').value,
    byzantine: +$('byzantine').value,
    seed: +$('seed').value,
    minLatencyMs: 80,
    maxLatencyMs: 500,
    failurePercent: 0,
    maliciousValidators: list('malicious'),
    unavailableValidators: list('down'),
    badSignatureValidators: [],
    refuseValidators: [],
    networkPartitions: [],
    realtime: true
  };
}

function clearView() {
  ['ledger', 'timeline', 'events', 'results'].forEach(id => $(id).replaceChildren());
  $('root').textContent = '—';
  $('proof').textContent = '—';
  $('request').textContent = '—';
  $('approval').textContent = `0 / ${$('quorum').value}`;
  $('final').textContent = `0 / ${$('finality').value}`;
  $('status').textContent = 'Ready';
}

function drawMembers(config) {
  $('members').value = config.members.length;
  $('quorum').value = config.approvalQuorum;
  $('finality').value = config.finalityQuorum;
  $('byzantine').value = config.maxByzantine;
  $('authorities').replaceChildren();
  if (!$('ledger').children.length) {
    $('approval').textContent = `0 / ${config.approvalQuorum}`;
    $('final').textContent = `0 / ${config.finalityQuorum}`;
  }
  for (const member of config.members) {
    const row = text('div', '', 'authority');
    row.id = member.id;
    row.append(text('span', member.id), text('span', 'ready'), text('span', '·'));
    $('authorities').append(row);
  }
}

function event(message) {
  const isolated = message.kind.startsWith('scenario/');
  const line = text('div', `${message.time || ''} ${message.operator || 'system'} / ${message.kind} / ${message.message || ''}`, message.kind);
  $('events').prepend(line);
  while ($('events').children.length > 150) $('events').lastChild.remove();
  // Isolated attack runs are evidence about their own worlds, never the live registry.
  if (isolated) return;
  if (message.kind === 'reset') {
    clearView();
    return;
  }
  if (message.kind === 'proposed') {
    $('request').textContent = `${message.subject} → ${message.message}`;
    $('status').textContent = 'PROPOSED';
    lastEvent = message.message;
    $('approval').textContent = `0 / ${$('quorum').value}`;
    $('final').textContent = `0 / ${$('finality').value}`;
    document.querySelectorAll('.authority').forEach(row => {
      row.children[1].textContent = 'pending';
      row.children[2].textContent = '…';
      row.children[2].className = '';
    });
  }
  if (message.operator && $(message.operator)) {
    const row = $(message.operator);
    const signed = ['signed', 'finality-vote'].includes(message.kind);
    row.children[1].textContent = message.kind;
    row.children[2].textContent = signed ? '✓' : '×';
    row.children[2].className = signed ? 'ok' : 'error';
  }
  if (message.kind === 'signed') $('approval').textContent = `${message.count} / ${message.required}`;
  if (message.kind === 'finality-vote') $('final').textContent = `${message.count} / ${message.required}`;
  if (message.kind === 'approved') $('status').textContent = 'APPROVED';
  if (message.kind === 'committed') {
    $('status').textContent = 'FINALIZED';
    $('root').textContent = message.head.root;
    // Reconnection can replay SSE history. Show each sequence only once.
    const sequenceId = `entry-${message.head.size}`;
    if (!$(sequenceId)) {
      const row = document.createElement('tr');
      row.id = sequenceId;
      [message.head.size, message.subject, lastEvent, message.head.root.slice(0, 16) + '…'].forEach(value => row.append(text('td', value)));
      $('ledger').prepend(row);
      const block = text('div', '', 'block');
      block.title = `Entry #${message.head.size} / ${message.subject}`;
      $('timeline').append(block);
    }
  }
  if (message.kind === 'verified') $('status').textContent = 'VERIFIED';
  if (message.kind === 'phase') $('status').textContent = message.message;
  if (message.kind === 'error') $('status').textContent = 'FAILED';
}

async function request(action, data = {}) {
  if ($('runtime').value === 'wasm' && !worker) throw Error('WASM worker is unavailable. Switch runtime or reconnect.');
  if (worker) {
    return new Promise((resolve, reject) => {
      waiting = { resolve, reject };
      worker.postMessage(JSON.stringify({ action, ...data }));
    });
  }
  const paths = { reset: '/v1/simulation', submit: '/v1/subjects', tick: '/v1/tick', scenarios: '/v1/scenarios', trace: '/v1/trace' };
  let init;
  if (action !== 'trace') {
    init = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(action === 'reset' ? data.options : data)
    };
  }
  const response = await fetch(paths[action], init);
  const result = await response.json();
  if (!response.ok) throw Error(result.error || `HTTP ${response.status}`);
  return result;
}

async function run(action) {
  if (busy) return;
  busy = true;
  const controls = document.querySelectorAll('button, input, select');
  controls.forEach(control => { control.disabled = true; });
  try {
    await action();
  } catch (error) {
    event({ kind: 'error', message: error.message });
  } finally {
    busy = false;
    controls.forEach(control => { control.disabled = false; });
  }
}

async function connect() {
  const epoch = ++connectionEpoch;
  if (source) source.close();
  if (worker) worker.terminate();
  source = null;
  worker = null;
  waiting = null;
  clearView();
  $('connection').textContent = 'Connecting…';
  if ($('runtime').value === 'wasm') {
    worker = new Worker('worker.js');
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        worker.terminate();
        worker = null;
        $('connection').textContent = 'WASM unavailable';
        reject(Error('WASM startup timed out. Check the worker and simulator.wasm files.'));
      }, 15000);
      function fail(error) {
        clearTimeout(deadline);
        if (worker) worker.terminate();
        worker = null;
        if (waiting) {
          waiting.reject(error);
          waiting = null;
        }
        $('connection').textContent = 'WASM unavailable';
        reject(error);
      }
      worker.onerror = error => fail(Error(error.message || 'Worker failed to load'));
      worker.onmessage = received => {
        if (epoch !== connectionEpoch) return;
        const message = received.data;
        if (message.type === 'ready') {
          clearTimeout(deadline);
          resolve();
        } else if (message.type === 'event') {
          event(JSON.parse(message.data));
        } else if (message.type === 'result' && waiting) {
          const pending = waiting;
          waiting = null;
          if (message.error) pending.reject(Error(message.error));
          else pending.resolve(JSON.parse(message.data));
        } else if (message.error) {
          fail(Error(message.error));
        }
      };
    });
    $('connection').textContent = 'Local WASM worker';
    drawMembers(await request('reset', { options: options() }));
  } else {
    const response = await fetch('/v1/config');
    if (!response.ok) throw Error(`Configuration unavailable: HTTP ${response.status}`);
    drawMembers(await response.json());
    source = new EventSource('/v1/events');
    source.onmessage = received => {
      if (epoch === connectionEpoch) event(JSON.parse(received.data));
    };
    source.onopen = () => { $('connection').textContent = 'Connected / SSE'; };
    source.onerror = () => { $('connection').textContent = 'SSE disconnected / retrying'; };
  }
}

$('runtime').onchange = () => run(connect);
$('reset').onclick = () => run(async () => {
  const config = await request('reset', { options: options() });
  drawMembers(config);
  clearView();
});
document.querySelectorAll('[data-event]').forEach(button => {
  button.onclick = () => run(async () => {
    const result = await request('submit', { event: button.dataset.event, forged: false });
    $('proof').textContent = JSON.stringify(result, null, 2);
  });
});
$('forge').onclick = () => run(async () => {
  $('proof').textContent = JSON.stringify(await request('submit', { event: 'issue', forged: true }), null, 2);
});
$('tick').onclick = () => run(() => request('tick', { seconds: 10 }));
$('scenarios').onclick = () => run(async () => {
  const results = await request('scenarios');
  $('results').replaceChildren();
  for (const result of results) {
    const row = text('div', `${result.passed ? '✓' : '×'} ${result.name}`, 'result ' + (result.passed ? 'ok' : 'error'));
    row.append(text('p', result.detail));
    $('results').append(row);
  }
});
$('export').onclick = () => run(async () => {
  const data = await request('trace');
  const anchor = document.createElement('a');
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  anchor.href = url;
  anchor.download = 'quorum-pki-trace.json';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
run(connect);
