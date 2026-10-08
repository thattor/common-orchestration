// Private stdio helper; never prints bearer, ticket, URL or server errors.
import readline from 'node:readline';
const MAX = 2 * 1024 * 1024;
let socket, config, pending, timer, total = 0, count = 0, stopped = false;
const queue = [];
const ids = new Set();
function stop() {
  if (stopped) return;
  stopped = true;
  clearTimeout(timer);
  try { socket?.close(); } catch {}
  process.exit(1);
}
function pump() {
  if (pending || socket?.readyState !== WebSocket.OPEN || !queue.length) return;
  pending = queue.shift();
  timer = setTimeout(stop, config.timeoutMs);
  socket.send(JSON.stringify(pending));
}
async function connect(input) {
  const endpoint = new URL(input.endpoint);
  if (endpoint.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(endpoint.hostname)
      || !endpoint.port || endpoint.username || endpoint.password || endpoint.search
      || endpoint.hash || endpoint.pathname !== '/' || typeof input.bearer !== 'string'
      || !input.bearer || !Number.isInteger(input.timeoutMs) || input.timeoutMs < 1
      || input.timeoutMs > 120000) throw Error();
  config = {timeoutMs: input.timeoutMs};
  timer = setTimeout(stop, config.timeoutMs);
  const response = await fetch(new URL('/api/auth/websocket-ticket', endpoint), {
    method: 'POST', headers: {authorization: `Bearer ${input.bearer}`},
    redirect: 'error', signal: AbortSignal.timeout(config.timeoutMs),
  });
  input.bearer = undefined;
  if (!response.ok) throw Error();
  // Stream size check avoids unbounded response.json().
  let text = '';
  for await (const chunk of response.body) {
    if (text.length + chunk.length > 16384) throw Error();
    text += new TextDecoder().decode(chunk);
  }
  const ticket = JSON.parse(text).ticket;
  text = '';
  if (typeof ticket !== 'string' || !ticket || ticket.length > 8192) throw Error();
  const url = new URL('/ws', endpoint);
  url.protocol = 'ws:';
  url.searchParams.set('orchestrationProtocol', '2');
  url.searchParams.set('wsTicket', ticket);
  socket = new WebSocket(url);
  socket.addEventListener('open', () => { clearTimeout(timer); pump(); });
  socket.addEventListener('error', stop);
  socket.addEventListener('close', stop);
  socket.addEventListener('message', (event) => {
    try {
      if (typeof event.data !== 'string' || Buffer.byteLength(event.data) > MAX
          || ++count > 4096 || (total += Buffer.byteLength(event.data)) > 32 * MAX) throw Error();
      const frame = JSON.parse(event.data);
      if (frame._tag === 'Ping') { socket.send(JSON.stringify({_tag: 'Pong'})); return; }
      if (!pending || frame._tag !== 'Exit' || frame.requestId !== pending.id
          || !frame.exit || !['Success', 'Failure'].includes(frame.exit._tag)) throw Error();
      if (frame.exit._tag === 'Failure') throw Error(); // Never emit raw server causes.
      // Forward original JSON for Python's duplicate-key rejection.
      const drained = process.stdout.write(event.data + '\n');
      const complete = () => {
        clearTimeout(timer);
        pending = undefined;
        pump();
      };
      if (drained) complete();
      else process.stdout.once('drain', complete);
    } catch { stop(); }
  });
}
let started = false;
const lines = readline.createInterface({input: process.stdin, crlfDelay: Infinity});
let buffered = 0;
process.stdin.on('data', chunk => {
  buffered += chunk.length;
  if (buffered > 4 * MAX) stop();
});
lines.on('line', line => {
  buffered = 0;
  try {
    if (Buffer.byteLength(line) > MAX) throw Error();
    const input = JSON.parse(line);
    if (!started) { started = true; connect(input).catch(stop); return; }
    if (queue.length >= 4 || input._tag !== 'Request' || typeof input.id !== 'string'
        || !input.id || ids.has(input.id) || ids.size >= 4096
        || !['orchestration.launchThread', 'orchestration.getThreadProjection',
             'orchestration.dispatchCommand'].includes(input.tag)) throw Error();
    ids.add(input.id);
    queue.push(input);
    pump();
  } catch { stop(); }
});
lines.on('close', stop);
process.on('uncaughtException', stop);
process.on('unhandledRejection', stop);
