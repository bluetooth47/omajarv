// Per-turn sudo broker. A requester supplies arguments only: the bridge shows
// exactly what it will run and starts sudo itself, so a request cannot display
// one command and collect a password for another, or name its own encryption
// key. Only ciphertext passes through the HTTP bridge.
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { randomBytes, createPublicKey, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { paths } from './config.mjs';

const VALUE_OPTIONS = new Map([['-u', '-u'], ['--user', '-u'], ['-g', '-g'], ['--group', '-g']]);
const FLAG_OPTIONS = new Map([['-H', '-H'], ['--set-home', '-H'], ['-n', '-n'], ['--non-interactive', '-n']]);
const MAX_RUNS = 4;
export const SUDO_USAGE = 'Use: sudo [-u user] [-g group] [-H] [-n] command [arguments]. Other sudo options are unavailable here.';

// Split requester arguments into the few sudo options that are safe to pass on
// and the command. Options that redirect the password or prompt are refused.
export function parseSudoArgs(args) {
  if (!Array.isArray(args) || !args.length || args.length > 256) return null;
  if (args.some(arg => typeof arg !== 'string' || arg.includes('\0')) || JSON.stringify(args).length > 8000) return null;
  const options = [];
  let index = 0;
  for (; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--') { index++; break; }
    if (!arg.startsWith('-')) break;
    const equals = arg.startsWith('--') ? arg.indexOf('=') : -1;
    const name = equals > 0 ? arg.slice(0, equals) : arg;
    if (FLAG_OPTIONS.has(arg)) options.push(FLAG_OPTIONS.get(arg));
    else if (VALUE_OPTIONS.has(name)) {
      const value = equals > 0 ? arg.slice(equals + 1) : args[++index];
      if (!value || value.startsWith('-')) return null;
      options.push(VALUE_OPTIONS.get(name), value);
    } else return null;
  }
  const command = args.slice(index);
  return command.length ? {options, command} : null;
}

export async function createSudoSession({signal, timeoutMs = 120000, settleMs = 5000, sudoPath = '/usr/bin/sudo'} = {}) {
  const dir = fs.mkdtempSync(path.join(paths.tmp, 'sudo-'));
  fs.chmodSync(dir, 0o700);
  const socketPath = path.join(dir, 'ask.sock');
  const runner = path.join(paths.root, 'sudo-run.mjs');
  const ticket = randomBytes(32).toString('hex');
  const pending = new Map();
  const runs = new Set();
  const sockets = new Set();
  const approvalWaiters = new Set();
  const runWaiters = new Set();
  const notify = () => {
    if (!pending.size) { for (const resolve of approvalWaiters) resolve(); approvalWaiters.clear(); }
    if (!runs.size) { for (const resolve of runWaiters) resolve(); runWaiters.clear(); }
  };
  let closed = false;
  // Hand the phone's answer (or a cancellation) to the runner that asked.
  const settle = (id, message) => {
    const entry = pending.get(id);
    if (!entry) return false;
    pending.delete(id);
    clearTimeout(entry.timer);
    entry.run.answer(message);
    notify();
    return true;
  };

  function start(socket, {options, command}, cwd) {
    // Built here from the arguments that are executed, never taken from the requester.
    const display = 'sudo ' + [...options, ...command].map(arg => JSON.stringify(arg)).join(' ');
    const child = spawn(process.execPath, [runner, sudoPath, cwd, ...options, '--', ...command], {stdio:['pipe', 'pipe', 'pipe', 'pipe']});
    const send = value => { if (!socket.destroyed) socket.write(JSON.stringify(value) + '\n'); };
    let id = null, answered = false;
    const run = {
      answer(message) {
        if (answered) return;
        answered = true;
        child.stdin.end(JSON.stringify(message) + '\n');
      },
      stop() { run.answer({cancelled:true}); child.kill('SIGTERM'); },
    };
    runs.add(run);
    child.stdin.on('error', () => {});
    child.on('error', () => {});
    child.stdout.on('data', chunk => send({out:chunk.toString('base64')}));
    child.stderr.on('data', chunk => send({err:chunk.toString('base64')}));
    // The runner asks at most once, and only when sudo really wants a password.
    readline.createInterface({input:child.stdio[3]}).once('line', line => {
      try {
        const key = createPublicKey(JSON.parse(line).publicKey);
        if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength !== 3072 || closed || answered) throw new Error();
        id = randomBytes(24).toString('hex');
        const expiresAt = Date.now() + timeoutMs;
        const timer = setTimeout(() => settle(id, {cancelled:true}), timeoutMs);
        pending.set(id, {id, command:display, cwd, prompt:'Computer password',
          publicKey:key.export({type:'spki', format:'pem'}).toString(), expiresAt, timer, run});
      } catch { run.stop(); }
    });
    child.on('close', code => {
      runs.delete(run);
      if (id && pending.has(id)) { clearTimeout(pending.get(id).timer); pending.delete(id); }
      notify();
      send({exit:code ?? 1});
      socket.end();
    });
    // The requester went away: Stop, a turn timeout or a killed tool call.
    socket.on('close', () => run.stop());
  }

  const server = net.createServer(socket => {
    sockets.add(socket);
    let buffer = '', received = false;
    socket.setTimeout(5000, () => { if (!received) socket.destroy(); });
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    socket.on('data', data => {
      // One request per connection; nothing later from the requester is read.
      if (received) return;
      buffer += data.toString();
      if (buffer.length > 20000) { socket.destroy(); return; }
      if (!buffer.includes('\n')) return;
      received = true;
      socket.setTimeout(0);
      const refuse = error => socket.end(JSON.stringify({error}) + '\n');
      try {
        const input = JSON.parse(buffer);
        buffer = '';
        const provided = Buffer.from(String(input.ticket || ''));
        const expected = Buffer.from(ticket);
        if (provided.length !== expected.length || !timingSafeEqual(provided, expected) || closed) return refuse('Phone sudo authorization is unavailable.');
        if (runs.size >= MAX_RUNS) return refuse('Too many sudo commands are waiting. Retry after one finishes.');
        const parsed = parseSudoArgs(input.args);
        if (!parsed) return refuse(SUDO_USAGE);
        if (typeof input.cwd !== 'string' || input.cwd.length > 4096 || !path.isAbsolute(input.cwd) || !fs.statSync(input.cwd).isDirectory()) throw new Error();
        start(socket, parsed, input.cwd);
      } catch { refuse('Invalid sudo request.'); }
    });
  });
  const close = () => {
    if (closed) return;
    closed = true;
    signal?.removeEventListener('abort', close);
    for (const id of [...pending.keys()]) settle(id, {cancelled:true});
    for (const run of [...runs]) run.stop();
    for (const socket of sockets) socket.destroy();
    server.close();
    fs.rmSync(dir, {recursive:true, force:true});
  };
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    fs.chmodSync(socketPath, 0o600);
    const wrapper = path.join(dir, 'sudo');
    const helper = pathToFileURL(path.join(paths.root, 'sudo-command.mjs')).href;
    // The per-turn capability is kept in a private file, never in the model prompt.
    // It only lets a requester ask; it carries no key and chooses no display text.
    fs.writeFileSync(wrapper, `#!${process.execPath}\nimport { runSudo } from ${JSON.stringify(helper)};\nawait runSudo(${JSON.stringify({socketPath, ticket})}, process.argv.slice(2));\n`, {mode:0o700});
    signal?.addEventListener('abort', close, {once:true});
    if (signal?.aborted) close();
    return {
      env:{PATH:dir + path.delimiter + process.env.PATH},
      instruction:`For commands requiring sudo, use ${JSON.stringify(wrapper)} followed by the command and arguments. Before the command it accepts only -u, -g, -H and -n. It opens a separate phone authorization dialog showing that exact command. Standard input is not forwarded: put data in a file instead of using a pipe or heredoc. Run it in the foreground and allow at least 120 seconds for the user to respond; do not give it a short tool timeout, detach it, or finish your turn while it is waiting. Never ask for a password in chat, read password files, or pass a password through a tool prompt. Do not use sudo -S or echo passwords. If authorization is cancelled, stop that operation.`,
      // Resolves once no approval is outstanding. A command that was just
      // approved gets a short window to finish and flush its output.
      async waitForPending() {
        for (;;) {
          if (pending.size) { await new Promise(resolve => approvalWaiters.add(resolve)); continue; }
          if (!runs.size) return;
          let timer;
          await Promise.race([new Promise(resolve => runWaiters.add(resolve)),
            new Promise(resolve => { timer = setTimeout(resolve, settleMs); })]);
          clearTimeout(timer);
          if (!pending.size) return;
        }
      },
      list:() => [...pending.values()].map(({id, command, cwd, prompt, publicKey, expiresAt}) => ({id, command, cwd, prompt, publicKey, expiresAt})),
      reply(input) {
        if (!input || typeof input.id !== 'string' || Object.keys(input).some(key => !['id','ciphertext','cancel'].includes(key))) return false;
        if (input.cancel === true) return settle(input.id, {cancelled:true});
        // RSA-3072 always yields exactly 384 bytes. No plaintext is accepted here.
        if (typeof input.ciphertext !== 'string' || !/^[A-Za-z0-9+/]{512}$/.test(input.ciphertext)) return false;
        return settle(input.id, {ciphertext:input.ciphertext});
      },
      close,
    };
  } catch (error) { close(); throw error; }
}
