import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { publicEncrypt, generateKeyPairSync, constants } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'jarvis-sudo-'));
process.env.HOME = home;
process.env.FAKE_SUDO_RECORD = home;
process.env.FAKE_SUDO_PASSWORD = 'fixture-password-ä-$`';
const sudoPath = path.resolve(import.meta.dirname, 'fixtures/fake-sudo.mjs');
const password = process.env.FAKE_SUDO_PASSWORD;
let session;
const children = new Set();
try {
  const {ensureDirs} = await import('../server/lib/config.mjs');
  const {createSudoSession, parseSudoArgs} = await import('../server/lib/sudo.mjs');
  ensureDirs();

  // Only options that cannot redirect the password or prompt are passed on.
  assert.deepEqual(parseSudoArgs(['id', '-S']), {options:[], command:['id', '-S']});
  assert.deepEqual(parseSudoArgs(['--user=postgres', '-H', '--', '-odd', 'x']), {options:['-u', 'postgres', '-H'], command:['-odd', 'x']});
  assert.deepEqual(parseSudoArgs(['-g', 'wheel', '--non-interactive', 'id']), {options:['-g', 'wheel', '-n'], command:['id']});
  for (const bad of [[], ['-S', 'id'], ['--stdin', 'id'], ['-A', 'id'], ['-E', 'id'], ['-p', 'x', 'id'], ['-b', 'id'], ['-i'], ['-u'], ['-u', '-n', 'id'], ['--'], ['-nH', 'id'], [1], 'id', ['a\0b']]) {
    assert.equal(parseSudoArgs(bad), null, JSON.stringify(bad));
  }

  const controller = new AbortController();
  session = await createSudoSession({signal:controller.signal, sudoPath});
  const wrapper = session.env.PATH.split(path.delimiter)[0] + '/sudo';
  assert.equal(fs.statSync(path.dirname(wrapper)).mode & 0o777, 0o700);
  assert.equal(fs.statSync(wrapper).mode & 0o777, 0o700);
  const capabilityOf = file => JSON.parse(fs.readFileSync(file, 'utf8').match(/await runSudo\((\{.*\}), process/)[1]);
  const capability = capabilityOf(wrapper);
  assert.equal(fs.statSync(capability.socketPath).mode & 0o777, 0o600);
  assert.ok(!session.instruction.includes(capability.ticket));

  const calls = () => {
    try { return fs.readFileSync(path.join(home, 'sudo-calls'), 'utf8').trim().split('\n').map(line => JSON.parse(line)); }
    catch { return []; }
  };
  // Run the wrapper exactly as an agent tool would.
  const ask = (args, {target = wrapper, input} = {}) => {
    const child = spawn(target, args, {cwd:home, stdio:[input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe']});
    children.add(child);
    if (input !== undefined) child.stdin.end(input);
    let output = '', errors = '';
    child.stdout.on('data', data => output += data);
    child.stderr.on('data', data => errors += data);
    const exited = once(child, 'close').then(([code]) => { children.delete(child); return {code, output, errors}; });
    return {child, exited};
  };
  const waitRequest = async (from = session) => {
    for (let i = 0; i < 500; i++) {
      if (from.list().length) return from.list()[0];
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error('No sudo request registered');
  };
  const encrypt = (request, text) => publicEncrypt({key:request.publicKey, padding:constants.RSA_PKCS1_OAEP_PADDING, oaepHash:'sha256'}, Buffer.from(text)).toString('base64');

  const first = ask(['id', '-a']);
  const request = await waitRequest();
  let approvalFinished = false;
  const waiting = session.waitForPending().then(() => { approvalFinished = true; });
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(approvalFinished, false, 'agent completion must not dismiss pending authorization');
  assert.equal(request.command, 'sudo "id" "-a"');
  assert.equal(request.cwd, home);
  assert.ok(!JSON.stringify(request).includes(capability.ticket));
  assert.equal(session.reply({id:request.id, password:'must not accept plaintext'}), false);
  assert.equal(session.reply({id:request.id, ciphertext:'invalid'}), false);
  const ciphertext = encrypt(request, password);
  assert.ok(!ciphertext.includes(password));
  assert.equal(session.reply({id:request.id, ciphertext}), true);
  await waiting;
  assert.equal(approvalFinished, true);
  assert.equal(session.reply({id:request.id, ciphertext}), false, 'reply must be one-use');
  const result = await first.exited;
  assert.equal(result.code, 0, result.errors);
  // The requester gets the command's output and nothing else.
  assert.equal(result.output, 'privileged output\n');
  assert.equal(result.errors, 'privileged warning\n');
  assert.deepEqual(session.list(), []);
  // The bridge, not the requester, started sudo with exactly the displayed command.
  assert.deepEqual(calls(), [{args:['-S', '-k', '--', 'id', '-a'], cwd:home, password}]);

  // A requester holding the capability cannot choose the displayed command or the key.
  const attacker = generateKeyPairSync('rsa', {modulusLength:3072}).publicKey.export({type:'spki', format:'pem'}).toString();
  const forged = net.connect(capability.socketPath);
  forged.on('error', () => {});
  forged.write(JSON.stringify({ticket:capability.ticket, args:['real', 'command'], cwd:home,
    command:'sudo "harmless"', publicKey:attacker, prompt:'Phone PIN'}) + '\n');
  const shown = await waitRequest();
  assert.equal(shown.command, 'sudo "real" "command"');
  assert.equal(shown.prompt, 'Computer password');
  assert.notEqual(shown.publicKey, attacker);
  forged.destroy();
  for (let i = 0; i < 200 && session.list().length; i++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.deepEqual(session.list(), [], 'a requester that disconnects withdraws its request');

  // Refused usage never reaches sudo or the phone.
  for (const args of [['-S', 'id'], ['-A', 'id'], ['-E', 'id'], []]) {
    const refused = await ask(args).exited;
    assert.equal(refused.code, 1);
    assert.match(refused.errors, /Use: sudo/);
  }
  const piped = await ask(['tee', '/etc/fixture'], {input:'file contents'}).exited;
  assert.equal(piped.code, 2);
  assert.match(piped.errors, /does not forward standard input/);
  assert.deepEqual(session.list(), []);
  assert.equal(calls().length, 1);

  // Passwordless commands run without a dialog; exit status and options pass through.
  const passwordless = await ask(['-u', 'postgres', 'nopasswd']).exited;
  assert.equal(passwordless.code, 0, passwordless.errors);
  assert.equal(passwordless.output, 'privileged output\n');
  assert.deepEqual(calls().at(-1), {args:['-S', '-k', '-u', 'postgres', '--', 'nopasswd'], cwd:home, password:null});
  assert.equal((await ask(['-n', 'reads-input']).exited).output, 'input:');
  assert.match((await ask(['-n', 'id']).exited).errors, /a password is required/);
  const failing = ask(['fail']);
  assert.equal(session.reply({id:(await waitRequest()).id, ciphertext:encrypt(await waitRequest(), password)}), true);
  assert.equal((await failing.exited).code, 7);

  // A rejected password is not retried, re-requested or echoed.
  const wrong = ask(['id']);
  const wrongRequest = await waitRequest();
  assert.equal(session.reply({id:wrongRequest.id, ciphertext:encrypt(wrongRequest, 'not-the-password')}), true);
  const wrongResult = await wrong.exited;
  assert.equal(wrongResult.code, 1);
  assert.match(wrongResult.errors, /Sorry, try again/);
  assert.ok(!/jarvis-sudo-|not-the-password/.test(wrongResult.errors + wrongResult.output));
  assert.deepEqual(session.list(), []);

  const before = calls().length;
  const cancelled = ask(['id']);
  assert.equal(session.reply({id:(await waitRequest()).id, cancel:true}), true);
  const cancelResult = await cancelled.exited;
  assert.equal(cancelResult.code, 1);
  assert.equal(cancelResult.output, '');
  assert.match(cancelResult.errors, /cancelled, expired, or unavailable/);
  const aborted = ask(['id']);
  await waitRequest();
  controller.abort();
  assert.equal((await aborted.exited).output, '');
  assert.equal(fs.existsSync(wrapper), false);
  assert.deepEqual(session.list(), []);
  assert.equal(calls().length, before, 'cancelled and aborted requests must not deliver a password');

  // Requests not holding the per-turn capability cannot register a challenge.
  session = await createSudoSession({timeoutMs:1500, sudoPath});
  const nextWrapper = session.env.PATH.split(path.delimiter)[0] + '/sudo';
  const socket = net.connect(capabilityOf(nextWrapper).socketPath);
  socket.on('error', () => {});
  socket.end(JSON.stringify({ticket:'wrong', args:['id'], cwd:home}) + '\n');
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.deepEqual(session.list(), []);
  const expired = ask(['id'], {target:nextWrapper});
  await waitRequest();
  const expiredResult = await expired.exited;
  assert.equal(expiredResult.code, 1);
  assert.equal(expiredResult.output, '');
  assert.deepEqual(session.list(), []);
  console.log('PASS: bridge-run sudo with honest display and bridge-owned key, encrypted delivery, private permissions, one-use replies, plaintext and option rejection, piped input refusal, passwordless path, cancellation, abort, expiry and capability checks; no real sudo invoked.');
} finally {
  session?.close();
  for (const child of children) child.kill('SIGTERM');
  fs.rmSync(home, {recursive:true, force:true});
}
