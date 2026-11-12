#!/usr/bin/env node
// Started by the bridge to run one sudo command. Only this process holds the
// ephemeral private key and the plaintext password. The requesting agent is not
// its parent and receives nothing but the command's output and exit status.
//
//   node sudo-run.mjs <sudo path> <working directory> [sudo options] -- command...
//
// fd 0 receives the bridge's single answer, fd 3 carries the public key out,
// and fds 1 and 2 are the command's output.
import fs from 'node:fs';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { generateKeyPairSync, privateDecrypt, randomBytes, constants } from 'node:crypto';

const [sudoPath, cwd, ...args] = process.argv.slice(2);
const CANCELLED = 'Phone sudo authorization cancelled, expired, or unavailable.\n';
// sudo prints its prompt only when it needs a password. A random prompt, passed
// in sudo's own environment where other processes cannot read it, tells us when
// to ask the phone and cannot be forged by the command being run.
const marker = Buffer.from(`[jarvis-sudo-${randomBytes(16).toString('hex')}]`);
const nonInteractive = args.slice(0, args.indexOf('--')).includes('-n');

const child = spawn(sudoPath, ['-S', '-k', ...args], {
  cwd, stdio:['pipe', 'inherit', 'pipe'], env:{...process.env, SUDO_PROMPT:marker.toString()},
});
child.stdin.on('error', () => {});
let started = false;
child.once('spawn', () => { started = true; });
// Later errors are failed signals to a root-owned process, not a failed start.
child.on('error', () => { if (!started) { process.stderr.write('Unable to start system sudo.\n'); process.exit(1); } });
// With -n sudo never prompts, so the command can see end-of-input immediately.
// Otherwise input stays open until sudo either asks or exits: closing it early
// would make a late prompt fail, and writing early could hand data to sudo.
if (nonInteractive) child.stdin.end();

let asked = false;
function prompted() {
  // A second prompt means sudo rejected the password. Never ask twice.
  if (asked) { child.stdin.end(); return; }
  asked = true;
  authorize().catch(() => { process.stderr.write(CANCELLED); child.stdin.end(); });
}

async function authorize() {
  const {publicKey, privateKey} = generateKeyPairSync('rsa', {modulusLength:3072});
  fs.writeSync(3, JSON.stringify({publicKey:publicKey.export({type:'spki', format:'pem'}).toString()}) + '\n');
  const answer = await new Promise((resolve, reject) => {
    const lines = readline.createInterface({input:process.stdin});
    lines.once('line', line => { resolve(line); lines.close(); });
    lines.once('close', () => reject(new Error('cancelled')));
  });
  const response = JSON.parse(answer);
  if (typeof response.ciphertext !== 'string') throw new Error('cancelled');
  const password = privateDecrypt({key:privateKey, padding:constants.RSA_PKCS1_OAEP_PADDING, oaepHash:'sha256'}, Buffer.from(response.ciphertext, 'base64'));
  let line;
  try {
    if (!password.length || password.length > 256 || password.includes(10) || password.includes(13) || password.includes(0)) throw new Error('invalid password');
    // sudo reads exactly one line; the command then sees end-of-input.
    line = Buffer.concat([password, Buffer.from('\n')]);
    await new Promise(resolve => child.stdin.end(line, resolve));
  } finally { password.fill(0); line?.fill(0); }
}

// Forward sudo's and the command's stderr, removing the prompt marker.
let held = Buffer.alloc(0);
child.stderr.on('data', chunk => {
  held = Buffer.concat([held, chunk]);
  for (let at = held.indexOf(marker); at >= 0; at = held.indexOf(marker)) {
    process.stderr.write(held.subarray(0, at));
    held = held.subarray(at + marker.length);
    prompted();
  }
  // Keep back only a tail that could still become the marker.
  let keep = Math.min(held.length, marker.length - 1);
  while (keep > 0 && !marker.subarray(0, keep).equals(held.subarray(held.length - keep))) keep--;
  process.stderr.write(held.subarray(0, held.length - keep));
  held = held.subarray(held.length - keep);
});

// The bridge stops a run with SIGTERM. A command already running as root may
// not accept our signal; closing its input and output is the most we can do.
process.on('SIGTERM', () => { child.stdin.end(); child.kill('SIGTERM'); setTimeout(() => process.exit(1), 1000).unref(); });
child.on('close', code => {
  // Never include request bodies, decrypted values, or crypto errors in diagnostics.
  process.stderr.write(held);
  process.exit(code ?? 1);
});
