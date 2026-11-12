#!/usr/bin/env node
// Stand-in for /usr/bin/sudo -S: prompts on stderr only when a password is
// needed, reads one line from stdin, and records what it was given. Fixture
// commands: "nopasswd" never prompts, "fail" exits 7, "reads-input" echoes stdin.
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const command = args.slice(args.indexOf('--') + 1);
const record = extra => fs.appendFileSync(path.join(process.env.FAKE_SUDO_RECORD, 'sudo-calls'),
  JSON.stringify({args, cwd:process.cwd(), ...extra}) + '\n');
const run = () => {
  if (command[0] === 'reads-input') {
    let input = '';
    process.stdin.on('data', data => input += data);
    process.stdin.on('end', () => { process.stdout.write('input:' + input); process.exit(0); });
    return;
  }
  process.stdout.write('privileged output\n');
  process.stderr.write('privileged warning\n');
  process.exit(command[0] === 'fail' ? 7 : 0);
};
if (command[0] === 'nopasswd' || command[0] === 'reads-input') { record({password:null}); run(); }
else if (args.includes('-n')) { process.stderr.write('sudo: a password is required\n'); process.exit(1); }
else {
  let buffer = '', attempts = 0;
  const prompt = () => process.stderr.write(process.env.SUDO_PROMPT);
  process.stdin.on('data', data => {
    buffer += data;
    const end = buffer.indexOf('\n');
    if (end < 0) return;
    const password = buffer.slice(0, end);
    buffer = buffer.slice(end + 1);
    record({password});
    if (password === process.env.FAKE_SUDO_PASSWORD) { process.stdin.removeAllListeners(); run(); }
    else { attempts++; process.stderr.write('Sorry, try again.\n'); prompt(); }
  });
  process.stdin.on('end', () => {
    process.stderr.write(attempts ? 'sudo: 1 incorrect password attempt\n' : 'sudo: no password was provided\n');
    process.exit(1);
  });
  prompt();
}
