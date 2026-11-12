// Called by the private per-turn sudo wrapper. It only asks the bridge to run a
// command and relays the output: no password or key ever enters this process.
import fs from 'node:fs';
import net from 'node:net';

const PIPED = 'This sudo helper does not forward standard input. Write the data to a file and pass the file to the command instead.';

// A pipe or heredoc would be silently dropped, leaving commands such as tee to
// write empty files as root. Refuse when input is evidently being supplied.
function pipedInput() {
  let stat;
  try { stat = fs.fstatSync(0); } catch { return Promise.resolve(false); }
  if (stat.isFile()) return Promise.resolve(stat.size > 0);
  if (!stat.isFIFO() && !stat.isSocket()) return Promise.resolve(false);
  return new Promise(resolve => {
    const done = value => { clearTimeout(timer); process.stdin.destroy(); resolve(value); };
    const timer = setTimeout(() => done(false), 150);
    process.stdin.once('data', () => done(true));
    process.stdin.once('end', () => done(false));
    process.stdin.once('error', () => done(false));
  });
}

export async function runSudo({socketPath, ticket}, args, {hasInput = pipedInput, stdout = process.stdout, stderr = process.stderr} = {}) {
  if (await hasInput()) {
    stderr.write(PIPED + '\n');
    process.exitCode = 2;
    return;
  }
  process.exitCode = await new Promise(resolve => {
    const socket = net.connect(socketPath);
    let buffer = '', status = 1;
    socket.on('error', () => { stderr.write('Phone sudo authorization is unavailable.\n'); resolve(1); });
    socket.on('connect', () => socket.write(JSON.stringify({ticket, args, cwd:process.cwd()}) + '\n'));
    socket.on('data', chunk => {
      buffer += chunk;
      for (let end = buffer.indexOf('\n'); end >= 0; end = buffer.indexOf('\n')) {
        let message;
        try { message = JSON.parse(buffer.slice(0, end)); } catch { message = {}; }
        buffer = buffer.slice(end + 1);
        if (typeof message.out === 'string') stdout.write(Buffer.from(message.out, 'base64'));
        else if (typeof message.err === 'string') stderr.write(Buffer.from(message.err, 'base64'));
        else if (typeof message.error === 'string') stderr.write(message.error + '\n');
        else if (Number.isInteger(message.exit)) status = message.exit;
      }
    });
    socket.on('close', () => resolve(status));
  });
}
