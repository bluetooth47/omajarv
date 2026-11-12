import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Event shapes follow `claude -p --output-format stream-json --verbose
// --include-partial-messages`: incremental text deltas, then the complete
// assistant message for the same content block.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'jarvis-claude-'));
const oldHome = process.env.HOME;
const oldPath = process.env.PATH;
process.env.HOME = home;
process.env.PATH = path.join(home, 'bin') + ':' + oldPath;
process.env.JARVIS_AGENT_TEST_HOME = home;
try {
  fs.mkdirSync(path.join(home, 'bin'));
  fs.writeFileSync(path.join(home, 'bin', 'claude'), `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const send = value => console.log(JSON.stringify(value));
const delta = (text, extra = {}) => send({type:'stream_event', session_id:'claude-session', parent_tool_use_id:null, ...extra,
  event:{type:'content_block_delta', index:0, delta:{type:'text_delta', text}}});
const assistant = (id, content, extra = {}) => send({type:'assistant', session_id:'claude-session', parent_tool_use_id:null, ...extra, message:{id, content}});
let prompt = '';
process.stdin.on('data', data => prompt += data);
process.stdin.on('end', () => {
  fs.writeFileSync(path.join(process.env.JARVIS_AGENT_TEST_HOME, 'invocation'), JSON.stringify({args, prompt, cwd:process.cwd()}));
  send({type:'system', subtype:'init', session_id:'claude-session'});
  if (prompt.includes('slow request')) { setTimeout(() => {}, 30000); return; }
  if (prompt.includes('whole messages only')) {
    assistant('msg_1', [{type:'text', text:'No partial messages here.'}]);
  } else {
    send({type:'stream_event', session_id:'claude-session', parent_tool_use_id:null, event:{type:'message_start'}});
    // A delta that repeats or extends the previous one is still new text.
    for (const text of ['Port ', '1', '10', ' is', ' ha', ' ha', ' open.']) delta(text);
    assistant('msg_1', [{type:'text', text:'Port 110 is ha ha open.'}]);
    assistant('msg_1', [{type:'tool_use', id:'tool_1', name:'Task', input:{}}]);
    delta('private subagent text', {parent_tool_use_id:'tool_1'});
    assistant('msg_sub', [{type:'text', text:'private subagent text'}], {parent_tool_use_id:'tool_1'});
    for (const text of [' Done', '.']) delta(text);
    assistant('msg_2', [{type:'text', text:' Done.'}]);
  }
  send({type:'result', subtype:'success', session_id:'claude-session', result:'ignored'});
});
`, {mode:0o755});
  const {agentStatus, agentTimeoutMs, runAgent} = await import('../server/lib/agent.mjs');
  const config = {agent:'claude', workDir:home, systemPrompt:'private system instructions'};
  assert.deepEqual(agentStatus(config), {id:'claude', label:'Claude Code', ready:true});
  for (const full of [false, true]) {
    const chunks = [];
    const text = 'private request "quotes" $(touch NEVER)';
    const result = await runAgent({config:{...config, agentFullAccess:full}, text, onText:chunk => chunks.push(chunk)});
    assert.equal(result.text, 'Port 110 is ha ha open. Done.');
    assert.equal(chunks.join(''), result.text);
    assert.equal(result.session, 'claude-session');
    const invocation = JSON.parse(fs.readFileSync(path.join(home, 'invocation')));
    assert.equal(invocation.prompt, config.systemPrompt + '\n\nSpoken user request: ' + text);
    assert.ok(!JSON.stringify(invocation.args).includes('private'));
    assert.equal(invocation.cwd, home);
    // Claude always runs in reviewed auto mode; full access never selects a bypass.
    assert.equal(invocation.args[invocation.args.indexOf('--permission-mode') + 1], 'auto');
    assert.ok(!invocation.args.some(arg => /bypass|dangerously/i.test(arg)));
  }
  const resumed = await runAgent({config, text:'whole messages only', sessionId:'claude-session'});
  assert.equal(resumed.text, 'No partial messages here.');
  const invocation = JSON.parse(fs.readFileSync(path.join(home, 'invocation')));
  assert.equal(invocation.args[invocation.args.indexOf('--resume') + 1], 'claude-session');

  assert.equal(agentTimeoutMs({}), 240000);
  assert.equal(agentTimeoutMs({agentTimeoutSec:900}), 900000);
  for (const bad of [0, 5, -1, 99999, 'soon', null, Infinity]) assert.equal(agentTimeoutMs({agentTimeoutSec:bad}), 240000);
  const started = Date.now();
  await assert.rejects(runAgent({config:{...config, agentTimeoutSec:30}, text:'slow request', signal:AbortSignal.timeout(200)}), /Cancelled/);
  assert.ok(Date.now() - started < 5000);
  console.log('PASS: Claude deltas forwarded exactly once, whole-message fallback, subagent text excluded, reviewed auto mode, resume and turn timeout.');
} finally {
  process.env.HOME = oldHome;
  process.env.PATH = oldPath;
  delete process.env.JARVIS_AGENT_TEST_HOME;
  fs.rmSync(home, {recursive:true, force:true});
}
