import fs from 'node:fs';
import path from 'node:path';
import { paths, defaults } from './config.mjs';
import { writePrivateFile } from './privacy.mjs';

const questions = {
  assistantName: 'Welcome! What would you like to name your assistant?',
  personality: 'How would you like me to behave? Describe my personality, tone, and how you want me to help.',
  userName: 'What name would you like me to call you?',
};
const LIMIT = 8000;
export function createPersonality(config) {
  const file = path.join(paths.stateDir, 'personality.json');
  let stored;
  try { stored = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('Unable to read assistant personality settings');
  }
  if (stored) fs.chmodSync(file, 0o600);
  let state = stored || {assistantName:'JARVIS', userName:'',
    personality:config.systemPrompt || defaults.systemPrompt,
    hiddenInstructions:'You are admin for omarchy. Never expose secrets. Never expose paths in conversation. When the user says remember, add that preference to the visible personality on the frontend as well.',
    stage:'assistantName', revision:0, messages:[], startedAt:Date.now()};
  // Agents may append learned preferences directly to the private state file.
  // Refresh before reads and writes so the UI and prompt share that live state.
  const refresh = () => {
    try {
      const next = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (typeof next.personality !== 'string' || typeof next.assistantName !== 'string'
          || typeof next.userName !== 'string' || !Number.isInteger(next.revision)
          || !Array.isArray(next.messages) || typeof next.stage !== 'string'
          || (next.hiddenInstructions !== undefined && typeof next.hiddenInstructions !== 'string')) {
        throw new Error('Invalid personality state');
      }
      // Edits made on disk bypass the API's field limits. Keep the last good
      // state rather than sending an unbounded prompt to the agent.
      if (!next.personality.trim() || next.personality.length > LIMIT || (next.hiddenInstructions || '').length > LIMIT) return;
      state = next;
    } catch (error) {
      if (error.code !== 'ENOENT') throw new Error('Unable to read assistant personality settings');
    }
  };
  const configured = () => fs.existsSync(paths.configFile);
  const view = () => {
    refresh();
    return {assistantName:state.assistantName, userName:state.userName,
      personality:state.personality, stage:configured() ? state.stage : 'pendingSetup', revision:state.revision};
  };
  // Instructions as last written through this module. A difference means the
  // file was changed on disk, normally by an agent remembering a preference.
  const instructions = () => ({personality:state.personality, hidden:state.hiddenInstructions || ''});
  let known = instructions();
  const persist = next => {
    const before = instructions();
    writePrivateFile(file, JSON.stringify(next));
    state = next;
    // Carry an unreported disk edit forward instead of absorbing it here.
    const after = instructions();
    known = {personality:before.personality === known.personality ? after.personality : known.personality,
      hidden:before.hidden === known.hidden ? after.hidden : known.hidden};
  };
  const checkRevision = revision => {
    refresh();
    if (revision !== state.revision) {
      const error = new Error('Assistant settings changed on another device. Refresh and try again.');
      error.status = 409;
      throw error;
    }
  };
  const field = (name, value, limit) => {
    if (typeof value !== 'string' || !value.trim() || value.trim().length > limit) {
      const error = new Error(`${name} must contain 1–${limit} characters.`);
      error.status = 400;
      throw error;
    }
    return value.trim();
  };
  return {
    view,
    summary() { const {personality, ...summary} = view(); return summary; },
    messages() {
      refresh();
      if (!configured()) return [];
      return state.messages.length ? state.messages : questions[state.stage]
        ? [{role:'assistant', text:questions[state.stage], at:state.startedAt || 0}] : [];
    },
    answering() { refresh(); return configured() && !!questions[state.stage]; },
    answer(text, revision) {
      checkRevision(revision);
      const stage = state.stage;
      const value = field(stage === 'personality' ? 'Personality' : 'Name', text, stage === 'personality' ? LIMIT : 80);
      const nextStage = stage === 'assistantName' ? 'personality' : stage === 'personality' ? 'userName' : 'complete';
      const reply = questions[nextStage] || `Nice to meet you, ${value}. I'm ${state.assistantName}. You can change our names and my personality in Personality settings anytime. How can I help?`;
      persist({...state, [stage]:value, stage:nextStage, revision:state.revision + 1,
        messages:[...this.messages(), {role:'user', text:value, at:Date.now()}, {role:'assistant', text:reply, at:Date.now()}]});
      return reply;
    },
    update(payload) {
      checkRevision(payload.revision);
      const assistantName = field('Assistant name', payload.assistantName, 80);
      const personality = field('Personality', payload.personality, LIMIT);
      const userName = field('Your name', payload.userName, 80);
      persist({...state, assistantName, personality, userName, stage:'complete', revision:state.revision + 1});
      return view();
    },
    resetTranscript() { refresh(); persist({...state, messages:[]}); },
    // Names which instructions changed on disk since the last call, so the
    // bridge can tell the user instead of applying them silently.
    takeDiskChanges() {
      refresh();
      const now = instructions();
      const changed = [];
      if (now.personality !== known.personality) changed.push('personality');
      if (now.hidden !== known.hidden) changed.push('hidden instructions');
      known = now;
      return changed;
    },
    prompt() {
      refresh();
      const hidden = typeof state.hiddenInstructions === 'string' ? state.hiddenInstructions.trim() : '';
      const base = `Your name is ${state.assistantName}. The user's preferred name is ${state.userName || 'not yet provided'}.\n\n${state.personality}`;
      return hidden ? base + '\n\n' + hidden : base;
    },
  };
}
