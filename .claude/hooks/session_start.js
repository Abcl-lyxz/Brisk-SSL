// SessionStart: tell Claude where the project stands so the user can just type "ต่อ" / "continue".
// Injects: current milestone + next unchecked ROADMAP tasks, the last handoff notes, git state.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const read = (p) => { try { return fs.readFileSync(path.join(root, p), 'utf8'); } catch { return ''; } };
const git = (...a) => {
  const r = spawnSync('git', a, { cwd: root, encoding: 'utf8', timeout: 3000 });
  return r.status === 0 ? r.stdout.trim() : '';
};

function nextTasks(roadmap, max = 6) {
  let heading = '', current = '', tasks = [];
  for (const line of roadmap.split(/\r?\n/)) {
    const h = line.match(/^#{2,3}\s+(.*)/);
    if (h) { heading = h[1].trim(); continue; }
    const t = line.match(/^\s*- \[ \]\s+(.*)/);
    if (t && tasks.length < max) {
      if (!current) current = heading;
      tasks.push(`${heading === current ? '' : `[${heading}] `}${t[1].trim()}`);
    }
  }
  return { current, tasks };
}

const { current, tasks } = nextTasks(read('docs/ROADMAP.md'));
const handoff = read('.claude/state/handoff.md').split(/\r?\n/).slice(0, 40).join('\n').trim();
const dirty = git('status', '--porcelain').split('\n').filter(Boolean).length;

const out = [
  '# Brisk-SSL session context (auto-injected by .claude/hooks/session_start.js)',
  `Current milestone: ${current || '(ROADMAP complete or missing)'}`,
  tasks.length ? 'Next unchecked tasks:\n' + tasks.map((t) => `- ${t}`).join('\n') : '',
  `Git: branch ${git('rev-parse', '--abbrev-ref', 'HEAD') || '?'}, ${dirty} uncommitted file(s)`,
  'Recent commits:\n' + (git('log', '--oneline', '-5') || '(none)'),
  handoff ? `Last handoff (.claude/state/handoff.md):\n${handoff}` : '',
  'If the user says "ต่อ", "continue", "next" or gives no specific task: run /next.',
].filter(Boolean).join('\n\n');

process.stdout.write(JSON.stringify({
  hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: out.slice(0, 9500) },
}));
