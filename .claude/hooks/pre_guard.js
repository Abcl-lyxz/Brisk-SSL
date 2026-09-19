// PreToolUse: refuse hand edits to vendored generated code and a few irreversible git/shell commands.
const path = require('path');

let raw = '';
process.stdin.on('data', (d) => (raw += d)).on('end', () => {
  let input;
  try { input = JSON.parse(raw); } catch { return; }
  const ti = input.tool_input || {};
  const root = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  let reason = '';

  if (ti.file_path) {
    const rel = path.relative(root, ti.file_path).replace(/\\/g, '/');
    if (rel.startsWith('vendor/') && !rel.endsWith('.md')) {
      reason = 'vendor/ holds generated upstream code (fiat-crypto). Never hand-edit it: re-vendor ' +
        'from the pinned commit and record it in vendor/VENDORED.md.';
    }
  } else if (typeof ti.command === 'string') {
    const c = ti.command;
    const rules = [
      [/\bgit\s+push\b[^\n;&|]*\s(--force\b|--force-with-lease\b|-f\b)/, 'force-push rewrites shared history'],
      [/\bgit\s+reset\s+--hard\b/, 'git reset --hard discards work; use git stash or a new commit'],
      [/\bgit\s+clean\s+-[a-z]*f/, 'git clean -f deletes untracked files irreversibly'],
      [/\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(\/|~|\.|\.\.|\*|\.git)(\s|$)/, 'recursive delete of a root-level path'],
    ];
    for (const [re, why] of rules) {
      if (re.test(c)) { reason = `Blocked: ${why}. Ask the user to run it themselves if really intended.`; break; }
    }
  }
  if (reason) {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
    }));
  }
});
