// Claude Code status line: model · context bar · cost · duration · lines +/- · git · effort.
// stdin = session JSON (https://code.claude.com/docs/en/statusline). Keep it fast: runs every update.
const { spawnSync } = require('child_process');

const C = { dim: '\x1b[2m', red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m', cyn: '\x1b[36m', mag: '\x1b[35m', off: '\x1b[0m' };

function gitInfo(cwd) {
  const run = (...a) => spawnSync('git', a, { cwd, encoding: 'utf8', timeout: 800 });
  const b = run('rev-parse', '--abbrev-ref', 'HEAD');
  if (b.status !== 0) return '';
  const dirty = (run('status', '--porcelain').stdout || '').trim() ? '*' : '';
  return b.stdout.trim() + dirty;
}

function bar(pct, width = 10) {
  const full = Math.round((Math.min(100, Math.max(0, pct)) / 100) * width);
  return '█'.repeat(full) + '░'.repeat(width - full);
}

function duration(ms) {
  const m = Math.floor((ms || 0) / 60000);
  return m >= 60 ? `${Math.floor(m / 60)}h${String(m % 60).padStart(2, '0')}m` : `${m}m`;
}

// ---- the one function to customise: d = parsed stdin JSON, git = "branch*" or "" -------------
function format(d, git) {
  const ctx = d.context_window || {};
  const pct = ctx.used_percentage ?? 0;
  const col = pct >= 80 ? C.red : pct >= 50 ? C.yel : C.grn;
  const cost = d.cost || {};
  return [
    `${C.cyn}${d.model?.display_name || '?'}${C.off}`,
    `${col}ctx ${bar(pct)} ${Math.round(pct)}%${C.off}`,
    `$${(cost.total_cost_usd ?? 0).toFixed(2)}`,
    duration(cost.total_duration_ms),
    `${C.grn}+${cost.total_lines_added ?? 0}${C.off}/${C.red}-${cost.total_lines_removed ?? 0}${C.off}`,
    git && `${C.mag}${git}${C.off}`,
    d.effort?.level && `${C.dim}${d.effort.level}${C.off}`,
  ].filter(Boolean).join(`${C.dim} │ ${C.off}`);
}
// ------------------------------------------------------------------------------------------------

let raw = '';
process.stdin.on('data', (x) => (raw += x)).on('end', () => {
  let d = {};
  try { d = JSON.parse(raw); } catch {}
  const cwd = d.workspace?.current_dir || d.cwd || process.cwd();
  process.stdout.write(format(d, gitInfo(cwd)) + '\n');
});
