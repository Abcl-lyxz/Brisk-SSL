// Stop: if C sources changed since the last green run, run the fast native suite
// (cmake --workflow --preset dev). A failure blocks "done" and hands Claude the failing lines.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

let raw = '';
process.stdin.on('data', (d) => (raw += d)).on('end', () => {
  let input = {};
  try { input = JSON.parse(raw); } catch {}
  if (input.stop_hook_active) return; // already continuing because of us: never loop

  const root = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  if (!fs.existsSync(path.join(root, 'CMakeLists.txt'))) return;

  // fingerprint = path + size + mtime of every build input
  const h = crypto.createHash('sha256');
  const walk = (dir) => {
    let ents = [];
    try { ents = fs.readdirSync(path.join(root, dir), { withFileTypes: true }); } catch { return; }
    for (const e of ents.sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(rel);
      else if (/\.(c|h|inc|txt|json|cmake)$/.test(e.name)) {
        const st = fs.statSync(path.join(root, rel));
        h.update(`${rel}:${st.size}:${st.mtimeMs}\n`);
      }
    }
  };
  ['include', 'src', 'tests', 'cmake'].forEach(walk);
  ['CMakeLists.txt', 'CMakePresets.json'].forEach((f) => {
    try { const st = fs.statSync(path.join(root, f)); h.update(`${f}:${st.size}:${st.mtimeMs}\n`); } catch {}
  });
  const fp = h.digest('hex');
  const stamp = path.join(root, 'build', '.last_green');
  let last = '';
  try { last = fs.readFileSync(stamp, 'utf8').trim(); } catch {}
  if (fp === last) return;

  const r = spawnSync('cmake', ['--workflow', '--preset', 'dev'], { cwd: root, encoding: 'utf8', timeout: 540000 });
  if (r.error) return; // cmake not available: don't block
  if (r.status === 0) {
    fs.mkdirSync(path.dirname(stamp), { recursive: true });
    fs.writeFileSync(stamp, fp + '\n');
    return;
  }
  const log = `${r.stdout || ''}\n${r.stderr || ''}`.split('\n');
  const fails = log.filter((l) => /FAIL|error|Error|failed/.test(l)).slice(0, 30);
  process.stdout.write(JSON.stringify({
    decision: 'block',
    reason: 'Native tests failed (cmake --workflow --preset dev). Fix the root cause before finishing:\n' +
      (fails.length ? fails : log.slice(-40)).join('\n'),
  }));
});
