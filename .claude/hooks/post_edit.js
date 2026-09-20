// PostToolUse (Edit|Write|MultiEdit): clang-format the edited C file (if clang-format is installed),
// then `gcc -fsyntax-only` it with the project's warning set. Problems are fed straight back to Claude.
const path = require('path');
const { spawnSync } = require('child_process');

let raw = '';
process.stdin.on('data', (d) => (raw += d)).on('end', () => {
  let file;
  try { file = JSON.parse(raw).tool_input.file_path; } catch { return; }
  if (!file || !/\.(c|h)$/.test(file)) return;
  const root = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const rel = path.relative(root, file).replace(/\\/g, '/');
  if (rel.startsWith('..') || rel.startsWith('vendor/') || rel.startsWith('build/')) return;

  const fmt = spawnSync('clang-format', ['-i', file], { cwd: root, encoding: 'utf8', timeout: 20000 });
  const fmtNote = fmt.error ? '' : fmt.status ? `clang-format failed: ${fmt.stderr}` : '';

  // src/os/ uses Linux headers that mingw lacks; the Stop hook / Docker presets cover it.
  if (rel.startsWith('src/os/')) return fmtNote && console.error(fmtNote);
  const args = ['-fsyntax-only', '-std=c99', '-Wall', '-Wextra', '-Wpedantic', '-Wshadow',
    '-Wcast-align', '-Wstrict-prototypes', '-Wundef', '-Wvla', '-Iinclude', '-Isrc', '-Itests', '-Ivendor'];
  if (rel.startsWith('tests/')) args.push('-Wno-overlength-strings');
  const cc = spawnSync('gcc', [...args, file], { cwd: root, encoding: 'utf8', timeout: 30000 });
  if (cc.error) return; // no gcc on PATH: nothing to check with
  const diag = (cc.stderr || '').trim();
  if (cc.status !== 0 || diag || fmtNote) {
    process.stdout.write(JSON.stringify({
      decision: 'block',
      reason: `${rel}: ${fmtNote}\ngcc -fsyntax-only reported:\n${diag.split('\n').slice(0, 40).join('\n')}`,
    }));
  }
});
