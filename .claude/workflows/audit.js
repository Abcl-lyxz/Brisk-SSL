export const meta = {
  name: 'audit',
  description: 'Brisk-SSL read-only security audit of a path: 5 lenses find, 3 skeptics vote on each finding, report survivors',
  whenToUse: 'Before a release or after a big change. Pass a path such as "src/tls" (default: src).',
  phases: [
    { title: 'Find', detail: 'memory safety, crypto/CT, protocol, API defaults, portability' },
    { title: 'Verify', detail: '3 independent skeptics per finding, majority must confirm' },
  ],
}

const target = (typeof args === 'string' && args) || (args && args.path) || 'src'
const RO = `Brisk-SSL repo, audit target: ${target}. READ-ONLY: never modify files. Report only real, ` +
  `exploitable or correctness-breaking defects with file:line, a concrete scenario and a fix.`
const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' }, line: { type: 'integer' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
          summary: { type: 'string' }, scenario: { type: 'string' }, fix: { type: 'string' },
        },
        required: ['file', 'line', 'severity', 'summary', 'scenario', 'fix'],
      },
    },
  },
  required: ['findings'],
}
const VERDICT = {
  type: 'object',
  properties: { refuted: { type: 'boolean' }, reasoning: { type: 'string' } },
  required: ['refuted', 'reasoning'],
}
const LENSES = [
  ['memory', 'Memory safety of every parser and buffer: bounds checks before reads, length arithmetic overflow (32-bit size_t), off-by-one, use of uninitialised data, stack usage > 4 KB.'],
  ['crypto', 'Constant-time behaviour on secrets, secret wiping, tag comparison, RNG use, key/nonce reuse, validation of peer public values.', 'crypto-reviewer'],
  ['protocol', 'RFC MUST/MUST NOT compliance, state machine accepting out-of-order or duplicate messages, downgrade, alert handling, limits.', 'rfc-auditor'],
  ['api', 'Insecure or surprising defaults, misuse-prone API (aliasing, ownership, error codes ignored), information leaks through errors/logs.'],
  ['portability', 'Endianness, alignment, integer promotion/UB, 32-bit truncation, libgcc helpers, amalgamation clashes.', 'portability-reviewer'],
]

phase('Find')
const found = (await parallel(LENSES.map(([key, focus, agentType]) => () =>
  agent(`${RO}\nLENS ${key}: ${focus}`, { label: `find:${key}`, phase: 'Find', schema: FINDINGS, ...(agentType ? { agentType } : {}) })
    .then(r => (r ? r.findings.map(f => ({ ...f, lens: key })) : []))))).flat()

const seen = new Set()
const unique = found.filter(f => { const k = `${f.file}:${f.line}`; if (seen.has(k)) return false; seen.add(k); return true })
log(`${found.length} raw findings, ${unique.length} after dedup`)

phase('Verify')
const judged = await parallel(unique.map(f => () =>
  parallel([0, 1, 2].map(i => () =>
    agent(`${RO}\nSkeptic #${i + 1}: try to REFUTE this claimed defect by reading the actual code. refuted=true if it is ` +
      `wrong, speculative, unreachable or already handled.\n${JSON.stringify(f)}`,
      { label: `verify:${f.file}:${f.line}:${i}`, phase: 'Verify', schema: VERDICT })))
    .then(vs => ({ ...f, confirmations: vs.filter(v => v && !v.refuted).length }))))
const confirmed = judged.filter(f => f && f.confirmations >= 2)
  .sort((a, b) => ['critical', 'high', 'medium', 'low'].indexOf(a.severity) - ['critical', 'high', 'medium', 'low'].indexOf(b.severity))
return { target, raw: found.length, unique: unique.length, confirmed }
