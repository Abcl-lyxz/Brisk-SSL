export const meta = {
  name: 'implement-module',
  description: 'Brisk-SSL: spec + official vectors -> tests first -> implementation -> 3 reviewers -> refute -> fix loop, green on every arch',
  whenToUse: 'Implementing a whole ROADMAP item such as "ChaCha20-Poly1305 (M1b)" or "X.509 DER parser (M2)". Pass the task text as args.',
  phases: [
    { title: 'Spec', detail: 'requirements, sections, vector sources (read-only)' },
    { title: 'Build', detail: 'vectors -> tests -> code -> all archs green' },
    { title: 'Review', detail: 'crypto / portability / RFC reviewers' },
    { title: 'Verify', detail: 'skeptics try to refute each finding' },
    { title: 'Fix', detail: 'fix confirmed findings, re-run every arch' },
  ],
}

const task = typeof args === 'string' ? args : (args && args.task) || ''
if (!task) throw new Error('usage: /implement-module <task>, e.g. "ChaCha20-Poly1305 (M1b)"')

const SPEC = {
  type: 'object',
  properties: {
    module: { type: 'string', description: 'e.g. crypto/aead' },
    is_crypto: { type: 'boolean' },
    requirements: { type: 'array', items: { type: 'string' }, description: 'each with spec section' },
    vector_sources: { type: 'array', items: { type: 'string' }, description: 'official URLs + what they cover' },
    api: { type: 'string', description: 'proposed internal/public function signatures' },
    tests: { type: 'array', items: { type: 'string' } },
    risks: { type: 'array', items: { type: 'string' } },
  },
  required: ['module', 'is_crypto', 'requirements', 'vector_sources', 'api', 'tests', 'risks'],
}
const BUILD = {
  type: 'object',
  properties: {
    files_changed: { type: 'array', items: { type: 'string' } },
    all_archs_green: { type: 'boolean' },
    test_summary: { type: 'string' },
    size_report: { type: 'string' },
  },
  required: ['files_changed', 'all_archs_green', 'test_summary', 'size_report'],
}
const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' }, line: { type: 'integer' },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
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

phase('Spec')
const spec = await agent(
  `Brisk-SSL task: "${task}". READ-ONLY research. Read CLAUDE.md, docs/ARCHITECTURE.md, docs/ROADMAP.md, ` +
  `.claude/rules/*.md and the existing code this touches. Use the rfc MCP tools (rfc_get/rfc_search) for exact ` +
  `spec text. Produce the implementation spec: module path, every client-relevant requirement with its section, ` +
  `official test-vector sources (NIST/RFC appendix/Wycheproof incl. invalid cases), function signatures following ` +
  `the brisk__/brisk_ conventions, the test list (unaligned buffers, split input, invalid inputs), and risks ` +
  `(constant-time, 32-bit, big-endian, size).`,
  { label: 'spec', phase: 'Spec', schema: SPEC })

phase('Build')
let build = await agent(
  `Implement Brisk-SSL task "${task}" per this spec:\n${JSON.stringify(spec, null, 1)}\n\n` +
  `Follow CLAUDE.md and .claude/rules. Order: (1) add vectors to tools/kat.py with Python cross-checks and run it, ` +
  `(2) write tests/test_<module>.c and register the suite, (3) implement, (4) \`python tools/dev.py test\` then ` +
  `\`python tools/dev.py test --arch all\` until every preset passes, (5) \`python tools/dev.py size --arch all --md\`. ` +
  `Do not commit. Report honestly whether all archs are green.`,
  { label: 'build', phase: 'Build', schema: BUILD })

const reviewers = [
  ...(spec.is_crypto ? ['crypto-reviewer'] : []),
  'portability-reviewer',
  'rfc-auditor',
]
const history = []
for (let round = 1; round <= 3; round++) {
  const found = (await parallel(reviewers.map(r => () =>
    agent(`Review the uncommitted Brisk-SSL changes for task "${task}" (git diff + new files: ${build.files_changed.join(', ')}). ` +
      `Report only real defects.`, { label: `review:${r}:r${round}`, phase: 'Review', agentType: r, schema: FINDINGS })
      .then(res => (res ? res.findings.map(f => ({ ...f, by: r })) : []))))).flat()
  const judged = await parallel(found.map(f => () =>
    agent(`A reviewer claims this defect in the uncommitted Brisk-SSL changes. Read the code (and spec) and try hard ` +
      `to REFUTE it. refuted=true if wrong, speculative, already handled or not a real defect.\n${JSON.stringify(f)}`,
      { label: `verify:${f.file}:${f.line}`, phase: 'Verify', schema: VERDICT })
      .then(v => ({ ...f, verdict: v }))))
  const confirmed = judged.filter(f => f && f.verdict && !f.verdict.refuted)
  history.push({ round, found: found.length, confirmed: confirmed.length })
  log(`round ${round}: ${found.length} findings, ${confirmed.length} confirmed`)
  if (!confirmed.length) break
  build = await agent(
    `Fix these confirmed findings in the uncommitted Brisk-SSL work for "${task}" at the root cause, add a regression ` +
    `test for each where possible, then re-run \`python tools/dev.py test --arch all\` until green:\n` +
    JSON.stringify(confirmed.map(({ verdict, ...f }) => f), null, 1),
    { label: `fix:r${round}`, phase: 'Fix', schema: BUILD })
}
return { task, spec: { module: spec.module, requirements: spec.requirements.length }, build, review_rounds: history }
