#!/usr/bin/env node
/*
 * The browser suites' mutation set, replayed (audits/_MASTER-TEMPLATE.md 4.1c).
 *
 *   node scripts/mutations.mjs            run every mutation
 *   node scripts/mutations.mjs M2 M6      run some
 *
 * Each mutation is a CONCRETE PATCH: a file, an anchor that must occur exactly
 * once, and its replacement. A kill is counted only when all four hold, and the
 * script checks every one rather than trusting a red run:
 *   1. the owning test PASSED unmutated, in this same run;
 *   2. the patch actually CHANGED the file (anchor found exactly once);
 *   3. the served bundle is the MUTATED one (its hash moved), and the build
 *      succeeded — a mutation that does not compile is DOES-NOT-BUILD, never a kill;
 *   4. the owning test then FAILED.
 * After each mutation the file is restored and the bundle hash must return to
 * its starting value, so no mutation leaks into the next.
 *
 * Results are printed by this script as it runs them. They are not written into
 * any file: a stored "killed" line would be a second copy of an answer this
 * script re-establishes every time it runs.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';

const MUTATIONS = [
  { id: 'M1', what: 'muted text contrast degraded', project: 'a11y', grep: 'dark-preference OS$',
    file: 'src/style.css', anchor: '  --text-dim: #a9b4c2;', replace: '  --text-dim: #4a5160;' },
  { id: 'M2', what: 'negative claim weakened: "and verify" dropped', project: 'claims-chromium', grep: 'negative claim',
    file: 'index.html', anchor: 'key. Both still decrypt and verify;', replace: 'key. Both still decrypt;' },
  { id: 'M2b', what: 'negative claim deleted', project: 'claims-chromium', grep: 'negative claim',
    file: 'index.html',
    anchor: '<strong>What MGM does not give you:</strong> confidentiality for two messages that share an ICN under one\n            key. Both still decrypt and verify; MGM has no check that fails here, because nothing it checks is wrong.',
    replace: '' },
  { id: 'M3', what: 'a check inside the negative-claim fixture reports failure', project: 'claims-chromium', grep: 'negative claim',
    file: 'src/mgm/misuse.ts', anchor: 'verified1: mgmDecrypt(cipher, icn, aad, a.ciphertext, a.tag).ok,', replace: 'verified1: false,' },
  { id: 'M4', what: 'the [hidden] rule removed', project: 'claims-chromium', grep: 'hidden',
    file: 'src/style.css', anchor: '[hidden] { display: none !important; }', replace: '' },
  { id: 'M5', what: 'the no-op guard on tag length removed', project: 'claims-chromium', grep: 'retires',
    file: 'src/ui/workbench.ts', anchor: '    if (sealed && Number(tagLen.value) === sealed.result.tag.length) return;', replace: '' },
  { id: 'M6', what: 'the GCM column shows H at every position', project: 'claims-chromium', grep: 'powers of the single H',
    file: 'src/mgm/compare.ts', anchor: 'gcmShape: bytesToHex(powers[m - i - 1]),', replace: 'gcmShape: bytesToHex(powers[0]),' },
  { id: 'M7', what: 'wrong 64-bit field polynomial', project: 'claims-chromium', grep: 'Magma example 1',
    file: 'src/mgm/gf.ts', anchor: '8: 0x1bn', replace: '8: 0x1dn' },
  { id: 'M8', what: 'a tampered message releases its plaintext', project: 'claims-chromium', grep: 'flipped bit of C',
    file: 'src/mgm/mgm.ts', anchor: '  if (!equalBytes(expected, tag)) return { ok: false, expectedTag: expected, trace: base };',
    replace: '  if (false && !equalBytes(expected, tag)) return { ok: false, expectedTag: expected, trace: base };' },
  { id: 'M9', what: 'the TLSTREE record count ignores C_3', project: 'claims-chromium', grep: 'TLSTREE',
    file: 'src/mgm/limits.ts', anchor: '  return 2 ** trailingZeroBits(s.c3);', replace: '  return 2 ** trailingZeroBits(s.c2);' },
];

const pick = process.argv.slice(2);
const selected = pick.length ? MUTATIONS.filter((m) => pick.includes(m.id)) : MUTATIONS;

function build() {
  const r = spawnSync('npm', ['run', 'build'], { stdio: 'pipe', encoding: 'utf8' });
  return r.status === 0;
}

function bundleHash() {
  const h = createHash('sha256');
  for (const f of readdirSync('dist/assets').sort()) h.update(readFileSync(`dist/assets/${f}`));
  h.update(readFileSync('dist/index.html'));
  return h.digest('hex').slice(0, 12);
}

/** Runs the owning test against a fresh build (the webServer builds first). true = passed. */
function runTest(m) {
  const r = spawnSync('npx', ['playwright', 'test', `--project=${m.project}`, '-g', m.grep, '--reporter=line'],
    { stdio: 'pipe', encoding: 'utf8', env: { ...process.env, CI: '' } });
  const out = r.stdout + r.stderr;
  if (/Process from config\.webServer|ECONNREFUSED|was not able to start/.test(out)) return 'NO-SERVER';
  if (!/\d+ passed|\d+ failed/.test(out)) return 'NO-TESTS';
  return r.status === 0;
}

let failures = 0;
for (const m of selected) {
  const original = readFileSync(m.file, 'utf8');
  const tag = `[${m.id}] ${m.what}`;
  if (!build()) { console.log(`${tag}: BASELINE DOES NOT BUILD`); failures++; continue; }
  const h0 = bundleHash();
  const baseline = runTest(m);
  if (baseline !== true) { console.log(`${tag}: owning test did not pass unmutated (${baseline}) — proves nothing`); failures++; continue; }
  const count = original.split(m.anchor).length - 1;
  if (count !== 1) { console.log(`${tag}: anchor occurs ${count} times — patch not applied`); failures++; continue; }
  writeFileSync(m.file, original.replace(m.anchor, m.replace));
  let verdict;
  try {
    if (!build()) verdict = 'DOES-NOT-BUILD (not a kill)';
    else {
      const h1 = bundleHash();
      if (h1 === h0) verdict = 'bundle unchanged — the mutation never reached the browser';
      else {
        const mutated = runTest(m);
        verdict = mutated === false ? `KILLED (bundle ${h0} -> ${h1})`
          : mutated === true ? `SURVIVED (bundle ${h0} -> ${h1})` : `INCONCLUSIVE (${mutated})`;
      }
    }
  } finally {
    writeFileSync(m.file, original);
  }
  build();
  const h2 = bundleHash();
  if (h2 !== h0) verdict += ` — RESTORE FAILED (bundle ${h2}, expected ${h0})`;
  if (!verdict.startsWith('KILLED') || h2 !== h0) failures++;
  console.log(`${tag}: ${verdict}`);
}
execFileSync('git', ['diff', '--quiet', '--', ...new Set(selected.map((m) => m.file))]);
console.log(`\n${selected.length - failures} of ${selected.length} killed under all four rules.`);
process.exit(failures ? 1 : 0);
