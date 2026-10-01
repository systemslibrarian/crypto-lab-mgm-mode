#!/usr/bin/env node
/*
 * Regenerate src/mgm/vectors.ts from the text of RFC 9058 Appendix A.
 *
 *   curl -sS -o rfc9058.txt https://www.rfc-editor.org/rfc/rfc9058.txt
 *   node scripts/extract-vectors.mjs rfc9058.txt > src/mgm/vectors.ts
 *
 * The vectors are extracted, not retyped, because there are several hundred
 * bytes of them and every intermediate value (Y_i, E_K(Y_i), Z_i, H_i, the
 * running sum) is used. The RFC text's sha256 is written into the output, so a
 * reader can tell which text the bytes came from. The RFC is not committed.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const path = process.argv[2];
if (!path) { console.error('usage: extract-vectors.mjs <rfc9058.txt>'); process.exit(2); }
const text = readFileSync(path, 'utf8');
const sha = createHash('sha256').update(text).digest('hex');

const lines = text.split('\n').filter((l) => !/^RFC 9058|^Smyshlyaev|^\f/.test(l));
const start = lines.findIndex((l) => l.startsWith('A.1.1.  Example 1'));
const end = lines.findIndex((l) => l.startsWith('Contributors'));
const body = lines.slice(start, end);

// A label line, then zero or more "00000:   AA BB ..." hex lines.
const examples = [];
let cur = null;
let label = null;
for (const line of body) {
  const ex = /^A\.(\d)\.(\d)\.  Example (\d)/.exec(line);
  if (ex) { cur = { cipher: ex[1] === '1' ? 'Kuznyechik' : 'Magma', example: Number(ex[3]), fields: [] }; examples.push(cur); continue; }
  const hexLine = /^\s+[0-9a-f]{5}:\s*((?:[0-9A-F]{2}\s*)*)$/i.exec(line);
  if (hexLine && label !== null) { cur.fields.at(-1).hex += hexLine[1].replace(/\s+/g, '').toLowerCase(); continue; }
  const lab = /^\s+(\S.*?):?\s*$/.exec(line);
  if (lab && !/^\d\.  /.test(lab[1].trim())) {
    label = lab[1].replace(/:$/, '').trim();
    if (/^\d\.\s/.test(label)) { label = null; continue; }
    cur.fields.push({ label, hex: '' });
  } else if (/^\s+\d\.\s/.test(line)) {
    label = null;
  }
}

function pick(fields, re) { return fields.filter((f) => re.test(f.label)).map((f) => f.hex); }
function one(fields, re) {
  const all = pick(fields, re);
  if (all.length !== 1) throw new Error(`expected one ${re}, got ${all.length}`);
  return all[0];
}

const out = examples.map((e) => {
  const f = e.fields;
  return {
    cipher: e.cipher,
    example: e.example,
    key: one(f, /^Encryption key K$/),
    icn: one(f, /^ICN$/),
    aad: one(f, /^Associated authenticated data A$/),
    plaintext: one(f, /^Plaintext P$/),
    y: pick(f, /^Y_\d+$/),
    keystream: pick(f, /^E_K\(Y_\d+\)$/),
    ciphertext: pick(f, /^C$/)[0],
    z: pick(f, /^Z_\d+$/),
    h: pick(f, /^H_\d+$/),
    runningSum: pick(f, /^current sum$/),
    lengthBlock: one(f, /^len\(A\) \|\| len\(C\)$/),
    finalSum: one(f, /^sum \(xor\)/),
    tag: one(f, /^Tag T$/),
  };
});

console.log(`/**
 * RFC 9058 Appendix A, every value, extracted by scripts/extract-vectors.mjs
 * from the RFC text with sha256 ${sha}.
 * Do not edit by hand: regenerate it.
 *
 * Per example: the inputs, then each intermediate value the RFC prints — Y_i,
 * E_K(Y_i), Z_i, H_i, the running sum after every block — and the tag. The
 * tests compare the implementation against ALL of them, so a bug that happens
 * to produce the right tag by accident cannot pass.
 */
export interface MgmVector {
  cipher: 'Magma' | 'Kuznyechik';
  example: number;
  key: string; icn: string; aad: string; plaintext: string;
  y: string[]; keystream: string[]; ciphertext: string;
  z: string[]; h: string[]; runningSum: string[];
  lengthBlock: string; finalSum: string; tag: string;
}

export const RFC9058_SHA256 = '${sha}';

export const RFC9058_VECTORS: MgmVector[] = ${JSON.stringify(out, null, 2)};`);
