/** Exhibits 3-6. Each computes with the real implementation and shows its work. */
import { Kuznyechik } from '../cipher/kuznyechik';
import { Magma, SBOX_PARAM_Z } from '../cipher/magma';
import { bytesToHex, hexToBytes } from '../cipher/bytes';
import type { BlockCipher } from '../cipher/types';
import { mgmEncrypt } from '../mgm/mgm';
import { reuseIcn } from '../mgm/misuse';
import {
  TLSTREE_SUITES, log2ConfidentialityBound, maxBlocksForBound, recordsPerLeafKey,
} from '../mgm/limits';
import { RFC9058_VECTORS } from '../mgm/vectors';
import { byId, el, setVerdict } from './dom';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

/* ---------------- Exhibit 3: against RFC 9058 Appendix A ---------------- */

export function mountRfcCheck(): void {
  const select = byId<HTMLSelectElement>('rfc-example');
  select.replaceChildren(...RFC9058_VECTORS.map((v, i) => el('option', {
    value: i, text: `${v.cipher}, Appendix A.${v.cipher === 'Kuznyechik' ? 1 : 2}.${v.example} (|A| = ${v.aad.length / 2} bytes, |P| = ${v.plaintext.length / 2} bytes)`,
  })));
  byId('rfc-run').addEventListener('click', runRfc);
  select.addEventListener('change', () => {
    byId('rfc-table-body').replaceChildren();
    // An empty table is not shown: headers with no data cells say nothing.
    byId('rfc-table-wrap').hidden = true;
    setVerdict(byId('rfc-verdict'), 'idle', 'Example changed. Run the check again.', 'retired');
  });
  setVerdict(byId('rfc-verdict'), 'idle', 'Not run yet.', 'idle');
}

function runRfc(): void {
  const v = RFC9058_VECTORS[Number(byId<HTMLSelectElement>('rfc-example').value)];
  const cipher: BlockCipher = v.cipher === 'Magma' ? new Magma(hexToBytes(v.key)) : new Kuznyechik(hexToBytes(v.key));
  const r = mgmEncrypt(cipher, hexToBytes(v.icn), hexToBytes(v.aad), hexToBytes(v.plaintext));
  const t = r.trace;
  const pairs: [string, string, string][] = [];
  v.y.forEach((x, i) => pairs.push([`Y_${i + 1}`, x, bytesToHex(t.y[i] ?? new Uint8Array())]));
  v.keystream.forEach((x, i) => pairs.push([`E_K(Y_${i + 1})`, x, bytesToHex(t.keystream[i] ?? new Uint8Array())]));
  if (v.plaintext.length) pairs.push(['C', v.ciphertext, bytesToHex(r.ciphertext)]);
  v.z.forEach((x, i) => pairs.push([`Z_${i + 1}`, x, bytesToHex(t.z[i] ?? new Uint8Array())]));
  v.h.forEach((x, i) => pairs.push([`H_${i + 1}`, x, bytesToHex(t.h[i] ?? new Uint8Array())]));
  v.runningSum.forEach((x, i) => pairs.push([`sum after block ${i + 1}`, x, bytesToHex(t.runningSum[i] ?? new Uint8Array())]));
  pairs.push(['len(A) || len(C)', v.lengthBlock, bytesToHex(t.lengthBlock)]);
  pairs.push(['sum ⊕ H_last ⊗ len', v.finalSum, bytesToHex(t.finalSum)]);
  pairs.push(['Tag T', v.tag, bytesToHex(r.tag)]);
  const matched = pairs.filter(([, a, b]) => a === b).length;
  byId('rfc-table-body').replaceChildren(...pairs.map(([label, rfc, ours]) => el('tr', { 'data-match': rfc === ours ? 'yes' : 'no' },
    el('th', { scope: 'row', text: label }),
    el('td', { class: 'mono', text: rfc }),
    el('td', { class: 'mono', text: ours }),
    el('td', { class: rfc === ours ? 'match-yes' : 'match-no', text: rfc === ours ? '✓ same' : '✗ differs' }))));
  byId('rfc-table-wrap').hidden = false;
  setVerdict(byId('rfc-verdict'), matched === pairs.length ? 'ok' : 'bad',
    `${matched} of ${pairs.length} values computed here match the values RFC 9058 prints.`,
    matched === pairs.length ? 'rfc-all-match' : 'rfc-mismatch');
  byId('rfc-verdict').dataset.matched = String(matched);
  byId('rfc-verdict').dataset.total = String(pairs.length);
}

/* ---------------- Exhibit 4: a repeated ICN ---------------- */

export function mountReuse(): void {
  byId('ru-run').addEventListener('click', runReuse);
  for (const id of ['ru-p1', 'ru-p2', 'ru-cipher', 'ru-distinct']) {
    byId(id).addEventListener('input', () => {
      byId('ru-result').hidden = true;
      setVerdict(byId('ru-verdict'), 'idle', 'Inputs changed. Run it again.', 'retired');
    });
  }
  setVerdict(byId('ru-verdict'), 'idle', 'Not run yet.', 'idle');
}

function runReuse(): void {
  const name = byId<HTMLSelectElement>('ru-cipher').value;
  const cipher: BlockCipher = name === 'Magma'
    ? new Magma(hexToBytes(RFC9058_VECTORS[2].key)) : new Kuznyechik(hexToBytes(RFC9058_VECTORS[0].key));
  const n = cipher.blockBytes;
  const icn = new Uint8Array(n); icn[n - 1] = 0x2a;
  const p1 = enc.encode(byId<HTMLTextAreaElement>('ru-p1').value);
  const p2 = enc.encode(byId<HTMLTextAreaElement>('ru-p2').value);
  if (p1.length === 0 || p2.length === 0) {
    setVerdict(byId('ru-verdict'), 'bad', 'Both messages need at least one byte.', 'refused');
    return;
  }
  const aad = enc.encode('hdr');
  const distinct = byId<HTMLInputElement>('ru-distinct').checked;
  let d;
  if (distinct) {
    // Give message 2 its own ICN: the honest use, as the control.
    const icn2 = icn.slice(); icn2[n - 1] = 0x2b;
    const a = mgmEncrypt(cipher, icn, aad, p1);
    const b = mgmEncrypt(cipher, icn2, aad, p2);
    const len = Math.min(p1.length, p2.length);
    const xc = a.ciphertext.subarray(0, len).map((x, i) => x ^ b.ciphertext[i]);
    const xp = p1.subarray(0, len).map((x, i) => x ^ p2[i]);
    d = { c1: a.ciphertext, c2: b.ciphertext, xorCiphertexts: xc, xorPlaintexts: xp, verified1: true, verified2: true,
      leaks: bytesToHex(xc) === bytesToHex(xp) };
  } else {
    d = reuseIcn(cipher, icn, aad, p1, p2);
  }
  const len = d.xorCiphertexts.length;
  const recovered = d.xorCiphertexts.map((x, i) => x ^ p1[i]);
  byId('ru-xc').textContent = bytesToHex(d.xorCiphertexts);
  byId('ru-xp').textContent = bytesToHex(d.xorPlaintexts);
  byId('ru-recovered').textContent = `"${dec.decode(recovered)}"`;
  byId('ru-v1').textContent = d.verified1 ? '✓ message 1 verifies' : '✗ message 1 rejected';
  byId('ru-v2').textContent = d.verified2 ? '✓ message 2 verifies' : '✗ message 2 rejected';
  byId('ru-result').hidden = false;
  byId('ru-result').dataset.leaks = String(d.leaks);
  if (d.leaks) {
    setVerdict(byId('ru-verdict'), 'bad',
      `VERIFIED — AND LEAKED. Both messages pass every check the receiver makes, and C1 ⊕ C2 equals P1 ⊕ P2 over all ${len} common bytes. Anyone who knows or guesses message 1 reads message 2 without the key.`,
      'verified-and-leaked');
  } else {
    setVerdict(byId('ru-verdict'), 'ok',
      `Distinct ICNs: C1 ⊕ C2 no longer equals P1 ⊕ P2, so xoring the ciphertexts tells an eavesdropper nothing about the plaintexts.`,
      'no-leak');
  }
}

/* ---------------- Exhibit 5: 64 bits versus 128 ---------------- */

function fmtBytes(bytes: number): string {
  const units = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
  let u = 0; let v = bytes;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[u]}`;
}

export function mountLimits(): void {
  const slider = byId<HTMLInputElement>('lm-volume');
  const update = () => {
    const log2Bytes = Number(slider.value);
    const bytes = 2 ** log2Bytes;
    byId('lm-volume-out').textContent = `${fmtBytes(bytes)} (2^${log2Bytes} bytes) under one key`;
    for (const [n, id] of [[64, 'lm-magma'], [128, 'lm-kuz']] as const) {
      const s = bytes / (n / 8);
      const adv = log2ConfidentialityBound({ n, s, q: 1 });
      const cell = byId(id);
      // A bound of 1 or more is vacuous: it no longer rules anything out.
      const broken = adv >= 0;
      cell.dataset.log2 = adv.toFixed(2);
      cell.textContent = broken
        ? `bound 2^${adv.toFixed(1)}: at or above 1, so the bound guarantees nothing at all`
        : `bound 2^${adv.toFixed(1)} (about 1 in ${fmtOdds(-adv)})`;
      cell.className = broken ? 'bad-text' : adv > -32 ? 'warn-text' : 'ok-text';
    }
  };
  slider.addEventListener('input', update);
  update();

  const target = 32;
  byId('lm-budget').replaceChildren(...([64, 128] as const).map((n) => {
    const blocks = maxBlocksForBound(n, target, 1);
    return el('li', { 'data-n': n, text: `n = ${n}: about ${fmtBytes(blocks * (n / 8))} keeps the confidentiality bound at or below 2^-${target}.` });
  }));

  byId('lm-tls-body').replaceChildren(...TLSTREE_SUITES.map((s) => el('tr', {},
    el('th', { scope: 'row', class: 'mono', text: s.suite }),
    el('td', { text: s.cipher }),
    el('td', { class: 'mono', text: `0x${s.c3.toString(16)}` }),
    el('td', { 'data-records': recordsPerLeafKey(s), text: recordsPerLeafKey(s).toLocaleString('en-US') }),
    el('td', { text: `2^${s.snmaxLog2} − 1` }))));
}

function fmtOdds(log2: number): string {
  if (log2 < 20) return Math.round(2 ** log2).toLocaleString('en-US');
  return `2^${log2.toFixed(0)}`;
}

/* ---------------- Exhibit 6: Magma's S-box ---------------- */

export function mountSbox(): void {
  const table = byId('sb-table-body');
  const render = (swapped: number[][] | null, row: number, a: number, b: number) => {
    table.replaceChildren(...(swapped ?? SBOX_PARAM_Z).map((r, i) => el('tr', {},
      el('th', { scope: 'row', text: `Pi'_${i}` }),
      ...r.map((x, j) => el('td', { class: swapped && i === row && (j === a || j === b) ? 'swapped' : undefined, text: x.toString(16) })))));
  };
  render(null, -1, -1, -1);
  const key = hexToBytes('ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  const block = hexToBytes('fedcba9876543210');
  const reference = bytesToHex(new Magma(key).encryptBlock(block));
  byId('sb-reference').textContent = reference;

  byId('sb-swap').addEventListener('click', () => {
    const row = Number(byId<HTMLSelectElement>('sb-row').value);
    const a = Number(byId<HTMLSelectElement>('sb-a').value);
    const b = Number(byId<HTMLSelectElement>('sb-b').value);
    if (a === b) {
      setVerdict(byId('sb-verdict'), 'warn', 'Pick two different positions; swapping an entry with itself changes nothing.', 'noop');
      return;
    }
    const swapped = SBOX_PARAM_Z.map((r) => r.slice());
    [swapped[row][a], swapped[row][b]] = [swapped[row][b], swapped[row][a]];
    const variant = new Magma(key, swapped);
    const out = bytesToHex(variant.encryptBlock(block));
    const back = bytesToHex(variant.decryptBlock(hexToBytes(out)));
    render(swapped, row, a, b);
    byId('sb-variant').textContent = out;
    setVerdict(byId('sb-verdict'), out === reference ? 'warn' : 'ok',
      out === reference
        ? 'Same ciphertext this time. A swap the test block never reaches can leave this one block unchanged; try another pair.'
        : `A different cipher: the same key and block now give ${out}, not ${reference}. It still decrypts (${back === bytesToHex(block) ? 'round trip holds' : 'round trip FAILED'}), it is simply not Magma.`,
      out === reference ? 'unchanged' : 'different-cipher');
  });
  byId('sb-restore').addEventListener('click', () => {
    render(null, -1, -1, -1);
    byId('sb-variant').textContent = '—';
    setVerdict(byId('sb-verdict'), 'idle', 'Back to param-Z, the table Magma fixes.', 'idle');
  });
  for (const id of ['sb-row', 'sb-a', 'sb-b']) {
    byId<HTMLSelectElement>(id).replaceChildren(...Array.from({ length: id === 'sb-row' ? 8 : 16 }, (_, i) =>
      el('option', { value: i, text: id === 'sb-row' ? `Pi'_${i}` : `entry ${i.toString(16)}` })));
  }
  byId<HTMLSelectElement>('sb-b').value = '1';
  setVerdict(byId('sb-verdict'), 'idle', 'param-Z, the table Magma fixes.', 'idle');
}
