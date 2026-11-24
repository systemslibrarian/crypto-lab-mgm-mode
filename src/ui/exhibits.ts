/** Exhibits 3-6. Each computes with the real implementation and shows its work. */
import { Kuznyechik } from '../cipher/kuznyechik';
import { Magma, SBOX_PARAM_Z } from '../cipher/magma';
import { bytesToHex, hexToBytes } from '../cipher/bytes';
import type { BlockCipher } from '../cipher/types';
import { mgmDecrypt, mgmEncrypt } from '../mgm/mgm';
import { reuseIcn } from '../mgm/misuse';
import {
  TLSTREE_SUITES, log2ConfidentialityBound, maxBlocksForBound, recordsPerLeafKey,
  exceedsInputLimit, maxInputBits,
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
  function addSeries(label: (index: number) => string, expected: string[], computed: Uint8Array[], count: number) {
    for (let i = 0; i < Math.max(count, expected.length, computed.length); i++) {
      pairs.push([label(i + 1), expected[i] ?? 'Missing RFC value',
        computed[i] ? bytesToHex(computed[i]) : 'Missing computed value']);
    }
  }
  const dataBlocks = Math.ceil(v.plaintext.length / (2 * cipher.blockBytes));
  const authBlocks = dataBlocks + Math.ceil(v.aad.length / (2 * cipher.blockBytes));
  addSeries(i => `Y_${i}`, v.y, t.y, dataBlocks);
  addSeries(i => `E_K(Y_${i})`, v.keystream, t.keystream, dataBlocks);
  if (v.plaintext.length) pairs.push(['C', v.ciphertext, bytesToHex(r.ciphertext)]);
  addSeries(i => `Z_${i}`, v.z, t.z, authBlocks + 1);
  addSeries(i => `H_${i}`, v.h, t.h, authBlocks + 1);
  addSeries(i => `sum after block ${i}`, v.runningSum, t.runningSum, authBlocks);
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
    d = { c1: a.ciphertext, c2: b.ciphertext, xorCiphertexts: xc, xorPlaintexts: xp, verified1: mgmDecrypt(cipher, icn, aad, a.ciphertext, a.tag).ok,
      verified2: mgmDecrypt(cipher, icn2, aad, b.ciphertext, b.tag).ok,
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
  if (!d.verified1 || !d.verified2) {
    setVerdict(byId('ru-verdict'), 'bad', 'Receiver verification failed. Check both receiver verdicts.', 'receiver-failed');
  } else if (distinct && d.leaks) {
    setVerdict(byId('ru-verdict'), 'warn', 'The XOR values happen to agree over this sample with distinct ICNs.', 'coincidence');
  } else if (d.leaks) {
    setVerdict(byId('ru-verdict'), 'bad',
      `VERIFIED — AND LEAKED. Both messages pass every check the receiver makes, and C1 ⊕ C2 equals P1 ⊕ P2 over all ${len} common bytes. The displayed equality applies to those overlapping bytes.`,
      'verified-and-leaked');
  } else {
    setVerdict(byId('ru-verdict'), 'ok',
      `With distinct ICNs, the two XOR values differ for these inputs. This comparison tests the displayed samples.`,
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
  /* q was fixed at 1 until 2026-11-17, which made the plot say something the
     RFC forbids: at the old 32 GiB default, one message of 2^38 bits is far
     past section 4.1's 2^32-bit ceiling for Magma, so the bound was drawn for
     an input this lab's own engine refuses. q is a control now, and the length
     rule is shown beside the bound rather than left implicit. */
  const messages = byId<HTMLInputElement>('lm-messages');
  const update = () => {
    const log2Bytes = Number(slider.value);
    const bytes = 2 ** log2Bytes;
    // The model splits whole bytes equally among nonempty messages.
    messages.max = String(Math.min(40, log2Bytes));
    const log2q = Number(messages.value);
    const q = 2 ** log2q;
    const perMessage = bytes / q;
    byId('lm-volume-out').textContent = `${fmtBytes(bytes)} (2^${log2Bytes} bytes) under one key`;
    byId('lm-messages-out').textContent =
      `${q.toLocaleString('en-US')} message${q === 1 ? '' : 's'} (q = 2^${log2q}), so ${fmtBytes(perMessage)} each`;
    for (const [n, id, lenId] of [[64, 'lm-magma', 'lm-magma-len'], [128, 'lm-kuz', 'lm-kuz-len']] as const) {
      const s = q * Math.ceil(perMessage / (n / 8));
      const adv = log2ConfidentialityBound({ n, s, q });
      const cell = byId(id);
      // A bound of 1 or more is vacuous: it no longer rules anything out.
      const broken = adv >= 0;
      cell.dataset.log2 = adv.toFixed(2);
      cell.textContent = broken
        ? `bound 2^${adv.toFixed(1)}: at or above 1, so the bound guarantees nothing at all`
        : `bound 2^${adv.toFixed(1)} (about 1 in ${fmtOdds(-adv)})`;
      cell.className = broken ? 'bad-text' : adv > -32 ? 'warn-text' : 'ok-text';

      const over = exceedsInputLimit(n, perMessage);
      const len = byId(lenId);
      len.dataset.over = String(over);
      len.textContent = over
        ? `${fmtBytes(perMessage)} per message is at or past the 2^${n / 2}-bit limit (${fmtBytes(maxInputBits(n) / 8)}): MGM must not encrypt this`
        : `${fmtBytes(perMessage)} per message is inside the 2^${n / 2}-bit limit (${fmtBytes(maxInputBits(n) / 8)})`;
      len.className = over ? 'bad-text' : 'ok-text';
    }
    byId('lm-budget').replaceChildren(...([64, 128] as const).map((n) => {
      const blocks = Math.floor(maxBlocksForBound(n, 32, q));
      const text = blocks < q
        ? `n = ${n}: no positive message size meets the 2^-32 target for ${q.toLocaleString('en-US')} messages.`
        : `n = ${n}: the 2^-32 bound allows up to ${blocks.toLocaleString('en-US')} total blocks at this message count. The per-message length rule also applies.`;
      return el('li', { 'data-n': n, text });
    }));
  };
  slider.addEventListener('input', update);
  messages.addEventListener('input', update);
  update();

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
      render(null, -1, -1, -1);
      byId('sb-variant').textContent = '—';
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
  for (const id of ['sb-row', 'sb-a', 'sb-b']) {
    byId(id).addEventListener('change', () => {
      render(null, -1, -1, -1);
      byId('sb-variant').textContent = '—';
      setVerdict(byId('sb-verdict'), 'idle', 'Selection changed. Run the swap to compare.', 'pending');
    });
  }
  byId<HTMLSelectElement>('sb-b').value = '1';
  setVerdict(byId('sb-verdict'), 'idle', 'param-Z, the table Magma fixes.', 'idle');
}
