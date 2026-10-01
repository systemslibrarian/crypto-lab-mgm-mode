/**
 * Exhibit 1 (seal and open) and Exhibit 2 (where each coefficient comes from)
 * share one state: what you seal in 1 is what 2 takes apart.
 */
import { Kuznyechik } from '../cipher/kuznyechik';
import { Magma } from '../cipher/magma';
import { bytesToHex, hexToBytes } from '../cipher/bytes';
import type { BlockCipher, CipherName } from '../cipher/types';
import { MgmInputError, mgmDecrypt, mgmEncrypt, type MgmResult } from '../mgm/mgm';
import { gfMul } from '../mgm/gf';
import { allDistinct, coefficientRows } from '../mgm/compare';
import { RFC9058_VECTORS } from '../mgm/vectors';
import { blockHex, byId, el, randomBytes, setVerdict } from './dom';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

interface Sealed {
  cipher: BlockCipher;
  icn: Uint8Array;
  aad: Uint8Array;
  result: MgmResult;
}

const DEFAULTS: Record<CipherName, { key: string; icn: string }> = {
  // The keys and ICNs of RFC 9058 Appendix A example 1, so the first thing a
  // visitor seals is under exactly the inputs the RFC tests.
  Magma: { key: RFC9058_VECTORS[2].key, icn: RFC9058_VECTORS[2].icn },
  Kuznyechik: { key: RFC9058_VECTORS[0].key, icn: RFC9058_VECTORS[0].icn },
};

let sealed: Sealed | null = null;
let step = 0;

function makeCipher(name: CipherName, key: Uint8Array): BlockCipher {
  return name === 'Magma' ? new Magma(key) : new Kuznyechik(key);
}

function parseHex(value: string, bytes: number, what: string): Uint8Array {
  const clean = value.replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new MgmInputError(`${what} must be hex digits only`);
  if (clean.length !== bytes * 2) throw new MgmInputError(`${what} must be exactly ${bytes * 2} hex digits (${bytes} bytes), got ${clean.length}`);
  return hexToBytes(clean);
}

function cipherName(): CipherName {
  return (document.querySelector<HTMLInputElement>('input[name="wb-cipher"]:checked')?.value ?? 'Magma') as CipherName;
}

function blockBytes(): 8 | 16 {
  return cipherName() === 'Magma' ? 8 : 16;
}

export function mountWorkbench(): void {
  const root = byId('ex-seal-body');
  const cipherSet = el('fieldset', { class: 'choice' },
    el('legend', { text: 'Block cipher under MGM' }),
    el('label', {}, el('input', { type: 'radio', name: 'wb-cipher', value: 'Magma', checked: true }), ' Magma (64-bit block)'),
    el('label', {}, el('input', { type: 'radio', name: 'wb-cipher', value: 'Kuznyechik' }), ' Kuznyechik (128-bit block)'));

  const key = el('input', { id: 'wb-key', class: 'hex', spellcheck: 'false', autocomplete: 'off', value: DEFAULTS.Magma.key });
  const icn = el('input', { id: 'wb-icn', class: 'hex', spellcheck: 'false', autocomplete: 'off', value: DEFAULTS.Magma.icn });
  const aad = el('textarea', { id: 'wb-aad', rows: 2 });
  aad.value = 'record header: seq=7 type=application';
  const pt = el('textarea', { id: 'wb-pt', rows: 3 });
  pt.value = 'Meet at the north gate at nine. Bring the second key.';
  const tagLen = el('select', { id: 'wb-taglen' });
  const status = el('p', { id: 'wb-status', class: 'status', role: 'status', 'aria-live': 'polite' });

  const refillTagLengths = () => {
    const n = blockBytes();
    tagLen.replaceChildren(...Array.from({ length: n - 3 }, (_, i) => {
      const b = n - i;
      return el('option', { value: b, text: `${b} bytes (S = ${b * 8} bits)${b === n ? ', full block' : ''}` });
    }));
  };
  refillTagLengths();

  const sealBtn = el('button', { id: 'wb-seal', type: 'button', class: 'primary', text: 'Seal with MGM' });
  const out = el('div', { id: 'wb-out', class: 'out', hidden: true });

  root.append(
    el('div', { class: 'grid-2' },
      cipherSet,
      el('div', { class: 'stack' },
        el('label', { for: 'wb-key', text: 'Key K (256 bits, hex)' }), key,
        el('button', { type: 'button', id: 'wb-key-rand', text: 'New random key' }))),
    el('div', { class: 'stack' },
      el('label', { for: 'wb-icn', id: 'wb-icn-label', text: 'Initial counter nonce ICN (8 bytes, top bit 0)' }), icn,
      el('button', { type: 'button', id: 'wb-icn-rand', text: 'New random ICN' })),
    el('div', { class: 'grid-2' },
      el('div', { class: 'stack' }, el('label', { for: 'wb-aad', text: 'Associated data A (authenticated, not encrypted)' }), aad),
      el('div', { class: 'stack' }, el('label', { for: 'wb-pt', text: 'Plaintext P' }), pt)),
    el('div', { class: 'row' }, el('label', { for: 'wb-taglen', text: 'Tag length' }), tagLen, sealBtn),
    status, out);

  const retire = (why: string) => {
    if (!sealed) return;
    sealed = null;
    out.hidden = true;
    setVerdict(status as HTMLElement, 'idle', `${why} The previous seal is retired; seal again to continue.`, 'retired');
    renderCoefficients();
  };

  document.querySelectorAll<HTMLInputElement>('input[name="wb-cipher"]').forEach((r) => r.addEventListener('change', () => {
    const name = cipherName();
    key.value = DEFAULTS[name].key;
    icn.value = DEFAULTS[name].icn;
    byId('wb-icn-label').textContent = `Initial counter nonce ICN (${blockBytes()} bytes, top bit 0)`;
    refillTagLengths();
    retire(`Switched to ${name}.`);
  }));
  byId('wb-key-rand').addEventListener('click', () => { key.value = bytesToHex(randomBytes(32)); retire('New key.'); });
  byId('wb-icn-rand').addEventListener('click', () => {
    const b = randomBytes(blockBytes()); b[0] &= 0x7f; icn.value = bytesToHex(b); retire('New ICN.');
  });
  for (const input of [key, icn, aad, pt]) {
    input.addEventListener('input', () => {
      // A no-op guard: retiring on an edit that changes nothing would throw away a fresh verdict.
      if (sealed && input.value === input.dataset.sealedValue) return;
      retire('An input changed.');
    });
  }
  tagLen.addEventListener('change', () => {
    // No-op guard: re-choosing the tag length a message was sealed with changes nothing.
    if (sealed && Number(tagLen.value) === sealed.result.tag.length) return;
    retire('Tag length changed.');
  });

  sealBtn.addEventListener('click', () => {
    try {
      const n = blockBytes();
      const cipher = makeCipher(cipherName(), parseHex(key.value, 32, 'The key'));
      const icnBytes = parseHex(icn.value, n, 'The ICN');
      const aadBytes = enc.encode(aad.value);
      const result = mgmEncrypt(cipher, icnBytes, aadBytes, enc.encode(pt.value), Number(tagLen.value));
      sealed = { cipher, icn: icnBytes, aad: aadBytes, result };
      for (const input of [key, icn, aad, pt]) input.dataset.sealedValue = input.value;
      step = 0;
      setVerdict(status as HTMLElement, 'ok',
        `Sealed ${pt.value.length === 0 ? 'no plaintext' : `${result.ciphertext.length} bytes`} and ${aadBytes.length} bytes of associated data under ${cipher.name}.`, 'sealed');
      renderSealed();
      renderCoefficients();
    } catch (e) {
      sealed = null;
      out.hidden = true;
      setVerdict(status as HTMLElement, 'bad', e instanceof Error ? e.message : String(e), 'refused');
      renderCoefficients();
    }
  });

  mountCoefficientControls();
  sealBtn.click();
}

/** The receiver: the sealed values, editable, with one-bit tamper buttons. */
function renderSealed(): void {
  const out = byId('wb-out');
  if (!sealed) { out.hidden = true; return; }
  const { cipher, result } = sealed;
  const n = cipher.blockBytes;
  const ct = el('textarea', { id: 'rx-ct', class: 'hex', rows: 3, spellcheck: 'false' });
  ct.value = blockHex(bytesToHex(result.ciphertext), n);
  const tag = el('input', { id: 'rx-tag', class: 'hex', spellcheck: 'false', value: bytesToHex(result.tag) });
  const aad = el('textarea', { id: 'rx-aad', rows: 2 });
  aad.value = dec.decode(sealed.aad);
  const verdict = el('p', { id: 'rx-verdict', class: 'verdict', role: 'status', 'aria-live': 'polite' });
  const opened = el('p', { id: 'rx-plain', class: 'mono' });

  const flip = (target: 'ct' | 'tag' | 'aad') => {
    if (target === 'aad') {
      const b = enc.encode(aad.value);
      if (b.length === 0) return;
      b[0] ^= 0x01;
      aad.value = dec.decode(b);
    } else {
      const field = target === 'ct' ? ct : tag;
      const clean = field.value.replace(/\s+/g, '');
      if (clean.length < 2) return;
      const b = hexToBytes(clean);
      b[b.length - 1] ^= 0x01;
      field.value = target === 'ct' ? blockHex(bytesToHex(b), n) : bytesToHex(b);
    }
    setVerdict(verdict, 'idle', 'Changed one bit. Verify to see what the receiver does with it.', 'pending');
    opened.textContent = '';
  };

  out.replaceChildren(
    el('h3', { text: 'What travels: ciphertext C and tag T' }),
    el('p', { class: 'hint', text: `The receiver gets the ICN, A, C and T. Hex is grouped in ${n}-byte blocks, the cipher's block size.` }),
    el('div', { class: 'stack' }, el('label', { for: 'rx-ct', text: 'Ciphertext C (editable)' }), ct),
    el('div', { class: 'stack' }, el('label', { for: 'rx-tag', text: `Tag T (${result.tag.length} bytes, editable)` }), tag),
    el('div', { class: 'stack' }, el('label', { for: 'rx-aad', text: 'Associated data A as received (editable)' }), aad),
    el('div', { class: 'row' },
      el('button', { type: 'button', id: 'rx-flip-ct', text: 'Flip one bit of C' }),
      el('button', { type: 'button', id: 'rx-flip-aad', text: 'Flip one bit of A' }),
      el('button', { type: 'button', id: 'rx-flip-tag', text: 'Flip one bit of T' }),
      el('button', { type: 'button', id: 'rx-restore', text: 'Restore what was sent' }),
      el('button', { type: 'button', id: 'rx-open', class: 'primary', text: 'Verify and open' })),
    verdict, opened);

  byId('rx-flip-ct').addEventListener('click', () => flip('ct'));
  byId('rx-flip-aad').addEventListener('click', () => flip('aad'));
  byId('rx-flip-tag').addEventListener('click', () => flip('tag'));
  byId('rx-restore').addEventListener('click', () => {
    ct.value = blockHex(bytesToHex(result.ciphertext), n);
    tag.value = bytesToHex(result.tag);
    aad.value = dec.decode(sealed!.aad);
    setVerdict(verdict, 'idle', 'Restored the values exactly as sealed.', 'pending');
    opened.textContent = '';
  });
  byId('rx-open').addEventListener('click', () => {
    if (!sealed) return;
    try {
      const c = parseHex(ct.value, ct.value.replace(/\s+/g, '').length / 2, 'The ciphertext');
      const t = hexToBytes(tag.value.replace(/\s+/g, ''));
      const r = mgmDecrypt(sealed.cipher, sealed.icn, enc.encode(aad.value), c, t);
      if (r.ok) {
        setVerdict(verdict, 'ok', 'VERIFIED: the recomputed tag equals T, so the plaintext is released.', 'verified');
        opened.textContent = `P = "${dec.decode(r.plaintext)}"`;
      } else {
        setVerdict(verdict, 'bad', `REJECTED: the recomputed tag is ${bytesToHex(r.expectedTag)}, not ${bytesToHex(t)}. No plaintext is released, not even partly.`, 'rejected');
        opened.textContent = '';
      }
    } catch (e) {
      setVerdict(verdict, 'bad', `REFUSED: ${e instanceof Error ? e.message : String(e)}`, 'refused');
      opened.textContent = '';
    }
  });
  setVerdict(verdict, 'idle', 'Nothing checked yet.', 'pending');
  out.hidden = false;
}

function mountCoefficientControls(): void {
  byId('cf-step').addEventListener('click', () => { step += 1; renderCoefficients(); });
  byId('cf-all').addEventListener('click', () => { step = Number.MAX_SAFE_INTEGER; renderCoefficients(); });
  byId('cf-reset').addEventListener('click', () => { step = 0; renderCoefficients(); });
}

/** Exhibit 2: the coefficient table and the step-through. */
function renderCoefficients(): void {
  const body = byId('cf-table-body');
  const summary = byId('cf-summary');
  const walk = byId('cf-walk');
  const buttons = ['cf-step', 'cf-all', 'cf-reset'].map((id) => byId<HTMLButtonElement>(id));
  if (!sealed) {
    body.replaceChildren();
    byId('cf-table-wrap').hidden = true; // headers with no rows say nothing
    byId('cf-progress').textContent = '';
    walk.replaceChildren(el('p', { class: 'hint', text: 'Seal a message in Exhibit 1 first; this exhibit takes that exact message apart.' }));
    setVerdict(summary, 'idle', 'No sealed message.', 'idle');
    buttons.forEach((b) => { b.disabled = true; });
    return;
  }
  buttons.forEach((b) => { b.disabled = false; });
  byId('cf-table-wrap').hidden = false;
  const { cipher, result } = sealed;
  const { trace } = result;
  const { rows, h } = coefficientRows(cipher, trace);
  const total = rows.length;
  const shown = Math.min(step, total);
  byId<HTMLButtonElement>('cf-step').disabled = shown >= total;

  body.replaceChildren(...rows.map((row, i) => el('tr', { class: i < shown ? 'done' : undefined },
    el('th', { scope: 'row', text: row.label }),
    el('td', { class: 'mono', text: i < trace.authBlocks.length ? bytesToHex(trace.authBlocks[i].block) : bytesToHex(trace.lengthBlock) }),
    el('td', { class: 'mono gcm', text: `H^${row.power} = ${row.gcmShape}` }),
    el('td', { class: 'mono mgm', text: `H_${i + 1} = ${row.mgm}` }))));

  const distinct = allDistinct(rows.map((r) => r.mgm));
  setVerdict(summary, distinct ? 'ok' : 'bad',
    `${total} positions. GCM-shaped: every coefficient is a power of the one H = ${h}, so learning H gives all ${total}. MGM: ${distinct ? `all ${total}` : 'NOT all'} coefficients are distinct block-cipher outputs, and none is computed from another.`,
    distinct ? 'distinct' : 'repeated');

  // The step-through: Z_i -> H_i = E_K(Z_i) -> H_i (x) block -> running sum.
  const items: HTMLElement[] = [
    el('li', {}, el('span', { class: 'k', text: '1 || ICN' }), ` = ${bytesToHex(sealed.icn.map((b, j) => (j === 0 ? b | 0x80 : b)))}  → Z_1 = E_K(1 || ICN) = ${bytesToHex(trace.z[0])}`),
  ];
  for (let i = 0; i < shown && i < trace.authBlocks.length; i++) {
    const blk = trace.authBlocks[i];
    items.push(el('li', {},
      el('span', { class: 'k', text: `${blk.kind}${blk.index}` }),
      ` Z_${i + 1} = ${bytesToHex(trace.z[i])}  → H_${i + 1} = E_K(Z_${i + 1}) = ${bytesToHex(trace.h[i])};  H_${i + 1} ⊗ ${blk.kind}${blk.index} = ${bytesToHex(gfMul(trace.h[i], blk.block))};  sum = ${bytesToHex(trace.runningSum[i])}`));
  }
  if (shown >= total) {
    const last = trace.h.length - 1;
    items.push(el('li', {},
      el('span', { class: 'k', text: 'len' }),
      ` len(A) || len(C) = ${bytesToHex(trace.lengthBlock)} (bits);  H_${last + 1} = ${bytesToHex(trace.h[last])};  sum ⊕ H_${last + 1} ⊗ len = ${bytesToHex(trace.finalSum)}`));
    items.push(el('li', { class: 'final' },
      el('span', { class: 'k', text: 'T' }),
      ` = MSB_${result.tag.length * 8}(E_K(sum)) = ${bytesToHex(result.tag)} — the sum is encrypted before it leaves, so a tag never shows the polynomial value itself.`));
    // Check the walk against the tag the mode produced, by an independent route.
    const recomputed = cipher.encryptBlock(trace.finalSum).slice(0, result.tag.length);
    const match = bytesToHex(recomputed) === bytesToHex(result.tag);
    items.push(el('li', { 'data-verdict': match ? 'walk-matches' : 'walk-differs', text: match
      ? 'Recomputed E_K(final sum) here and compared with the sealed tag: identical.'
      : 'Recomputed E_K(final sum) differs from the sealed tag.' }));
  }
  walk.replaceChildren(el('ol', { class: 'walk', id: 'cf-walk-list' }, ...items));
  byId('cf-progress').textContent = `${shown} of ${total} positions folded into the sum.`;
}
