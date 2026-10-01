/** Tiny DOM helpers. Text always goes in through textContent, never innerHTML,
 * so nothing a visitor types is ever parsed as markup. */

type Attrs = Record<string, string | number | boolean | undefined>;
type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'text') node.textContent = String(v);
    else if (k === 'class') node.className = String(v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}

export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing #${id}`);
  return node as T;
}

/** Group hex into blocks of `n` bytes so a reader can see block boundaries. */
export function blockHex(hex: string, n: number): string {
  const parts: string[] = [];
  for (let i = 0; i < hex.length; i += 2 * n) parts.push(hex.slice(i, i + 2 * n));
  return parts.join(' ');
}

export type Tone = 'ok' | 'bad' | 'warn' | 'idle';

const ICON: Record<Tone, string> = { ok: '✓', bad: '✗', warn: '!', idle: '•' };

/**
 * A verdict: icon + text + colour, never colour alone (WCAG 1.4.1). `data-verdict`
 * carries the machine-readable state the claims suite reads.
 */
export function setVerdict(node: HTMLElement, tone: Tone, text: string, verdict: string): void {
  node.className = `verdict verdict-${tone}`;
  node.dataset.verdict = verdict;
  node.replaceChildren(el('span', { class: 'verdict-icon', 'aria-hidden': 'true', text: ICON[tone] }), el('span', { text }));
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
