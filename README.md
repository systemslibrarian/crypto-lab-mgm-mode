# MGM Mode

**Multilinear Galois Mode (RFC 9058) over Magma and Kuznyechik, in the browser, with every intermediate value shown and checked.**

## What It Is

MGM is an authenticated-encryption (AEAD) block cipher mode from the Russian GOST standards, published in English as
[RFC 9058](https://www.rfc-editor.org/rfc/rfc9058). It encrypts in counter mode and authenticates with a multilinear
function: every authenticated block is multiplied, in GF(2^n), by its own coefficient `H_i = E_K(Z_i)` produced by
the block cipher from a second counter, the products are xored, and the sum is encrypted once more to give the tag.
GCM, by contrast, weights every block by a power of one hash subkey `H`. That difference is the subject of this lab.

The lab implements, in plain TypeScript with no runtime dependencies:

- **Magma**, the 64-bit GOST R 34.12-2015 block cipher ([RFC 8891](https://www.rfc-editor.org/rfc/rfc8891));
- **Kuznyechik**, the 128-bit GOST R 34.12-2015 block cipher ([RFC 7801](https://www.rfc-editor.org/rfc/rfc7801));
- **MGM** encryption, tag generation and verify-then-decrypt over both (RFC 9058 sections 4.1 and 4.2).

RFC 9058 is an **Independent Submission**, Informational: it documents a national standard and is not an IETF
recommendation. Its real-world use is the GOST cipher suites for TLS 1.3, [RFC 9367](https://www.rfc-editor.org/rfc/rfc9367),
itself also an Independent Submission.

**This is a teaching demo, not production crypto.** The implementations are written to be read, not to resist side
channels: nothing here is constant-time, keys live in page memory, and the code has not been reviewed.

## Exhibits

1. **Seal and open.** Seal a message under Magma or Kuznyechik (defaults: RFC 9058's own example key and nonce),
   then act as the receiver: flip one bit of the ciphertext, the associated data or the tag and verify. MGM checks
   the tag before decrypting, so a rejected message releases no plaintext at all. Inputs RFC 9058 forbids — empty
   associated data with empty plaintext, an ICN with its top bit set — are refused, with the reason.
2. **One H, or one H per block.** The headline. For the message you sealed, every authenticated position with the
   coefficient that multiplies it: a GCM-shaped column of powers of one `H`, beside MGM's distinct `H_i`. Step
   through the tag one block at a time: `Z_i`, `H_i = E_K(Z_i)`, `H_i ⊗ block`, the running sum, the length block and
   the final encryption. (The GCM column uses MGM's cipher and field to show the structure; it is not AES-GCM.)
3. **Check every value against RFC 9058.** Runs each of the RFC's four Appendix A examples and sets every computed
   value — each `Y_i`, `E_K(Y_i)`, `Z_i`, `H_i`, running sum, the length block, the encrypted sum and the tag — beside
   the value the RFC prints.
4. **Repeat the nonce.** Two messages under one ICN: both verify, and `C1 ⊕ C2 = P1 ⊕ P2`, so knowing one message
   reveals the other without the key. The verdict reads **VERIFIED — AND LEAKED**; a checkbox gives the second
   message its own ICN as the control.
5. **64 bits versus 128.** RFC 9058's confidentiality bound `3(s + 4q)² / 2^n` for a chosen data volume, for both
   block sizes, and the volume that keeps it under 2^-32 for each. Then RFC 9367's TLSTREE re-keying, with records
   per key derived from each suite's `C_3` constant: 8,192 for Kuznyechik-L, 128 for Magma-L, 8 and 1 for the S suites.
6. **Magma's S-box.** GOST 28147-89 defined no S-boxes (RFC 5830: "the standard doesn't define any S-boxes"); Magma
   fixes `id-tc26-gost-28147-param-Z`. Swap two entries and watch the same key and block give a different cipher.

## When to Use It

- Use it to see how an AEAD's tag is actually assembled, because MGM shows every intermediate and RFC 9058 prints them.
- Use it to compare MGM's per-block coefficients with GCM's single `H`, because the difference is the mode's design argument.
- Use it to see why 64-bit block ciphers need short key lifetimes, because the bound and RFC 9367's re-keying are computed, not asserted.
- Do not use it to protect real data, because it is a demo app and does not provide hardened operational controls.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-mgm-mode/

Seal and tamper with messages, step through the tag computation, check the implementation against RFC 9058, reuse a
nonce, and move the data-volume slider for both block sizes.

## What Can Go Wrong

- **Repeating an ICN under one key.** The encryption counter depends only on the key and the ICN, so the keystream
  repeats and `C1 ⊕ C2 = P1 ⊕ P2`. MGM still verifies both messages; nothing it checks is wrong. (Exhibit 4.)
- **Encrypting too much under one key with a 64-bit block.** At 32 GiB under one Magma key the confidentiality bound
  exceeds 1 and guarantees nothing; the same volume under Kuznyechik leaves it near 2^-64. (Exhibit 5.)
- **Empty A and empty P together.** RFC 9058 section 6 forbids it: the tag would no longer depend on the nonce. The lab
  refuses it rather than computing it.
- **Not a forgery demo.** GCM's nonce reuse leaks `H`; MGM encrypts its sum before output, and this lab demonstrates
  no forgery against it.

## Real-World Usage

MGM is standardised in Russia (R 1323565.1.026-2019) and used as the AEAD mode for GOST block ciphers in TLS 1.3
(RFC 9367, cipher suites `TLS_GOSTR341112_256_WITH_{KUZNYECHIK,MAGMA}_MGM_{L,S}`) and IPsec. RFC 9367's suites
re-key inside a connection through TLSTREE, more aggressively for Magma than for Kuznyechik.

## How to Run Locally

```
npm ci
npm run dev        # http://localhost:5173/crypto-lab-mgm-mode/
npm test           # unit and known-answer tests
npm run test:a11y  # WCAG gate (builds, then serves on port 4659)
npm run test:e2e   # claims suite
```

## Related Demos

- [World Ciphers](https://systemslibrarian.github.io/crypto-lab-world-ciphers/) — Kuznyechik beside AES, Camellia, ARIA and SM4.
- [Feistel Forge](https://systemslibrarian.github.io/crypto-lab-feistel-forge/) — the Feistel network and the 64-bit birthday bound (Sweet32).
- [Sleeve Check](https://systemslibrarian.github.io/crypto-lab-sleeve-check/) — where Kuznyechik's S-box came from.
- [Nonce Collision](https://systemslibrarian.github.io/crypto-lab-nonce-collision/) — the birthday bound in the nonce space.

## Build & Verify

- **69 unit tests** (Vitest). They cover every example RFC 8891 and RFC 7801 print, including all 31 Magma rounds, the
  Kuznyechik round keys and both `pi` tables. They cover **every intermediate value of all four RFC 9058 Appendix A
  examples** (`src/mgm/vectors.ts`, extracted from the RFC text by `scripts/extract-vectors.mjs`, with the text's
  sha256 recorded). They also cover tamper rejection at every byte, refusal of every forbidden input, the
  RFC 7836 / RFC 8891 S-box cross-check, and the bound and TLSTREE arithmetic.
- **44 claims tests** (Playwright, desktop and phone). They re-derive what the page shows by a different route: the
  RFC column against the RFC text, the GCM column and every walk step with an independently written GF(2^n)
  multiplier, the bounds from the formula, and records per key from the printed `C_3`. They also cover the negative
  claim's fixture and visibility, retirement and no-op guards, and the `[hidden]` probe.
- **WCAG 2.1 A/AA gate**, 4 drives (desktop and 380px, dark- and light-preference OS) scanning 24 driven states each with
  axe (violations and incomplete), arithmetic contrast, non-text contrast, reflow, scroller reachability and focus visibility.
- **Mutation set**: `node scripts/mutations.mjs` replays 10 source mutations and counts a kill only when the owning
  test passed unmutated, the patch applied, the build succeeded with a changed bundle, and the test then failed.
  10 of 10 are killed.

The deploy workflow runs the unit tests, the build, the WCAG gate and the claims suite, and publishes only if all pass.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
