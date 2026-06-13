# Ternary Cipher — Cryptographic Primitives over Z₃

**Ternary Cipher** implements a complete suite of cryptographic primitives over the finite field **GF(3)** — one-time pads, Feistel ciphers, substitution boxes, hash commitments, Shamir secret sharing, and Merkle trees — all using balanced ternary arithmetic on **T = {−1, 0, +1}**. The crate is `#![no_std]` and `#![forbid(unsafe_code)]`, making it suitable for embedded ternary processors and constrained environments.

## Why It Matters

Binary cryptography (AES, SHA-256, RSA) is ubiquitous, but the emergence of ternary hardware — ternary logic gates, memristor-based ternary ALUs, and balanced ternary processors — creates a need for **native ternary cryptography** that avoids binary conversion overhead. Even on conventional hardware, ternary ciphers offer unique properties:

- **Information-theoretic security:** The ternary one-time pad is Shannon-perfect. With key space {−1, 0, +1}ⁿ, the ciphertext reveals zero information about the plaintext when the key is uniformly random.
- **Efficient secret sharing:** Shamir's scheme over GF(3) uses degree-(k−1) polynomials evaluated in a field of characteristic 3, requiring no bignum arithmetic.
- **Compact commitments:** Ternary hash commitments produce a single trit of digest per message block — extreme compression for resource-constrained devices.

The Feistel construction provides a **provably invertible** cipher structure: any round function F yields a decryption algorithm automatically, eliminating a common source of cipher bugs.

## How It Works

### Ternary Arithmetic in GF(3)

All operations are performed modulo 3 in the balanced representation {−1, 0, +1}, which maps bijectively to GF(3) = {0, 1, 2}:

| Operation | Formula | GF(3) Equivalent |
|---|---|---|
| `ternary_add(a, b)` | (a + b + 3) mod 3 → remap | a ⊕ b in GF(3) |
| `ternary_sub(a, b)` | add(a, −b) | a ⊖ b in GF(3) |
| `ternary_mul(a, b)` | (a × b) mod 3 | a ⊗ b in GF(3) |
| `xor_ternary(a, b)` | = add(a, b) | Addition = XOR in prime fields |

**Complexity:** O(1) per operation — two integer additions, one modulo, one comparison.

**Algebraic properties:** (T, add) forms a cyclic group Z₃. (T, add, mul) forms the finite field GF(3). Multiplicative inverses: 1⁻¹ = 1, (−1)⁻¹ = −1, 0 has no inverse.

### One-Time Pad (OTP)

```
encrypt: c[i] = m[i] ⊕ k[i]     (ternary add mod 3)
decrypt: m[i] = c[i] ⊖ k[i]     (ternary sub mod 3)
```

**Security proof (Shannon 1949):** If K is uniformly random over Tⁿ and used once, then Pr[C = c | M = m] = 3⁻ⁿ for all m, c — the ciphertext is independent of the plaintext. This gives **perfect secrecy**: I(M; C) = 0.

**Complexity:** O(n) for n trits. Key length must equal message length.

### Feistel Cipher

The Feistel network splits the message into left (L) and right (R) halves and applies r rounds:

```
L_{i+1} = R_i
R_{i+1} = L_i ⊖ F(R_i, K_i)

where F(R, K) = SBox(R ⊕ K)
```

**Invertibility:** Decryption uses the same structure with keys in reverse order. The Feistel construction guarantees invertibility regardless of F — even if F is not invertible.

**Complexity:** O(r × n/2) for r rounds on n-trit messages. Each round requires n/2 additions + n/2 S-box lookups.

**Security:** With sufficient rounds, the Feistel network is a **pseudorandom permutation** (Luby-Rackoff theorem): 3–4 rounds with a secure F-function suffice to resist chosen-plaintext attacks.

### Substitution Box (S-Box)

A ternary S-box maps each input trit to an output trit via a 3-entry lookup table:

- **Identity:** −1→−1, 0→0, +1→+1 (no-op)
- **Invert:** −1→+1, 0→0, +1→−1 (multiplicative inverse in GF(3))

The inversion S-box provides **nonlinearity** — the only nonlinear component in the cipher. Without it, the Feistel cipher would be a linear transformation, trivially breakable.

### Hash Function

```
h ← 0
for i, v in enumerate(input):
    h ← h ⊕ ((v + i) mod 3)     // rotate-xor
    h ← h ⊗ (−1)                 // multiply by generator
return h
```

**Properties:** Deterministic, produces a single trit. Avalanche: changing one input trit changes the output with probability 2/3. **Note:** This is a lightweight hash suitable for commitments and Merkle trees, not a cryptographic hash function.

**Complexity:** O(n) for n input trits.

### Commitment Scheme

```
commit(value, randomness) = ternary_hash([value, randomness])
```

**Binding:** Computationally infeasible to find (value', randomness') ≠ (value, randomness) with the same commitment, given the hash function's preimage resistance.

**Complexity:** O(1) — single hash evaluation on 2 trits.

### Shamir's Secret Sharing over GF(3)

**Sharing:** Given secret s ∈ GF(3), choose a random polynomial of degree k−1:

```
f(x) = s + a₁x + a₂x² + ... + a_{k−1}x^{k−1}    (mod 3)
share_i = (x_i, f(x_i))    for x_i ∈ {1, ..., n}
```

**Reconstruction:** Given k shares, recover f(0) = s via Lagrange interpolation:

```
s = ∑ⱼ y_j · ∏_{i≠j} (−x_i) / (x_j − x_i)    (mod 3)
```

**Security (threshold property):** Any k shares uniquely determine s. Any k−1 shares reveal **zero information** about s (Shannon-perfect for the threshold). This follows from the fact that a degree-(k−1) polynomial is determined by k points but passes through any given point for exactly one choice of k−1 random coefficients.

**Complexity:** Share generation O(n × k) polynomial evaluations. Reconstruction O(k²) for Lagrange basis computation. Space: O(k) shares stored.

**Limitation:** GF(3) has only 3 elements, so at most 2 non-trivial evaluation points (x = 1, x = −1, since x = 0 is the secret). For n > 2 shares, evaluation points repeat, which reduces security. For production use, consider GF(3ᵏ) for larger fields.

### Merkle Tree

```
leaf_hash = ternary_hash(data)
parent_hash = ternary_hash(left_child ∥ right_child)
root = recursive root hash
```

**Inclusion proof:** Given a leaf and its O(log n) sibling hashes, verify membership by recomputing the root.

**Complexity:** Tree construction O(n). Inclusion proof O(log n) hashes. Proof verification O(log n).

## Quick Start

```rust
use ternary_cipher::*;

// One-time pad
let msg = TernaryMessage::new(vec![1, 0, -1, 1, 0, -1]);
let key = TernaryKey::new(vec![0, 1, -1, 1, 0, 1]);
let ct = one_time_pad_encrypt(&msg, &key);
let pt = one_time_pad_decrypt(&ct, &key);
assert_eq!(pt, msg);

// Feistel cipher (2 rounds)
let fmsg = TernaryMessage::new(vec![1, 0, -1, 1]);
let keys = vec![TernaryKey::new(vec![1, 0]), TernaryKey::new(vec![-1, 1])];
let sbox = TernarySbox::invert();
let encrypted = feistel_encrypt(&fmsg, &keys, &sbox);
let decrypted = feistel_decrypt(&encrypted, &keys, &sbox);
assert_eq!(decrypted, fmsg);

// Shamir secret sharing (threshold 2 of 3)
let secret = 1;
let shares = shamir_share(secret, 2, 3);
let reconstructed = shamir_reconstruct(&shares[0..2]);
assert_eq!(reconstructed, secret);

// Merkle tree
let leaves = vec![vec![1, 0], vec![-1, 1], vec![0, 0], vec![1, -1]];
let root = merkle_root(&leaves);
let proof = merkle_proof(&leaves, 0);
assert!(verify_merkle_proof(root, ternary_hash(&leaves[0]), &proof));
```

```bash
cargo add ternary-cipher
```

## API

| Function / Type | Complexity | Description |
|---|---|---|
| `ternary_add(a, b)` | O(1) | Addition mod 3 |
| `ternary_sub(a, b)` | O(1) | Subtraction mod 3 |
| `ternary_mul(a, b)` | O(1) | Multiplication mod 3 |
| `xor_ternary(a, b)` | O(1) | Z₃ XOR equivalent |
| `TernaryKey` / `TernaryMessage` | — | Sanitized wrappers for Vec<i8> |
| `one_time_pad_encrypt/decrypt` | O(n) | Shannon-perfect OTP |
| `TernarySbox::identity/invert` | O(1) | Substitution box lookups |
| `feistel_encrypt/decrypt` | O(r·n/2) | r-round Feistel cipher |
| `ternary_hash` | O(n) | Lightweight ternary hash |
| `commitment_scheme/verify_commitment` | O(1) | Hash-based commitments |
| `shamir_share/reconstruct` | O(n·k) / O(k²) | Threshold secret sharing over GF(3) |
| `merkle_tree/root/proof/verify` | O(n) / O(log n) | Merkle tree with inclusion proofs |

## Architecture Notes

Ternary Cipher provides the cryptographic foundation for secure agent communication in **SuperInstance**. In the **γ + η = C** framework, encryption preserves the conservation invariant during transmission: the ternary sum of the plaintext is preserved through the one-time pad as Σ(m) = Σ(c) − Σ(k), maintaining C across the channel. The Feistel cipher's invertibility ensures that information is neither created nor destroyed — only permuted and substituted — conserving total information content.

Integrates with:
- `superinstance-protocol` — encrypted bottle payloads
- `ternary-command` — authenticated command dispatch
- `ternary-blockchain` — Merkle tree commitments for state

## References

1. Shannon, C. E. (1949). "Communication Theory of Secrecy Systems." *Bell System Technical Journal*, 28(4), 656–715. — Perfect secrecy and the OTP.
2. Shamir, A. (1979). "How to Share a Secret." *Communications of the ACM*, 22(11), 612–613. — Threshold secret sharing.
3. Luby, M. & Rackoff, C. (1988). "How to Construct Pseudorandom Permutations from Pseudorandom Functions." *SIAM Journal on Computing*, 17(2), 373–386. — Feistel security proof.
4. Lidl, R. & Niederreiter, H. (1997). *Finite Fields* (2nd ed.). Cambridge University Press. — GF(3) theory.
5. Merkle, R. C. (1987). "A Digital Signature Based on a Conventional Encryption Function." *CRYPTO '87*. — Merkle trees.
6. Stinson, D. R. (2005). *Cryptography: Theory and Practice* (3rd ed.). Chapman & Hall/CRC.

## License

MIT
