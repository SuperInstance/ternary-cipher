# ternary-cipher

**Secrets in three symbols. Encryption, commitment, Shamir sharing, and Merkle trees over Z₃.**

Most cryptography assumes binary: every bit is 0 or 1. But Z₃ — the integers modulo 3 — is also a field, and every binary cryptographic primitive has a ternary analog. XOR becomes addition mod 3 (with subtraction for decryption). Binary S-boxes become ternary substitution tables. Binary Shamir becomes polynomial interpolation over GF(3).

This crate implements the full stack: ternary one-time pads (additive ciphers with perfect secrecy), Feistel networks (multi-round block ciphers with S-box diffusion), hash-based commitments (bind to a value without revealing it), Shamir's secret sharing (split a secret into shares, reconstruct from a threshold), and Merkle trees (authenticated data structures over ternary hashes).

## What's Inside

- **`ternary_add/sub/mul`** — arithmetic in Z₃
- **`TernaryKey`, `TernaryMessage`** — key and message types
- **`one_time_pad_encrypt/decrypt`** — perfect secrecy with additive cipher
- **`TernarySbox`** — substitution boxes (identity, invert)
- **`feistel_encrypt/decrypt`** — multi-round Feistel block cipher
- **`ternary_hash(input)`** — rotate-XOR-accumulate hash function
- **`commitment_scheme/verify_commitment`** — hash-based commitment binding
- **`shamir_share/reconstruct`** — threshold secret sharing over GF(3)
- **`merkle_tree/root/proof`** — Merkle tree with proof generation and verification

## Quick Example

```rust
use ternary_cipher::*;

// One-time pad
let msg = TernaryMessage::new(vec![1, 0, -1, 1]);
let key = TernaryKey::new(vec![0, 1, -1, 1]);
let ct = one_time_pad_encrypt(&msg, &key);
let pt = one_time_pad_decrypt(&ct, &key);
assert_eq!(pt, msg);

// Shamir's secret sharing
let secret = 1;
let shares = shamir_share(secret, 2, 3); // 2-of-3
let reconstructed = shamir_reconstruct(&shares[0..2]);
assert_eq!(reconstructed, secret);

// Merkle tree
let leaves = vec![vec![1, 0], vec![-1, 1], vec![0, 0], vec![1, -1]];
let root = merkle_root(&leaves);
let proof = merkle_proof(&leaves, 0);
assert!(verify_merkle_proof(root, ternary_hash(&leaves[0]), &proof));
```

## The Deeper Truth

**Z₃ cryptography is information-theoretically identical to binary cryptography, but algebraically richer.** Every primitive that exists in binary (one-time pads, Feistel ciphers, Shamir sharing, Merkle trees) has an exact analog over GF(3). The algebraic structure is richer because GF(3) has three elements instead of two, meaning every polynomial has one more degree of freedom.

The one-time pad over Z₃ achieves perfect secrecy by the same argument as Shannon's original proof: if the key is uniformly random over {-1, 0, 1}, the ciphertext reveals nothing about the message. The difference is that each ternary symbol carries log₂(3) ≈ 1.585 bits of information — 58.5% more efficient per symbol than binary.

Shamir's secret sharing over GF(3) is particularly elegant: a secret is encoded as the constant term of a random polynomial of degree (threshold-1). Each share is a point (x, f(x)). To reconstruct, you perform Lagrange interpolation — which in GF(3) requires computing modular inverses (1⁻¹ = 1, -1⁻¹ = -1, 0 has no inverse). This is simpler than the GF(2⁸) arithmetic used in real implementations.

**Use cases:**
- **Post-quantum exploration** — ternary crypto may have different quantum vulnerability profiles
- **Educational cryptography** — every primitive is small enough to compute by hand
- **Ternary communication** — encrypt ternary channels without converting to binary
- **Multi-party computation** — Shamir sharing for ternary-valued secrets
- **Agent trust** — commitment schemes and Merkle proofs for fleet verification

## See Also

- **ternary-codes** — error-correcting codes over Z₃
- **ternary-hash** — dedicated hash functions
- **ternary-ring** — algebraic foundations (GF(3))
- **ternary-trust** — trust mechanisms using cryptographic primitives
- **ternary-protocol** — secure communication protocols
- **ternary-consensus** — Byzantine agreement using Shamir sharing

## Install

```bash
cargo add ternary-cipher
```

## License

MIT
