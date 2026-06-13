# Ternary Cipher

**Ternary Cipher** implements cryptographic primitives over Z₃ — one-time pads, Feistel ciphers, hash commitments, Shamir secret sharing, and Merkle trees using ternary arithmetic modulo 3.

## Why It Matters

Binary cryptography (AES, SHA-256) is ubiquitous, but ternary computation hardware is emerging. Ternary cipher primitives provide the foundation for a future where ternary processors handle both computation and cryptography natively, without binary conversion. Even on binary hardware, ternary ciphers offer information-theoretic security properties: the ternary one-time pad is provably secure with key length equal to message length, and ternary Shamir secret sharing distributes trust among participants using polynomial interpolation over GF(3).

## How It Works

### Ternary Arithmetic (Z₃)

All operations are modulo 3, mapping {-1, 0, +1} to {2, 0, 1} in GF(3):

```
add(a, b) = (a + b + 3) mod 3 → map back to {-1, 0, +1}
sub(a, b) = add(a, -b)
mul(a, b) = (a × b) mod 3
xor(a, b) = add(a, b)   // XOR equivalent in Z₃
```

All arithmetic: **O(1)** per operation.

### One-Time Pad

```
encrypt(plaintext, key):
    ciphertext[i] = ternary_add(plaintext[i], key[i])

decrypt(ciphertext, key):
    plaintext[i] = ternary_sub(ciphertext[i], key[i])
```

Security: information-theoretic (Shannon-perfect) when key is truly random and used once. Encrypt/decrypt: **O(N)** for N trits. Key must equal message length.

### Feistel Cipher

Multi-round Feistel network with ternary round functions:

```
L_{i+1} = R_i
R_{i+1} = L_i ⊕ F(R_i, K_i)    // ⊕ = ternary add mod 3
```

Each round: **O(N/2)** for N-bit half-block. r rounds: **O(r × N/2)**. Security depends on round function F quality.

### Shamir Secret Sharing

Split secret S into n shares, any k of which reconstruct S:

```
Share_i = f(i)   where f(x) = S + a₁x + a₂x² + ... + a_{k-1}x^{k-1} (mod 3)

Reconstruction: Lagrange interpolation over k points in GF(3)
```

Share generation: **O(n × k)** polynomial evaluations. Reconstruction: **O(k²)** for k shares.

### Hash Commitment

```
commit(message) → (commitment, nonce)
    nonce = random ternary vector
    commitment = ternary_hash(message ∥ nonce)

verify(message, nonce, commitment):
    return hash(message ∥ nonce) == commitment
```

Binding: infeasible to find different (message, nonce) matching commitment. Cost: **O(N)** per hash.

### Merkle Tree

Binary (or ternary) tree of hash commitments:

```
leaf_hash = ternary_hash(data)
parent_hash = ternary_hash(left_child ∥ right_child)
root = root hash of the tree
```

Proof of inclusion: **O(log N)** hash verifications for N leaves. Tree construction: **O(N)**.

## Quick Start

```rust
use ternary_cipher::{ternary_add, ternary_sub, TernaryKey};

let plaintext = vec![-1, 0, 1, 1, 0, -1];
let key = TernaryKey::new(vec![1, -1, 0, 1, 1, 0]);

let encrypted: Vec<i8> = plaintext.iter().zip(&key.values)
    .map(|(&p, &k)| ternary_add(p, k)).collect();
let decrypted: Vec<i8> = encrypted.iter().zip(&key.values)
    .map(|(&c, &k)| ternary_sub(c, k)).collect();

assert_eq!(plaintext, decrypted);
```

## API

| Function | Complexity | Description |
|----------|------------|-------------|
| `ternary_add(a, b)` | O(1) | Addition mod 3 |
| `ternary_sub(a, b)` | O(1) | Subtraction mod 3 |
| `ternary_mul(a, b)` | O(1) | Multiplication mod 3 |
| `xor_ternary(a, b)` | O(1) | Z₃ XOR equivalent |
| `TernaryKey` | — | Key wrapper with sanitization |
| OTP encrypt/decrypt | O(N) | One-time pad |
| Feistel cipher | O(r·N/2) | Multi-round Feistel |
| Shamir sharing | O(n·k) | Threshold secret sharing |
| Merkle tree | O(N) | Inclusion proofs |

## Architecture Notes

Ternary Cipher provides the cryptographic layer for secure agent communication in SuperInstance. In γ + η = C, encryption protects the conservation invariant during transmission — the ternary sum of the plaintext equals the ternary sum of the ciphertext plus key, preserving C. Integrates with `superinstance-protocol` for encrypted bottle payloads and `ternary-command` for authenticated command dispatch.

See [ARCHITECTURE.md](https://github.com/SuperInstance/SuperInstance/blob/main/ARCHITECTURE.md) for security architecture.

## References

1. Shannon, C. E. (1949). "Communication Theory of Secrecy Systems." *Bell System Technical Journal*, 28(4), 656–715.
2. Shamir, A. (1979). "How to Share a Secret." *Communications of the ACM*, 22(11), 612–613.
3. Stinson, D. R. (2005). *Cryptography: Theory and Practice*, 3rd ed. Chapman & Hall/CRC.

## License

MIT
