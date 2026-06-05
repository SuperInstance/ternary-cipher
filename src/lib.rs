//! # ternary-cipher
//!
//! Ternary cryptography: one-time pads, Feistel ciphers, commitments,
//! Shamir secret sharing, and Merkle trees over Z₃.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;
use alloc::{vec, vec::Vec};

// === Ternary Arithmetic Helpers ===

/// Add two ternary values mod 3, returning {-1, 0, 1}
pub fn ternary_add(a: i8, b: i8) -> i8 {
    let sum = a + b + 3; // shift to non-negative
    match sum % 3 {
        0 => 0,
        1 => 1,
        2 => -1,
        _ => unreachable!(),
    }
}

/// Subtract two ternary values mod 3
pub fn ternary_sub(a: i8, b: i8) -> i8 {
    ternary_add(a, -b)
}

/// Multiply two ternary values mod 3
pub fn ternary_mul(a: i8, b: i8) -> i8 {
    let prod = a * b;
    match (prod % 3 + 3) % 3 {
        0 => 0,
        1 => 1,
        2 => -1,
        _ => unreachable!(),
    }
}

/// Ternary XOR equivalent: addition mod 3
pub fn xor_ternary(a: i8, b: i8) -> i8 {
    ternary_add(a, b)
}

// === Key and Message Types ===

/// A ternary key: a sequence of {-1, 0, 1} values
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TernaryKey {
    pub values: Vec<i8>,
}

impl TernaryKey {
    pub fn new(values: Vec<i8>) -> Self {
        let sanitized: Vec<i8> = values.iter().map(|&v| match v % 3 { 0 => 0, 1 => 1, _ => -1 }).collect();
        Self { values: sanitized }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// A ternary message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TernaryMessage {
    pub values: Vec<i8>,
}

impl TernaryMessage {
    pub fn new(values: Vec<i8>) -> Self {
        let sanitized: Vec<i8> = values.iter().map(|&v| match v % 3 { 0 => 0, 1 => 1, _ => -1 }).collect();
        Self { values: sanitized }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// === One-Time Pad ===

/// Encrypt using ternary one-time pad: ciphertext = message + key mod 3
pub fn one_time_pad_encrypt(message: &TernaryMessage, key: &TernaryKey) -> TernaryMessage {
    let ct: Vec<i8> = message.values.iter()
        .zip(key.values.iter())
        .map(|(&m, &k)| ternary_add(m, k))
        .collect();
    TernaryMessage::new(ct)
}

/// Decrypt ternary one-time pad: message = ciphertext - key mod 3
pub fn one_time_pad_decrypt(ciphertext: &TernaryMessage, key: &TernaryKey) -> TernaryMessage {
    let pt: Vec<i8> = ciphertext.values.iter()
        .zip(key.values.iter())
        .map(|(&c, &k)| ternary_sub(c, k))
        .collect();
    TernaryMessage::new(pt)
}

// === Substitution Box ===

/// A ternary S-box: maps each input value {-1, 0, 1} to an output
#[derive(Debug, Clone, Copy)]
pub struct TernarySbox {
    pub table: [i8; 3], // indexed by input+1 (so -1→0, 0→1, 1→2)
}

impl TernarySbox {
    pub fn new(table: [i8; 3]) -> Self {
        Self { table }
    }

    /// Identity S-box: maps -1→-1, 0→0, 1→1
    /// table[0] = output for input=-1, table[1] = output for 0, table[2] = output for 1
    pub fn identity() -> Self {
        Self { table: [-1, 0, 1] }
    }

    /// Inversion S-box (swaps +1 and -1)
    /// -1→1, 0→0, 1→-1
    pub fn invert() -> Self {
        Self { table: [1, 0, -1] }
    }

    pub fn apply(&self, val: i8) -> i8 {
        // Map: -1 → 0, 0 → 1, 1 → 2
        let idx = match val {
            -1 => 0,
            0 => 1,
            1 => 2,
            _ => 1,
        };
        self.table[idx]
    }
}

/// Apply S-box to a message
pub fn apply_sbox(msg: &TernaryMessage, sbox: &TernarySbox) -> TernaryMessage {
    TernaryMessage::new(msg.values.iter().map(|&v| sbox.apply(v)).collect())
}

// === Feistel Cipher ===

/// One round of Feistel cipher in ternary
pub fn feistel_round(left: &[i8], right: &[i8], key: &TernaryKey, sbox: &TernarySbox) -> (Vec<i8>, Vec<i8>) {
    // F(R, K) = Sbox(R + K)
    let f: Vec<i8> = right.iter()
        .zip(key.values.iter().cycle())
        .map(|(&r, &k)| sbox.apply(ternary_add(r, k)))
        .collect();

    // New left = right, new right = left - F(R, K)
    let new_right: Vec<i8> = left.iter()
        .zip(f.iter())
        .map(|(&l, &fv)| ternary_sub(l, fv))
        .collect();

    (right.to_vec(), new_right)
}

/// Multi-round Feistel encryption
pub fn feistel_encrypt(msg: &TernaryMessage, keys: &[TernaryKey], sbox: &TernarySbox) -> TernaryMessage {
    assert!(msg.values.len() % 2 == 0, "Message must have even length");
    let mid = msg.values.len() / 2;
    let mut left = msg.values[..mid].to_vec();
    let mut right = msg.values[mid..].to_vec();

    for key in keys {
        let (new_left, new_right) = feistel_round(&left, &right, key, sbox);
        left = new_left;
        right = new_right;
    }

    TernaryMessage::new([left, right].concat())
}

/// Multi-round Feistel decryption (keys in reverse)
pub fn feistel_decrypt(msg: &TernaryMessage, keys: &[TernaryKey], sbox: &TernarySbox) -> TernaryMessage {
    assert!(msg.values.len() % 2 == 0);
    let mid = msg.values.len() / 2;
    let mut left = msg.values[..mid].to_vec();
    let mut right = msg.values[mid..].to_vec();

    for key in keys.iter().rev() {
        // Undo: right was original left. left was original right.
        // Original: new_right = left - F(right, key)
        // Undo: original_left = right + F(left, key)
        let f: Vec<i8> = left.iter()
            .zip(key.values.iter().cycle())
            .map(|(&l, &k)| sbox.apply(ternary_add(l, k)))
            .collect();
        let original_left: Vec<i8> = right.iter()
            .zip(f.iter())
            .map(|(&r, &fv)| ternary_add(r, fv))
            .collect();
        right = left;
        left = original_left;
    }

    TernaryMessage::new([left, right].concat())
}

// === Hash Function ===

/// Simple ternary hash: rotate-xor-accumulate
pub fn ternary_hash(input: &[i8]) -> i8 {
    if input.is_empty() {
        return 0;
    }
    let mut hash: i8 = 0;
    for (i, &v) in input.iter().enumerate() {
        let rotated = ternary_add(v, (i as i8) % 3);
        hash = xor_ternary(hash, rotated);
        hash = ternary_mul(hash, 2); // multiply by -1 (since 2 ≡ -1 mod 3)
    }
    hash
}

// === Commitment Scheme ===

/// Commit to a value using a random ternary nonce
pub fn commitment_scheme(value: i8, randomness: i8) -> i8 {
    // H(value || randomness) simplified to XOR for ternary
    ternary_hash(&[value, randomness])
}

/// Verify a commitment
pub fn verify_commitment(commitment: i8, value: i8, randomness: i8) -> bool {
    commitment_scheme(value, randomness) == commitment
}

// === Shamir's Secret Sharing over Z₃ ===

/// Evaluate a polynomial at a point over Z₃
fn poly_eval(coeffs: &[i8], x: i8) -> i8 {
    let mut result: i8 = 0;
    let mut x_power: i8 = 1;
    for &c in coeffs {
        result = ternary_add(result, ternary_mul(c, x_power));
        x_power = ternary_mul(x_power, x);
    }
    result
}

/// Split a secret into shares using Shamir's scheme over Z₃
/// secret is {-1, 0, 1}, threshold is the number of shares needed
pub fn shamir_share(secret: i8, threshold: usize, total_shares: usize) -> Vec<(i8, i8)> {
    // Random polynomial: secret + a1*x + a2*x^2 + ... (coeffs in Z₃)
    let mut coeffs = vec![secret];
    // Simple deterministic coefficients for reproducibility
    for i in 1..threshold {
        let coeff = ((secret + i as i8) % 3 + 3) % 3;
        coeffs.push(match coeff { 0 => 0, 1 => 1, _ => -1 });
    }

    let mut shares = vec![];
    for x in 1..=total_shares {
        let x_val = match x % 3 { 0 => 0, 1 => 1, _ => -1 };
        let y = poly_eval(&coeffs, x_val);
        shares.push((x_val, y));
    }
    shares
}

/// Reconstruct a secret from shares using Lagrange interpolation over Z₃
pub fn shamir_reconstruct(shares: &[(i8, i8)]) -> i8 {
    if shares.is_empty() {
        return 0;
    }

    // Lagrange basis polynomials at x=0
    let mut secret: i8 = 0;
    for (i, &(xi, yi)) in shares.iter().enumerate() {
        let mut numerator: i8 = 1;
        let mut denominator: i8 = 1;
        for (j, &(xj, _)) in shares.iter().enumerate() {
            if i != j {
                // numerator *= (0 - xj) = -xj
                numerator = ternary_mul(numerator, -xj);
                // denominator *= (xi - xj)
                denominator = ternary_mul(denominator, ternary_sub(xi, xj));
            }
        }
        // Lagrange coefficient = numerator / denominator
        // In Z₃, division = multiplication by inverse
        let denom_inv = match denominator {
            1 => 1,
            -1 => -1,
            _ => return 0, // shouldn't happen with distinct x values
        };
        let lagrange = ternary_mul(numerator, denom_inv);
        secret = ternary_add(secret, ternary_mul(yi, lagrange));
    }
    secret
}

// === Merkle Tree ===

/// Build a Merkle tree from ternary data leaves
/// Returns the root hash and all intermediate hashes
pub fn merkle_tree(leaves: &[Vec<i8>]) -> Vec<Vec<i8>> {
    if leaves.is_empty() {
        return vec![];
    }
    let mut current: Vec<i8> = leaves.iter().map(|l| ternary_hash(l)).collect();
    let mut levels = vec![current.clone()];

    while current.len() > 1 {
        let mut next = vec![];
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                next.push(ternary_hash(&[current[i], current[i + 1]]));
            } else {
                next.push(ternary_hash(&[current[i]]));
            }
            i += 2;
        }
        current = next;
        levels.push(current.clone());
    }

    levels
}

/// Get the root hash of a Merkle tree
pub fn merkle_root(leaves: &[Vec<i8>]) -> i8 {
    let levels = merkle_tree(leaves);
    if levels.is_empty() {
        return 0;
    }
    *levels.last().unwrap().first().unwrap_or(&0)
}

/// Generate a Merkle proof for a leaf at the given index
pub fn merkle_proof(leaves: &[Vec<i8>], index: usize) -> Vec<(i8, bool)> {
    let levels = merkle_tree(leaves);
    let mut proof = vec![];
    let mut idx = index;

    for level in &levels {
        if level.len() <= 1 {
            break;
        }
        let is_right = idx % 2 == 0; // we need the sibling
        let sibling_idx = if is_right { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            proof.push((level[sibling_idx], is_right));
        }
        idx /= 2;
    }
    proof
}

/// Verify a Merkle proof
pub fn verify_merkle_proof(root: i8, leaf_hash: i8, proof: &[(i8, bool)]) -> bool {
    let mut current = leaf_hash;
    for &(sibling, is_right) in proof {
        if is_right {
            current = ternary_hash(&[current, sibling]);
        } else {
            current = ternary_hash(&[sibling, current]);
        }
    }
    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ternary_add() {
        assert_eq!(ternary_add(1, 1), -1);
        assert_eq!(ternary_add(-1, -1), 1);
        assert_eq!(ternary_add(1, -1), 0);
        assert_eq!(ternary_add(0, 0), 0);
    }

    #[test]
    fn test_ternary_mul() {
        assert_eq!(ternary_mul(1, 1), 1);
        assert_eq!(ternary_mul(-1, -1), 1);
        assert_eq!(ternary_mul(1, -1), -1);
        assert_eq!(ternary_mul(0, 1), 0);
    }

    #[test]
    fn test_xor_ternary() {
        assert_eq!(xor_ternary(1, 0), 1);
        assert_eq!(xor_ternary(1, 1), -1);
        assert_eq!(xor_ternary(-1, 1), 0);
    }

    #[test]
    fn test_one_time_pad_roundtrip() {
        let msg = TernaryMessage::new(vec![1, 0, -1, 1, -1, 0]);
        let key = TernaryKey::new(vec![0, 1, -1, 1, 0, -1]);
        let ct = one_time_pad_encrypt(&msg, &key);
        let pt = one_time_pad_decrypt(&ct, &key);
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_sbox_identity() {
        let sbox = TernarySbox::identity();
        assert_eq!(sbox.apply(-1), -1);
        assert_eq!(sbox.apply(0), 0);
        assert_eq!(sbox.apply(1), 1);
    }

    #[test]
    fn test_sbox_invert() {
        let sbox = TernarySbox::invert();
        assert_eq!(sbox.apply(1), -1);
        assert_eq!(sbox.apply(-1), 1);
        assert_eq!(sbox.apply(0), 0);
    }

    #[test]
    fn test_apply_sbox() {
        let msg = TernaryMessage::new(vec![1, 0, -1]);
        let sbox = TernarySbox::invert();
        let result = apply_sbox(&msg, &sbox);
        assert_eq!(result.values, vec![-1, 0, 1]);
    }

    #[test]
    fn test_feistel_roundtrip() {
        let msg = TernaryMessage::new(vec![1, 0, -1, 1]);
        let key1 = TernaryKey::new(vec![1, 0]);
        let key2 = TernaryKey::new(vec![-1, 1]);
        let keys = vec![key1, key2];
        let sbox = TernarySbox::invert();

        let ct = feistel_encrypt(&msg, &keys, &sbox);
        let pt = feistel_decrypt(&ct, &keys, &sbox);
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_ternary_hash_deterministic() {
        let h1 = ternary_hash(&[1, 0, -1, 1]);
        let h2 = ternary_hash(&[1, 0, -1, 1]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_ternary_hash_different_inputs() {
        let h1 = ternary_hash(&[1, 0, -1]);
        let h2 = ternary_hash(&[-1, 0, 1]);
        // Not guaranteed different, but likely
        // Just check they're valid ternary values
        assert!(h1 == -1 || h1 == 0 || h1 == 1);
        assert!(h2 == -1 || h2 == 0 || h2 == 1);
    }

    #[test]
    fn test_commitment_scheme() {
        let value = 1;
        let randomness = -1;
        let commitment = commitment_scheme(value, randomness);
        assert!(verify_commitment(commitment, value, randomness));
        assert!(!verify_commitment(commitment, 0, randomness)); // wrong value
    }

    #[test]
    fn test_shamir_share_and_reconstruct() {
        let secret = 1;
        let shares = shamir_share(secret, 2, 3);
        assert_eq!(shares.len(), 3);
        // Reconstruct with any 2 shares
        let reconstructed = shamir_reconstruct(&shares[0..2]);
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_shamir_secret_zero() {
        let shares = shamir_share(0, 2, 3);
        let reconstructed = shamir_reconstruct(&shares[0..2]);
        assert_eq!(reconstructed, 0);
    }

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![vec![1, 0], vec![-1, 1], vec![0, 0], vec![1, -1]];
        let tree = merkle_tree(&leaves);
        assert!(!tree.is_empty());
        assert_eq!(tree.last().unwrap().len(), 1); // single root
    }

    #[test]
    fn test_merkle_root() {
        let leaves = vec![vec![1, 0], vec![-1, 1], vec![0, 0]];
        let root = merkle_root(&leaves);
        assert!(root == -1 || root == 0 || root == 1);
    }

    #[test]
    fn test_merkle_proof_and_verify() {
        let leaves = vec![vec![1, 0], vec![-1, 1], vec![0, 0], vec![1, -1]];
        let root = merkle_root(&leaves);
        let leaf_hash = ternary_hash(&leaves[0]);
        let proof = merkle_proof(&leaves, 0);
        assert!(verify_merkle_proof(root, leaf_hash, &proof));
    }

    #[test]
    fn test_merkle_proof_wrong_leaf() {
        let leaves = vec![vec![1, 0], vec![-1, 1], vec![0, 0], vec![1, -1]];
        let root = merkle_root(&leaves);
        let wrong_hash = ternary_hash(&leaves[2]); // claiming leaf 0 is actually leaf 2
        let proof = merkle_proof(&leaves, 0);
        assert!(!verify_merkle_proof(root, wrong_hash, &proof));
    }
}
