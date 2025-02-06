//! RSA cipher, decipher, OAEP padding and OAEP unpadding
//!
//! message -> padding -> cipher -> ciphertext
//! ciphertext -> decipher -> unpadd -> message
//!
//! Ciphering a message: c = m^e mod n
//! Deciphering a cipher: m = m^d mod n
//!
//! Padding and unpadding rely on the cancelling property of XORing something twice

use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};

// the default value for the OAEP label is an empty string
pub const LABEL: &[u8] = &[0x21];

/// message to ciphertext
/// c = m^e mod n
pub fn cipher(message: &[u8], n: &BigUint, e: &BigUint) -> Result<Vec<u8>, &'static str> {
    let message = BigUint::from_bytes_be(message);

    if message >= *n {
        return Err("message lenght must be < than n");
    }

    let ciphertext = (message.modpow(e, n)).to_bytes_be();

    Ok(ciphertext)
}

/// ciphertext to message
/// m = c^d mod n
pub fn decipher(ciphertext: &[u8], n: &BigUint, d: &BigUint) -> Result<Vec<u8>, &'static str> {
    let ciphertext = BigUint::from_bytes_be(ciphertext);

    if ciphertext >= *n {
        return Err("ciphertext lenght must be < than n");
    }

    let mut message = (ciphertext.modpow(d, n)).to_bytes_be();

    if message.len() < (n.bits() as usize + 7) / 8 {
        let mut padded = vec![0; 1];
        padded.extend(message);
        message = padded;
    }

    Ok(message)
}

/// A Mask Generation Function is similar to a hash function, except that it's
/// output lenght is arbitrary within it's bounds and can be passed as a parameter.
/// This means you can extend a mask over the entirety of the message, thus spreading
/// entropy over the entire message.
fn mgf1(seed: &[u8], lenght: usize) -> Vec<u8> {
    let mut t = Vec::new();
    let mut count = 0u32;

    while t.len() < lenght {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&count.to_be_bytes());
        t.extend_from_slice(&hasher.finalize());
        count += 1;
    }

    t.truncate(lenght);

    t
}

pub fn oaep_pad(message: &[u8], label: &[u8], k: usize) -> Result<Vec<u8>, &'static str> {
    // since we're using SHA-256, the hash lenght is 32 bytes
    let hash_len = 32;

    // the maximum lenght of the message is
    // message_len <= k - 2 * hash_len - 2, where
    // k := RSA lenght (mod n)
    // hash_len := lenght of hash function output
    let max_message_len = k - 2 * hash_len - 2;

    if message.len() > max_message_len {
        return Err(
            "Message is {message.len()} bytes long. The maximum lenght is {max_message_len} bytes.",
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(label);
    let label_hash = hasher.finalize();

    // datablock := label_hash || PS (0's) || 0x01 || Message
    let mut db = Vec::with_capacity(k - hash_len - 1);
    db.extend_from_slice(&label_hash);
    db.extend(vec![0u8; k - message.len() - 2 * hash_len - 2]);
    db.push(0x01);
    db.extend_from_slice(message);

    let mut seed = vec![0u8; hash_len];
    rand::thread_rng().fill_bytes(&mut seed);

    let db_mask = mgf1(&seed, k - hash_len - 1);
    let mut masked_db = db.clone();
    // bitwise XOR between DB and MGF'ed seed
    for (db_bit, mask_bit) in masked_db.iter_mut().zip(db_mask) {
        *db_bit ^= mask_bit;
    }

    let seed_mask = mgf1(&masked_db, hash_len);
    let mut masked_seed = seed.clone();
    for (seed_bit, mask_bit) in masked_seed.iter_mut().zip(seed_mask) {
        *seed_bit ^= mask_bit;
    }

    let mut encoded_message = Vec::with_capacity(k);
    encoded_message.push(0x00);
    encoded_message.extend(masked_seed);
    encoded_message.extend(masked_db);

    Ok(encoded_message)
}

pub fn oaep_unpad(encoded_message: &[u8], label: &[u8]) -> Result<Vec<u8>, &'static str> {
    let hash_len = 32;
    let k = encoded_message.len();

    if encoded_message[0] != 0 {
        return Err("Decoding error: first byte is not 0");
    }

    if k < 2 * hash_len + 2 {
        return Err("Decoding error: ?");
    }

    let seed_masked = &encoded_message[1..hash_len + 1];
    let db_masked = &encoded_message[hash_len + 1..];

    // seed unmasking [ mgf(mgf(x)) = x ]
    let seed_mask = mgf1(db_masked, hash_len);
    let mut seed = Vec::with_capacity(hash_len);
    for (seed_bit, mask_bit) in seed_masked.iter().zip(seed_mask) {
        seed.push(seed_bit ^ mask_bit);
    }

    // datablock unmasking [ mgf(mgf(x)) = x ]
    let db_mask = mgf1(&seed, k - hash_len - 1);
    let mut db = Vec::with_capacity(k - hash_len - 1);
    for (db_bit, mask_bit) in db_masked.iter().zip(db_mask) {
        db.push(db_bit ^ mask_bit);
    }

    // verify label hash
    let mut hasher = Sha256::new();
    hasher.update(label);
    let label_hash = hasher.finalize();

    if db[..hash_len] != label_hash[..] {
        return Err("Decoding error: label hashes don't match.");
    }

    // find the message
    let mut message_start = hash_len;
    while message_start < db.len() {
        if db[message_start] == 0x01 {
            message_start += 1;
            return Ok(db[message_start..].to_vec());
        }

        if db[message_start] != 0x00 {
            return Err("Decoding error: ?");
        }

        message_start += 1;
    }

    Err("Decoding error: ?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher() {
        let m0 = BigUint::from(42u32).to_bytes_be();
        let e0 = BigUint::from(17u32);
        let _d0 = BigUint::from(2753u32);
        let n0 = BigUint::from(3233u32);
        let c0 = BigUint::from(2557u32);
        assert_eq!(cipher(&m0, &n0, &e0).unwrap(), c0.to_bytes_be());

        let m1 = BigUint::from(3232u32).to_bytes_be();
        let e1 = BigUint::from(17u32);
        let _d1 = BigUint::from(2753u32);
        let n1 = BigUint::from(3233u32);
        let c1 = BigUint::from(3232u32);
        assert_eq!(cipher(&m1, &n1, &e1).unwrap(), c1.to_bytes_be());

        // must return an Err (m > n)
        let m2 = BigUint::from(3235u32).to_bytes_be();
        let e2 = BigUint::from(17u32);
        let _d2 = BigUint::from(2753u32);
        let n2 = BigUint::from(3233u32);
        let _c2 = BigUint::from(3232u32);
        assert!(cipher(&m2, &n2, &e2).is_err());
    }

    #[test]
    fn test_decipher() {
        let c0 = BigUint::from(2557u32).to_bytes_be();
        let d0 = BigUint::from(2753u32);
        let n0 = BigUint::from(3233u32);
        let m0 = BigUint::from(42u32);
        assert_eq!(decipher(&c0, &n0, &d0).unwrap(), m0.to_bytes_be());

        let c1 = BigUint::from(3232u32).to_bytes_be();
        let d1 = BigUint::from(2753u32);
        let n1 = BigUint::from(3233u32);
        let m1 = BigUint::from(3232u32);
        assert_eq!(decipher(&c1, &n1, &d1).unwrap(), m1.to_bytes_be());

        // must return an Err (c > n)
        let c0 = BigUint::from(5000u32).to_bytes_be();
        let d0 = BigUint::from(2753u32);
        let n0 = BigUint::from(3233u32);
        let _m0 = BigUint::from(42u32);
        assert!(decipher(&c0, &n0, &d0).is_err());
    }

    #[test]
    fn test_pad_unpad() {
        let msg = b"test";
        let label = b"label";
        let k = 128;

        let padded = oaep_pad(msg, label, k).unwrap();
        assert_eq!(padded.len(), k);
        let unpadded = oaep_unpad(&padded, label).unwrap();
        assert_eq!(unpadded, msg);
    }
}
