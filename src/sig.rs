//! RSA Sign and Verify
//!
//! Signature Generation
//! We can generate a signature using RSA via the same deciphering process (m = c^d mod n),
//! except that the ciphertext will be the hash of the message:
//! s = h^d mod n, where h = SHA3-512(message)
//!
//! Signature Verification
//! Given a signature `s`, we can verify that it was actually signed by the holder of the 
//! private key `d` by verifying it with the corresponding public key `e`. This is done
//! computing h' = s^e mod n
//! 
//! The signature is valid iff h' = h.

use num_bigint::BigUint;
use sha3::{Sha3_512, Digest};

/// s = h^d mod n
pub fn sign(message: &[u8], n: &BigUint, d: &BigUint) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    let message_digest = hasher.finalize();
    let message_digest = BigUint::from_bytes_be(&message_digest);
    
    let signature = message_digest.modpow(d, n).to_bytes_be();

    signature
}

/// h' = s^e mod n
pub fn verify(message: &[u8], signature: &[u8], n: &BigUint, e: &BigUint) -> bool {
    let mut hasher = Sha3_512::new();
    hasher.update(message);
    let message_digest = hasher.finalize();
    let message_digest = BigUint::from_bytes_be(&message_digest);

    let signature = BigUint::from_bytes_be(signature);
    if signature >= *n { return false; }

    // h' = s^e mod n
    let message_digest_prime = signature.modpow(e, n);
    
    // check if h = h'
    message_digest == message_digest_prime 
}