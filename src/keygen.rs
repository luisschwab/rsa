//! RSA key generation
//!
//! Choose two integers, `p` and `q`, such that they are prime, large, and `p` != `q`.
//!
//! Derive `n`, the modulus, such that `n` = `p` * `q`.
//!
//! Calulate Euler's totient function (the number of positive integers up to `n` that
//! a coprime to `n`. `a` and `b` are coprimes if their Greatest Common Divisor is 1) of `n`,
//! φ(n). This can be calculated by this formula: `φ(n)` = `(p-1)` × `(q-1)`.
//!
//! Choose a public exponent `e`, which must be coprime to φ(n), larger than 1 and smallet than φ(n) (usually
//! set to `2^16 + 1`).
//!
//! Calculate the private exponent `d`, such that (`d` * `e`) mod `φ(n)` = 1, by extended Euclidean algorithm.
//!
//! We end up with:
//!   - Pubkey: (n, e)
//!   - Privkey: (n, d)

const PRIME_LENGHT: u64 = 512; // in bits
const ROUNDS: u32 = 64;
// `e` is defined elsewhere since rust won't allow heap-allocated constants

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::identities::{One, Zero};
use rand::thread_rng;
use std::fmt::{Display, Formatter, Result};

#[derive(Default)]
pub struct KeyPair {
    pub n: BigUint, // modulo
    pub e: BigUint, // pubkey
    pub d: BigUint, // privkey
}

impl Display for KeyPair {
    fn fmt(&self, f: &mut Formatter) -> Result {
        writeln!(f, "KeyPair {{")?;
        writeln!(f, "\tn: {:02x},", self.n)?;
        writeln!(f, "\te: {:02x},", self.e)?;
        writeln!(f, "\td: {:02x},", self.d)?;
        write!(f, "}}")
    }
}

/// Generate a `KeyPair`, with keysize of 2 * `PRIME_LENGHT`
pub fn generate_keypair() -> KeyPair {
    // usually defined as 2^16 + 1
    let e = BigUint::from(65537u32);

    let p = generate_prime();
    let q = generate_prime();

    let n = &p * &q;

    // `φ(n)` = `(p-1)` × `(q-1)`
    let phi_n = (p - BigUint::one()) * (q - BigUint::one());

    // `d` is the modular inverse of `e` mod `phi_n`
    let d = mod_inverse(&e, &phi_n).expect("err: failed to compute `d`.");

    KeyPair { n, e, d }
}

/// Generates a prime of PRIME_LENGHT bits
fn generate_prime() -> BigUint {
    let mut rng = thread_rng();

    loop {
        let mut n = rng.gen_biguint(PRIME_LENGHT);
        n |= BigUint::from(1u32);
        n |= BigUint::from(1u32) << (PRIME_LENGHT - 1);

        // perform primality test
        if miller_rabin(&n) {
            return n;
        }
    }
}

/// Determines P(prime) via the Miller-Rabin test
/// The probability of error `P(Err)` is 4^-k, where `k` is the number of rounds
fn miller_rabin(n: &BigUint) -> bool {
    let k = ROUNDS;

    if n <= &BigUint::from(1u32) {
        return false;
    }
    if n <= &BigUint::from(3u32) {
        return true;
    }
    if n.modpow(&BigUint::from(1u32), &BigUint::from(2u32)) == BigUint::from(0u32) {
        return false;
    }

    let mut r = 0u32;
    let mut d = n - BigUint::from(1u32);
    while (&d & BigUint::from(1u32)) == BigUint::from(0u32) {
        r += 1;
        d >>= 1;
    }

    let mut rng = thread_rng();
    'witness: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::from(2u32)));
        let mut x = a.modpow(&d, n);

        if x == BigUint::from(1u32) || x == n - BigUint::from(1u32) {
            continue 'witness;
        }

        for _ in 0..r - 1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n - BigUint::from(1u32) {
                continue 'witness;
            }
            if x == BigUint::from(1u32) {
                return false;
            }
        }
        return false;
    }
    true
}

/// Modular inverse (a * a^-1 (mod m) = 1)
/// Returns an Option<T> because not all numbers have an inverse
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let (mut t, mut newt) = (BigInt::from(0), BigInt::from(1));
    let (mut r, mut newr) = (BigInt::from(m.clone()), BigInt::from(a.clone()));

    while !newr.is_zero() {
        let quotient = &r / &newr;
        let tmp_t = t.clone();
        t = newt.clone();
        newt = tmp_t - &quotient * newt;

        let tmp_r = r.clone();
        r = newr.clone();
        newr = tmp_r - quotient * newr;
    }

    if r > BigInt::from(1) {
        return None;
    }

    while t < BigInt::from(0) {
        t = t + BigInt::from(m.clone());
    }

    Some(t.to_biguint().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inverse() {
        let a0 = BigUint::from(2u32);
        let m0 = BigUint::from(1000000007u32);
        let inv0 = mod_inverse(&a0, &m0);
        assert_eq!(inv0, Some(BigUint::from(500000004u32)));

        let a1 = BigUint::from(17u32);
        let m1 = BigUint::from(3120u32);
        let inv1 = mod_inverse(&a1, &m1);
        assert_eq!(inv1, Some(BigUint::from(2753u32)));

        let a2 = BigUint::from(15u32);
        let m2 = BigUint::from(45u32);
        let inv2 = mod_inverse(&a2, &m2);
        assert_eq!(inv2, None);

        let a3 = BigUint::from(14u32);
        let m3 = BigUint::from(28u32);
        let inv3 = mod_inverse(&a3, &m3);
        assert_eq!(inv3, None);
    }

    #[test]
    fn test_miller_rabin() {
        // large prime from NIST test vectors
        let p0 = BigUint::from(2305843009213693951u64);
        let b0 = true;
        assert_eq!(miller_rabin(&p0), b0);

        // large prime from NIST test vectors
        let p1 = BigUint::from(618970019642690137449562111u128);
        let b1 = true;
        assert_eq!(miller_rabin(&p1), b1);

        // Carmichael number
        let p2 = BigUint::from(25326001u32);
        let b2 = false;
        assert_eq!(miller_rabin(&p2), b2);

        // Carmichael number
        let p3 = BigUint::from(8481906873u64);
        let b3 = false;
        assert_eq!(miller_rabin(&p3), b3);

        // pseudoprime
        let p4 = BigUint::from(2152302898747u64);
        let b4 = false;
        assert_eq!(miller_rabin(&p4), b4);

        // pseudoprime
        let p5 = BigUint::from(8481906873u64);
        let b5 = false;
        assert_eq!(miller_rabin(&p5), b5);
    }
}
