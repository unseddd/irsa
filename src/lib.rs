#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use num::bigint::BigUint;
use num::{Integer, One, Zero};
use rand::thread_rng;

mod math;
mod primes;

pub use math::inv_mod_slow;

/// Default RSA public exponent (from wolfSSL: wolfssl/wolfssl/wolfcrypt/rsa.h)
pub const E: u32 = 65537;

/// Length of RSA 1024-bit modulus
pub const RSA_1024_LEN: usize = 1024;

/// Length of RSA 2048-bit modulus
pub const RSA_2048_LEN: usize = 2048;

/// Length of RSA 3072-bit modulus
pub const RSA_3072_LEN: usize = 3072;

/// Length of RSA 4096-bit modulus
pub const RSA_4096_LEN: usize = 4096;

/// RSA errors
#[derive(Debug)]
pub enum Error {
    CiphertextOutOfRange,
    IntegerOutOfRange,
    MessageOutOfRange,
    InvalidCiphertext,
    InvalidMessage,
    InvalidModulus,
    InvalidPrime,
    InvalidRsaKey,
    InvalidSize,
    InvalidXorLength,
}

/// RSA public key
pub struct RsaPublicKey {
    /// RSA public modulus, composite of private primes p and q
    pub n: BigUint,
    /// Bit-length of the RSA public modulus
    pub n_len: usize,
    /// RSA public exponent
    pub e: BigUint,
}

impl RsaPublicKey {
    /// Create a new RSA public key from a private key
    ///
    /// Alias for from_private_key
    pub fn new(key: &RsaPrivateKey) -> Result<Self, Error> {
        Self::from_private_key(&key)
    }

    /// Create a new RSA public key from a private key
    pub fn from_private_key(key: &RsaPrivateKey) -> Result<Self, Error> {
        // if in debug mode, check the private key for validity
        if cfg!(debug_assertions) {
            check_key(&key)?;
        }

        Ok(Self {
            n: key.n.clone(),
            n_len: key.n_len,
            e: key.e.clone(),
        })
    }

    /// Encrypt a message under the public key
    ///
    /// Interprets the bytes in big-endian byte order
    ///
    /// The resulting ciphertext is a BigUint in big-endian byte order
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > self.n_len {
            return Err(Error::InvalidMessage);
        }

        let msg_bn = BigUint::from_bytes_be(&message);

        if msg_bn >= self.n {
            return Err(Error::InvalidMessage);
        }

        Ok(msg_bn.modpow(&self.e, &self.n).to_bytes_be())
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    /// Implements the From trait for RsaPublicKey
    ///
    /// Panics in debug mode when RsaPrivateKey is invalid
    fn from(key: &RsaPrivateKey) -> Self {
        RsaPublicKey::from_private_key(&key).unwrap()
    }
}

/// RSA private key
pub struct RsaPrivateKey {
    /// RSA public modulus, composite of private primes p and q
    n: BigUint,
    /// Bit-length of the RSA public modulus
    n_len: usize,
    /// RSA public exponent
    e: BigUint,
    /// RSA private exponent
    d: BigUint,
    /// RSA prime 1
    p: BigUint,
    /// RSA prime 2
    q: BigUint,
    /// RSA exponent 1: d mod (p - 1)
    dp: BigUint,
    /// RSA exponent 2: d mod (q - 1)
    dq: BigUint,
    /// RSA coefficient: (inverse of q) mod p
    invq: BigUint,
}

impl RsaPrivateKey {
    /// Create a new RSA private key of a given bit-length
    ///
    /// Uses default value from wolfSSL for public exponent
    ///
    /// Size must be one of: 1024, 2048, 3072, 4096
    ///
    /// 512 is not supported, because it's way too short
    ///
    /// Based on wolfSSL implementation wc_MakeRsaKey: wolfssl/wolfcrypt/src/rsa.c
    pub fn new(size: usize) -> Result<Self, Error> {
        Self::from_exponent(E, size)
    }

    /// Create a new RSA private key from a given public exponent and bit-length
    ///
    /// Size must be one of: 1024, 2048, 3072, 4096
    ///
    /// 512 is not supported, because it's way too short
    ///
    /// Based on wolfSSL implementation wc_MakeRsaKey: wolfssl/wolfcrypt/src/rsa.c
    pub fn from_exponent(e: u32, size: usize) -> Result<Self, Error> {
        let mut e = BigUint::from_bytes_le(e.to_le_bytes().as_ref());

        length_check(size)?;

        let mut rng = thread_rng();

        let mut p = primes::generate_prime(size, &e, None, &mut rng)?;
        let mut q = primes::generate_prime(size, &e, Some(&p), &mut rng)?;

        // P must be larger than Q
        if p < q {
            // swap if P is smaller
            let mut tmp = p.clone();
            p.clone_from(&q);
            q.clone_from(&tmp);

            // clear the temporary variable
            tmp.set_zero();
        }

        let mut p1 = p.clone();
        p1 -= 1_u32;

        let mut q1 = q.clone();
        q1 -= 1_u32;

        let mut lcm = p1.lcm(&q1);

        // d = (1 / e) mod lcm(p - 1, q - 1)
        let mut d = math::inv_mod_slow(&e, &lcm)?;
        let mut n = p.clone();
        n *= &q;

        let res = Self {
            n: n.clone(),
            n_len: size,
            e: e.clone(),
            d: d.clone(),
            p: p.clone(),
            q: q.clone(),
            dp: d.mod_floor(&p1),
            dq: d.mod_floor(&q1),
            // u = 1 / q mod p
            invq: math::inv_mod_slow(&q, &p)?,
        };

        // clear temporary variables
        n.set_zero();
        e.set_zero();
        d.set_zero();
        p.set_zero();
        p1.set_zero();
        q.set_zero();
        q1.set_zero();
        lcm.set_zero();

        // Perform the pair-wise consistency test on the new key
        if cfg!(debug_assertions) {
            check_key(&res)?;
        }

        Ok(res)
    }

    /// Clear the internal variables
    pub fn clear(&mut self) {
        self.n.set_zero();
        self.n_len = 0;
        self.e.set_zero();
        self.d.set_zero();
        self.p.set_zero();
        self.q.set_zero();
        self.dp.set_zero();
        self.dq.set_zero();
        self.invq.set_zero();
    }

    /// Decrypt a ciphertext under this private key
    ///
    /// Interprets the ciphertext as BigUint bytes in big-endian order
    ///
    /// The resulting message is in big-endian byte order
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() > self.n_len {
            return Err(Error::InvalidCiphertext);
        }

        let ciph_bn = BigUint::from_bytes_be(&ciphertext);

        if ciph_bn >= self.n {
            return Err(Error::InvalidCiphertext);
        }

        // m_1 = c**dP mod P
        let mut m1 = ciph_bn.modpow(&self.dp, &self.p);
        // m_2 = c**dQ mod Q
        let mut m2 = ciph_bn.modpow(&self.dq, &self.q);

        // h = ((m_1 - m_2) * qInv) mod p
        m1 -= &m2;
        m1 *= &self.invq;
        m1 = m1.mod_floor(&self.p);

        // m = m_2 + q * h
        m1 *= &self.q;
        m1 += &m2;

        // clear the temp m2
        m2.set_zero();

        let res = m1.to_bytes_be();

        // clear the temp m1
        m1.set_zero();

        Ok(res)
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}
/* From wolfSSL: wolfssl/wolfcrypt/src/rsa.c
 *
 * Check the pair-wise consistency of the RSA key.
 * From NIST SP 800-56B, section 6.4.1.1.
 * Verify that k = (k^e)^d, for some k: 1 < k < n-1. */
pub fn check_key(key: &RsaPrivateKey) -> Result<(), Error> {
    length_check(key.n_len)?;

    let mut k = BigUint::from_bytes_le(0x2342_u16.to_le_bytes().as_ref());
    let mut temp = k.modpow(&key.e, &key.n);
    temp = temp.modpow(&key.d, &key.n);

    let mut res = Ok(());

    if k != temp {
        res = Err(Error::InvalidRsaKey);
    }

    // clear the temporary K value
    k.set_zero();

    // check d <= N
    if key.d > key.n {
        res = Err(Error::InvalidRsaKey);
    }

    // check P * Q == N
    temp = key.p.clone();
    temp *= &key.q;
    if temp != key.n {
        res = Err(Error::InvalidRsaKey);
    }

    let mut p1 = key.p.clone();
    p1 -= 1_u32;

    // check dP <= P - 1
    if key.dp > p1 {
        res = Err(Error::InvalidRsaKey);
    }

    // check e*dP % (P - 1) == 1
    temp = key.e.clone();
    temp *= &key.dp;
    temp = temp.mod_floor(&p1);
    if !temp.is_one() {
        res = Err(Error::InvalidRsaKey);
    }

    // clear temp P - 1
    p1.set_zero();

    let mut q1 = key.q.clone();
    q1 -= 1_u32;

    // check dQ <= Q - 1
    if key.dq > q1 {
        res = Err(Error::InvalidRsaKey);
    }

    // check e*dQ % (Q - 1) == 1
    temp = key.e.clone();
    temp *= &key.dq;
    temp = temp.mod_floor(&q1);
    if !temp.is_one() {
        res = Err(Error::InvalidRsaKey);
    }

    // clear temp Q - 1
    q1.set_zero();

    // check 1 / Q <= P
    if key.invq > key.p {
        res = Err(Error::InvalidRsaKey);
    }

    // check ((1/Q) * Q) % p == 1
    temp = key.invq.clone();
    temp *= &key.q;
    temp = temp.mod_floor(&key.p);
    if !temp.is_one() {
        res = Err(Error::InvalidRsaKey);
    }

    // clear the temporary variable
    temp.set_zero();

    res
}

/// Check the provided size is a valid RSA public modulus bit-length
#[inline(always)]
pub(crate) fn length_check(size: usize) -> Result<(), Error> {
    match size {
        RSA_1024_LEN => Ok(()),
        RSA_2048_LEN => Ok(()),
        RSA_3072_LEN => Ok(()),
        RSA_4096_LEN => Ok(()),
        _ => return Err(Error::InvalidSize),
    }
}

/// Bitwise exlusive-OR of two byte slices
#[inline(always)]
pub fn xor(el: &[u8], ar: &[u8]) -> Vec<u8> {
    let el_len = el.len();
    let ar_len = ar.len();
    let len = if el_len < ar_len { el_len } else { ar_len };

    el[..len]
        .iter()
        .zip(ar[..len].iter())
        .map(|(&e, &r)| e ^ r)
        .collect()
}

/// Bitwise exlusive-OR of two byte slices, assiging result to left byte slice
#[inline(always)]
pub fn xor_assign(el: &mut [u8], ar: &[u8]) {
    let el_len = el.len();
    let ar_len = ar.len();
    let len = if el_len < ar_len { el_len } else { ar_len };

    for (e, &r) in el[..len].iter_mut().zip(ar[..len].iter()) {
        *e ^= r;
    }
}

#[cfg(test)]
mod tests {
    use core::convert::{TryFrom, TryInto};
    use rand::thread_rng;

    use super::*;

    #[test]
    fn check_inv_mod_slow() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random integers
        for _ in 0..10 {
            for &rsa_len in [RSA_1024_LEN, RSA_2048_LEN, RSA_3072_LEN, RSA_4096_LEN].iter() {
                let k = primes::init_bigint(rsa_len, &mut rng);

                let mut inv_e = math::inv_mod_slow(&e, &k).unwrap();

                inv_e *= &e;
                inv_e = inv_e.mod_floor(&k);

                assert_eq!(inv_e, one);

                // test against the lcm(k - 1, k)
                let mut k_lcm = k.clone();

                k_lcm -= 1_u32;
                k_lcm = k_lcm.lcm(&k);

                inv_e = math::inv_mod_slow(&e, &k_lcm).unwrap();

                inv_e *= &e;
                inv_e = inv_e.mod_floor(&k_lcm);

                assert_eq!(inv_e, one);
            }
        }
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_1024() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_1024_LEN, &e, None, &mut rng).unwrap();

        let mut inv_e = math::inv_mod_slow(&e, &k).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against the lcm(k - 1, k)
        let mut k_lcm = k.clone();

        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = math::inv_mod_slow(&e, &k_lcm).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_2048() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_2048_LEN, &e, None, &mut rng).unwrap();

        let mut inv_e = math::inv_mod_slow(&e, &k).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against the (k - 1)**2
        let mut k_lcm = k.clone();

        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = math::inv_mod_slow(&e, &k_lcm).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_3072() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_3072_LEN, &e, None, &mut rng).unwrap();

        let mut inv_e = math::inv_mod_slow(&e, &k).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against (k - 1)**2
        let mut k_lcm = k.clone();

        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = math::inv_mod_slow(&e, &k_lcm).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_4096() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_4096_LEN, &e, None, &mut rng).unwrap();
        let mut inv_e = math::inv_mod_slow(&e, &k).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against the (k - 1)**2
        assert_eq!(inv_e, one);

        let mut k_lcm = k.clone();
        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = math::inv_mod_slow(&e, &k_lcm).unwrap();

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    fn check_rsa_1024_keygen() {
        let key = RsaPrivateKey::new(RSA_1024_LEN).unwrap();

        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_2048_keygen() {
        let key = RsaPrivateKey::new(RSA_2048_LEN).unwrap();
        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_3072_keygen() {
        let key = RsaPrivateKey::new(RSA_3072_LEN).unwrap();
        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_4096_keygen() {
        let key = RsaPrivateKey::new(RSA_4096_LEN).unwrap();
        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_1024_public_key() {
        let pvt_key = RsaPrivateKey::new(RSA_1024_LEN).unwrap();

        let _pub_key = RsaPublicKey::try_from(&pvt_key).unwrap();
        let _pub_key = RsaPublicKey::from(&pvt_key);

        let _pub_key: RsaPublicKey = (&pvt_key).try_into().unwrap();
        let _pub_key: RsaPublicKey = (&pvt_key).into();
    }

    #[test]
    fn check_encryption_1024() {
        let pvt_key = RsaPrivateKey::new(RSA_1024_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_encryption_2048() {
        let pvt_key = RsaPrivateKey::new(RSA_2048_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_encryption_3072() {
        let pvt_key = RsaPrivateKey::new(RSA_3072_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_encryption_4096() {
        let pvt_key = RsaPrivateKey::new(RSA_4096_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }
}