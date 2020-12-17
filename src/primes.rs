//! From wolfSSL and TomsFastMath 0.10 by Tom St Denis:
//! wolfssl/wolfcrypt/src/tfm.c
//!
//! http://math.libtomcrypt.com
//!
//! original C edited by Moises Guimaraes (moises@wolfssl.com)
//! to fit wolfSSL's needs.
//!
//! Ported to Rust by Nym Seddon

use alloc::vec::Vec;
use num::bigint::BigUint;
use num::{Integer, One, Zero};

use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};

use crate::{length_check, Error};

const PRIMES_LEN: usize = 256;

const PRIME_BOUND_LEN: usize = 256;

// First 256 primes
//
// From wolfSSL: wolfssl/wolfcrypt/src/tfm.c
const PRIMES: [u16; PRIMES_LEN] = [
    0x0002, 0x0003, 0x0005, 0x0007, 0x000b, 0x000d, 0x0011, 0x0013, 0x0017, 0x001d, 0x001f, 0x0025,
    0x0029, 0x002b, 0x002f, 0x0035, 0x003b, 0x003d, 0x0043, 0x0047, 0x0049, 0x004f, 0x0053, 0x0059,
    0x0061, 0x0065, 0x0067, 0x006b, 0x006d, 0x0071, 0x007f, 0x0083, 0x0089, 0x008b, 0x0095, 0x0097,
    0x009d, 0x00a3, 0x00a7, 0x00ad, 0x00b3, 0x00b5, 0x00bf, 0x00c1, 0x00c5, 0x00c7, 0x00d3, 0x00df,
    0x00e3, 0x00e5, 0x00e9, 0x00ef, 0x00f1, 0x00fb, 0x0101, 0x0107, 0x010d, 0x010f, 0x0115, 0x0119,
    0x011b, 0x0125, 0x0133, 0x0137, 0x0139, 0x013d, 0x014b, 0x0151, 0x015b, 0x015d, 0x0161, 0x0167,
    0x016f, 0x0175, 0x017b, 0x017f, 0x0185, 0x018d, 0x0191, 0x0199, 0x01a3, 0x01a5, 0x01af, 0x01b1,
    0x01b7, 0x01bb, 0x01c1, 0x01c9, 0x01cd, 0x01cf, 0x01d3, 0x01df, 0x01e7, 0x01eb, 0x01f3, 0x01f7,
    0x01fd, 0x0209, 0x020b, 0x021d, 0x0223, 0x022d, 0x0233, 0x0239, 0x023b, 0x0241, 0x024b, 0x0251,
    0x0257, 0x0259, 0x025f, 0x0265, 0x0269, 0x026b, 0x0277, 0x0281, 0x0283, 0x0287, 0x028d, 0x0293,
    0x0295, 0x02a1, 0x02a5, 0x02ab, 0x02b3, 0x02bd, 0x02c5, 0x02cf, 0x02d7, 0x02dd, 0x02e3, 0x02e7,
    0x02ef, 0x02f5, 0x02f9, 0x0301, 0x0305, 0x0313, 0x031d, 0x0329, 0x032b, 0x0335, 0x0337, 0x033b,
    0x033d, 0x0347, 0x0355, 0x0359, 0x035b, 0x035f, 0x036d, 0x0371, 0x0373, 0x0377, 0x038b, 0x038f,
    0x0397, 0x03a1, 0x03a9, 0x03ad, 0x03b3, 0x03b9, 0x03c7, 0x03cb, 0x03d1, 0x03d7, 0x03df, 0x03e5,
    0x03f1, 0x03f5, 0x03fb, 0x03fd, 0x0407, 0x0409, 0x040f, 0x0419, 0x041b, 0x0425, 0x0427, 0x042d,
    0x043f, 0x0443, 0x0445, 0x0449, 0x044f, 0x0455, 0x045d, 0x0463, 0x0469, 0x047f, 0x0481, 0x048b,
    0x0493, 0x049d, 0x04a3, 0x04a9, 0x04b1, 0x04bd, 0x04c1, 0x04c7, 0x04cd, 0x04cf, 0x04d5, 0x04e1,
    0x04eb, 0x04fd, 0x04ff, 0x0503, 0x0509, 0x050b, 0x0511, 0x0515, 0x0517, 0x051b, 0x0527, 0x0529,
    0x052f, 0x0551, 0x0557, 0x055d, 0x0565, 0x0577, 0x0581, 0x058f, 0x0593, 0x0595, 0x0599, 0x059f,
    0x05a7, 0x05ab, 0x05ad, 0x05b3, 0x05bf, 0x05c9, 0x05cb, 0x05cf, 0x05d1, 0x05d5, 0x05db, 0x05e7,
    0x05f3, 0x05fb, 0x0607, 0x060d, 0x0611, 0x0617, 0x061f, 0x0623, 0x062b, 0x062f, 0x063d, 0x0641,
    0x0647, 0x0649, 0x064d, 0x0653,
];

/* From wolfSSL: wolfssl/wolfcrypt/src/rsa.c
 *
 * The lower_bound value is floor(2^(0.5) * 2^((nlen/2)-1)) where nlen is 4096.
 * This number was calculated using a small test tool written with a common
 * large number math library. Other values of nlen may be checked with a subset
 * of lower_bound. */
const LOWER_PRIME_BOUND: [u8; PRIME_BOUND_LEN] = [
    0xb5, 0x04, 0xf3, 0x33, 0xf9, 0xde, 0x64, 0x84, 0x59, 0x7d, 0x89, 0xb3, 0x75, 0x4a, 0xbe, 0x9f,
    0x1d, 0x6f, 0x60, 0xba, 0x89, 0x3b, 0xa8, 0x4c, 0xed, 0x17, 0xac, 0x85, 0x83, 0x33, 0x99, 0x15,
    /* 512 */
    0x4a, 0xfc, 0x83, 0x04, 0x3a, 0xb8, 0xa2, 0xc3, 0xa8, 0xb1, 0xfe, 0x6f, 0xdc, 0x83, 0xdb, 0x39,
    0x0f, 0x74, 0xa8, 0x5e, 0x43, 0x9c, 0x7b, 0x4a, 0x78, 0x04, 0x87, 0x36, 0x3d, 0xfa, 0x27, 0x68,
    /* 1024 */
    0xd2, 0x20, 0x2e, 0x87, 0x42, 0xaf, 0x1f, 0x4e, 0x53, 0x05, 0x9c, 0x60, 0x11, 0xbc, 0x33, 0x7b,
    0xca, 0xb1, 0xbc, 0x91, 0x16, 0x88, 0x45, 0x8a, 0x46, 0x0a, 0xbc, 0x72, 0x2f, 0x7c, 0x4e, 0x33,
    0xc6, 0xd5, 0xa8, 0xa3, 0x8b, 0xb7, 0xe9, 0xdc, 0xcb, 0x2a, 0x63, 0x43, 0x31, 0xf3, 0xc8, 0x4d,
    0xf5, 0x2f, 0x12, 0x0f, 0x83, 0x6e, 0x58, 0x2e, 0xea, 0xa4, 0xa0, 0x89, 0x90, 0x40, 0xca, 0x4a,
    /* 2048 */
    0x81, 0x39, 0x4a, 0xb6, 0xd8, 0xfd, 0x0e, 0xfd, 0xf4, 0xd3, 0xa0, 0x2c, 0xeb, 0xc9, 0x3e, 0x0c,
    0x42, 0x64, 0xda, 0xbc, 0xd5, 0x28, 0xb6, 0x51, 0xb8, 0xcf, 0x34, 0x1b, 0x6f, 0x82, 0x36, 0xc7,
    0x01, 0x04, 0xdc, 0x01, 0xfe, 0x32, 0x35, 0x2f, 0x33, 0x2a, 0x5e, 0x9f, 0x7b, 0xda, 0x1e, 0xbf,
    0xf6, 0xa1, 0xbe, 0x3f, 0xca, 0x22, 0x13, 0x07, 0xde, 0xa0, 0x62, 0x41, 0xf7, 0xaa, 0x81, 0xc2,
    /* 3072 */
    0xc1, 0xfc, 0xbd, 0xde, 0xa2, 0xf7, 0xdc, 0x33, 0x18, 0x83, 0x8a, 0x2e, 0xaf, 0xf5, 0xf3, 0xb2,
    0xd2, 0x4f, 0x4a, 0x76, 0x3f, 0xac, 0xb8, 0x82, 0xfd, 0xfe, 0x17, 0x0f, 0xd3, 0xb1, 0xf7, 0x80,
    0xf9, 0xac, 0xce, 0x41, 0x79, 0x7f, 0x28, 0x05, 0xc2, 0x46, 0x78, 0x5e, 0x92, 0x95, 0x70, 0x23,
    0x5f, 0xcf, 0x8f, 0x7b, 0xca, 0x3e, 0xa3, 0x3b, 0x4d, 0x7c, 0x60, 0xa5, 0xe6, 0x33, 0xe3,
    0xe1,
    /* 4096 */
];

// Check the difference of P and Q is in valid range
//
// Caller must validate size
fn compare_diff_pq(p: &BigUint, q: &BigUint, size: usize) -> bool {
    // c = 2^((size/2) - 100)
    let mut c = BigUint::from_bytes_le(&[2]).pow((size as u32 / 2) - 100);

    // d = |p - q|
    let mut d = if p > q { p - q } else { q - p };

    let ret = d > c;

    // clear temporary variables
    c.set_zero();
    d.set_zero();

    ret
}

/// Generate prime for use in RSA private keys
pub fn generate_prime(
    size: usize,
    e: &BigUint,
    p: Option<&BigUint>,
    rng: &mut ThreadRng,
) -> Result<BigUint, Error> {
    length_check(size)?;

    /* size is the size of n in bits
     * prime_size is in bytes
     *
     * divide by 16 to ensure P * Q results in N <= size bits
     */
    let prime_size = size / 16;
    let mut prime_buf: Vec<u8> = Vec::with_capacity(prime_size);
    prime_buf.resize(prime_size, 0);

    /* The fail_count value comes from NIST FIPS 186-4, section B.3.3,
     * process steps 4.7 and 5.8.
     * */
    let fail_count = 5 * (size / 2);
    let mut i = 0;

    while i < fail_count {
        rng.fill(prime_buf.as_mut_slice());

        // prime lower bound has the MSB set, set it in the candidate
        prime_buf[0] |= 0x80;

        // make candidate odd
        prime_buf[prime_size - 1] |= 0x01;

        // convert to BigUint
        let prime = BigUint::from_bytes_be(&prime_buf);

        if check_probable_prime(&prime, &e, size, rng) {
            match p {
                Some(p_ref) => {
                    if compare_diff_pq(p_ref, &prime, size) {
                        return Ok(prime);
                    }
                }
                None => return Ok(prime),
            }
        }

        i += 1;
    }

    Err(Error::InvalidPrime)
}

/// Create a random BigUint of the given bit size
///
/// Caller must validate size
pub(crate) fn init_bigint(size: usize, rng: &mut ThreadRng) -> BigUint {
    let size_bytes = size / 8;

    let mut buf: Vec<u8> = Vec::with_capacity(size_bytes);
    buf.resize(size_bytes, 0);

    rng.fill(buf.as_mut_slice());

    BigUint::from_bytes_le(&buf)
}

// From wolfSSL: wolfssl/wolfcrypt/src/rsa.c
//
// Port of wc_CheckProbablePrime_ex
fn check_probable_prime(p: &BigUint, e: &BigUint, size: usize, rng: &mut ThreadRng) -> bool {
    /* 4.4,5.5 - Check that prime >= (2^(1/2))(2^((nlen/2)-1))
     *           This is a comparison against lowerBound */
    let tmp1 = BigUint::from_bytes_be(&LOWER_PRIME_BOUND[..size / 16]);
    if p < &tmp1 {
        return false;
    }

    /* 4.5,5.6 - Check that GCD(p-1, e) == 1 */
    if !(p - 1_u32).gcd(&e).is_one() {
        // e divides p - 1
        return false;
    }

    /* NOTE: M-R is Miller-Rabin
     *
     * 4.5.1,5.6.1 - Check primality of p with 8 rounds of M-R.
     * mp_prime_is_prime_ex() performs test divisions against the first 256
     * prime numbers. After that it performs 8 rounds of M-R using random
     * bases between 2 and n-2.
     * mp_prime_is_prime() performs the same test divisions and then does
     * M-R with the first 8 primes. Both functions set isPrime as a
     * side-effect. */
    is_prime(&p, 8, size, rng)
}

// From wolfSSL: wolfssl/wolfcrypt/src/tfm.c
//
// Port of mp_prime_is_prime_ex
fn is_prime(p: &BigUint, t: u32, size: usize, rng: &mut ThreadRng) -> bool {
    for prime in PRIMES.iter() {
        let bn_p = BigUint::from_bytes_be(prime.to_be_bytes().as_ref());
        // check against primes table
        if *p == bn_p {
            return true;
        }

        // do trial division
        if p.mod_floor(&bn_p).is_zero() {
            return false;
        }
    }

    let two = BigUint::from_bytes_le(&[2]);
    let c = p - &two;

    for _t in 0..t {
        let mut b = init_bigint(size, rng);

        // divergence from wolfSSL, get a random number in range
        // wolfSSL uses a while loop, and iterates without modifying the counter
        if b < two {
            b += rng.next_u32();
        } else if b > c {
            b = &c - rng.next_u32();
        }

        if !miller_rabin(&p, &b) {
            return false;
        }
    }

    true
}

/* Port of fp_prime_miller_rabin_ex from wolfSSL:
 * wolfssl/wolfcrypt/src/tfm.c
 *
 * Miller-Rabin test of "a" to the base of "b" as described in
 * HAC pp. 139 Algorithm 4.24
 *
 * Sets result to 0 if definitely composite or 1 if probably prime.
 * Randomly the chance of error is no more than 1/4 and often
 * very much lower.
 */
fn miller_rabin(a: &BigUint, b: &BigUint) -> bool {
    if b <= &One::one() {
        return false;
    }

    let n1: BigUint = a - 1_u32;

    // count the number of least significant bits that are zero
    let s = count_lsb(&n1);

    let two = BigUint::from_bytes_le(&[2]);

    // compute 2**s
    let two_s = two.pow(s);

    // set r = n1 / 2**s
    let r = n1.clone() / two_s;

    // compute y = b**r mod a
    let mut y = b.modpow(&r, &a);

    if !y.is_one() && y != n1 {
        let mut j = 1;

        while j <= (s - 1) && y != n1 {
            // y = a**2 mod y
            y = a.modpow(&two, &y);

            // if y == 1, then a is composite
            if y.is_one() {
                return false;
            }

            j += 1;
        }

        // if y != n1, then a is composite
        if y != n1 {
            return false;
        }
    }

    return true;
}

// Count the number of zeroes in the least-significant bits
#[inline(always)]
fn count_lsb(n: &BigUint) -> u32 {
    let mut res = 0_u32;

    for &b in n.to_bytes_le().iter() {
        if b == 0 {
            res += 8;
        } else {
            if b & 0b0111_1111 == 0 {
                res += 7;
            } else if b & 0b0011_1111 == 0 {
                res += 6;
            } else if b & 0b0001_1111 == 0 {
                res += 5;
            } else if b & 0b0000_1111 == 0 {
                res += 4;
            } else if b & 0b0000_0111 == 0 {
                res += 3;
            } else if b & 0b0000_0011 == 0 {
                res += 2;
            } else if b & 0b0000_0001 == 0 {
                res += 1;
            }

            break;
        }
    }

    res
}
