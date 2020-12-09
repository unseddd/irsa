use core::cmp::Ordering;
use num::bigint::{BigInt, BigUint};
use num::{Integer, One, Zero};

use crate::Error;

/// Port of fp_invmod_slow from wolfSSL: wolfssl/wolfcrypt/src/tfm.c
pub fn inv_mod_slow(base: &BigUint, modulus: &BigUint) -> Result<BigUint, Error> {
    let x: BigInt = base.mod_floor(&modulus).into();
    let y: BigInt = modulus.clone().into();

    if x.is_even() && y.is_even() {
        return Err(Error::InvalidModulus);
    }

    /* 3. u=x, v=y, A=1, B=0, C=0, D-1 */
    let mut u = x.clone();
    let mut v = y.clone();
    let mut ba = BigInt::one();
    let mut bb = BigInt::zero();
    let mut bc = BigInt::zero();
    let mut bd = BigInt::one();

    // here an infinite loop takes the place of `goto top`
    // where a condition calls for `goto top`, simply continue
    //
    // NOTE: need to be cautious to always break/return, else infinite loop
    loop {
        /* 4. while u is even do */
        while u.is_even() {
            /* 4.1 u = u / 2 */
            u /= 2_u32;

            /* 4.2 if A or B is odd then */
            if ba.is_odd() || bb.is_odd() {
                /* A = (A+y)/2, B = (B-x)/2*/
                // div 2 happens unconditionally below
                ba += &y;
                bb -= &x;
            }

            ba /= 2_u32;
            bb /= 2_u32;
        }

        /* 5. while v is even do */
        while v.is_even() {
            /* 5.1 v = v / 2 */
            v /= 2_u32;

            /* 5.2 if C or D is odd then */
            if bc.is_odd() || bd.is_odd() {
                /* C = (C+y)/2, D = (D-x)/2 */
                // div 2 happens unconditionally below
                bc += &y;
                bd -= &x;
            }

            /* C = C/2, D = D/2 */
            bc /= 2_u32;
            bd /= 2_u32;
        }

        /* 6. if u >= v then */
        if u >= v {
            /* u = u - v, A = A - C, B = B - D */
            u -= &v;
            ba -= &bc;
            bb -= &bd;
        } else {
            /* v = v - u, C = C - A, D = D - B */
            v -= &u;
            bc -= &ba;
            bd -= &bb;
        }

        /* if u != 0, goto step 4 */
        if !u.is_zero() {
            continue;
        }

        /* now a = C, b = D, gcd == g*v */
        if !v.is_one() {
            // if v != 1, there is no inverse
            return Err(Error::InvalidModulus);
        }

        /* while C is too low */
        let zero: BigInt = Zero::zero();
        while bc < zero {
            bc += &y;
        }

        /* while C is too big */
        while cmp_mag(&bc, &y) == Ordering::Greater {
            bc -= &y
        }

        /* C is now the inverse */

        let (sign, bytes) = bc.to_bytes_le();

        if sign == num::bigint::Sign::Minus {
            return Err(Error::InvalidModulus);
        }

        return Ok(BigUint::from_bytes_le(bytes.as_ref()));
    }
}

/// Compare the magnitude of two BigInts
#[inline(always)]
fn cmp_mag(el: &BigInt, ar: &BigInt) -> Ordering {
    let (_, el_bytes) = el.to_bytes_be();
    let (_, ar_bytes) = ar.to_bytes_be();

    let el_bytes_len = el_bytes.len();
    let ar_bytes_len = ar_bytes.len();

    if el_bytes_len > ar_bytes_len {
        return Ordering::Greater;
    } else if ar_bytes_len > el_bytes_len {
        return Ordering::Less;
    } else {
        for (el_b, ar_b) in el_bytes.iter().zip(ar_bytes.iter()) {
            if el_b > ar_b {
                return Ordering::Greater;
            } else if el_b < ar_b {
                return Ordering::Less;
            }
        }
    }

    Ordering::Equal
}
