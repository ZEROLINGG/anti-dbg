//anti-dbg/src/lib.rs
pub use anti_dbg_macros::*;
pub use lib_unknown as lib;
use lib_unknown::crypto::base::{derive, mix64};
use lib_unknown::rand::{seed, shuffle};
use std::hint::black_box;

pub mod unix;
pub mod win;

pub fn checks(x: u8) -> bool {
    #[cfg(windows)]
    {
        win::checks(x)
    }
    #[cfg(unix)]
    {
        unix::checks(x)
    }
    #[cfg(not(any(windows, unix)))]
    false
}

pub fn pow_sleep<S: Into<f64>>(ms: S) -> u64 {
    let t = black_box(ms.into());

    let i = if t <= 0.0 {
        0
    } else {
        #[cfg(debug_assertions)]
        {
            let intercept = -1.46;
            let slope = 0.2802;

            ((t - intercept).max(0.0) / slope).max(1.0).round() as usize
        }
        #[cfg(not(debug_assertions))]
        {
            let intercept = 1.01;
            let slope = 0.04639;

            ((t - intercept).max(0.0) / slope).max(1.0).round() as usize
        }
    };
    print!("{i}");

    let mut table = vec![0u64; 7];
    let mut s = black_box(seed() ^ derive(t as u64));
    let mut m1 = black_box(s as u32);
    let mut m2 = black_box(s as u32 % u16::MAX as u32);
    for slot in table.iter_mut() {
        s = black_box(mix64(s));
        *slot = s;
    }

    for j in 0..i {
        let j = black_box(j) + black_box(0);
        table[j % 7] ^= black_box(j as u64);
        table = black_box(shuffle(table));
        s ^= black_box(mix64(s));
        if table[0].is_multiple_of(2) {
            'k1: for k in 0..black_box(u16::MAX + black_box(t as u16 % black_box(1)).min(m2 as u16))
            {
                let k = black_box(black_box(k) + black_box(0));

                m1 = black_box(m1.saturating_mul(s as u32));
                m2 = black_box((m2 as u16).saturating_add(m1 as u16)) as u32;

                table[0] = black_box(table[6].wrapping_add(s));
                table[k as usize % 7] ^= black_box(derive(k as u64 ^ m1 as u64 ^ s));
                table = black_box(shuffle(table));
                if table[6] as u8 == j as u8 {
                    break 'k1;
                }
                s ^= black_box(table[0]);
            }
        } else {
            'k2: for k in 0..black_box(u16::MAX + black_box(s as u16 % black_box(1)).min(m1 as u16))
            {
                let k = black_box(black_box(k) + black_box(0));

                m1 = black_box(m1.saturating_mul(s as u32));
                m2 = black_box((m2 as u16).saturating_add(m1 as u16)) as u32;

                table[0] = black_box(table[5].wrapping_add(s));
                table[k as usize % 7] ^= black_box(derive(k as u64 ^ m2 as u64 | s));
                table = black_box(shuffle(table));
                if table[5] as u8 == k as u8 {
                    break 'k2;
                }
                s ^= black_box(table[0]);
            }
        }

        s ^= black_box(derive(table.clone()));
    }
    let payload = s & m1 as u64;
    let signature = mix64(payload ^ mix64(t as u64) ^ mix64(m2 as u64)) >> 32;

    (signature << 32) | payload
}

#[inline(always)]
pub fn verify_sleep(s: u64, ms: impl Into<f64>) -> bool {
    let t: f64 = ms.into();

    let m1: u64 = u32::MAX as u64;
    let m2: u64 = u16::MAX as u64;

    let payload = s & m1;
    let extracted_signature = s >> 32;

    let expected_signature = mix64(payload ^ mix64(t as u64) ^ mix64(m2)) >> 32;
    extracted_signature == expected_signature
}

pub fn probe() -> u64 {
    lib_unknown::rand::probe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn it_works() {
        let mut target_ms = 1.0;
        loop {
            let a = Instant::now();
            let _s = pow_sleep(target_ms);
            let b = Instant::now();
            println!(",{}", (b - a).as_micros());
            // println!(
            //     "| Target: {target_ms:<5.0}ms | Actual: {:<5?}ms | verify: {}",
            //     (b - a).as_millis(),
            //     verify_sleep(s, target_ms)
            // );
            target_ms += 1.0;
            if target_ms > 5.0 {
                break;
            }
        }
    }
}
