//! An exact reimplementation of the parts of CPython's `random.Random` the fuzzer curricula use.
//!
//! The generator is MT19937 seeded from an int the way `random.seed(int)` does (`init_by_array` over the absolute
//! value's 32-bit little-endian words). On top of it, `random()`, `getrandbits`, `_randbelow` (the
//! `getrandbits` rejection loop), `choice`, `shuffle`, `sample`, `randrange`, `randint`, `uniform` and `choices`
//! with cumulative weights follow the CPython 3.11 to 3.13 sources statement by statement, so a seeded stream
//! equals CPython's call for call.

use std::fmt;

use sha2::{Digest, Sha512};

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

/// Why a call is refused, mirroring the exception CPython raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RandomError {
    /// `IndexError`: `choice` on an empty sequence.
    #[error("cannot choose from an empty sequence")]
    Empty,
    /// `ValueError`: an argument outside its domain.
    #[error("{0}")]
    Value(&'static str),
}

/// `random.Random` seeded from an int.
#[derive(Clone)]
pub struct Random {
    mt: [u32; N],
    index: usize,
}

impl fmt::Debug for Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Random").field("index", &self.index).finish_non_exhaustive()
    }
}

impl Random {
    /// `random.Random(seed)` for a non-negative int seed.
    pub fn new(seed: u64) -> Self {
        let mut key = Vec::with_capacity(2);
        let mut rest = seed;
        while rest != 0 {
            key.push((rest & 0xffff_ffff) as u32);
            rest >>= 32;
        }
        if key.is_empty() {
            key.push(0);
        }
        Self::from_key(&key)
    }

    /// `random.Random(seed)` for an int of any sign: CPython seeds from the absolute value.
    pub fn from_signed(seed: i64) -> Self {
        Self::new(seed.unsigned_abs())
    }

    /// `random.Random(text)`: version-2 seeding of a `str`, which seeds from `int.from_bytes(utf8 + sha512(utf8), "big")`.
    pub fn from_text(seed: &str) -> Self {
        Self::from_bytes(seed.as_bytes())
    }

    /// `random.Random(bytes)`: the same version-2 seeding of a `bytes` value.
    pub fn from_bytes(seed: &[u8]) -> Self {
        let mut bytes = seed.to_vec();
        bytes.extend_from_slice(&Sha512::digest(seed));
        Self::from_big_endian(&bytes)
    }

    /// `random.Random(int.from_bytes(bytes, "big"))` for an integer of any size.
    pub fn from_big_endian(bytes: &[u8]) -> Self {
        let significant: &[u8] = match bytes.iter().position(|&byte| byte != 0) {
            Some(first) => &bytes[first..],
            None => &[],
        };
        let mut key: Vec<u32> = Vec::with_capacity(significant.len() / 4 + 1);
        for chunk in significant.rchunks(4) {
            let mut word = 0u32;
            for &byte in chunk {
                word = (word << 8) | u32::from(byte);
            }
            key.push(word);
        }
        if key.is_empty() {
            key.push(0);
        }
        Self::from_key(&key)
    }

    /// `init_by_array` over little-endian 32-bit key words.
    pub fn from_key(key: &[u32]) -> Self {
        let mut rng = Self { mt: [0; N], index: N + 1 };
        rng.init_genrand(19_650_218);
        let key_length = key.len();
        let mut i = 1usize;
        let mut j = 0usize;
        let mut k = N.max(key_length);
        while k > 0 {
            let prev = rng.mt[i - 1];
            rng.mt[i] = (rng.mt[i] ^ (prev ^ (prev >> 30)).wrapping_mul(1_664_525)).wrapping_add(key[j]).wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                rng.mt[0] = rng.mt[N - 1];
                i = 1;
            }
            if j >= key_length {
                j = 0;
            }
            k -= 1;
        }
        k = N - 1;
        while k > 0 {
            let prev = rng.mt[i - 1];
            rng.mt[i] = (rng.mt[i] ^ (prev ^ (prev >> 30)).wrapping_mul(1_566_083_941)).wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                rng.mt[0] = rng.mt[N - 1];
                i = 1;
            }
            k -= 1;
        }
        rng.mt[0] = 0x8000_0000;
        rng.index = N;
        rng
    }

    fn init_genrand(&mut self, seed: u32) {
        self.mt[0] = seed;
        for i in 1..N {
            let prev = self.mt[i - 1];
            self.mt[i] = 1_812_433_253u32.wrapping_mul(prev ^ (prev >> 30)).wrapping_add(i as u32);
        }
        self.index = N;
    }

    fn twist(&mut self) {
        for kk in 0..N {
            let y = (self.mt[kk] & UPPER_MASK) | (self.mt[(kk + 1) % N] & LOWER_MASK);
            let mut next = self.mt[(kk + M) % N] ^ (y >> 1);
            if y & 1 != 0 {
                next ^= MATRIX_A;
            }
            self.mt[kk] = next;
        }
        self.index = 0;
    }

    /// `genrand_uint32`.
    pub fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }
        let mut y = self.mt[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// `random()`: 53 random bits as a float in `[0, 1)`.
    pub fn random(&mut self) -> f64 {
        let a = f64::from(self.next_u32() >> 5);
        let b = f64::from(self.next_u32() >> 6);
        (a * 67_108_864.0 + b) * (1.0 / 9_007_199_254_740_992.0)
    }

    /// `getrandbits(k)` for `k <= 64`, as the integer value.
    pub fn getrandbits(&mut self, k: u32) -> Result<u64, RandomError> {
        if k > 64 {
            return Err(RandomError::Value("getrandbits above 64 bits needs getrandbits_words"));
        }
        if k == 0 {
            return Ok(0);
        }
        if k <= 32 {
            return Ok(u64::from(self.next_u32() >> (32 - k)));
        }
        let words = self.getrandbits_words(k)?;
        Ok(u64::from(words[0]) | (u64::from(words[1]) << 32))
    }

    /// `getrandbits(k)` as little-endian 32-bit words, for any `k >= 1`.
    pub fn getrandbits_words(&mut self, k: u32) -> Result<Vec<u32>, RandomError> {
        if k == 0 {
            return Err(RandomError::Value("number of bits must be greater than zero"));
        }
        let count = k.div_ceil(32) as usize;
        let mut words = vec![0u32; count];
        let mut remaining = k;
        for word in words.iter_mut() {
            let mut r = self.next_u32();
            if remaining < 32 {
                r >>= 32 - remaining;
            }
            *word = r;
            remaining = remaining.saturating_sub(32);
        }
        Ok(words)
    }

    /// `_randbelow(n)` (`_randbelow_with_getrandbits`): an int in `[0, n)`; `0` when `n` is `0`.
    pub fn randbelow(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let k = 64 - n.leading_zeros();
        let mut r = self.getrandbits(k).unwrap_or(0);
        while r >= n {
            r = self.getrandbits(k).unwrap_or(0);
        }
        r
    }

    /// `choice(seq)`: the index `choice` picks from a sequence of `len` items.
    pub fn choice_index(&mut self, len: usize) -> Result<usize, RandomError> {
        if len == 0 {
            return Err(RandomError::Empty);
        }
        Ok(self.randbelow(len as u64) as usize)
    }

    /// `choice(seq)`.
    pub fn choice<'a, T>(&mut self, items: &'a [T]) -> Result<&'a T, RandomError> {
        let index = self.choice_index(items.len())?;
        Ok(&items[index])
    }

    /// `shuffle(x)`: Fisher-Yates from the back.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.randbelow(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }

    /// `sample(population, k)`: the indexes of the chosen items, in result order.
    pub fn sample_indices(&mut self, n: usize, k: usize) -> Result<Vec<usize>, RandomError> {
        if k > n {
            return Err(RandomError::Value("Sample larger than population or is negative"));
        }
        let mut setsize: u64 = 21;
        if k > 5 {
            let exponent = ((k * 3) as f64).ln() / 4f64.ln();
            setsize += 4u64.pow(exponent.ceil() as u32);
        }
        let mut result = Vec::with_capacity(k);
        if (n as u64) <= setsize {
            let mut pool: Vec<usize> = (0..n).collect();
            for i in 0..k {
                let j = self.randbelow((n - i) as u64) as usize;
                result.push(pool[j]);
                pool[j] = pool[n - i - 1];
            }
        } else {
            let mut selected = std::collections::BTreeSet::new();
            for _ in 0..k {
                let mut j = self.randbelow(n as u64) as usize;
                while selected.contains(&j) {
                    j = self.randbelow(n as u64) as usize;
                }
                selected.insert(j);
                result.push(j);
            }
        }
        Ok(result)
    }

    /// `sample(population, k)`.
    pub fn sample<T: Clone>(&mut self, items: &[T], k: usize) -> Result<Vec<T>, RandomError> {
        Ok(self.sample_indices(items.len(), k)?.into_iter().map(|index| items[index].clone()).collect())
    }

    /// `randrange(start, stop, step)`.
    pub fn randrange(&mut self, start: i64, stop: i64, step: i64) -> Result<i64, RandomError> {
        let width = i128::from(stop) - i128::from(start);
        if step == 1 {
            if width > 0 {
                return Ok((i128::from(start) + i128::from(self.randbelow(width as u64))) as i64);
            }
            return Err(RandomError::Value("empty range in randrange"));
        }
        let step_wide = i128::from(step);
        let n = if step > 0 {
            floor_div(width + step_wide - 1, step_wide)
        } else if step < 0 {
            floor_div(width + step_wide + 1, step_wide)
        } else {
            return Err(RandomError::Value("zero step for randrange"));
        };
        if n <= 0 {
            return Err(RandomError::Value("empty range in randrange"));
        }
        Ok((i128::from(start) + step_wide * i128::from(self.randbelow(n as u64))) as i64)
    }

    /// `randrange(stop)`: the one-argument form.
    pub fn randrange_stop(&mut self, stop: i64) -> Result<i64, RandomError> {
        if stop > 0 { Ok(self.randbelow(stop as u64) as i64) } else { Err(RandomError::Value("empty range in randrange")) }
    }

    /// `randint(a, b)`.
    pub fn randint(&mut self, a: i64, b: i64) -> Result<i64, RandomError> {
        self.randrange(a, b + 1, 1)
    }

    /// `uniform(a, b)`.
    pub fn uniform(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.random()
    }

    /// `choices(population, cum_weights=..., k=k)`: the picked indexes.
    pub fn choices_cumulative(&mut self, cum_weights: &[f64], k: usize) -> Result<Vec<usize>, RandomError> {
        let n = cum_weights.len();
        let total = match cum_weights.last() {
            Some(total) => *total + 0.0,
            None => return Err(RandomError::Value("The number of weights does not match the population")),
        };
        if total <= 0.0 {
            return Err(RandomError::Value("Total of weights must be greater than zero"));
        }
        if !total.is_finite() {
            return Err(RandomError::Value("Total of weights must be finite"));
        }
        let hi = n - 1;
        let mut picks = Vec::with_capacity(k);
        for _ in 0..k {
            let x = self.random() * total;
            picks.push(bisect_right(cum_weights, x, hi));
        }
        Ok(picks)
    }

    /// `choices(population, weights=..., k=k)`: accumulates the weights with float addition, as `itertools.accumulate`.
    pub fn choices_weighted(&mut self, weights: &[f64], k: usize) -> Result<Vec<usize>, RandomError> {
        let mut total = 0.0;
        let mut cumulative = Vec::with_capacity(weights.len());
        for (index, weight) in weights.iter().enumerate() {
            total = if index == 0 { *weight } else { total + *weight };
            cumulative.push(total);
        }
        self.choices_cumulative(&cumulative, k)
    }

    /// `choices(population, k=k)` without weights: `floor(random() * n)`.
    pub fn choices_uniform(&mut self, n: usize, k: usize) -> Vec<usize> {
        let n = n as f64;
        (0..k).map(|_| (self.random() * n).floor() as usize).collect()
    }
}

fn floor_div(numerator: i128, denominator: i128) -> i128 {
    let quotient = numerator / denominator;
    if numerator % denominator != 0 && ((numerator < 0) != (denominator < 0)) { quotient - 1 } else { quotient }
}

/// `bisect.bisect_right(a, x, 0, hi)`.
fn bisect_right(a: &[f64], x: f64, hi: usize) -> usize {
    let mut lo = 0usize;
    let mut hi = hi;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if x < a[mid] {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}
