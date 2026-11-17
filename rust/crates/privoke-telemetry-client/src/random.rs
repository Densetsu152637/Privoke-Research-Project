//! The random draw of CPython's `random.SystemRandom`, on an injectable byte source.
//!
//! The oracle's draws are built from `os.urandom` only:
//!
//! * `random()` reads seven bytes, drops the low three bits of the 56-bit big-endian integer and scales the remaining
//!   53 bits by 2^-53: a uniform multiple of 2^-53 in `[0, 1)`;
//! * `getrandbits(k)` reads `ceil(k / 8)` bytes and keeps the high `k` bits of the big-endian integer;
//! * `choice` over `n` items is `_randbelow(n)`: draw `getrandbits(bit_length(n))` until the value is below `n`
//!   (rejection sampling), and take that item.
//!
//! The same bytes through the functions below give the same draws and consume the same number of bytes. Production
//! code reads the operating system through [`OsRandom`]; tests inject [`ReplayRandom`].

use std::sync::{Arc, Mutex, PoisonError};

use crate::error::RandomError;

/// 2^-53, exactly (CPython's `RECIP_BPF`).
const RECIP_BPF: f64 = 1.0 / 9_007_199_254_740_992.0;

/// A source of random bytes.
pub trait RandomSource {
    /// Fill `buffer` completely or fail without a partial result being used.
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), RandomError>;
}

/// The operating-system random source (`getrandom`), the counterpart of `os.urandom`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(buffer).map_err(|error| RandomError(error.to_string()))
    }
}

/// A fixed byte string served in order; reading past its end fails. Clones share the read position, so a test can keep
/// a handle to count what the code under test consumed.
#[derive(Debug, Clone)]
pub struct ReplayRandom {
    data: Arc<[u8]>,
    position: Arc<Mutex<usize>>,
}

impl ReplayRandom {
    /// Serve `data` from its first byte.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: Arc::from(data.into()), position: Arc::new(Mutex::new(0)) }
    }

    /// Bytes read so far.
    pub fn consumed(&self) -> usize {
        *self.position.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.consumed()
    }
}

impl RandomSource for ReplayRandom {
    fn fill(&mut self, buffer: &mut [u8]) -> Result<(), RandomError> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let end = position.checked_add(buffer.len()).filter(|end| *end <= self.data.len());
        match end {
            Some(end) => {
                buffer.copy_from_slice(&self.data[*position..end]);
                *position = end;
                Ok(())
            }
            None => Err(RandomError(format!("replay stream exhausted at {} reading {}", *position, buffer.len()))),
        }
    }
}

/// `random.SystemRandom().random()`: a uniform multiple of 2^-53 in `[0, 1)`. Reads seven bytes.
pub fn random_unit(source: &mut dyn RandomSource) -> Result<f64, RandomError> {
    let mut bytes = [0_u8; 7];
    source.fill(&mut bytes)?;
    let mut word = [0_u8; 8];
    word[1..].copy_from_slice(&bytes);
    let integer = u64::from_be_bytes(word) >> 3;
    // `integer` < 2^53, so the conversion and the scaling by a power of two are exact.
    Ok(integer as f64 * RECIP_BPF)
}

/// `random.SystemRandom().getrandbits(k)` for `0 <= k <= 64`. Reads `ceil(k / 8)` bytes.
pub fn random_bits(source: &mut dyn RandomSource, k: u32) -> Result<u64, RandomError> {
    if k > 64 {
        return Err(RandomError(format!("{k} random bits requested; at most 64 are supported")));
    }
    let count = k.div_ceil(8) as usize;
    let mut bytes = [0_u8; 8];
    source.fill(&mut bytes[..count])?;
    let mut word = [0_u8; 8];
    word[8 - count..].copy_from_slice(&bytes[..count]);
    let integer = u64::from_be_bytes(word);
    // `count * 8 - k` is below 8, so the shift cannot overflow.
    Ok(integer >> (count as u32 * 8 - k))
}

/// CPython's `_randbelow_with_getrandbits(n)` for `1 <= n`: rejection sampling of `n.bit_length()` bits.
pub fn random_below(source: &mut dyn RandomSource, n: usize) -> Result<usize, RandomError> {
    if n == 0 {
        return Err(RandomError("random_below needs a positive bound".to_string()));
    }
    let bound = n as u64;
    // `n` is a bit length of at least one, even for n = 1 ("don't use n - 1 here").
    let k = u64::BITS - bound.leading_zeros();
    loop {
        let candidate = random_bits(source, k)?;
        if candidate < bound {
            return Ok(candidate as usize);
        }
    }
}
