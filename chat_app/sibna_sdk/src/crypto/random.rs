use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use blake3::Hasher;
use super::{CryptoError, CryptoResult};

/// Secure Random Number Generator (wraps OsRng)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureRandom {
    #[zeroize(skip)]
    inner: rand_core::OsRng,
}

impl SecureRandom {
    pub fn new() -> CryptoResult<Self> {
        Ok(Self {
            inner: rand_core::OsRng,
        })
    }
    
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }
    
    pub fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    pub fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
}

