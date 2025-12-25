#![no_main]
use libfuzzer_sys::fuzz_target;
use secure_protocol::{DoubleRatchetSession, Config};

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    
    let root_key = [0u8; 32];
    let bob_public = [0u8; 32];
    let config = Config::default();
    
    let mut session = DoubleRatchetSession::new(config, root_key, bob_public.into());
    
    // Split data into header and ciphertext
    let header = &data[..32];
    let ad = &data[32..40];
    let ciphertext = &data[40..];
    
    let _ = session.decrypt(header, ciphertext, ad);
});
