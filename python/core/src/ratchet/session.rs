use super::{ChainKey, DoubleRatchetState};
use crate::crypto::{Encryptor, CryptoError};
use crate::error::{ProtocolError, ProtocolResult};
use crate::Config;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use parking_lot::RwLock;
use std::collections::HashMap;
use rand_core::OsRng;

pub struct DoubleRatchetSession {
    state: RwLock<DoubleRatchetState>,
    config: Config,
}

impl DoubleRatchetSession {
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let dh_local = StaticSecret::random_from_rng(&mut OsRng);
        let dh_local_bytes = dh_local.to_bytes().to_vec();
        
        let state = DoubleRatchetState {
            root_key: [0u8; 32],
            sending_chain: None,
            receiving_chain: None,
            dh_local: Some(dh_local),
            dh_local_bytes,
            dh_remote: None,
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
        };
        
        Ok(Self {
            state: RwLock::new(state),
            config,
        })
    }
    
    // Create from existing shared secret (post-handshake)
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        local_dh: StaticSecret,
        remote_dh: PublicKey,
        config: Config,
    ) -> ProtocolResult<Self> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut root_key = [0u8; 32];
        hkdf.expand(b"root_key", &mut root_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
            
        let mut sending_key = [0u8; 32];
        hkdf.expand(b"sending_chain", &mut sending_key)
            .map_err(|_| ProtocolError::KeyDerivationFailed)?;
            
        let sending_chain = ChainKey::new(sending_key);
        let dh_local_bytes = local_dh.to_bytes().to_vec();
        
        let state = DoubleRatchetState {
            root_key,
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            dh_local: Some(local_dh),
            dh_local_bytes,
            dh_remote: Some(remote_dh),
            skipped_message_keys: HashMap::new(),
            max_skip: config.max_skipped_messages,
            previous_counter: 0,
        };
        
        Ok(Self {
            state: RwLock::new(state),
            config,
        })
    }
    
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let mut state = self.state.write();
        
        let sending_chain = state.sending_chain.as_mut().ok_or(ProtocolError::InvalidState)?;
        let message_key = sending_chain.next_message_key();
        
        let dh_pub = state.dh_local.as_ref()
            .map(PublicKey::from)
            .ok_or(ProtocolError::InvalidState)?;
        
        let mut header = Vec::with_capacity(32 + 8 + 8);
        header.extend_from_slice(dh_pub.as_bytes());
        header.extend_from_slice(&(sending_chain.index - 1).to_le_bytes());
        header.extend_from_slice(&state.previous_counter.to_le_bytes());
        
        let encryptor = Encryptor::new(&message_key, u64::MAX).map_err(ProtocolError::from)?;
        let mut final_ad = Vec::new();
        final_ad.extend_from_slice(associated_data);
        final_ad.extend_from_slice(&header);
        
        let ciphertext = encryptor.encrypt_message(plaintext, &final_ad)?;
        
        let mut result = Vec::with_capacity(header.len() + ciphertext.len());
        result.extend_from_slice(&header);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    pub fn decrypt(&mut self, message: &[u8], associated_data: &[u8]) -> ProtocolResult<Vec<u8>> {
        if message.len() < 48 {
            return Err(ProtocolError::InvalidMessage);
        }
        
        let header_dh = &message[..32];
        let n = u64::from_le_bytes(message[32..40].try_into().unwrap());
        let pn = u64::from_le_bytes(message[40..48].try_into().unwrap());
        let ciphertext = &message[48..];
        let header_bytes = &message[..48];
        
        let mut state = self.state.write();
        let remote_dh = PublicKey::from(<[u8; 32]>::try_from(header_dh).unwrap());

        // 1. Try to find key in skipped keys
        if let Some(mk) = state.skipped_message_keys.remove(&(remote_dh.as_bytes().clone(), n)) {
            let encryptor = Encryptor::new(&mk, u64::MAX).map_err(ProtocolError::from)?;
            let mut ad = Vec::from(associated_data);
            ad.extend_from_slice(header_bytes);
            return encryptor.decrypt_message(ciphertext, &ad).map_err(ProtocolError::from);
        }

        // 2. DH Ratchet
        if state.dh_remote.is_none() || state.dh_remote.unwrap() != remote_dh {
            self.skip_message_keys(&mut state, pn)?;
            self.dh_ratchet(&mut state, remote_dh)?;
        }

        // 3. Handle messages in current receiving chain
        let mk = if let Some(receiving_chain) = state.receiving_chain.as_mut() {
            if n < receiving_chain.index {
                // Replay attack or out-of-order message that was already skipped but not found in skipped_keys (expired/dropped)
                return Err(ProtocolError::InvalidMessage);
            }
            
            // Skip up to N-1
            self.skip_message_keys(&mut state, n)?;
            
            // The message key for N should be exactly at receiving_chain.index now
            if n != receiving_chain.index {
                 return Err(ProtocolError::InternalError("Chain index mismatch after skip".into()));
            }
            
            receiving_chain.next_message_key()
        } else {
            return Err(ProtocolError::InvalidState);
        };

        // 4. Decrypt
        let encryptor = Encryptor::new(&mk, u64::MAX).map_err(ProtocolError::from)?;

        let mut final_ad = Vec::from(associated_data);
        final_ad.extend_from_slice(header_bytes);
        
        encryptor.decrypt_message(ciphertext, &final_ad).map_err(ProtocolError::from)
    }

    fn skip_message_keys(&self, state: &mut DoubleRatchetState, until_n: u64) -> ProtocolResult<()> {
        if let Some(chain) = state.receiving_chain.as_mut() {
            if until_n > chain.index + self.config.max_skipped_messages as u64 {
                return Err(ProtocolError::InternalError("Too many skipped messages".into()));
            }

            while chain.index < until_n {
                let mk = chain.next_message_key();
                let dh_remote = state.dh_remote.ok_or(ProtocolError::InvalidState)?;
                state.skipped_message_keys.insert((dh_remote.as_bytes().clone(), chain.index - 1), mk);
                
                if state.skipped_message_keys.len() > self.config.max_skipped_messages {
                     return Err(ProtocolError::InternalError("Maximum skipped message keys exceeded".into()));
                }
            }
        }
        Ok(())
    }

    fn dh_ratchet(&self, state: &mut DoubleRatchetState, remote_dh: PublicKey) -> ProtocolResult<()> {
        state.previous_counter = state.sending_chain.as_ref().map(|c| c.index).unwrap_or(0);
        state.dh_remote = Some(remote_dh);
        
        // Root Ratchet (Receiving)
        let shared_secret = state.dh_local.as_ref().unwrap().diffie_hellman(&remote_dh);
        let (root_key, receiving_key) = self.kdf_rk(&state.root_key, shared_secret.as_bytes())?;
        state.root_key = root_key;
        state.receiving_chain = Some(ChainKey::new(receiving_key));

        // Generate new local key
        let new_local = StaticSecret::random_from_rng(&mut OsRng);
        let new_local_pub = PublicKey::from(&new_local);
        
        // Root Ratchet (Sending)
        let shared_secret_send = new_local.diffie_hellman(&remote_dh);
        let (root_key, sending_key) = self.kdf_rk(&state.root_key, shared_secret_send.as_bytes())?;
        state.root_key = root_key;
        state.sending_chain = Some(ChainKey::new(sending_key));
        
        state.dh_local = Some(new_local);
        state.dh_local_bytes = state.dh_local.as_ref().unwrap().to_bytes().to_vec();
        
        Ok(())
    }

    fn kdf_rk(&self, root_key: &[u8; 32], dh_out: &[u8; 32]) -> ProtocolResult<([u8; 32], [u8; 32])> {
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_out);
        let mut okm = [0u8; 64];
        hkdf.expand(b"ratchet_step", &mut okm).map_err(|_| ProtocolError::KeyDerivationFailed)?;
        
        let mut new_rk = [0u8; 32];
        let mut new_ck = [0u8; 32];
        new_rk.copy_from_slice(&okm[..32]);
        new_ck.copy_from_slice(&okm[32..]);
        
        Ok((new_rk, new_ck))
    }

    
    pub fn serialize_state(&self) -> ProtocolResult<Vec<u8>> {
        let state = self.state.read();
        serde_json::to_vec(&*state).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))
    }
    
    pub fn deserialize_state(&mut self, data: &[u8]) -> ProtocolResult<()> {
        let mut state = self.state.write();
        // Load basic struct
        let mut loaded: DoubleRatchetState = serde_json::from_slice(data)
            .map_err(|_| ProtocolError::InternalError("Deserialization failed".into()))?;
            
        // Restore StaticSecrets from bytes
        if !loaded.dh_local_bytes.is_empty() {
             let arr: [u8; 32] = loaded.dh_local_bytes.clone().try_into().unwrap_or([0; 32]);
             loaded.dh_local = Some(StaticSecret::from(arr));
        }
        
        *state = loaded;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{StaticSecret, PublicKey};
    use crate::Config;

    #[test]
    fn test_double_ratchet_flow() {
        let root_key = [0x42u8; 32];
        let bob_identity_secret = StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let bob_identity_public = PublicKey::from(&bob_identity_secret);
        
        let config = Config::default();
        
        // Setup Alice
        let mut alice_session = DoubleRatchetSession::new(config.clone(), root_key, bob_identity_public.clone());
        
        // Setup Bob (Bob starts as receiver, needs his identity secret)
        // For Bob to act as receiver correctly, he needs to have derived his root key from the same source
        let mut bob_session = DoubleRatchetSession::new(config.clone(), root_key, bob_identity_public.clone());
        {
            let mut state = bob_session.state.write();
            state.dh_local = Some(bob_identity_secret); // Bob's identity acts as initial DH key
        }

        // Alice sends to Bob
        let alice_msg1 = b"Hello Bob!";
        let (header1, ciphertext1) = alice_session.encrypt(alice_msg1, b"ad1").unwrap();
        
        // Bob decrypts
        let bob_decrypted1 = bob_session.decrypt(&header1, &ciphertext1, b"ad1").unwrap();
        assert_eq!(alice_msg1, bob_decrypted1.as_slice());

        // Bob responds (this should trigger a DH Ratchet)
        let bob_msg1 = b"Hi Alice!";
        let (header2, ciphertext2) = bob_session.encrypt(bob_msg1, b"ad2").unwrap();
        
        // Alice decrypts (this should trigger a DH Ratchet on Alice's side)
        let alice_decrypted1 = alice_session.decrypt(&header2, &ciphertext2, b"ad2").unwrap();
        assert_eq!(bob_msg1, alice_decrypted1.as_slice());
        
        println!("Double Ratchet bi-directional flow successful!");
    }
}
