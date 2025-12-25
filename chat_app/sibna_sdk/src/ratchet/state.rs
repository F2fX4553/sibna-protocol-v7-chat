use super::ChainKey;
use x25519_dalek::{PublicKey, StaticSecret};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    pub sending_chain: Option<ChainKey>,
    pub receiving_chain: Option<ChainKey>,
    
    #[serde(skip)]
    #[zeroize(skip)]
    pub dh_local: Option<StaticSecret>, // dalek StaticSecret zeroizes on drop already
    
    #[serde(with = "serde_bytes")]
    pub dh_local_bytes: Vec<u8>, 
    
    #[zeroize(skip)]
    pub dh_remote: Option<PublicKey>,
    
    #[zeroize(skip)]
    pub skipped_message_keys: HashMap<(u64, [u8; 32]), [u8; 32]>, 
    
    #[zeroize(skip)]
    pub max_skip: usize,
    
    #[zeroize(skip)]
    pub previous_counter: u64,
}


impl Clone for DoubleRatchetState {
    fn clone(&self) -> Self {
        // Need manual clone because StaticSecret doesn't derive Clone
        let dh_local_clone = if let Some(dh) = &self.dh_local {
            let bytes = dh.to_bytes();
            Some(StaticSecret::from(bytes))
        } else {
            None
        };

        Self {
            root_key: self.root_key,
            sending_chain: self.sending_chain.clone(),
            receiving_chain: self.receiving_chain.clone(),
            dh_local: dh_local_clone,
            dh_local_bytes: self.dh_local_bytes.clone(),
            dh_remote: self.dh_remote,
            skipped_message_keys: self.skipped_message_keys.clone(),
            max_skip: self.max_skip,
            previous_counter: self.previous_counter,
        }
    }
}

// Helpers for serialization of StaticSecret
mod serde_bytes {
    use super::*;
    use serde::{Serializer, Deserializer, de::Error};
    
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(bytes)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(bytes)
    }
}
