use super::*;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature, Verifier};
use x25519_dalek::{StaticSecret, PublicKey};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::OsRng;
use parking_lot::RwLock;
use sled;
use std::sync::Arc;

/// Identity Key Pair (Dual Ed25519/X25519)
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    #[serde(with = "serde_bytes")]
    pub private_seed: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ed25519_public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub x25519_public: Vec<u8>,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        
        let signing_key = SigningKey::from_bytes(&seed);
        let ed_public = VerifyingKey::from(&signing_key);
        
        let x_secret = StaticSecret::from(seed);
        let x_public = PublicKey::from(&x_secret);
        
        Self {
            private_seed: seed.to_vec(),
            ed25519_public: ed_public.to_bytes().to_vec(),
            x25519_public: x_public.as_bytes().to_vec(),
        }
    }

    pub fn from_bytes(public_ed: &[u8], public_x: &[u8], seed: &[u8]) -> Self {
        Self {
            private_seed: seed.to_vec(),
            ed25519_public: public_ed.to_vec(),
            x25519_public: public_x.to_vec(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> ProtocolResult<Vec<u8>> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.private_seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn get_x25519_secret(&self) -> StaticSecret {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.private_seed);
        StaticSecret::from(seed)
    }
}


mod serde_bytes {
    use serde::{Serializer, Deserializer};
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

/// Secure Key Store
pub struct KeyStore {
    identity_key: RwLock<Option<IdentityKeyPair>>, 
    db: sled::Tree,
    crypto: crate::crypto::CryptoHandler,
}

impl KeyStore {
    pub fn new(db: Arc<sled::Db>, storage_key: [u8; 32]) -> ProtocolResult<Self> {
        let tree = db.open_tree("keystore").map_err(|e| ProtocolError::InternalError(format!("DB open tree error: {}", e)))?;
        let crypto = crate::crypto::CryptoHandler::new(&storage_key).map_err(ProtocolError::from)?;

        let mut identity_key = None;
        if let Ok(Some(encrypted)) = tree.get(b"identity") {
            if let Ok(decrypted) = crypto.decrypt(&encrypted, b"keystore:identity") {
                if let Ok(loaded) = serde_json::from_slice::<IdentityKeyPair>(&decrypted) {
                    identity_key = Some(loaded);
                }
            }
        }

        if identity_key.is_none() {
            let identity = IdentityKeyPair::generate();
            let bytes = serde_json::to_vec(&identity).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
            let encrypted = crypto.encrypt(&bytes, b"keystore:identity").map_err(ProtocolError::from)?;
            tree.insert(b"identity", encrypted).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
            identity_key = Some(identity);
        }

        Ok(Self {
            identity_key: RwLock::new(identity_key),
            db: tree,
            crypto,
        })
    }
    
    pub fn set_identity(&self, identity: IdentityKeyPair) -> ProtocolResult<()> {
        let bytes = serde_json::to_vec(&identity).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
        let encrypted = self.crypto.encrypt(&bytes, b"keystore:identity").map_err(ProtocolError::from)?;
        self.db.insert(b"identity", encrypted).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
        
        let mut guard = self.identity_key.write();
        *guard = Some(identity);
        Ok(())
    }

    
    pub fn get_identity_keypair(&self) -> ProtocolResult<IdentityKeyPair> {
        let guard = self.identity_key.read();
        if let Some(key) = &*guard {
            // Manual clone because ZeroizeOnDrop prevents auto-derive clone sometimes or we want explicit copy
             Ok(IdentityKeyPair {
                 private_seed: key.private_seed.clone(),
                 ed25519_public: key.ed25519_public.clone(),
                 x25519_public: key.x25519_public.clone(),
             })

        } else {
            Err(ProtocolError::InvalidState)
        }
    }
    /// Save a One-Time PreKey
    pub fn save_prekey(&self, id: u32, keypair: &PreKeyPair) -> ProtocolResult<()> {
        let bytes = serde_json::to_vec(keypair).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
        let ad = format!("keystore:prekey:{}", id);
        let encrypted = self.crypto.encrypt(&bytes, ad.as_bytes()).map_err(ProtocolError::from)?;
        let key = format!("prekey:{}", id);
        self.db.insert(key.as_bytes(), encrypted).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
        Ok(())
    }

    /// Get a One-Time PreKey
    pub fn get_prekey(&self, id: u32) -> ProtocolResult<PreKeyPair> {
        let key = format!("prekey:{}", id);
        let ad = format!("keystore:prekey:{}", id);
        match self.db.get(key.as_bytes()).map_err(|e| ProtocolError::InternalError(format!("DB read error: {}", e)))? {
            Some(encrypted) => {
                let decrypted = self.crypto.decrypt(&encrypted, ad.as_bytes()).map_err(ProtocolError::from)?;
                serde_json::from_slice(&decrypted).map_err(|_| ProtocolError::InternalError("Deserialization failed".into()))
            },
            None => Err(ProtocolError::KeyNotFound),
        }
    }

    /// Remove a One-Time PreKey
    pub fn remove_prekey(&self, id: u32) -> ProtocolResult<()> {
        let key = format!("prekey:{}", id);
        self.db.remove(key.as_bytes()).map_err(|e| ProtocolError::InternalError(format!("DB remove error: {}", e)))?;
        Ok(())
    }

    /// Save a Signed PreKey
    pub fn save_signed_prekey(&self, id: u32, keypair: &SignedPreKeyPair) -> ProtocolResult<()> {
        let bytes = serde_json::to_vec(keypair).map_err(|_| ProtocolError::InternalError("Serialization failed".into()))?;
        let ad = format!("keystore:signed_prekey:{}", id);
        let encrypted = self.crypto.encrypt(&bytes, ad.as_bytes()).map_err(ProtocolError::from)?;
        let key = format!("signed_prekey:{}", id);
        self.db.insert(key.as_bytes(), encrypted).map_err(|e| ProtocolError::InternalError(format!("DB insert error: {}", e)))?;
        Ok(())
    }

    /// Get a Signed PreKey
    pub fn get_signed_prekey(&self, id: u32) -> ProtocolResult<SignedPreKeyPair> {
        let key = format!("signed_prekey:{}", id);
        let ad = format!("keystore:signed_prekey:{}", id);
        match self.db.get(key.as_bytes()).map_err(|e| ProtocolError::InternalError(format!("DB read error: {}", e)))? {
            Some(encrypted) => {
                let decrypted = self.crypto.decrypt(&encrypted, ad.as_bytes()).map_err(ProtocolError::from)?;
                serde_json::from_slice(&decrypted).map_err(|_| ProtocolError::InternalError("Deserialization failed".into()))
            },
            None => Err(ProtocolError::KeyNotFound),
        }
    }

}

/// PreKey Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreKeyPair {
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
}

/// Signed PreKey Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKeyPair {
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl SignedPreKeyPair {
    pub fn generate_signed(identity: &IdentityKeyPair) -> ProtocolResult<Self> {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        let public_bytes = public.as_bytes();
        
        let signature = identity.sign(public_bytes)?;
        
        Ok(Self {
            private: secret.to_bytes().to_vec(),
            public: public_bytes.to_vec(),
            signature,
        })
    }
}
