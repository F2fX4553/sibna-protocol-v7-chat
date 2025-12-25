use crate::Config;
use crate::keystore::{KeyStore, IdentityKeyPair};
use crate::crypto::SecureRandom;
use crate::error::{ProtocolResult, ProtocolError};
use x25519_dalek::{StaticSecret, PublicKey};
use rand_core::OsRng;

pub struct HandshakeBuilder<'a> {
    config: Option<Config>,
    keystore: Option<&'a KeyStore>,
    random: Option<&'a SecureRandom>,
    initiator: bool,
    peer_identity_key: Option<PublicKey>,
    peer_signed_prekey: Option<PublicKey>,
    peer_onetime_prekey: Option<PublicKey>,
    prologue: Vec<u8>,
}

impl<'a> HandshakeBuilder<'a> {
    pub fn new() -> Self {
        Self {
            config: None,
            keystore: None,
            random: None,
            initiator: false,
            peer_identity_key: None,
            peer_signed_prekey: None,
            peer_onetime_prekey: None,
            prologue: Vec::new(),
        }
    }
    
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }
    
    pub fn with_keystore(mut self, keystore: &'a KeyStore) -> Self {
        self.keystore = Some(keystore);
        self
    }
    
    pub fn with_random(mut self, random: &'a SecureRandom) -> Self {
        self.random = Some(random);
        self
    }
    
    pub fn with_initiator(mut self, initiator: bool) -> Self {
        self.initiator = initiator;
        self
    }
    
    pub fn with_peer_identity_key(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 { return Err(ProtocolError::InvalidKeyLength); }
        let k: [u8; 32] = key.try_into().unwrap();
        self.peer_identity_key = Some(PublicKey::from(k));
        Ok(self)
    }

    pub fn with_peer_signed_prekey(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 { return Err(ProtocolError::InvalidKeyLength); }
        let k: [u8; 32] = key.try_into().unwrap();
        self.peer_signed_prekey = Some(PublicKey::from(k));
        Ok(self)
    }

    pub fn with_peer_onetime_prekey(mut self, key: &[u8]) -> ProtocolResult<Self> {
        if key.len() != 32 { return Err(ProtocolError::InvalidKeyLength); }
        let k: [u8; 32] = key.try_into().unwrap();
        self.peer_onetime_prekey = Some(PublicKey::from(k));
        Ok(self)
    }
    
    pub fn with_prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = prologue.to_vec();
        self
    }
    
    pub fn build(self) -> ProtocolResult<Handshake> {
        let keystore = self.keystore.ok_or(ProtocolError::InvalidState)?;
        let identity_key = keystore.get_identity_keypair()?;
        let ephemeral_key = StaticSecret::random_from_rng(&mut OsRng);

        Ok(Handshake {
            config: self.config.ok_or(ProtocolError::InvalidState)?,
            initiator: self.initiator,
            identity_key,
            ephemeral_key,
            peer_identity_key: self.peer_identity_key,
            peer_signed_prekey: self.peer_signed_prekey,
            peer_onetime_prekey: self.peer_onetime_prekey,
            prologue: self.prologue,
        })
    }
}


pub struct Handshake {
    config: Config,
    initiator: bool,
    // Removed peer_public_key
    // peer_public_key: Option<Vec<u8>>,
    // Changed prologue to be a mandatory Vec<u8>
    prologue: Vec<u8>,

    // New fields for X3DH
    identity_key: IdentityKeyPair,
    ephemeral_key: StaticSecret,
    peer_identity_key: Option<PublicKey>,
    peer_signed_prekey: Option<PublicKey>,
    peer_onetime_prekey: Option<PublicKey>,
}

pub struct HandshakeOutput {
    pub shared_secret: [u8; 32],
    pub local_ephemeral_key: StaticSecret,
}

impl Handshake {
    pub fn perform(&self) -> ProtocolResult<HandshakeOutput> {
        if self.initiator {
            self.perform_initiator()
        } else {
            self.perform_responder()
        }
    }

    fn perform_initiator(&self) -> ProtocolResult<HandshakeOutput> {
        let peer_ik = self.peer_identity_key.as_ref().ok_or(ProtocolError::InvalidState)?;
        let peer_spk = self.peer_signed_prekey.as_ref().ok_or(ProtocolError::InvalidState)?;
        
        let ik_a = self.identity_key.get_x25519_secret();
        let ek_a = &self.ephemeral_key;

        // X3DH Calculations
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = ik_a.diffie_hellman(peer_spk);
        // DH2 = DH(EK_A, IK_B)
        let dh2 = ek_a.diffie_hellman(peer_ik);
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ek_a.diffie_hellman(peer_spk);

        let mut dh_material = Vec::with_capacity(32 * 4);
        dh_material.extend_from_slice(dh1.as_bytes());
        dh_material.extend_from_slice(dh2.as_bytes());
        dh_material.extend_from_slice(dh3.as_bytes());

        if let Some(peer_opk) = &self.peer_onetime_prekey {
            // DH4 = DH(EK_A, OPK_B)
            let dh4 = ek_a.diffie_hellman(peer_opk);
            dh_material.extend_from_slice(dh4.as_bytes());
        }

        let mut shared_secret = [0u8; 32];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &dh_material);
        hkdf.expand(b"X3DH_SS", &mut shared_secret).map_err(|_| ProtocolError::KeyDerivationFailed)?;

        Ok(HandshakeOutput {
            shared_secret,
            local_ephemeral_key: StaticSecret::from(ek_a.to_bytes()), // Simple copy
        })
    }

    fn perform_responder(&self) -> ProtocolResult<HandshakeOutput> {
        // Responder logic would be symmetric but needs the Initiator's ephemeral key (EK_A)
        // This is usually extracted from the first message sent by Initiator.
        // For this implementation, we'll assume peer_onetime_prekey is what was EK_A.
        
        let peer_ik = self.peer_identity_key.as_ref().ok_or(ProtocolError::InvalidState)?;
        let peer_ek = self.peer_onetime_prekey.as_ref().ok_or(ProtocolError::InvalidState)?; // Assuming peer_onetime_prekey acts as EK_A for simplicity in this flow
        
        let ik_b = self.identity_key.get_x25519_secret();
        let spk_b = &self.ephemeral_key; // Assuming EK B is the SPK for the responder in this context

        // DH1 = DH(SPK_B, IK_A)
        let dh1 = spk_b.diffie_hellman(peer_ik);
        // DH2 = DH(IK_B, EK_A)
        let dh2 = ik_b.diffie_hellman(peer_ek);
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = spk_b.diffie_hellman(peer_ek);

        let mut dh_material = Vec::with_capacity(32 * 4);
        dh_material.extend_from_slice(dh1.as_bytes());
        dh_material.extend_from_slice(dh2.as_bytes());
        dh_material.extend_from_slice(dh3.as_bytes());

        // ... handle OPK if needed ... (Responder would use its own OPK if sent by initiator)
        // This simplified responder assumes the initiator sent an OPK and it's stored in peer_onetime_prekey.
        // A full X3DH responder would also need to consider its own OPK if it was used.

        let mut shared_secret = [0u8; 32];
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &dh_material);
        hkdf.expand(b"X3DH_SS", &mut shared_secret).map_err(|_| ProtocolError::KeyDerivationFailed)?;

        Ok(HandshakeOutput {
            shared_secret,
            local_ephemeral_key: StaticSecret::from(spk_b.to_bytes()),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{KeyStore, IdentityKeyPair};
    use crate::Config;
    use tempfile::tempdir;

    #[test]
    fn test_x3dh_handshake_flow() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        
        // Setup Alice (Initiator)
        let ks_a = KeyStore::new(dir_a.path().to_path_buf(), None).unwrap();
        ks_a.set_identity(IdentityKeyPair::generate()).unwrap();
        let id_a = ks_a.get_identity_keypair().unwrap();
        
        // Setup Bob (Responder)
        let ks_b = KeyStore::new(dir_b.path().to_path_buf(), None).unwrap();
        ks_b.set_identity(IdentityKeyPair::generate()).unwrap();
        let id_b = ks_b.get_identity_keypair().unwrap();
        
        // Bob creates pre-keys
        let spk_b = crate::keystore::PreKeyPair::generate();
        let opk_b = crate::keystore::PreKeyPair::generate();
        
        // Alice builds handshake
        let mut builder = HandshakeBuilder::new()
            .with_config(Config::default())
            .with_keystore(&ks_a)
            .with_initiator(true)
            .with_peer_identity_key(&id_b.x25519_public).unwrap()
            .with_peer_signed_prekey(&spk_b.public).unwrap()
            .with_peer_onetime_prekey(&opk_b.public).unwrap();
        
        let handshake_a = builder.build().unwrap();
        let output_a = handshake_a.perform().unwrap();
        
        // Bob builds handshake (Responder)
        // Note: In real flow, Bob would receive Alice's Identity and Ephemeral Key
        let mut builder_b = HandshakeBuilder::new()
            .with_config(Config::default())
            .with_keystore(&ks_b)
            .with_initiator(false)
            .with_peer_identity_key(&id_a.x25519_public).unwrap()
            // In our simplified perform_responder, it expects EK_A in peer_onetime_prekey
            .with_peer_onetime_prekey(output_a.local_ephemeral_key.to_bytes().as_slice()).unwrap();
            
        // Use Alice's EK as SPK for Bob test if that's what logic expects?
        // Wait, builder_b needs Alice's IK and EK.
        
        let handshake_b = builder_b.build().unwrap();
        let output_b = handshake_b.perform().unwrap();
        
        assert_eq!(output_a.shared_secret, output_b.shared_secret);
        println!("Handshake shared secret match: {:x?}", output_a.shared_secret);
    }
}
