use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use chacha20poly1305::{
    aead::{AeadMut, Payload, Aead},
    AeadCore, AeadInPlace, ChaCha20Poly1305, KeyInit,
};

// http://www.plantuml.com/plantuml/uml/SyfFKj2rKt3CoKnELR1Io4ZDoSa70000

pub const IPFS_NOISE_PROTOCOL_NAME:  &str = "Noise_XX_25519_ChaChaPoly_SHA256";

pub type CipherKey = [u8; 32];
/// The key k and nonce n are used to encrypt static public keys and handshake payloads.
pub struct CipherState {
    k: Option<CipherKey>,
    n: u64,
}

impl CipherState {
    pub fn initialize_key(k: Option<CipherKey>) -> Self {
        Self { k, n: 0 }
    }

    /// ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = if let Some(k) = &self.k {
            let mut cipher = ChaCha20Poly1305::new(k.into());

            // Size of the nonce in ChaCha full round is 12 bytes, convert the u64 to 12 bytes
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.n.to_le_bytes());

            let payload = Payload {
                msg: plaintext,
                aad: ad,
            };

            let ciphertext = cipher
                .encrypt(&nonce.into(), payload)
                .context("while encrypting AEAD")?;

            // TODO: overflow
            self.n += 1;

            ciphertext
        } else {
            plaintext.into()
        };

        Ok(ciphertext)
    }

    /// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext.
    /// If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = if let Some(k) = &self.k {

            // TODO: might want to extract concrete implementation into newtype
            let cipher = ChaCha20Poly1305::new(k.into());

            // Size of the nonce in ChaCha full round is 12 bytes, convert the u64 to 12 bytes
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.n.to_le_bytes());


            let payload = Payload { msg: ciphertext, aad: ad };
            let plaintext = cipher.decrypt(&nonce.into(), payload).context("while decrypting AEAD")?;

            self.n += 1;

            plaintext
        } else {
            ciphertext.into()
        };

        Ok(plaintext)
    }
}

pub struct SymmetricState {
    cipher_state: CipherState,
    /// A chaining key that hashes all previous DH outputs. Once the handshake completes,
    /// the chaining key will be used to derive the encryption keys for transport messages.
    ck: Vec<u8>,
    /// A handshake hash value that hashes all the handshake data that's been sent and received.
    h: Vec<u8>,
}

impl SymmetricState {
    pub fn initialize_symmetric(protocol: &str) -> Self {
        assert_eq!(protocol, IPFS_NOISE_PROTOCOL_NAME, "Implementation currently supports only {IPFS_NOISE_PROTOCOL_NAME}");
        // TODO: do protocol padding
        //h = H(protocol)
        let h = todo!();
        let ck = h;
        Self {
            cipher_state: CipherState::initialize_key(None),
            ck: ck,
            h: h,
        }
    }

    pub fn mix_key(&mut self) {
        // use hkdf crate from rust crypto??? Or more likely hmac + description from noise
        todo!()
    }

    pub fn mix_hash(&mut self) {
        todo!()
    }
}

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    s: Vec<u8>,
    e: Vec<u8>,
    rs: Vec<u8>,
    re: Vec<u8>,
}
