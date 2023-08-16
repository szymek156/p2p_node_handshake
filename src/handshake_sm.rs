use std::collections::VecDeque;

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, BytesMut};
use chacha20poly1305::{
    aead::{Aead, AeadMut, Payload},
    AeadCore, AeadInPlace, ChaCha20Poly1305, KeyInit,
};
use snow::types::Dh;

use crate::crypto_primitives;

// TODO: put it somewhere else
pub const IPFS_NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const TAGLEN: usize = 16;

/// Key len for ChaCha
pub type CipherKey = [u8; 32];
/// Hash len for SHA256
pub type HashDigest = [u8; 32];
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
            let cipher = crypto_primitives::get_cipher_with_key(k)?;

            let ciphertext_len_with_tag = plaintext.len() + TAGLEN;

            let mut ciphertext = vec![0u8; ciphertext_len_with_tag];

            cipher.encrypt(self.n, ad, plaintext, &mut ciphertext);

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
            let cipher = crypto_primitives::get_cipher_with_key(k)?;

            let message_len = ciphertext.len() - TAGLEN;

            let mut plaintext = vec![0u8; message_len];
            cipher.decrypt(self.n, ad, ciphertext, &mut plaintext)?;

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
    ck: HashDigest,
    /// A handshake hash value that hashes all the handshake data that's been sent and received.
    h: HashDigest,
}

impl SymmetricState {
    pub fn initialize_symmetric(protocol_name: &str) -> Result<Self> {
        if protocol_name != IPFS_NOISE_PROTOCOL_NAME {
            return Err(anyhow!(
                "Implementation currently supports only {IPFS_NOISE_PROTOCOL_NAME}"
            ));
        }

        let hasher = crypto_primitives::get_hasher()?;

        let mut h = HashDigest::default();

        // 5.2 If protocol_name is less than or equal to HASHLEN bytes in length,
        // sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
        // Otherwise sets h = HASH(protocol_name).
        if protocol_name.len() <= hasher.hash_len() {
            h.copy_from_slice(protocol_name.as_bytes());
        } else {
            let mut hasher = hasher;
            hasher.reset();
            hasher.input(protocol_name.as_bytes());
            hasher.result(&mut h);
        }

        let ck = h.clone();

        Ok(Self {
            cipher_state: CipherState::initialize_key(None),
            ck,
            h,
        })
    }

    /// Sets ck, temp_k = HKDF(ck, input_key_material, 2).
    /// If HASHLEN is 64, then truncates temp_k to 32 bytes.
    /// Calls InitializeKey(temp_k).
    pub fn mix_key(&mut self) {
        // use hkdf crate from rust crypto??? Or more likely hmac + description from noise
    }

    /// Sets h = HASH(h || data)
    pub fn mix_hash(&mut self, data: &[u8]) -> Result<()> {
        let mut hasher = crypto_primitives::get_hasher()?;
        hasher.input(&self.h);
        hasher.input(data);
        hasher.result(&mut self.h);

        // TODO: remove
        println!("my mixhash: {:02X?}", self.h);

        Ok(())
    }
}

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    s: Option<Box<dyn Dh>>,
    e: Option<Vec<u8>>,
    rs: Option<Vec<u8>>,
    re: Option<Vec<u8>>,
    message_patterns: VecDeque<VecDeque<MessagePatternToken>>, // TODO: initiator flag
}

enum HandhsakePattern {
    XX,
}

enum MessagePatternToken {
    E,
    S,
    EE,
    ES,
    SE,
    SS
}
impl HandshakeState {
    // TODO: builder pattern required? Maybe typestate pattern, to enforce s to be set
    pub fn initialize(protocol_name: &str, local_static_priv: &[u8]) -> Result<Self> {
        let mut symmetric_state = SymmetricState::initialize_symmetric(protocol_name)?;

        // TODO: for now only XX is present, make the conversion to vecdeque nicer, or use other struct
        // TODO: convert str to enum
        let message_patterns = vec![
            vec![MessagePatternToken::E].into(),
            vec![MessagePatternToken::E, MessagePatternToken::EE, MessagePatternToken::S, MessagePatternToken::ES].into(),
            vec![MessagePatternToken::S, MessagePatternToken::SE].into(),
        ].into();

        let mut s_dh = crypto_primitives::get_dh()?;
        s_dh.set(local_static_priv);

        // mixhash empty prologue
        symmetric_state.mix_hash(&[])?;

        // Calls MixHash() once for each public key listed in the pre-messages
        // from handshake_pattern, with the specified public key as input
        // TODO: for XX we know only s is set a priori

        // TODO: confirm that happens
        // symmetric_state.mix_hash(s_dh.pubkey())?;


        Ok(Self {
            symmetric_state,
            s: Some(s_dh),
            e: None,
            rs: None,
            re: None,
            message_patterns,
        })
    }

    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<()> {
        if self.message_patterns.is_empty() {
            return Err(anyhow!("No more message patterns to consume"));
        }

        let current_token = &self.message_patterns[0][0];

        match current_token {
            MessagePatternToken::E => {
                if self.e.is_some() {
                    return Err(anyhow!("Invalid token, 'e' is already set"));
                }
                let dh = crypto_primitives::get_dh()?;

            }
            MessagePatternToken::S => todo!(),
            MessagePatternToken::EE => todo!(),
            MessagePatternToken::ES => todo!(),
            MessagePatternToken::SE => todo!(),
            MessagePatternToken::SS => todo!(),
        }

        if self.message_patterns[0].pop_front().is_none() {
            // All tokens from given step completed, move to next one
            self.message_patterns.pop_front();
        }

        Ok(())
    }
}
