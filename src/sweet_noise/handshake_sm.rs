/// This is a minimal implementation of noise state machine as defined in:
/// https://noiseprotocol.org/noise.html#processing-rules
use std::vec::IntoIter;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use snow::types::Dh;

use crate::sweet_noise::DH_LEN;

use super::{crypto_primitives, CipherKey, DhKey, HashDigest, TAGLEN};

use super::IPFS_NOISE_PROTOCOL_NAME;

/// Last valid nonce value, u64::MAX is reserved
const MAX_NONCE: u64 = u64::MAX - 1;

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

            self.increment_nonce()?;

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

            self.increment_nonce()?;

            plaintext
        } else {
            ciphertext.into()
        };

        Ok(plaintext)
    }

    fn increment_nonce(&mut self) -> Result<()> {
        if self.n == MAX_NONCE {
            return Err(anyhow!("Nonce overflow"));
        }

        self.n += 1;

        Ok(())
    }

    fn has_key(&self) -> bool {
        self.k.is_some()
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
    fn initialize_symmetric(protocol_name: &str) -> Result<Self> {
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
    fn mix_key(&mut self, input_key: &[u8]) -> Result<()> {
        let mut hasher = crypto_primitives::get_hasher()?;

        let mut ck = HashDigest::default();
        let mut temp_k = HashDigest::default();

        hasher.hkdf(&self.ck, input_key, 2, &mut ck, &mut temp_k, &mut []);

        self.cipher_state = CipherState::initialize_key(Some(temp_k.into()));
        self.ck = ck;

        Ok(())
    }

    /// Sets h = HASH(h || data)
    fn mix_hash(&mut self, data: &[u8]) -> Result<()> {
        let mut hasher = crypto_primitives::get_hasher()?;
        hasher.input(&self.h);
        hasher.input(data);
        hasher.result(&mut self.h);

        Ok(())
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = self.cipher_state.encrypt_with_ad(&self.h, plaintext)?;

        self.mix_hash(&ciphertext)?;

        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self.cipher_state.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext)?;
        Ok(plaintext)
    }

    /// Returns a pair of CipherState objects for encrypting transport messages.
    fn split(&self) -> Result<(CipherState, CipherState)> {
        let mut hasher = crypto_primitives::get_hasher()?;

        let mut temp_k1 = HashDigest::default();
        let mut temp_k2 = HashDigest::default();

        // Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
        hasher.hkdf(&self.ck, &[], 2, &mut temp_k1, &mut temp_k2, &mut []);

        let c1 = CipherState::initialize_key(Some(temp_k1.into()));
        let c2 = CipherState::initialize_key(Some(temp_k2.into()));

        Ok((c1, c2))
    }
}

pub struct HandshakeState {
    symmetric_state: SymmetricState,
    s: Option<Box<dyn Dh>>,
    e: Option<Box<dyn Dh>>,
    rs: Option<DhKey>,
    re: Option<DhKey>,
    message_patterns: IntoIter<Vec<MessagePatternToken>>,
}

#[derive(Debug)]
enum MessagePatternToken {
    E,
    S,
    DhOp(MessagePatternDhOpToken),
}

#[derive(Debug)]
enum MessagePatternDhOpToken {
    EE,
    ES,
    SE,
    #[allow(dead_code)]
    SS,
}

impl HandshakeState {
    pub fn initialize(protocol_name: &str, local_static_priv: &[u8]) -> Result<Self> {
        let mut symmetric_state = SymmetricState::initialize_symmetric(protocol_name)?;

        // For now support only XX
        let message_patterns = vec![
            vec![MessagePatternToken::E],
            vec![
                MessagePatternToken::E,
                MessagePatternToken::DhOp(MessagePatternDhOpToken::EE),
                MessagePatternToken::S,
                MessagePatternToken::DhOp(MessagePatternDhOpToken::ES),
            ],
            vec![
                MessagePatternToken::S,
                MessagePatternToken::DhOp(MessagePatternDhOpToken::SE),
            ],
        ]
        .into_iter();

        let mut s_dh = crypto_primitives::get_dh()?;
        s_dh.set(local_static_priv);

        // mixhash empty prologue
        symmetric_state.mix_hash(&[])?;

        Ok(Self {
            symmetric_state,
            s: Some(s_dh),
            e: None,
            rs: None,
            re: None,
            message_patterns,
        })
    }

    #[cfg(test)]
    pub fn set_local_ephemeral_for_testing(&mut self, local_ephemeral_priv: &[u8]) -> Result<()> {
        let mut e_dh = crypto_primitives::get_dh()?;
        e_dh.set(local_ephemeral_priv);
        self.e = Some(e_dh);

        Ok(())
    }

    /// Advances state machine and puts data to the out buffer that suppose to be send to the other side.
    pub fn write_message(&mut self, payload: &mut Bytes, out: &mut BytesMut) -> Result<usize> {
        let Some(current_pattern) = self.message_patterns.next() else {
            return Err(anyhow!("No more message patterns to consume"));
        };

        for token in current_pattern {
            match token {
                MessagePatternToken::E => {
                    let e_dh = if let Some(e) = &self.e {
                        // e might be already set for testing purposes
                        e
                    } else {
                        let mut e_dh = crypto_primitives::get_dh()?;
                        e_dh.generate(crypto_primitives::get_rand()?.as_mut());

                        self.e = Some(e_dh);

                        self.e.as_ref().unwrap()
                    };

                    out.put_slice(e_dh.pubkey());

                    self.symmetric_state.mix_hash(e_dh.pubkey())?;
                }
                MessagePatternToken::S => {
                    let Some(s) = &self.s else {
                        return Err(anyhow!("While parsing 's' there is no static key defined"))
                    };

                    let encrypted_s = self.symmetric_state.encrypt_and_hash(s.pubkey())?;
                    out.put_slice(&encrypted_s);
                }
                MessagePatternToken::DhOp(dh_operation) => self.handle_dh_exchange(dh_operation)?,
            }
        }

        // Appends EncryptAndHash(payload) to the buffer.
        let ct_payload = self.symmetric_state.encrypt_and_hash(payload)?;
        out.put_slice(&ct_payload);

        Ok(out.len())
    }

    /// Reads the response, takes action according to current machine state, writes out decrypted
    /// responder payload, if any.
    pub fn read_message(&mut self, input: &mut Bytes, payload: &mut BytesMut) -> Result<usize> {
        let Some(current_pattern) = self.message_patterns.next() else {
            return Err(anyhow!("No more message patterns to consume"));
        };

        for token in current_pattern {
            match token {
                MessagePatternToken::E => {
                    if self.re.is_some() {
                        return Err(anyhow!("Invalid token, 're' is already set"));
                    }

                    let mut re_pub = DhKey::default();

                    re_pub.copy_from_slice(&input.chunk()[..DH_LEN]);

                    input.advance(DH_LEN);

                    self.symmetric_state.mix_hash(&re_pub)?;

                    self.re = Some(re_pub)
                }
                MessagePatternToken::S => {
                    if self.rs.is_some() {
                        return Err(anyhow!("Invalid token, 'rs' is already set"));
                    }

                    let ct_len = if self.symmetric_state.cipher_state.has_key() {
                        // Message is encrypted with a tag
                        DH_LEN + TAGLEN
                    } else {
                        // No key set yet
                        DH_LEN
                    };

                    let plaintext = self
                        .symmetric_state
                        .decrypt_and_hash(&input.chunk()[..ct_len])
                        .context("while decrypting rs_pub")?;

                    input.advance(ct_len);

                    let mut rs_pub = DhKey::default();
                    rs_pub.copy_from_slice(&plaintext[..DH_LEN]);

                    self.rs = Some(rs_pub);
                }
                MessagePatternToken::DhOp(dh_operation) => {
                    self.handle_dh_exchange(dh_operation)?;
                }
            }
        }

        // Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
        let plaintext = self
            .symmetric_state
            .decrypt_and_hash(input)
            .context("while decrypting payload")?;

        payload.put_slice(&plaintext);

        Ok(plaintext.len())
    }

    pub fn split(&self) -> Result<(CipherState, CipherState)> {
        self.symmetric_state.split()
    }

    fn handle_dh_exchange(
        &mut self,
        dh_operation: MessagePatternDhOpToken,
    ) -> Result<(), anyhow::Error> {
        let (dh, pub_key) = match dh_operation {
            MessagePatternDhOpToken::EE => {
                let (Some(e), Some(re)) = (&self.e, &self.re) else {
                    return Err(anyhow!("While parsing 'ee', e or re is missing"));
                };

                (e, re)
            }
            MessagePatternDhOpToken::ES => {
                let (Some(e), Some(rs)) = (&self.e, &self.rs) else {
                    return Err(anyhow!("While parsing 'es', e or rs is missing"));
                };

                (e, rs)
            }
            MessagePatternDhOpToken::SE => {
                let (Some(s), Some(re)) = (&self.s, &self.re) else {
                    return Err(anyhow!("While parsing 'se', s or re is missing"));
                };

                (s, re)
            }
            MessagePatternDhOpToken::SS => {
                let (Some(s), Some(rs)) = (&self.s, &self.rs) else {
                    return Err(anyhow!("While parsing 'ss', s or rs is missing"));
                };

                (s, rs)
            }
        };
        let mut dh_exchange = DhKey::default();
        dh.dh(pub_key, &mut dh_exchange)?;
        self.symmetric_state.mix_key(&dh_exchange)?;
        Ok(())
    }

    pub(crate) fn get_remote_static(&self) -> Option<&DhKey> {
        self.rs.as_ref()
    }
}
