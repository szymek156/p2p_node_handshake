//! Minimal implementation of noise protocol handshake

use std::ops::{Deref, DerefMut};

use anyhow::Result;
use zeroize::ZeroizeOnDrop;

pub mod crypto_primitives;
pub mod handshake_sm;

pub const IPFS_NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Tag len for ChaChaPoly AEAD
pub const TAGLEN: usize = 16;

/// Len of DH priv and pub keys
pub const DH_LEN: usize = 32;

/// Len of the hash digest
pub const HASH_LEN: usize = 32;

/// Max length of one noise message
pub const MSG_LEN: usize = 65535;

/// Key length for ChaCha
pub const CIPHER_KEY_LEN: usize = 32;

/// Priv and Pub key type of Dh25519 curve
#[derive(ZeroizeOnDrop, Default)]
pub struct DhKey([u8; DH_LEN]);

impl From<[u8; DH_LEN]> for DhKey {
    fn from(value: [u8; DH_LEN]) -> Self {
        Self(value)
    }
}

impl Deref for DhKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // self.as_ref()
        &self.0
    }
}

impl DerefMut for DhKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Key type for ChaCha
#[derive(ZeroizeOnDrop)]
pub struct CipherKey([u8; CIPHER_KEY_LEN]);

impl From<[u8; CIPHER_KEY_LEN]> for CipherKey {
    fn from(value: [u8; CIPHER_KEY_LEN]) -> Self {
        Self(value)
    }
}

impl From<HashDigest> for CipherKey {
    fn from(value: HashDigest) -> Self {
        Self(value.0)
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // self.as_ref()
        &self.0
    }
}

/// Hash digest type for SHA256
#[derive(ZeroizeOnDrop, Default, Clone)]
pub struct HashDigest([u8; HASH_LEN]);

impl Deref for HashDigest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // self.as_ref()
        &self.0
    }
}

impl DerefMut for HashDigest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn generate_keypair() -> Result<snow::Keypair> {
    let mut rng = crypto_primitives::get_rand()?;
    let mut dh = crypto_primitives::get_dh()?;
    let mut private = vec![0u8; dh.priv_len()];
    let mut public = vec![0u8; dh.pub_len()];
    dh.generate(&mut *rng);

    private.copy_from_slice(dh.privkey());
    public.copy_from_slice(dh.pubkey());

    Ok(snow::Keypair { private, public })
}
