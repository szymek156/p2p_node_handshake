//! Minimal implementation of noise protocol handshake

use anyhow::{anyhow, Result};

pub mod crypto_primitives;
pub mod handshake_sm;

pub const IPFS_NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Tag len for ChaChaPoly AEAD
pub const TAGLEN: usize = 16;

/// Len of DH priv and pub keys
pub const DHLEN: usize = 32;

/// Len of the hash digest
pub const HASHLEN: usize = 32;

/// Max length of one noise message
pub const MSGLEN: usize = 65535;

/// Priv and Pub key type of Dh25519 curve
pub type DhKey = [u8; DHLEN];

/// Key type for ChaCha
// TODO: use secrecy or zeroize for keys
pub type CipherKey = [u8; 32];
/// Hash digest type for SHA256
pub type HashDigest = [u8; HASHLEN];

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
