//! Abstraction layer for creating crypto primitives.
//! For simplicity crypto primitives are resolved currently
//! with use of snow crate.

use anyhow::{anyhow, Result};
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};

use super::CipherKey;

pub fn get_cipher_with_key(k: &CipherKey) -> Result<Box<dyn Cipher>> {
    let mut cipher = DefaultResolver
        .resolve_cipher(&CipherChoice::ChaChaPoly)
        .ok_or(anyhow!("Cannot resolve cipher"))?;

    cipher.set(k);

    Ok(cipher)
}

pub fn get_hasher() -> Result<Box<dyn Hash>> {
    DefaultResolver
        .resolve_hash(&HashChoice::SHA256)
        .ok_or(anyhow!("Cannot resolve hasher"))
}

pub fn get_dh() -> Result<Box<dyn Dh>> {
    DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or(anyhow!("Cannot resolve DH curve"))
}

pub fn get_rand() -> Result<Box<dyn Random>> {
    DefaultResolver
        .resolve_rng()
        .ok_or(anyhow!("Cannot resolve random generator"))
}
