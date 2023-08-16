use anyhow::{anyhow, Result};
use snow::{
    params::CipherChoice,
    resolvers::{CryptoResolver, DefaultResolver},
    types::Cipher,
};

use crate::handshake_sm::CipherKey;

pub fn get_cipher_with_key(k: &CipherKey) -> Result<Box<dyn Cipher>> {
    let mut cipher = DefaultResolver::default()
        .resolve_cipher(&CipherChoice::ChaChaPoly)
        .ok_or(anyhow!("Cannot resolve cipher"))?;

    cipher.set(k);

    Ok(cipher)
}
