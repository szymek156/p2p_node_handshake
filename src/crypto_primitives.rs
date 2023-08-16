use anyhow::{anyhow, Result};
use snow::{
    params::CipherChoice,
    resolvers::{CryptoResolver, DefaultResolver},
    types::Cipher,
};

pub fn get_cipher() -> Result<Box<dyn Cipher>> {
    DefaultResolver::default()
        .resolve_cipher(&CipherChoice::ChaChaPoly)
        .ok_or(anyhow!("Cannot resolve cipher"))
}
