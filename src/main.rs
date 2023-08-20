mod multistream;
mod qnd_sync;
mod sweet_noise;

use anyhow::Result;

use log::info;

use sweet_noise::crypto_primitives;
use tokio::net::TcpStream;

pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/bep.protobufs.rs"));
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let address = "172.17.0.1:4001";

    info!("Connecting to IPFS node on {address}...");
    let mut connection = TcpStream::connect(address).await?;

    connect_to_ipfs_node(&mut connection).await?;
    // qnd_sync::test_connection()?;

    Ok(())
}

async fn connect_to_ipfs_node(connection: &mut TcpStream) -> Result<()> {
    multistream::negotiate_noise_protocol(connection).await?;

    let static_key = generate_keypair()?;
    // let ephemeral_key = generate_keypair()?;

    sweet_noise::handshake(connection, &static_key, None).await?;

    Ok(())
}

fn generate_keypair() -> Result<snow::Keypair> {
    let mut rng = crypto_primitives::get_rand()?;
    let mut dh = crypto_primitives::get_dh()?;
    let mut private = vec![0u8; dh.priv_len()];
    let mut public = vec![0u8; dh.pub_len()];
    dh.generate(&mut *rng);

    private.copy_from_slice(dh.privkey());
    public.copy_from_slice(dh.pubkey());

    Ok(snow::Keypair { private, public })
}
