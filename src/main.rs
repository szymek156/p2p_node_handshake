mod ipfs;
mod qnd_sync;
mod sweet_noise;

use anyhow::Result;

use ipfs::noise_handshake::IpfsNoiseHandshake1;
use log::info;

use prost::Message;
use sweet_noise::generate_keypair;
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

    ipfs::connect_to_node(&mut connection).await?;
    // qnd_sync::test_connection()?;

    Ok(())
}
