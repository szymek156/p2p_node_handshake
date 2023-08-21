mod ipfs;
mod sweet_noise;

use anyhow::Result;
use log::info;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let address = "127.0.0.1:4001";

    info!("Connecting to IPFS node on {address}...");
    let mut connection = TcpStream::connect(address).await?;
    ipfs::connect_to_node(&mut connection).await?;

    Ok(())
}
