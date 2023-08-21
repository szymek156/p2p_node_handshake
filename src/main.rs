mod ipfs;
mod qnd_sync;
mod sweet_noise;

use anyhow::Result;

use log::info;

use tokio::net::TcpStream;

use crate::qnd_sync::test_connection;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let address = "172.17.0.1:4001";

    info!("Connecting to IPFS node on {address}...");
    let _connection = TcpStream::connect(address).await?;

    // ipfs::connect_to_node(&mut connection).await?;

    test_connection().unwrap();

    Ok(())
}
