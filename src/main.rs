mod sweet_noise;
mod qnd_sync;
mod multistream;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use log::{debug, info};
use prost::Message;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

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
    noise_handshake(connection).await?;

    Ok(())
}


/// Establish secure connection using noise protocol handshake
async fn noise_handshake(connection: &mut TcpStream) -> Result<()> {
    todo!()
}
