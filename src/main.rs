mod ipfs;
mod sweet_noise;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use log::info;
use tokio::net::TcpStream;
use tokio_util::codec::LengthDelimitedCodec;

use crate::sweet_noise::MSG_LEN;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    let address = "127.0.0.1:4001";

    info!("Connecting to IPFS node on {address}...");
    let mut connection = TcpStream::connect(address).await?;
    let mut noise_transport = ipfs::connect_to_node(&mut connection).await?;

    // After successful handshake, Ipfs sends multistream message over secure transport layer
    let mut tcp_transport = LengthDelimitedCodec::builder()
        .length_field_type::<u16>()
        .max_frame_length(MSG_LEN)
        .new_framed(connection);

    let rcv_buf = tcp_transport
        .next()
        .await
        .context("Unexpected EOF")?
        .context("Invalid message format")?;

    let plaintext = noise_transport
        .read_message(&rcv_buf)
        .context("While decrypting the message after a handshake")?;

    info!(
        "Message over secure layer: {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    Ok(())
}
