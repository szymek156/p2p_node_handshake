mod crypto_primitives;
mod handshake_sm;
mod qnd_sync;

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use log::{debug, info};
use prost::Message;
use tokio::{io::AsyncReadExt, net::TcpStream};

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
    negotiate_noise_protocol(connection).await?;
    noise_handshake(connection).await?;

    Ok(())
}

/// Use multiselect stream protocol to agree on noise protocol selection
async fn negotiate_noise_protocol(connection: &mut TcpStream) -> Result<()> {
    info!("Using multiselect protocol to select noise...");
    let protocol_name = read_response(connection).await?;

    // Node says hello by message containing which multistream protocol version it supports
    if !protocol_name.starts_with("/multistream/1.0.0") {
        return Err(anyhow!("Expected /multistream/1.0.0 got: '{protocol_name}'"));
    }

    // Send our multistream support


    Ok(())
}

/// Length of the message is represented as varint. For simplicity of implementation
/// assume this field can occupy at most 1 byte. More than that would mean the following
/// string is longer than 127 bytes
fn get_message_len(buf: &mut BytesMut) -> Result<usize> {
    let len = buf.get_u8();
    if len < 0x80 {
        // Len is encoded on a single byte
        Ok(len as usize)
    } else {
        return Err(anyhow!("Message len occupies more than 1 byte"));
    }
}

// TODO: move to IPFS module?
async fn read_response(connection: &mut TcpStream) -> Result<String> {
    let mut buf = BytesMut::with_capacity(1024);

    let read = connection.read_buf(&mut buf).await?;

    let msg_len = get_message_len(&mut buf).context("while parsing message length")?;

    debug!("parsed message length {msg_len}, read {read}");
    if msg_len > read - 1 {
        let remaining = msg_len - read - 1;

        debug!("Remaining bytes to read: {remaining}");
        buf.resize(msg_len, 0);

        connection.read_exact(&mut buf[read..]).await?;
    }

    let protocol_name = String::from_utf8_lossy(&buf[..]);

    Ok(protocol_name.into())
}

/// Establish secure connection using noise protocol handshake
async fn noise_handshake(connection: &mut TcpStream) -> Result<()> {
    todo!()
}
