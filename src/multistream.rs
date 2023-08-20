//! Handling multistream protocol negotiation for IPFS node.
//! https://github.com/libp2p/specs/blob/master/connections/README.md
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use log::{debug, info};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const NOT_SUPPORTED: &str = "na";
const MULTISTREAM_PROTOCOL: &str = "/multistream/1.0.0";
const NOISE_PROTOCOL: &str = "/noise";

/// Use multiselect stream protocol to agree on noise protocol selection
pub async fn negotiate_noise_protocol(connection: &mut TcpStream) -> Result<()> {
    info!("Using multiselect protocol to select noise...");
    let response = read_message(connection).await?;

    // Node says hello by message containing which multistream protocol version it supports
    if response != MULTISTREAM_PROTOCOL {
        return Err(anyhow!("Expected {MULTISTREAM_PROTOCOL} got: '{response}'"));
    }

    // Send our multistream support
    write_message(connection, MULTISTREAM_PROTOCOL).await?;

    // Inform other side next connection to establish would be a noise
    write_message(connection, NOISE_PROTOCOL).await?;

    let response = read_message(connection).await?;

    match response.as_str() {
        // Responder accepts noise
        NOISE_PROTOCOL => {
            info!("Noise protocol negotiated!");
            Ok(())
        }
        NOT_SUPPORTED => Err(anyhow!("Node does not support {NOISE_PROTOCOL}")),
        _ => Err(anyhow!("Unexpected response: {response}")),
    }
}

/// Read multistream protocol response that should be structured as:
/// |message_len: varint|protocol_name: utf8 string|\n
/// or "na" if requested protocol is not supported
async fn read_message(connection: &mut TcpStream) -> Result<String> {
    // Length of the message is represented as varint. For simplicity of implementation
    // assume this field can occupy at most 1 byte. More than that would mean the following
    // string is longer than 127 bytes
    let msg_len = connection.read_u8().await?;
    debug!("Message length {msg_len}");
    if msg_len >= 0x80 {
        return Err(anyhow!("Message len occupies more than 1 byte"));
    }

    let mut buf = BytesMut::zeroed(msg_len as usize);

    connection.read_exact(&mut buf).await?;

    let protocol_name = String::from_utf8_lossy(&buf[..]);

    debug!("Read message {protocol_name}");
    // Each message is \n delimited
    Ok(protocol_name.trim_end_matches('\n').into())
}

/// Writes requested protocol name opaqued into multistream message to the Responder.
async fn write_message(connection: &mut TcpStream, protocol_name: &str) -> Result<()> {
    debug!("Writing protocol: {protocol_name}");

    // the string itself + newline character
    let msg_len = protocol_name.len() + 1;
    if msg_len > 127 {
        return Err(anyhow!("Protocol name exceeds 127 bytes"));
    }

    let mut out = BytesMut::with_capacity(msg_len + 1);
    out.put_u8(msg_len as u8);
    out.put_slice(protocol_name.as_bytes());
    out.put_bytes(b'\n', 1);

    connection.write_all(&out).await?;

    Ok(())
}
