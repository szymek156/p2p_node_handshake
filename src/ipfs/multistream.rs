//! Handling multistream protocol negotiation for IPFS node.
//! https://github.com/libp2p/specs/blob/master/connections/README.md
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use log::{debug, info};
use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const NOT_SUPPORTED: &str = "na";
const MULTISTREAM_PROTOCOL: &str = "/multistream/1.0.0";
const NOISE_PROTOCOL: &str = "/noise";

struct MultiselectConnection<'conn> {
    transport: Framed<&'conn mut TcpStream, LengthDelimitedCodec>,
}

impl<'conn> MultiselectConnection<'conn> {
    fn new(connection: &'conn mut TcpStream) -> MultiselectConnection<'conn> {
        // Length of the message is represented as varint. For simplicity of implementation
        // assume this field can occupy at most 1 byte. More than that would mean the following
        // string is longer than 127 bytes
        let transport = LengthDelimitedCodec::builder()
            .length_field_type::<u8>()
            .new_framed(connection);

        Self { transport }
    }

    /// Read multistream protocol response that should be structured as:
    /// |message_len: varint|protocol_name: utf8 string|\n
    /// or "na" if requested protocol is not supported
    async fn read_message(&mut self) -> Result<String> {
        let buf = self
            .transport
            .next()
            .await
            .context("Unexpected EOF")?
            .context("invalid message format")?;

        let protocol_name = String::from_utf8_lossy(&buf[..]);

        debug!("Read message {protocol_name}");
        // Each message is \n delimited
        Ok(protocol_name.trim_end_matches('\n').into())
    }

    /// Writes requested protocol name opaqued into multistream message to the Responder.
    async fn write_message(&mut self, protocol_name: &str) -> Result<()> {
        debug!("Writing protocol: {protocol_name}");

        let mut out = BytesMut::with_capacity(protocol_name.len() + 1);
        out.put_slice(protocol_name.as_bytes());
        out.put_bytes(b'\n', 1);

        self.transport.send(out.freeze()).await?;

        Ok(())
    }
}
/// Use multiselect stream protocol to agree on noise protocol selection
pub async fn negotiate_noise_protocol(connection: &mut TcpStream) -> Result<()> {
    info!("Using multiselect protocol to select noise...");
    let mut conn = MultiselectConnection::new(connection);

    let response = conn.read_message().await?;

    // Node says hello by message containing which multistream protocol version it supports
    if response != MULTISTREAM_PROTOCOL {
        return Err(anyhow!("Expected {MULTISTREAM_PROTOCOL} got: '{response}'"));
    }

    // Send our multistream support
    conn.write_message(MULTISTREAM_PROTOCOL).await?;

    // Inform other side next connection to establish would be a noise
    conn.write_message(NOISE_PROTOCOL).await?;

    let response = conn.read_message().await?;

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
