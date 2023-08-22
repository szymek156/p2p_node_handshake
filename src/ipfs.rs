use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};

use log::{debug, info};
use prost::Message;
use snow::Keypair;
use tokio::net::TcpStream;

use crate::sweet_noise::generate_keypair;

use self::noise_handshake::{
    messages::{self, NoiseHandshakePayload},
    IpfsNoiseHandshake1, NoiseSecureTransport,
};
mod multistream;
pub mod noise_handshake;

/// Connects to IPFS node, negotiates the noise protocol and follows the handshake
pub async fn connect_to_node(connection: &mut TcpStream) -> Result<NoiseSecureTransport> {
    multistream::negotiate_noise_protocol(connection)
        .await
        .context("while negotiating noise protocol")?;

    let noise_transport = execute_noise_handshake(connection)
        .await
        .context("While handshaking in noise")?;

    info!("Session established!");

    Ok(noise_transport)
}

/// Start noise handshake to upgrade current connection with the secure layer
async fn execute_noise_handshake(connection: &mut TcpStream) -> Result<NoiseSecureTransport> {
    info!("Noise handshake begin");
    let static_keypair = generate_keypair()?;
    let id_keypair = libp2p::identity::ed25519::Keypair::generate();

    let handshake = IpfsNoiseHandshake1::new(connection, &static_keypair).await?;

    let handshake = handshake.send_e().await.context("while sending e")?;

    let (remote_payload, handshake) = handshake
        .process_response()
        .await
        .context("while processing response")?;

    debug!("Got payload: {remote_payload:?}");

    let local_payload = create_payload(&static_keypair, &id_keypair)
        .context("while preparing the payload to send")?;

    let transport = handshake
        .send_s(local_payload)
        .await
        .context("while sending s")?;

    Ok(transport)
}

/// Creates a payload that is expected to be send at "-> s, se" stage of the handshake
pub fn create_payload(
    static_keypair: &Keypair,
    id_keypair: &libp2p::identity::ed25519::Keypair,
) -> Result<NoiseHandshakePayload> {
    let mut payload = NoiseHandshakePayload::default();

    let mut to_sign = BytesMut::new();
    to_sign.put_slice("noise-libp2p-static-key:".as_bytes());
    to_sign.put_slice(&static_keypair.public);

    let signature = id_keypair.sign(&to_sign);
    payload.identity_sig = Some(signature);

    let encoded_pub_key = messages::PublicKey {
        r#type: messages::KeyType::Ed25519 as i32,
        data: id_keypair.public().to_bytes().into(),
    };

    payload.identity_key = Some(encoded_pub_key.encode_to_vec());

    Ok(payload)
}
