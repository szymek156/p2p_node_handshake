//! Implementation of noise protocol handshake used in IPFS
//! Uses typestate pattern to avoid misuse

use crate::sweet_noise::{
    handshake_sm::{self, CipherState},
    IPFS_NOISE_PROTOCOL_NAME, MSG_LEN,
};
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use log::debug;
use prost::Message;

use tokio_util::codec::{Framed, LengthDelimitedCodec};

use self::{handshake_sm::HandshakeState, messages::NoiseHandshakePayload};

/// Compiled protobuf definitions for payloads used between IPFS nodes during the handshake
pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/ipfs.noise.rs"));
}

pub trait AsyncGenericResponder:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin
{
}

impl AsyncGenericResponder for tokio::net::TcpStream {}

/// Allows to establish secure connection to the IPFS node using noise protocol
/// Technical details: https://github.com/libp2p/specs/blob/master/noise/README.md
pub struct IpfsNoiseHandshake1<'conn, T: AsyncGenericResponder> {
    initiator: HandshakeState,
    transport: Framed<&'conn mut T, LengthDelimitedCodec>,
}

/// Implements first stage of the handshake: -> e
impl<'conn, T: AsyncGenericResponder> IpfsNoiseHandshake1<'conn, T> {
    pub async fn new(
        connection: &'conn mut T,
        static_keypair: &snow::Keypair,
    ) -> Result<IpfsNoiseHandshake1<'conn, T>> {
        // IPFS message is prefixed with u16 containing length
        // https://github.com/libp2p/specs/blob/master/noise/README.md#wire-format
        let transport = LengthDelimitedCodec::builder()
            .length_field_type::<u16>()
            .max_frame_length(MSG_LEN)
            .new_framed(connection);

        let initiator = handshake_sm::HandshakeState::initialize(
            IPFS_NOISE_PROTOCOL_NAME,
            &static_keypair.private,
        )
        .context("while initializing handshake SM")?;

        Ok(Self {
            initiator,
            transport,
        })
    }

    #[cfg(test)]
    async fn new_for_test(
        connection: &'conn mut T,
        static_keypair: &snow::Keypair,
        ephemeral_keypair: &snow::Keypair,
    ) -> Result<IpfsNoiseHandshake1<'conn, T>> {
        let mut new = Self::new(connection, static_keypair).await?;

        new.initiator
            .set_local_ephemeral_for_testing(&ephemeral_keypair.private)?;

        Ok(new)
    }

    /// Sends ephemeral key over the wire and returns second state
    pub async fn send_e(mut self) -> Result<IpfsNoiseHandshake2<'conn, T>> {
        debug!("-> e");
        let mut noise_message = BytesMut::with_capacity(MSG_LEN);
        self.initiator
            .write_message(&mut Bytes::new(), &mut noise_message)
            .context("while writing the message in the SM")?;

        self.transport.send(noise_message.freeze()).await?;

        Ok(IpfsNoiseHandshake2 {
            initiator: self.initiator,
            transport: self.transport,
        })
    }
}

/// Implements second stage of the handshake: <- e, ee, s, es
/// Handles receiving and processing the response: deriving keys, validating payload.
pub struct IpfsNoiseHandshake2<'conn, T: AsyncGenericResponder> {
    initiator: HandshakeState,
    transport: Framed<&'conn mut T, LengthDelimitedCodec>,
}

impl<'conn, T: AsyncGenericResponder> IpfsNoiseHandshake2<'conn, T> {
    /// Handles receiving and processing the response: deriving keys, validating payload.
    pub async fn process_response(
        mut self,
    ) -> Result<(NoiseHandshakePayload, IpfsNoiseHandshake3<'conn, T>)> {
        debug!("<- e, ee, s, es");

        let rcv_buf = self
            .transport
            .next()
            .await
            .context("End of stream")?
            .context("Invalid message")?;

        let mut raw_payload = BytesMut::new();
        debug!("<- read message");
        self.initiator
            .read_message(&mut rcv_buf.freeze(), &mut raw_payload)
            .context("while processing the response in 2nd stage")?;

        debug!("<- decode payload");
        let payload = self.decode_payload(&raw_payload)?;

        Ok((
            payload,
            IpfsNoiseHandshake3 {
                initiator: self.initiator,
                transport: self.transport,
            },
        ))
    }

    fn decode_payload(&self, raw_payload: &BytesMut) -> Result<messages::NoiseHandshakePayload> {
        let payload = messages::NoiseHandshakePayload::decode(&raw_payload[..])
            .context("While decoding remote payload")?;

        let Some(responder_key) = &payload.identity_key else  {
            return Err(anyhow!("Remote payload does not contain the identity key"));
        };

        let responder_key = messages::PublicKey::decode(responder_key.as_slice())
            .context("While decoding responder key")?;

        if responder_key.r#type != messages::KeyType::Ed25519 as i32 {
            return Err(anyhow!("Unsupported key type id: {}", responder_key.r#type));
        }

        let responder_key =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&responder_key.data)
                .context("While converting responder key")?;

        let rs = self
            .initiator
            .get_remote_static()
            .expect("rs should be set by state machine");

        let mut to_verify = BytesMut::new();
        to_verify.put_slice("noise-libp2p-static-key:".as_bytes());
        to_verify.put_slice(rs);

        assert!(responder_key.verify(&to_verify, payload.identity_sig()));

        Ok(payload)
    }
}

/// Implements third stage of the handshake: -> s, se
pub struct IpfsNoiseHandshake3<'conn, T: AsyncGenericResponder> {
    initiator: HandshakeState,
    transport: Framed<&'conn mut T, LengthDelimitedCodec>,
}

impl<'conn, T: AsyncGenericResponder> IpfsNoiseHandshake3<'conn, T> {
    pub async fn send_s(
        mut self,
        payload: messages::NoiseHandshakePayload,
    ) -> Result<NoiseSecureTransport> {
        debug!("-> s, se");

        let mut buf = BytesMut::with_capacity(MSG_LEN);
        let mut raw_payload = BytesMut::new();

        payload
            .encode(&mut raw_payload)
            .context("While encoding the payload to send")?;

        self.initiator
            .write_message(&mut raw_payload.freeze(), &mut buf)
            .context("While processing 3rd stage of the handshake")?;

        self.transport.send(buf.freeze()).await?;

        NoiseSecureTransport::init(self.initiator)
    }
}

/// Implements fourth stage of the handshake: generate keys for transport
pub struct NoiseSecureTransport {
    #[allow(dead_code)]
    encrypt: CipherState,
    decrypt: CipherState,
}

impl NoiseSecureTransport {
    pub fn init(initiator: HandshakeState) -> Result<Self> {
        let (encrypt, decrypt) = initiator.split()?;

        Ok(Self { encrypt, decrypt })
    }

    // TODO: make the interface unified
    pub(crate) fn read_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self.decrypt.decrypt_with_ad(&[], ciphertext)?;
        Ok(plaintext)
    }

    #[allow(dead_code)]
    pub fn write_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = self.decrypt.encrypt_with_ad(&[], plaintext)?;

        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use bytes::Buf;
    use tokio::io::AsyncReadExt;

    use crate::ipfs::create_payload;

    use super::*;
    /// Contains dump of one of successful session messages
    struct FakeResponder {
        read_buffers: Vec<Vec<u8>>,
        write_buffers: Vec<Vec<u8>>,
        static_keypair: snow::Keypair,
        ephemeral_keypair: snow::Keypair,
        id_keypair: libp2p::identity::ed25519::Keypair,
        decrypted_responder_payload: Vec<u8>,
        decrypted_message_after_handshake: Vec<u8>,
        current_read: usize,
        current_write: usize,
    }

    impl FakeResponder {
        pub fn new() -> Self {
            let ephemeral_keypair = snow::Keypair {
                private: vec![
                    24, 81, 254, 143, 214, 216, 196, 80, 30, 226, 186, 135, 208, 66, 139, 62, 4,
                    138, 22, 254, 41, 245, 43, 18, 131, 209, 152, 111, 150, 83, 144, 88,
                ],
                public: vec![
                    158, 85, 192, 115, 248, 205, 14, 23, 48, 114, 234, 254, 251, 79, 230, 232, 54,
                    58, 130, 146, 243, 104, 40, 48, 77, 172, 249, 44, 215, 213, 74, 32,
                ],
            };

            let static_keypair = snow::Keypair {
                private: vec![
                    168, 52, 148, 164, 50, 146, 162, 26, 182, 134, 5, 156, 189, 161, 7, 241, 243,
                    67, 61, 119, 162, 23, 249, 197, 170, 242, 133, 32, 215, 70, 238, 76,
                ],
                public: vec![
                    0, 244, 193, 240, 200, 30, 141, 37, 178, 23, 210, 103, 124, 98, 224, 218, 92,
                    81, 204, 110, 194, 56, 124, 99, 52, 187, 223, 35, 238, 64, 168, 58,
                ],
            };

            let id_keypair = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut [
                29, 80, 41, 218, 69, 171, 216, 208, 81, 85, 85, 197, 236, 17, 91, 96, 38, 65, 229,
                98, 2, 119, 16, 16, 207, 166, 129, 114, 45, 37, 227, 170, 70, 148, 207, 216, 172,
                243, 67, 32, 155, 81, 206, 155, 163, 129, 157, 241, 47, 94, 74, 33, 140, 75, 186,
                146, 3, 21, 11, 55, 46, 21, 142, 45,
            ])
            .unwrap();

            let decrypted_responder_payload = vec![
                10, 36, 8, 1, 18, 32, 186, 196, 179, 68, 95, 62, 73, 178, 197, 255, 107, 215, 61,
                156, 117, 45, 146, 6, 43, 121, 113, 235, 234, 110, 182, 75, 126, 17, 169, 138, 10,
                11, 18, 64, 17, 58, 221, 125, 207, 199, 49, 71, 103, 229, 165, 24, 89, 34, 237,
                189, 26, 213, 110, 14, 89, 26, 148, 93, 211, 247, 54, 173, 114, 241, 39, 124, 129,
                6, 8, 163, 40, 110, 20, 141, 132, 125, 128, 180, 183, 55, 147, 133, 83, 199, 97,
                83, 154, 107, 64, 215, 19, 170, 87, 28, 105, 219, 172, 7, 34, 28, 18, 12, 47, 121,
                97, 109, 117, 120, 47, 49, 46, 48, 46, 48, 18, 12, 47, 109, 112, 108, 101, 120, 47,
                54, 46, 55, 46, 48,
            ];

            let decrypted_message_after_handshake = vec![
                19, 47, 109, 117, 108, 116, 105, 115, 116, 114, 101, 97, 109, 47, 49, 46, 48, 46,
                48, 10,
            ];

            FakeResponder {
                read_buffers: vec![
                    // <- e, ee, s, es
                    vec![
                        121, 81, 106, 82, 151, 164, 245, 36, 216, 248, 241, 242, 248, 214, 183,
                        234, 149, 149, 20, 66, 25, 211, 193, 141, 40, 89, 194, 66, 234, 221, 180,
                        120, 37, 31, 67, 98, 171, 222, 20, 237, 223, 250, 39, 203, 34, 52, 103, 53,
                        253, 191, 228, 81, 187, 90, 245, 183, 223, 176, 139, 66, 246, 30, 139, 243,
                        25, 78, 245, 104, 24, 163, 158, 51, 84, 43, 13, 224, 45, 66, 186, 122, 91,
                        14, 197, 243, 107, 71, 131, 33, 180, 98, 61, 239, 73, 248, 97, 109, 47,
                        246, 64, 21, 73, 195, 128, 65, 58, 87, 195, 193, 221, 21, 135, 238, 222,
                        11, 102, 132, 75, 42, 114, 130, 148, 197, 52, 213, 65, 133, 213, 13, 63,
                        68, 152, 235, 120, 203, 41, 122, 64, 15, 33, 163, 91, 222, 67, 103, 192, 8,
                        107, 87, 163, 114, 186, 119, 189, 195, 121, 49, 84, 36, 225, 168, 181, 30,
                        86, 168, 95, 152, 79, 207, 37, 125, 114, 66, 123, 116, 5, 116, 89, 182,
                        144, 56, 186, 153, 60, 13, 123, 86, 186, 36, 29, 235, 5, 190, 191, 28, 147,
                        241, 25, 3, 151, 251, 231, 229, 43, 205, 136, 176, 114, 22, 48, 200, 220,
                        172, 92, 56, 196, 84, 48, 56, 118, 70, 213, 186, 184, 122, 176, 10, 90,
                        209, 20, 84,
                    ],
                    // response of the ipfs after the handshake
                    vec![
                        136, 142, 154, 77, 15, 8, 103, 63, 47, 2, 20, 89, 33, 31, 15, 143, 223,
                        113, 182, 113, 46, 27, 224, 103, 205, 34, 197, 154, 184, 122, 26, 205, 183,
                        157, 18, 179,
                    ],
                ],
                write_buffers: vec![
                    // -> e
                    ephemeral_keypair.public.clone(),
                    // -> s, se
                    vec![
                        63, 167, 91, 3, 94, 173, 97, 155, 117, 117, 199, 187, 244, 14, 125, 76, 98,
                        89, 67, 200, 23, 184, 160, 194, 228, 199, 123, 158, 137, 153, 40, 77, 77,
                        164, 61, 147, 18, 54, 8, 152, 135, 11, 206, 174, 54, 248, 10, 148, 19, 248,
                        95, 83, 176, 178, 11, 224, 102, 250, 47, 15, 49, 255, 36, 40, 30, 174, 64,
                        165, 35, 135, 196, 12, 116, 12, 153, 225, 90, 199, 101, 47, 190, 212, 176,
                        63, 185, 114, 42, 110, 225, 224, 179, 229, 224, 97, 103, 123, 202, 29, 105,
                        180, 233, 206, 19, 213, 119, 188, 43, 192, 170, 223, 231, 59, 0, 225, 229,
                        113, 214, 5, 66, 102, 69, 242, 121, 167, 216, 5, 190, 201, 48, 74, 61, 152,
                        100, 25, 38, 173, 108, 134, 9, 98, 249, 91, 63, 3, 106, 79, 75, 230, 230,
                        81, 187, 140, 224, 1, 153, 104, 90, 223, 157, 214, 183, 176, 205, 39, 19,
                        7, 23, 165,
                    ],
                ],
                static_keypair,
                ephemeral_keypair,
                id_keypair,
                decrypted_responder_payload,
                decrypted_message_after_handshake,

                current_read: 0,
                current_write: 0,
            }
        }

        fn static_keypair(&self) -> snow::Keypair {
            snow::Keypair {
                private: self.static_keypair.private.clone(),
                public: self.static_keypair.public.clone(),
            }
        }

        fn ephemeral_keypair(&self) -> snow::Keypair {
            snow::Keypair {
                private: self.ephemeral_keypair.private.clone(),
                public: self.ephemeral_keypair.public.clone(),
            }
        }

        fn id_keypair(&self) -> libp2p::identity::ed25519::Keypair {
            self.id_keypair.clone()
        }

        fn plaintext_message_after_handshake(&self) -> Vec<u8> {
            self.decrypted_message_after_handshake.clone()
        }
    }

    impl AsyncGenericResponder for FakeResponder {}

    const IPFS_HEADER_LEN: usize = 2;

    impl tokio::io::AsyncRead for FakeResponder {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let result = &self.read_buffers[self.current_read];
            let ipfs_header = result.len() as u16;
            buf.clear();

            buf.put_slice(&ipfs_header.to_be_bytes());
            buf.put_slice(result);

            self.current_read += 1;

            Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for FakeResponder {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> Poll<std::result::Result<usize, std::io::Error>> {
            let expected_result = &self.write_buffers[self.current_write];
            assert_eq!(&buf[IPFS_HEADER_LEN..], expected_result);

            self.current_write += 1;

            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<std::result::Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<std::result::Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_handshake() {
        pretty_env_logger::init();
        let mut fake_responder = FakeResponder::new();

        let static_keypair = fake_responder.static_keypair();
        let ephemeral_keypair = fake_responder.ephemeral_keypair();
        let id_keypair = fake_responder.id_keypair();
        let expected_payload =
            NoiseHandshakePayload::decode(fake_responder.decrypted_responder_payload.as_slice())
                .unwrap();
        let expected_plaintext = fake_responder.plaintext_message_after_handshake();

        let handshake = IpfsNoiseHandshake1::new_for_test(
            &mut fake_responder,
            &static_keypair,
            &ephemeral_keypair,
        )
        .await
        .unwrap();

        let handshake = handshake.send_e().await.unwrap();

        let (payload, handshake) = handshake.process_response().await.unwrap();
        assert_eq!(payload, expected_payload);

        let payload = create_payload(&static_keypair, &id_keypair).unwrap();

        let mut transport = handshake.send_s(payload).await.unwrap();

        // Message send over secure layer, try to decrypt
        let mut encrypted_message = BytesMut::zeroed(MSG_LEN);
        let n = fake_responder.read(&mut encrypted_message).await.unwrap();
        encrypted_message.resize(n, 0);

        // skip header
        encrypted_message.advance(2);

        let plaintext = transport.read_message(&encrypted_message).unwrap();

        assert_eq!(plaintext, expected_plaintext);
    }
}
