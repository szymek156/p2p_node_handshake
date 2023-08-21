//! Implementation of noise protocol handshake used in IPFS

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use log::{debug, info};
use prost::Message;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    messages::{self, NoiseHandshakePayload},
    sweet_noise::{handshake_sm, IPFS_NOISE_PROTOCOL_NAME, MSGLEN},
};

use self::handshake_sm::HandshakeState;

pub trait AsyncGenericResponder:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin
{
}

impl AsyncGenericResponder for tokio::net::TcpStream {}

/// Allows to establish secure connection to the IPFS node using noise protocol
/// Technical details: https://github.com/libp2p/specs/blob/master/noise/README.md
pub struct IpfsNoiseHandshake1<'a, T: AsyncGenericResponder> {
    initiator: HandshakeState,
    connection: &'a mut T,
}

impl<'a, T: AsyncGenericResponder> IpfsNoiseHandshake1<'a, T> {
    pub async fn new(
        connection: &'a mut T,
        static_keypair: &snow::Keypair,
        ephemeral_keypair: Option<&snow::Keypair>,
    ) -> Result<IpfsNoiseHandshake1<'a, T>> {
        let mut initiator = handshake_sm::HandshakeState::initialize(
            IPFS_NOISE_PROTOCOL_NAME,
            &static_keypair.private,
        )
        .context("while initializing handshake SM")?;

        if let Some(e) = ephemeral_keypair {
            initiator.set_local_ephemeral_for_testing(&e.private)?;
        }

        Ok(Self {
            initiator,
            connection,
        })
    }

    pub async fn send_e(mut self) -> Result<IpfsNoiseHandshake2<'a, T>> {
        debug!("-> e");
        let mut noise_message = vec![0u8; MSGLEN];
        let len = self
            .initiator
            .write_message(&[], &mut noise_message)
            .context("while writing the message in the SM")?;

        send_ipfs_message(self.connection, &noise_message[..len]).await?;

        Ok(IpfsNoiseHandshake2 {
            initiator: self.initiator,
            connection: self.connection,
        })
    }
}

async fn send_ipfs_message<T: AsyncGenericResponder>(
    connection: &mut T,
    payload: &[u8],
) -> Result<()> {
    let mut finalbuf = BytesMut::new();
    finalbuf.put_u16(payload.len() as u16);
    finalbuf.put_slice(&payload);
    connection.write_all(&finalbuf).await?;

    Ok(())
}

pub struct IpfsNoiseHandshake2<'a, T: AsyncGenericResponder> {
    initiator: HandshakeState,
    connection: &'a mut T,
}

impl<'a, T: AsyncGenericResponder> IpfsNoiseHandshake2<'a, T> {
    pub async fn process_response(
        mut self,
    ) -> Result<(NoiseHandshakePayload, IpfsNoiseHandshake3<'a, T>)> {
        debug!("<- e, ee, s, es");

        let mut rcv_buf = BytesMut::zeroed(65535);
        let rcv = self.connection.read(&mut rcv_buf).await?;
        debug!("read {rcv} bytes");
        rcv_buf.resize(rcv, 0);
        let len = rcv_buf.get_u16();
        debug!("len in payload {len} bytes");

        let mut raw_payload = BytesMut::zeroed(65535);
        let payload_len = self
            .initiator
            .read_message(&mut rcv_buf, &mut raw_payload)
            .unwrap();

        raw_payload.resize(payload_len, 0);

        let payload = self.decode_payload(&mut raw_payload)?;

        Ok((
            payload,
            IpfsNoiseHandshake3 {
                initiator: self.initiator,
                connection: self.connection,
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
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&responder_key.data).unwrap();

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

pub struct IpfsNoiseHandshake3<'a, T: AsyncGenericResponder> {
    initiator: HandshakeState,
    connection: &'a mut T,
}

impl<'a, T: AsyncGenericResponder> IpfsNoiseHandshake3<'a, T> {
    pub async fn send_s(mut self, payload: messages::NoiseHandshakePayload) -> Result<()> {
        debug!("-> s, se");

        let mut buf = vec![0u8; MSGLEN];
        let mut raw_payload = BytesMut::new();
        payload.encode(&mut raw_payload).unwrap();

        let len = self
            .initiator
            .write_message(&raw_payload, &mut buf)
            .unwrap();

        send_ipfs_message(self.connection, &buf[..len]).await?;

        // TODO: step 4 - call split?
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;

    use super::*;
    /// Contains dump of one of successful session messages
    struct FakeResponder {
        read_buffers: Vec<Vec<u8>>,
        write_buffers: Vec<Vec<u8>>,
        static_key: snow::Keypair,
        ephemeral_key: snow::Keypair,
        current_read: usize,
        current_write: usize,
    }

    impl FakeResponder {
        pub fn new() -> Self {
            let ephemeral_key = snow::Keypair {
                private: vec![
                    24, 81, 254, 143, 214, 216, 196, 80, 30, 226, 186, 135, 208, 66, 139, 62, 4,
                    138, 22, 254, 41, 245, 43, 18, 131, 209, 152, 111, 150, 83, 144, 88,
                ],

                public: vec![
                    158, 85, 192, 115, 248, 205, 14, 23, 48, 114, 234, 254, 251, 79, 230, 232, 54,
                    58, 130, 146, 243, 104, 40, 48, 77, 172, 249, 44, 215, 213, 74, 32,
                ],
            };

            FakeResponder {
                read_buffers: vec![
                    // <- e, ee, s, es
                    vec![
                        153, 227, 187, 95, 38, 18, 164, 53, 136, 46, 26, 192, 153, 135, 227, 14,
                        169, 30, 107, 75, 42, 237, 220, 30, 214, 34, 160, 196, 252, 134, 63, 81,
                        243, 42, 76, 1, 71, 167, 162, 19, 61, 216, 143, 150, 123, 220, 233, 59,
                        241, 16, 238, 247, 62, 25, 148, 216, 174, 10, 100, 81, 249, 244, 34, 19,
                        241, 208, 40, 187, 125, 82, 197, 178, 166, 44, 183, 1, 78, 142, 11, 42,
                        239, 194, 27, 46, 46, 25, 193, 97, 226, 141, 0, 148, 19, 180, 12, 6, 254,
                        139, 88, 15, 139, 123, 161, 184, 50, 74, 34, 100, 239, 25, 162, 207, 73,
                        46, 106, 100, 101, 248, 52, 59, 24, 100, 189, 139, 243, 71, 214, 188, 224,
                        162, 178, 159, 77, 55, 89, 222, 227, 254, 42, 193, 200, 144, 216, 106, 117,
                        101, 70, 102, 36, 129, 190, 180, 215, 221, 68, 216, 24, 184, 52, 246, 146,
                        27, 38, 54, 68, 184, 245, 13, 106, 191, 171, 167, 171, 5, 109, 115, 137,
                        152, 209, 201, 225, 58, 167, 176, 35, 31, 167, 173, 17, 5, 34, 96, 108, 22,
                        120, 157, 241, 251, 196, 126, 103, 63, 139, 138, 173, 188, 195, 71, 199,
                        249, 198, 169, 186, 111, 212, 177, 237, 96, 60, 72, 223, 208, 220, 67, 49,
                        133, 112, 83, 111, 89,
                    ],
                ],
                write_buffers: vec![
                    // -> e
                    ephemeral_key.public.clone(),
                    // TODO: add last steps
                ],
                static_key: snow::Keypair {
                    private: vec![
                        168, 52, 148, 164, 50, 146, 162, 26, 182, 134, 5, 156, 189, 161, 7, 241,
                        243, 67, 61, 119, 162, 23, 249, 197, 170, 242, 133, 32, 215, 70, 238, 76,
                    ],
                    public: vec![
                        0, 244, 193, 240, 200, 30, 141, 37, 178, 23, 210, 103, 124, 98, 224, 218,
                        92, 81, 204, 110, 194, 56, 124, 99, 52, 187, 223, 35, 238, 64, 168, 58,
                    ],
                },
                ephemeral_key,
                current_read: 0,
                current_write: 0,
            }
        }

        fn static_key(&self) -> snow::Keypair {
            snow::Keypair {
                private: self.static_key.private.clone(),
                public: self.static_key.public.clone(),
            }
        }

        fn ephemeral_key(&self) -> snow::Keypair {
            snow::Keypair {
                private: self.ephemeral_key.private.clone(),
                public: self.ephemeral_key.public.clone(),
            }
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
            buf.initialized_mut()[..IPFS_HEADER_LEN].copy_from_slice(&ipfs_header.to_be_bytes());
            buf.initialized_mut()[IPFS_HEADER_LEN..(IPFS_HEADER_LEN + result.len())]
                .copy_from_slice(result);
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

    // #[test]
    // fn test_snow_handshake() {
    //     let mut fake_responder = FakeResponder::new();

    //     let static_key = fake_responder.static_key();
    //     let ephemeral_key = fake_responder.ephemeral_key();
    //     handshake_with_snow(&mut fake_responder, &static_key, Some(&ephemeral_key)).unwrap();
    // }

    #[tokio::test]
    async fn test_handshake() {
        let mut fake_responder = FakeResponder::new();

        let static_keypair = fake_responder.static_key();
        let ephemeral_keypair = fake_responder.ephemeral_key();

        let handshake = IpfsNoiseHandshake1::new(
            &mut fake_responder,
            &static_keypair,
            Some(&ephemeral_keypair),
        )
        .await
        .unwrap();

        let handshake = handshake.send_e().await.unwrap();
        let (payload, handshake) = handshake.process_response().await.unwrap();

        handshake.send_s(payload).await.unwrap();
    }
}
