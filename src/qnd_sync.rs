use std::io::prelude::*;
use std::net::TcpStream;

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};

use prost::Message;

use crate::{
    crypto_primitives, messages,
    sweet_noise::{handshake_sm, IPFS_NOISE_PROTOCOL_NAME},
};

pub fn test_connection() -> Result<()> {
    let mut stream = TcpStream::connect("172.17.0.1:4001")?;

    // get /multistream/1.0.0
    get_resp(&mut stream)?;

    write_msg(&mut stream, "/multistream/1.0.0")?;
    write_msg(&mut stream, "/noise")?;
    get_resp(&mut stream)?;

    // supports both
    // write_msg(&mut stream, "/tls/1.0.0")?;
    // get_resp(&mut stream)?;

    // generate libp2p idendity keypair
    // use identity keypair to sign a Noise static key
    // noise handshake pattern: XX
    // crypto primitives used:
    // 25519DH, ChaChaPoly Sha256
    // Noise protocol name: Noise_XX_25519_ChaChaPoly_SHA256
    // All data is segmented into messages with the following structure:
    // noise_message_len 	                        noise_message
    // 2 bytes (16bit uint bigendian) 	            variable length
    //

    // p2p id can be retrieved using:
    // PeerId uses multihash for encoding
    // pub fn peer_id(i: u64) -> PeerId {
    //     ipfs_embed::identity::Keypair::Ed25519(keypair(i))
    //         .public()
    //         .into()
    // }

    let static_key = generate_keypair()?;
    // let ephemeral_key = generate_keypair()?;

    // handshake_with_snow(&mut stream, &static_key, Some(&ephemeral_key))?;

    handshake(&mut stream, &static_key, None)?;

    Ok(())
}

fn generate_keypair() -> Result<snow::Keypair> {
    let mut rng = crypto_primitives::get_rand()?;
    let mut dh = crypto_primitives::get_dh()?;
    let mut private = vec![0u8; dh.priv_len()];
    let mut public = vec![0u8; dh.pub_len()];
    dh.generate(&mut *rng);

    private.copy_from_slice(dh.privkey());
    public.copy_from_slice(dh.pubkey());

    Ok(snow::Keypair { private, public })
}

fn handshake_with_snow<T>(
    stream: &mut T,
    static_keypair: &snow::Keypair,
    ephemeral_keypair: Option<&snow::Keypair>,
) -> Result<()>
where
    T: std::io::Read + std::io::Write,
{
    println!("SNOW handshake begin");

    println!(
        "static key: priv: {:?}, pub {:?}",
        &static_keypair.private, &static_keypair.public
    );

    let static_key = static_keypair.private.clone();

    let mut builder = snow::Builder::new(IPFS_NOISE_PROTOCOL_NAME.parse().unwrap())
        .local_private_key(&static_key);

    if let Some(e) = ephemeral_keypair {
        builder = builder.fixed_ephemeral_key_for_testing_only(&e.private);

        println!("ephemeral key: priv: {:?}, pub {:?}", &e.private, &e.public);
    }

    let mut initiator = builder.build_initiator().unwrap();

    // e
    println!("-> e");
    let mut buf = vec![0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    println!("NOISE: buffer: {:?}, len: {len}", &buf[..len]);

    let mut finalbuf = BytesMut::new();
    finalbuf.put_u16(len as u16);
    finalbuf.put_slice(&buf[..len]);
    stream.write_all(&finalbuf).unwrap();

    println!("<- e, ee, s, es");
    let mut rcv_buf = BytesMut::zeroed(65535);
    let rcv = stream.read(&mut rcv_buf)?;

    rcv_buf.resize(rcv, 0);
    let len = rcv_buf.get_u16() as usize;

    println!("NOISE: buffer: {:?}, len: {len}", &rcv_buf[..]);

    // e, ee, s, es
    let mut raw_payload = BytesMut::zeroed(65535);
    let payload_len = initiator
        .read_message(&mut rcv_buf, &mut raw_payload)
        .unwrap();

    println!(
        "NOISE: decrypted payload: {:?}, len: {payload_len}",
        &raw_payload[..payload_len]
    );

    let mut payload = messages::NoiseHandshakePayload::decode(&raw_payload[..payload_len]).unwrap();
    // println!("payload from second msg: {payload:#?}");

    println!("decoding the responder key");
    let responder_key =
        messages::PublicKey::decode(payload.identity_key.as_ref().unwrap().clone().as_slice())
            .unwrap();

    assert_eq!(responder_key.r#type, messages::KeyType::Ed25519 as i32);
    let responder_key =
        libp2p::identity::ed25519::PublicKey::try_from_bytes(&responder_key.data).unwrap();

    println!("decoding the signature");
    let rs = initiator.get_remote_static().unwrap();
    let mut to_verify = BytesMut::new();
    to_verify.put_slice("noise-libp2p-static-key:".as_bytes());
    to_verify.put_slice(rs);

    assert_eq!(
        responder_key.verify(&to_verify, payload.identity_sig()),
        true
    );

    println!("preparing the payload");
    let id_keypair = libp2p::identity::ed25519::Keypair::generate();

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

    // -> s, se
    let mut buf = vec![0u8; 65535];
    let mut raw_payload = BytesMut::new();
    payload.encode(&mut raw_payload).unwrap();

    println!("encoded raw payload: {}", raw_payload.len());

    let len = initiator.write_message(&raw_payload, &mut buf).unwrap();
    println!("LEN: {len}");

    let mut finalbuf = BytesMut::new();
    finalbuf.put_u16(len as u16);
    finalbuf.put_slice(&buf[..len]);
    stream.write_all(&finalbuf).unwrap();

    let mut rcv_buf = BytesMut::zeroed(65535);
    let rcv = stream.read(&mut rcv_buf)?;
    println!("read {rcv} bytes");
    rcv_buf.resize(rcv, 0);
    let len = rcv_buf.get_u16();
    println!("len in payload {len} bytes");

    let mut noise = initiator.into_transport_mode().unwrap();
    println!("session established!");

    Ok(())
}

fn handshake<T>(
    stream: &mut T,
    static_keypair: &snow::Keypair,
    ephemeral_keypair: Option<&snow::Keypair>,
) -> Result<()>
where
    T: std::io::Read + std::io::Write,
{
    println!("MINE handshake begin");

    let mut initiator =
        handshake_sm::HandshakeState::initialize(IPFS_NOISE_PROTOCOL_NAME, &static_keypair.private)
            .unwrap();

    if let Some(e) = ephemeral_keypair {
        initiator.set_local_ephemeral_for_testing(&e.private)?;
    }

    // e
    println!("-> e");
    let mut buf = vec![0u8; 65535];
    let len = initiator.write_message(&[], &mut buf).unwrap();

    println!("LEN: {len}");
    let mut finalbuf = BytesMut::new();
    finalbuf.put_u16(len as u16);
    finalbuf.put_slice(&buf[..len]);
    stream.write_all(&finalbuf).unwrap();

    let mut rcv_buf = BytesMut::zeroed(65535);
    let rcv = stream.read(&mut rcv_buf)?;
    println!("read {rcv} bytes");
    rcv_buf.resize(rcv, 0);
    let len = rcv_buf.get_u16();
    println!("len in payload {len} bytes");

    // e, ee, s, es
    println!("-> e, ee, s, es");
    let mut raw_payload = BytesMut::zeroed(65535);
    let payload_len = initiator
        .read_message(&mut rcv_buf, &mut raw_payload)
        .unwrap();

    let mut payload = messages::NoiseHandshakePayload::decode(&raw_payload[..payload_len]).unwrap();
    println!("payload from second msg: {payload:#?}");

    println!("decoding the responder key");
    let responder_key =
        messages::PublicKey::decode(payload.identity_key.as_ref().unwrap().clone().as_slice())
            .unwrap();

    assert_eq!(responder_key.r#type, messages::KeyType::Ed25519 as i32);
    let responder_key =
        libp2p::identity::ed25519::PublicKey::try_from_bytes(&responder_key.data).unwrap();

    println!("decoding the signature");
    let rs = initiator.get_remote_static().unwrap();
    let mut to_verify = BytesMut::new();
    to_verify.put_slice("noise-libp2p-static-key:".as_bytes());
    to_verify.put_slice(rs);

    assert_eq!(
        responder_key.verify(&to_verify, payload.identity_sig()),
        true
    );

    println!("preparing the payload");
    let id_keypair = libp2p::identity::ed25519::Keypair::generate();

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

    // -> s, se
    let mut buf = vec![0u8; 65535];
    let mut raw_payload = BytesMut::new();
    payload.encode(&mut raw_payload).unwrap();

    println!("encoded raw payload: {}", raw_payload.len());

    let len = initiator.write_message(&raw_payload, &mut buf).unwrap();
    println!("LEN: {len}");

    let mut finalbuf = BytesMut::new();
    finalbuf.put_u16(len as u16);
    finalbuf.put_slice(&buf[..len]);
    stream.write_all(&finalbuf).unwrap();

    let mut rcv_buf = BytesMut::zeroed(65535);
    let rcv = stream.read(&mut rcv_buf)?;
    println!("read {rcv} bytes");
    rcv_buf.resize(rcv, 0);
    let len = rcv_buf.get_u16();
    println!("len in payload {len} bytes");
    // TODO: parse payload?

    // let mut noise = initiator.into_transport_mode().unwrap();
    println!("session established!");

    Ok(())
}

fn write_msg(stream: &mut TcpStream, arg: &str) -> Result<()> {
    println!("write {arg}");
    let mut out = BytesMut::new();

    let msg = format!("{arg}\n");
    out.put_u8(msg.len() as u8);
    out.put_slice(&msg.as_bytes());
    stream.write_all(&out)?;

    Ok(())
}

fn get_resp(stream: &mut TcpStream) -> Result<BytesMut> {
    let mut buf = BytesMut::zeroed(1024);

    let rcv = stream.read(&mut buf)?;

    // println!("read {rcv} bytes");

    // let hex = buf[..rcv]
    //     .iter()
    //     .map(|b| format!("{b:02X}"))
    //     .collect::<Vec<String>>();
    // println!("{hex:?}");

    let resp = String::from_utf8_lossy(&buf[1..rcv]);
    println!("{resp}");

    Ok(buf)
}

#[cfg(test)]
mod tests {
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

    const IPFS_HEADER_LEN: usize = 2;

    impl std::io::Read for FakeResponder {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let result = &self.read_buffers[self.current_read];

            let ipfs_header = result.len() as u16;
            buf[..IPFS_HEADER_LEN].copy_from_slice(&ipfs_header.to_be_bytes());
            buf[IPFS_HEADER_LEN..(IPFS_HEADER_LEN + result.len())].copy_from_slice(result);
            self.current_read += 1;

            Ok(result.len() + IPFS_HEADER_LEN)
        }
    }

    impl std::io::Write for FakeResponder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let expected_result = &self.write_buffers[self.current_write];
            self.current_write += 1;

            assert_eq!(&buf[IPFS_HEADER_LEN..], expected_result);

            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_snow_handshake() {
        let mut fake_responder = FakeResponder::new();

        let static_key = fake_responder.static_key();
        let ephemeral_key = fake_responder.ephemeral_key();
        handshake_with_snow(&mut fake_responder, &static_key, Some(&ephemeral_key)).unwrap();
    }

    #[test]
    fn test_handshake() {
        let mut fake_responder = FakeResponder::new();

        let static_key = fake_responder.static_key();
        let ephemeral_key = fake_responder.ephemeral_key();
        handshake(&mut fake_responder, &static_key, Some(&ephemeral_key)).unwrap();
    }
}
