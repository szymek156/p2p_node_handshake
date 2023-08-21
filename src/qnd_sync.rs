use std::io::prelude::*;
use std::net::TcpStream;

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};

use chacha20poly1305::aead::Payload;
use prost::Message;

use crate::{
    ipfs::noise_handshake::messages::{self, NoiseHandshakePayload},
    sweet_noise::{crypto_primitives, handshake_sm, IPFS_NOISE_PROTOCOL_NAME},
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

    // let static_key = generate_keypair()?;
    // let ephemeral_key = generate_keypair()?;

    let static_key = snow::Keypair {
        private: vec![
            168, 52, 148, 164, 50, 146, 162, 26, 182, 134, 5, 156, 189, 161, 7, 241, 243, 67, 61,
            119, 162, 23, 249, 197, 170, 242, 133, 32, 215, 70, 238, 76,
        ],
        public: vec![
            0, 244, 193, 240, 200, 30, 141, 37, 178, 23, 210, 103, 124, 98, 224, 218, 92, 81, 204,
            110, 194, 56, 124, 99, 52, 187, 223, 35, 238, 64, 168, 58,
        ],
    };

    let ephemeral_key = snow::Keypair {
        private: vec![
            24, 81, 254, 143, 214, 216, 196, 80, 30, 226, 186, 135, 208, 66, 139, 62, 4, 138, 22,
            254, 41, 245, 43, 18, 131, 209, 152, 111, 150, 83, 144, 88,
        ],

        public: vec![
            158, 85, 192, 115, 248, 205, 14, 23, 48, 114, 234, 254, 251, 79, 230, 232, 54, 58, 130,
            146, 243, 104, 40, 48, 77, 172, 249, 44, 215, 213, 74, 32,
        ],
    };

    let id_keypair = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut [
        29, 80, 41, 218, 69, 171, 216, 208, 81, 85, 85, 197, 236, 17, 91, 96, 38, 65, 229, 98, 2,
        119, 16, 16, 207, 166, 129, 114, 45, 37, 227, 170, 70, 148, 207, 216, 172, 243, 67, 32,
        155, 81, 206, 155, 163, 129, 157, 241, 47, 94, 74, 33, 140, 75, 186, 146, 3, 21, 11, 55,
        46, 21, 142, 45,
    ])
    .unwrap();

    handshake_with_snow(
        &mut stream,
        &static_key,
        Some(&ephemeral_key),
        Some(&id_keypair),
    )?;

    // handshake(&mut stream, &static_key, None)?;

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
    id_keypair: Option<&libp2p::identity::ed25519::Keypair>,
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

    assert!(responder_key.verify(&to_verify, payload.identity_sig()));

    println!("preparing the payload");
    let mut payload = NoiseHandshakePayload::default();
    let id_keypair = if let Some(id) = id_keypair {
        id.clone()
    } else {
        libp2p::identity::ed25519::Keypair::generate()
    };

    println!("SNOW: id keypair to sign: {:?}", id_keypair.to_bytes());

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

    println!("<- s, se");
    println!("NOISE: buffer to write: {:?}", &buf[..len]);

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

    println!("NOISE response: {:?}", &rcv_buf[..]);

    let _noise = initiator.into_transport_mode().unwrap();
    println!("session established!");

    Ok(())
}

fn handshake<T>(
    stream: &mut T,
    static_keypair: &snow::Keypair,
    ephemeral_keypair: Option<&snow::Keypair>,
    id_keypair: Option<&libp2p::identity::ed25519::Keypair>,
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

    assert!(responder_key.verify(&to_verify, payload.identity_sig()));

    println!("preparing the payload");
    let id_keypair = if let Some(id) = id_keypair {
        id.clone()
    } else {
        libp2p::identity::ed25519::Keypair::generate()
    };

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
    out.put_slice(msg.as_bytes());
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
        static_keypair: snow::Keypair,
        ephemeral_keypair: snow::Keypair,
        id_keypair: libp2p::identity::ed25519::Keypair,
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

            // TODO:
            // decrypted payload: [10, 36, 8, 1, 18, 32, 186, 196, 179, 68, 95, 62, 73, 178, 197, 255, 107, 215, 61, 156, 117, 45, 146, 6, 43, 121, 113, 235, 234, 110, 182, 75, 126, 17, 169, 138, 10, 11, 18, 64, 17, 58, 221, 125, 207, 199, 49, 71, 103, 229, 165, 24, 89, 34, 237, 189, 26, 213, 110, 14, 89, 26, 148, 93, 211, 247, 54, 173, 114, 241, 39, 124, 129, 6, 8, 163, 40, 110, 20, 141, 132, 125, 128, 180, 183, 55, 147, 133, 83, 199, 97, 83, 154, 107, 64, 215, 19, 170, 87, 28, 105, 219, 172, 7, 34, 28, 18, 12, 47, 121, 97, 109, 117, 120, 47, 49, 46, 48, 46, 48, 18, 12, 47, 109, 112, 108, 101, 120, 47, 54, 46, 55, 46, 48], len: 134

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

        let static_key = fake_responder.static_keypair();
        let ephemeral_key = fake_responder.ephemeral_keypair();
        let id_key = fake_responder.id_keypair();
        handshake_with_snow(
            &mut fake_responder,
            &static_key,
            Some(&ephemeral_key),
            Some(&id_key),
        )
        .unwrap();
    }

    #[test]
    fn test_handshake() {
        let mut fake_responder = FakeResponder::new();

        let static_key = fake_responder.static_keypair();
        let ephemeral_key = fake_responder.ephemeral_keypair();
        let id_key = fake_responder.id_keypair();
        handshake(
            &mut fake_responder,
            &static_key,
            Some(&ephemeral_key),
            Some(&id_key),
        )
        .unwrap();
    }
}
