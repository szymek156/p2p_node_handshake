mod handshake_sm;
mod crypto_primitives;

use std::io::prelude::*;
use std::net::TcpStream;

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};

use libp2p::identity::ed25519::Keypair;
use prost::Message;
use snow::{resolvers::CryptoResolver, params::CipherChoice};

use crate::handshake_sm::IPFS_NOISE_PROTOCOL_NAME;

pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/bep.protobufs.rs"));
}

fn main() -> Result<()> {
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

    with_snow(&mut stream)?;

    // my_attempt(&mut stream)?;

    Ok(())
}

fn with_snow(stream: &mut TcpStream) -> Result<()> {
    println!("SNOW handshake begin");

    let builder = snow::Builder::new(IPFS_NOISE_PROTOCOL_NAME.parse().unwrap());

    let static_keypair = builder.generate_keypair().unwrap();
    let static_key = static_keypair.private.clone();

    let mut initiator = builder
        .local_private_key(&static_key)
        .build_initiator()
        .unwrap();

    // e
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

    let mut noise = initiator.into_transport_mode().unwrap();
    println!("session established!");

    Ok(())
}

fn my_attempt(stream: &mut TcpStream) -> Result<()> {
    println!("ME handshake begin");
    let id_keypair = libp2p::identity::ed25519::Keypair::generate();
    let static_keypair = libp2p::identity::ed25519::Keypair::generate();


    let x = snow::resolvers::DefaultResolver::default();
    let dh = x.resolve_dh(&snow::params::DHChoice::Curve25519).unwrap();
    let c = x.resolve_cipher(&CipherChoice::ChaChaPoly).unwrap();
    let h = x.resolve_hash(&snow::params::HashChoice::SHA256).unwrap();



    let ephemeral_pub = id_keypair.public().to_bytes();

    // -> e
    let mut finalbuf = BytesMut::new();
    finalbuf.put_u16(ephemeral_pub.len() as u16);
    finalbuf.put_slice(&ephemeral_pub);
    stream.write_all(&finalbuf).unwrap();

    let mut buf = BytesMut::zeroed(1024);

    // The second message consists of a cleartext public key ("e")
    // followed by an encrypted public key ("s")
    // followed by an encrypted payload.
    // <- [len] e, ee, s, es [data]
    let rcv = stream.read(&mut buf)?;
    println!("read {rcv} bytes");

    buf.resize(rcv, 0);
    let len = buf.get_u16();
    println!("len in payload {len} bytes");



    // TODO:
    // look here:
    // libp2p-rs/protocols/noise/tests/testx.rs
    // https://docs.rs/x25519-dalek/latest/x25519_dalek/


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
