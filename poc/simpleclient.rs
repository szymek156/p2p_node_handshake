// TODO:
// docker run --rm  --network=host \                                                       ─╯
// -v /home/szym/test_st:/var/syncthing \
// syncthing/syncthing:latest

// use syncthing as CN - revese engineered from the code, to make the cert pass
// openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=syncthing'
// ~/rust/rustls/examples: cargo run --bin simpleclient --features dangerous_configuration
// in webui you will see ask to connect from the device (http://127.0.0.1:8384/#) click yes

use std::fs;
/// This is the simplest possible client using rustls that does something useful:
/// it accepts the default configuration, loads some root certs, and then connects
/// to google.com and issues a basic HTTP request.  The response is printed to stdout.
///
/// It makes use of rustls::Stream to treat the underlying TLS connection as a basic
/// bi-directional stream -- the underlying IO is performed transparently.
///
/// Note that `unwrap()` is used to deal with networking errors; this is not something
/// that is sensible outside of example code.
use std::sync::Arc;

use std::io::{stdout, BufReader, Read, Write};
use std::net::TcpStream;

use bytes::{BufMut, BytesMut, Buf};
use prost::Message;
use rustls::crypto::ring::Ring;
use rustls::{OwnedTrustAnchor, RootCertStore};

pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/bep.protobufs.rs"));
}

mod danger {
    use rustls::client::{HandshakeSignatureValid, WebPkiServerVerifier};
    use rustls::DigitallySignedStruct;

    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::Certificate,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            WebPkiServerVerifier::default_verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::Certificate,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            WebPkiServerVerifier::default_verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            WebPkiServerVerifier::default_supported_verify_schemes()
        }
    }
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );

    let certs = load_certs("./src/res/cert.pem");
    let key = load_private_key("./src/res/key.pem");

    let mut config = rustls::ClientConfig::<Ring>::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .unwrap();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));

    config.alpn_protocols = vec!["bep/1.0".as_bytes().to_vec()];

    let server_name = "127.0.0.1".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("127.0.0.1:22000").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let mut finalbuf = BytesMut::new();

    // device id: PDOGXD3-PHODC2X-WUTQ24G-WFT2YDN-JBUDB7Z-MO4JM6E-6FKD7G3-QSYFFQ7
    let hello = messages::Hello {
        device_name: "sampleDevice".to_string(),
        client_name: "syncthingClient".to_string(),
        client_version: "v1.1.1".to_string(),
    };
    let mut hello_buf = vec![];
    hello.encode(&mut hello_buf).unwrap();

    const HELLO_TAG: i32 = 0x2EA7_D90B;
    finalbuf.put_i32(HELLO_TAG);
    finalbuf.put_i16(hello_buf.len() as i16);
    finalbuf.put_slice(&hello_buf);

    tls.write_all(&finalbuf).unwrap();

    // let ciphersuite = tls
    //     .conn
    //     .negotiated_cipher_suite()
    //     .unwrap();
    // writeln!(
    //     &mut std::io::stderr(),
    //     "Current ciphersuite: {:?}",
    //     ciphersuite.suite()
    // )
    // .unwrap();
    loop {
        let mut plaintext = bytes::BytesMut::zeroed(1024);
        let rcv = tls.read(&mut plaintext[..]).unwrap();
        println!("Got {rcv} bytes {:?}", plaintext[..rcv].iter().map(|b| {format!("{b:02X}")}).collect::<Vec<String>>());
        if rcv > 4 {
            if HELLO_TAG == plaintext.get_i32() {
                let hello_len = plaintext.get_i16() as usize;


                let m = messages::Hello::decode(&plaintext[..hello_len]).unwrap();
                println!("Got HELLO message {m:?}");
            }


        }


    }

}
