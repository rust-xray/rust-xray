#[macro_use]
mod macros;
mod enums;
mod structs;
mod errors;
mod codec;
mod base;
mod rand;

/// Re-exports the contents of the [rustls-pki-types](https://docs.rs/rustls-pki-types) crate for easy access
pub mod pki_types {
    pub use rustls_pki_types::*;
}

use enums::NamedGroup;
use tokio::io::{copy_bidirectional, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

use bytes::{BytesMut, Buf};
use core::str;
use std::io::{self, Read};
use crate::enums::ProtocolVersion;
use crate::structs::{ClientHelloPayload, KeyShareEntry}; 
use crate::codec::{Codec, Reader};

use x25519_dalek::x25519;
use x25519_dalek::StaticSecret;
use x25519_dalek::PublicKey;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;

static PRIV_KEY : &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
// static Public_key: &str = "N8ITVSDyDqbEvJf1jC1Nhz94B5UeGQdeuUnvKTbishM";


async fn handle_client(mut stream: TcpStream) {


    let mut data = BytesMut::with_capacity(2048);

    loop {
        stream.readable().await.unwrap();

        // Try to read data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_read_buf(&mut data) {
            Ok(n) => {
                data.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    }


    // let handshake = data.get_u8();
    // println!("{:?}", handshake);
    //
    // println!("{:X}", data.get_u16());

    let mut rd = Reader::init(&data[9..]);

    let mut ch = ClientHelloPayload::read(&mut rd).unwrap();

    client_hello_processing(&mut ch);

    println!("{:?}", ch);


}

fn client_hello_processing(hello: &mut ClientHelloPayload) {
    // Are we doing TLS1.3?
    let maybe_versions_ext = hello.versions_extension();
    if let Some(versions) = maybe_versions_ext {
        if !versions.contains(&ProtocolVersion::TLSv1_3) {
            return
        }
    } else if u16::from(hello.client_version) < u16::from(ProtocolVersion::TLSv1_2) {
        return
    } else {
        return
    };

    let keyshares = match hello.keyshare_extension() {
        Some(x) => x,
        None => &[KeyShareEntry::new(NamedGroup::X448, b"payload"); 0],
    };

    for keyshare in keyshares.iter() {
        if keyshare.group == NamedGroup::X25519 && keyshare.payload.get_encoding().len() != 32 {
            continue;
        }

        let decoded_key: [u8; 32] = STANDARD_NO_PAD.decode(PRIV_KEY).unwrap()[..32].try_into().unwrap();
        let sec_key = StaticSecret::from(decoded_key);

        let decoded_public: [u8; 32] = keyshare.payload.get_encoding()[..32].try_into().unwrap();
        let remote_pub = PublicKey::from(decoded_public);

        let priv_key = x25519(sec_key.to_bytes(), remote_pub.to_bytes());
        let hk = Hkdf::<Sha256>::new(Some(&hello.random.get_encoding()[..20]), &priv_key);
        let mut okm = [0u8; 42];
        let info: &str = "REALITY";
        hk.expand(info.as_bytes(), &mut okm).expect("42 is a valid length for Sha256 to output");
        
        
    }


}


#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();

    // accept connections and process them serially
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(handle_client(stream));
    };
}
