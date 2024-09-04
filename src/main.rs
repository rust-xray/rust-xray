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

use tokio::io::{copy_bidirectional, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

use bytes::{BytesMut, Buf};
use std::{u8, u16};
use std::io;
use crate::structs::ClientHelloPayload; 
use crate::codec::{Codec, Reader};


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

    let ch = ClientHelloPayload::read(&mut rd).unwrap();

    println!("{:?}", ch);


}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();

    // accept connections and process them serially
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(handle_client(stream));
    };
}
