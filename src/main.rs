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

use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use std::{net::{TcpListener, TcpStream}, io::Read, u8, u16};
use crate::{structs::{ClientExtension, ServerName, UnknownExtension, ClientHelloPayload}, enums::ExtensionType, codec::{Codec, Reader}};


fn handle_client(mut stream: TcpStream) {


    let mut handshake: Vec<u8> = vec![0; 1];
    stream.set_nodelay(true).unwrap();
    match stream.read_exact(&mut handshake) {
        Ok(_) => println!("{:?}", handshake),
        Err(e) => panic!("encountered IO error: {e}"),
    };

    let mut tls_ver = [0u8; 2];

    stream.set_nodelay(true).unwrap();
    match stream.read_exact(&mut tls_ver) {
        Ok(_) => println!("{:X}", u16::from_be_bytes(tls_ver)),
        Err(e) => panic!("encountered IO error: {e}"),
    };

    let mut length = [0u8; 2];

    stream.set_nodelay(true).unwrap();
    stream.read_exact(&mut length).unwrap();

    let mut frame = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut frame).unwrap();

    let mut rd = Reader::init(&frame.as_slice()[4..]);
    
    let ch = ClientHelloPayload::read(&mut rd).unwrap();

    
 
    // let mut buf = Cursor::new(frame);
    // buf.read_u8().unwrap();
    // buf.read_uint::<BigEndian>(3).unwrap();
    // 
    // ch.version = buf.read_u16::<BigEndian>().unwrap();
    // buf.read_exact(&mut ch.random).unwrap();
    //
    // let sesion_length = buf.read_u8().unwrap();
    // 
    // ch.session_id = vec![0u8; sesion_length as usize];
    //
    // buf.read_exact(&mut ch.session_id).unwrap();
    //
    // let chiper_length = buf.read_u16::<BigEndian>().unwrap();
    // ch.chiper_suites = vec![0u16; (chiper_length/2) as usize ];
    // buf.read_u16_into::<BigEndian>(&mut ch.chiper_suites).unwrap();
    //
    // let comp_len = buf.read_u8().unwrap();
    // println!("{}", &comp_len);
    // ch.compression_method = vec![0u8; comp_len as usize];
    // buf.read_exact(&mut ch.compression_method).unwrap();
    //
    // let _ = buf.read_u16::<BigEndian>().unwrap();
    //
    // loop{
    //     let t = match buf.read_u16::<BigEndian>() {
    //         Err(_) => break,
    //         Ok(t) => t, 
    //     };
    //     let typ = ExtensionType::from(t);
    //     let len = buf.read_u16::<BigEndian>().unwrap();
    //     let extension: ClientExtension = match typ {
    //        // ExtensionType::ServerName => {
    //        //      let mut list_len = buf.read_u16::<BigEndian>().unwrap();
    //        //      let mut sn: Vec<ServerName> = vec![];
    //        //
    //        //      while list_len > 0{
    //        //          let t = buf.read_u8().unwrap();
    //        //          let l = buf.read_u16::<BigEndian>().unwrap();
    //        //          let mut hn = vec![0u8; l as usize];
    //        //          buf.read_exact(&mut hn).unwrap();
    //        //          sn.push(ServerName::new(t, String::from_utf8(hn).unwrap()));
    //        //          list_len-=3;
    //        //          list_len-=l;
    //        //      };
    //        //      ClientExtension::ServerName(sn)
    //        //  }, 
    //         _ => {
    //             
    //             let mut ext_buf = vec![0u8; len as usize];
    //             let _ = buf.read_exact(&mut ext_buf);
    //
    //             ClientExtension::Unknown(UnknownExtension{
    //                 typ: ExtensionType::from(t),
    //                 payload: ext_buf,
    //             })
    //         },
    //     };
    //     
    //     ch.extetensions.push(extension);
    // }

    println!("{:?}", ch)
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    // accept connections and process them serially
    let (stream, _) = listener.accept().unwrap();
    handle_client(stream);
}
