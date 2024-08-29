use std::{net::{TcpListener, TcpStream}, io::Read, u8, u16};



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
    match stream.read_exact(&mut length) {
        Ok(_) => println!("{:?}", u16::from_be_bytes(length)),
        Err(e) => panic!("encountered IO error: {e}"),
    };

    let mut frame = vec![0u8; u16::from_be_bytes(length) as usize];
    match stream.read_exact(&mut frame) {
        Ok(_) => println!("{:?}", frame),
        Err(e) => panic!("encountered IO error: {e}"),
    };
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    // accept connections and process them serially
    let (stream, _) = listener.accept().unwrap();
    handle_client(stream);
}
