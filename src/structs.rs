use crate::enums::ClientExtension;

#[derive(Debug)]
pub(super) struct ClientHello {
    pub version: u16,
    pub random: Vec<u8>,
    pub session_id: Vec<u8>,
    pub chiper_suites: Vec<u16>,
    pub compression_method: Vec<u8>,
    pub extetensions: Vec<ClientExtension>
}

impl ClientHello {
  pub fn new() -> ClientHello {
        ClientHello {
            version: 0,
            random: vec![0; 32],
            session_id: vec![],
            chiper_suites: vec![],
            compression_method: vec![],
            extetensions: vec![],
        }
        
    }
}

