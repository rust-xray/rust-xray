use std::io::{Error, ErrorKind};

const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;

/// Tracks XTLS Vision uplink unpadding state for one VLESS connection.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VisionUnpadState {
    user_uuid: [u8; 16],
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: i32,
    within_padding: bool,
}

#[allow(dead_code)]
impl VisionUnpadState {
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            within_padding: true,
        }
    }

    pub fn within_padding(&self) -> bool {
        self.within_padding
    }

    pub fn unpad(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        if !self.within_padding {
            return Ok(input.to_vec());
        }

        let mut output = Vec::new();
        let mut pos = 0usize;

        if self.remaining_command == -1
            && self.remaining_content == -1
            && self.remaining_padding == -1
        {
            if input.len() >= 21 && input[..16] == self.user_uuid {
                pos = 16;
                self.remaining_command = 5;
            } else {
                self.within_padding = false;
                return Ok(input.to_vec());
            }
        }

        loop {
            if self.remaining_command > 0 {
                let data = *input
                    .get(pos)
                    .ok_or_else(|| vision_unexpected_eof("vision frame header"))?;
                pos += 1;

                match self.remaining_command {
                    5 => self.current_command = i32::from(data),
                    4 => self.remaining_content = i32::from(data) << 8,
                    3 => self.remaining_content |= i32::from(data),
                    2 => self.remaining_padding = i32::from(data) << 8,
                    1 => self.remaining_padding |= i32::from(data),
                    _ => {}
                }
                self.remaining_command -= 1;
                continue;
            }

            if self.remaining_content > 0 {
                let available = input.len().saturating_sub(pos);
                if available == 0 {
                    break;
                }

                let take = (self.remaining_content as usize).min(available);
                output.extend_from_slice(&input[pos..pos + take]);
                pos += take;
                self.remaining_content -= take as i32;
                continue;
            }

            if self.remaining_padding > 0 {
                let available = input.len().saturating_sub(pos);
                if available == 0 {
                    break;
                }

                let skip = (self.remaining_padding as usize).min(available);
                pos += skip;
                self.remaining_padding -= skip as i32;
                continue;
            }

            if self.remaining_command == -1
                && self.remaining_content == -1
                && self.remaining_padding == -1
            {
                break;
            }

            match self.current_command {
                cmd if cmd == i32::from(COMMAND_PADDING_CONTINUE) => {
                    self.remaining_command = 5;
                    if pos >= input.len() {
                        break;
                    }
                }
                cmd if cmd == i32::from(COMMAND_PADDING_END)
                    || cmd == i32::from(COMMAND_PADDING_DIRECT) =>
                {
                    self.within_padding = false;
                    self.remaining_command = -1;
                    self.remaining_content = -1;
                    self.remaining_padding = -1;
                    if pos < input.len() {
                        output.extend_from_slice(&input[pos..]);
                    }
                    break;
                }
                command => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("unknown vision padding command: {command}"),
                    ));
                }
            }
        }

        Ok(output)
    }
}

pub fn is_vision_client_flow(flow: Option<&str>) -> bool {
    matches!(flow, Some("xtls-rprx-vision"))
}

/// Vision direct-copy uplink passthrough is not implemented on the REALITY server path.
pub fn vision_direct_copy_relay_supported() -> bool {
    false
}

pub fn unsupported_vision_relay_error() -> Error {
    Error::new(
        ErrorKind::Unsupported,
        "xtls-rprx-vision is parsed but runtime support is not implemented yet",
    )
}

fn vision_unexpected_eof(context: &str) -> Error {
    Error::new(
        ErrorKind::UnexpectedEof,
        format!("unexpected end while reading {context}"),
    )
}

#[cfg(test)]
pub fn encode_vision_flow_addons_protobuf() -> Vec<u8> {
    let flow = b"xtls-rprx-vision";
    let mut addons = Vec::with_capacity(2 + flow.len());
    addons.push(0x0a);
    addons.push(flow.len() as u8);
    addons.extend_from_slice(flow);
    addons
}

#[cfg(test)]
pub fn wrap_vision_uplink_block(user_uuid: &[u8; 16], content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 5 + content.len());
    out.extend_from_slice(user_uuid);
    out.push(COMMAND_PADDING_END);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_UUID: [u8; 16] = [0x11; 16];

    #[test]
    fn unpad_vision_uplink_strips_uuid_prefix_and_returns_tls_client_hello() {
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02];
        let framed = wrap_vision_uplink_block(&USER_UUID, &client_hello);

        let mut state = VisionUnpadState::new(USER_UUID);
        let unpad = state.unpad(&framed).unwrap();

        assert_eq!(unpad, client_hello);
        assert!(!state.within_padding());
    }

    #[test]
    fn unpad_vision_uplink_passes_through_without_uuid_prefix() {
        let raw = [0x16, 0x03, 0x01, 0x00, 0x10];
        let mut state = VisionUnpadState::new(USER_UUID);
        let unpad = state.unpad(&raw).unwrap();

        assert_eq!(unpad, raw);
        assert!(!state.within_padding());
    }

    #[test]
    fn unpad_vision_uplink_after_first_block_passes_through_remaining_bytes() {
        let first = wrap_vision_uplink_block(&USER_UUID, &[0x16, 0x03]);
        let mut state = VisionUnpadState::new(USER_UUID);
        let first_plain = state.unpad(&first).unwrap();
        assert_eq!(first_plain, [0x16, 0x03]);

        let tail = [0x04, 0x05, 0x06];
        let second_plain = state.unpad(&tail).unwrap();
        assert_eq!(second_plain, tail);
    }
}
