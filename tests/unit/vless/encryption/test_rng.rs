//! Deterministic RNG for VLESS encryption handshake tests.

use crate::vless::encryption::padding::RngDraw;
use crate::vless::encryption::{HandshakeRng, SeededRng};

pub struct TestHandshakeRng {
    inner: SeededRng,
}

impl TestHandshakeRng {
    pub fn new(seed: u64) -> Self {
        Self {
            inner: SeededRng::new(seed),
        }
    }
}

impl HandshakeRng for TestHandshakeRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = (self.inner.draw_between(0, 255) & 0xff) as u8;
        }
    }

    fn gen_u32(&mut self) -> u32 {
        self.inner.draw_between(0, i32::MAX) as u32
    }
}

impl RngDraw for TestHandshakeRng {
    fn draw_percent(&mut self) -> u32 {
        self.inner.draw_percent()
    }

    fn draw_between(&mut self, min: i32, max: i32) -> u32 {
        self.inner.draw_between(min, max)
    }
}
