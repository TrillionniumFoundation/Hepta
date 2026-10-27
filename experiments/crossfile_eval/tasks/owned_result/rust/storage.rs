pub struct Packet { pub bytes: Vec<u8> }
pub fn make(n: usize) -> Packet { Packet { bytes: vec![0u8; n] } }
pub fn close(packet: Packet) { drop(packet); }
