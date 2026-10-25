pub struct Packet { pub bytes: Vec<u8> }
pub fn make(n: usize) -> Result<Packet, i32> {
    if n == 0 { return Err(1); }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(n).is_err() { return Err(3); }
    bytes.resize(n, 0u8);
    for i in 0..n { bytes[i] = ((i * 7 + 3) % 251) as u8; }
    Ok(Packet { bytes })
}
pub fn close(packet: Packet) { drop(packet); }
