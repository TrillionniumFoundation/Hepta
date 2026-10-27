use crate::candidate::storage;
pub fn process(n: usize, abort_after_create: bool) -> i64 {
    match storage::make(n) {
        Err(code) => -(code as i64),
        Ok(packet) => {
            if abort_after_create { storage::close(packet); return -2; }
            let value = packet.bytes.iter().map(|byte| *byte as i64).sum();
            storage::close(packet);
            value
        }
    }
}
