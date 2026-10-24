use crate::candidate::storage;
pub fn process(n: usize, abort_after_create: bool) -> i64 {
    let packet = storage::make(n);
    let value = if abort_after_create { -2 } else { packet.bytes.len() as i64 };
    storage::close(packet);
    value
}
