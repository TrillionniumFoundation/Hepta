//! Exercise the real memory executor and inspect retained bytes after failure.
use super::*;

fn scalar(value: u64) -> RuntimeValue { RuntimeValue::Scalar(json!(value)) }

#[test]
fn word_store_is_complete_or_leaves_every_byte_unchanged() {
    for length in 0..40_u64 {
        for offset in [0, 1, 7, 8, length.saturating_sub(8), length, length + 1,
                       1 << 32, (1 << 32) + 1, 1 << 63, u64::MAX] {
            for (opcode, little) in [("buffer.store.u64.le", true), ("buffer.store.u64.be", false)] {
                let mut memory = ByteMemory::new(1024, None);
                let original = vec![0xa5; length as usize];
                let owner = memory.new_owner(original.clone());
                let root = memory.storage(&owner).unwrap();
                let view = memory.borrow(&owner, true, false).unwrap();
                let value = 0xFEDC_BA98_7654_3210_u64;
                let result = memory.operation(opcode, &[view, scalar(offset), scalar(value)]);
                if offset <= length && 8 <= length - offset {
                    assert!(result.is_ok());
                    let mut expected = original;
                    expected[offset as usize..offset as usize + 8].copy_from_slice(
                        &if little { value.to_le_bytes() } else { value.to_be_bytes() });
                    assert_eq!(memory.owners[&root], expected);
                } else {
                    assert!(matches!(result, Err(Halt::Trap("bounds"))));
                    assert_eq!(memory.owners[&root], original);
                }
            }
        }
    }
}

#[test]
fn word_load_reads_exact_order_and_checks_before_narrowing() {
    for length in 0..40_u64 {
        for offset in [0, 1, 7, length.saturating_sub(8), length, (1 << 32) + 1, u64::MAX] {
            for (opcode, little) in [("buffer.load.u64.le", true), ("buffer.load.u64.be", false)] {
                let mut memory = ByteMemory::new(1024, None);
                let original: Vec<u8> = (0..length).map(|i| (i * 17 + 91) as u8).collect();
                let owner = memory.new_owner(original.clone());
                let root = memory.storage(&owner).unwrap();
                let view = memory.borrow(&owner, false, false).unwrap();
                let result = memory.operation(opcode, &[view, scalar(offset)]);
                if offset <= length && 8 <= length - offset {
                    let bytes: [u8; 8] = original[offset as usize..offset as usize + 8].try_into().unwrap();
                    let expected = if little { u64::from_le_bytes(bytes) } else { u64::from_be_bytes(bytes) };
                    let values = result.unwrap();
                    assert!(matches!(&values[..], [RuntimeValue::Scalar(value)] if *value == json!(expected)));
                } else {
                    assert!(matches!(result, Err(Halt::Trap("bounds"))));
                }
                assert_eq!(memory.owners[&root], original);
            }
        }
    }
}

#[test]
fn word_write_cannot_bypass_readonly_or_suspended_parent_loan() {
    let mut memory = ByteMemory::new(1024, None);
    let owner = memory.new_owner(vec![0xa5; 16]);
    let root = memory.storage(&owner).unwrap();
    let reader = memory.borrow(&owner, false, false).unwrap();
    assert!(memory.operation("buffer.store.u64.le", &[reader, scalar(0), scalar(9)]).is_err());
    assert_eq!(memory.owners[&root], vec![0xa5; 16]);
    let mut memory = ByteMemory::new(1024, None);
    let owner = memory.new_owner(vec![0xa5; 16]);
    let root = memory.storage(&owner).unwrap();
    let writer = memory.borrow(&owner, true, false).unwrap();
    let _child = memory.borrow(&writer, false, false).unwrap();
    assert!(memory.operation("buffer.store.u64.be", &[writer, scalar(0), scalar(9)]).is_err());
    assert_eq!(memory.owners[&root], vec![0xa5; 16]);
}
