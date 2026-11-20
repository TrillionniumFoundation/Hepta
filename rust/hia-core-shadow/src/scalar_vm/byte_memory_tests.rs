//! Existing byte-memory ledger tests, kept outside the production module.
use super::*;

fn scalar(n: u64) -> RuntimeValue { RuntimeValue::Scalar(json!(n)) }

#[test]
fn shared_call_alias_reads_do_not_enable_parent_writes_or_early_end() {
    let mut memory = ByteMemory::new(8, None);
    let owner = memory.operation("buffer.new", &[scalar(1)]).unwrap().remove(0);
    let parent = memory.operation("borrow.mut", std::slice::from_ref(&owner)).unwrap().remove(0);
    let params = json!([{"name":"left","type":"readbuf"},{"name":"right","type":"readbuf"}]);
    let (formal, scope) = memory.enter_call(&params, vec![parent.clone(), parent.clone()]).unwrap();
    let shared = memory.operation("borrow.read", &[formal[0].clone()]).unwrap().remove(0);
    let read = memory.operation("buffer.load", &[formal[1].clone(), scalar(0)]).unwrap();
    assert_eq!(read[0].scalar().unwrap(), &json!(0));
    assert!(matches!(memory.operation("buffer.load", &[formal[0].clone(), scalar(0)]),
                     Err(Halt::Internal)));
    assert!(matches!(memory.operation("buffer.store", &[parent.clone(), scalar(0), scalar(42)]),
                     Err(Halt::Internal)));
    assert!(matches!(memory.operation("loan.end", std::slice::from_ref(&parent)), Err(Halt::Internal)));
    assert!(matches!(memory.operation("borrow.mut", std::slice::from_ref(&shared)), Err(Halt::Internal)));
    assert_eq!(memory.report(false)["live_local_loans"], 2);
    memory.operation("loan.end", &[shared]).unwrap();
    memory.leave_call(&scope).unwrap();
    memory.operation("buffer.store", &[parent.clone(), scalar(0), scalar(42)]).unwrap();
    memory.operation("loan.end", &[parent]).unwrap();
    memory.operation("owner.drop", &[owner]).unwrap();
    assert!(memory.is_clean());
}

#[test]
fn mutable_child_still_suspends_parent_reads_and_writes() {
    let mut memory = ByteMemory::new(8, None);
    let owner = memory.operation("buffer.new", &[scalar(1)]).unwrap().remove(0);
    let parent = memory.operation("borrow.mut", std::slice::from_ref(&owner)).unwrap().remove(0);
    let child = memory.operation("borrow.mut", std::slice::from_ref(&parent)).unwrap().remove(0);
    assert!(matches!(memory.operation("buffer.load", &[parent.clone(), scalar(0)]),
                     Err(Halt::Internal)));
    assert!(matches!(memory.operation("buffer.store", &[parent.clone(), scalar(0), scalar(7)]),
                     Err(Halt::Internal)));
    memory.operation("buffer.store", &[child.clone(), scalar(0), scalar(7)]).unwrap();
    memory.operation("loan.end", &[child]).unwrap();
    let read = memory.operation("buffer.load", &[parent.clone(), scalar(0)]).unwrap();
    assert_eq!(read[0].scalar().unwrap(), &json!(7));
    memory.operation("loan.end", &[parent]).unwrap();
    memory.operation("owner.drop", &[owner]).unwrap();
    assert!(memory.is_clean());
}

#[test]
fn copy_checks_both_extents_and_distinct_roots_before_writing() {
    let mut memory = ByteMemory::new(32, None);
    memory.new_owner(vec![11, 22, 33, 44]);
    memory.new_owner(vec![99; 4]);
    for (dst, src, count) in [(0, 3, 2), (3, 0, 2), (0, 0, u64::MAX),
                               (u64::MAX, 0, 0), (0, u64::MAX, 0)] {
        assert!(matches!(memory.copy_distinct(2, 1, dst, src, count), Err(Halt::Trap("bounds"))));
        assert_eq!(memory.owners[&2], vec![99; 4]);
    }
    assert!(matches!(memory.copy_distinct(1, 1, 4, 4, 0), Err(Halt::Internal)));
    memory.copy_distinct(2, 1, 4, 4, 0).unwrap();
    assert_eq!(memory.owners[&2], vec![99; 4]);
}

#[test]
fn multi_chunk_copy_preserves_exact_bytes_and_resource_ledger() {
    let mut memory = ByteMemory::new(20000, None);
    let source: Vec<u8> = (0..8250).map(|index| (index % 251) as u8).collect();
    memory.new_owner(source.clone());
    memory.new_owner(vec![254; 8250]);
    let ledger = memory.report(false);
    memory.copy_distinct(2, 1, 3, 25, 8200).unwrap();
    let mut expected = vec![254; 8250];
    expected[3..8203].copy_from_slice(&source[25..8225]);
    assert_eq!(memory.owners[&1], source);
    assert_eq!(memory.owners[&2], expected);
    assert_eq!(memory.report(false), ledger);
}

#[test]
fn all_bulk_bounds_are_checked_before_writes_and_copy_crosses_scratch_chunks() {
    let mut memory = ByteMemory::new(20_000, None);
    let source_bytes: Vec<u8> = (0..8193).map(|i| (i % 251) as u8).collect();
    let source = memory.new_owner(source_bytes.clone());
    let destination = memory.new_owner(vec![97; 8193]);
    let source_id = memory.storage(&source).unwrap();
    let destination_id = memory.storage(&destination).unwrap();
    let reader = memory.operation("borrow.read", std::slice::from_ref(&source)).unwrap().remove(0);
    let writer = memory.operation("borrow.mut", std::slice::from_ref(&destination)).unwrap().remove(0);
    for (dst, src, size) in [(0, 8193, 1), (8193, 0, 1), (0, u64::MAX, 0),
                            (u64::MAX, 0, 0), (1, 0, u64::MAX)] {
        let before = memory.owners[&destination_id].clone();
        assert!(matches!(memory.operation("buffer.copy_range", &[
            writer.clone(), reader.clone(), scalar(dst), scalar(src), scalar(size)]),
            Err(Halt::Trap("bounds"))));
        assert_eq!(memory.owners[&destination_id], before);
    }
    memory.operation("buffer.copy_range", &[writer.clone(), reader.clone(),
        scalar(1), scalar(0), scalar(8192)]).unwrap();
    assert_eq!(memory.owners[&destination_id][0], 97);
    assert_eq!(&memory.owners[&destination_id][1..], &source_bytes[..8192]);
    assert_eq!(memory.owners[&source_id], source_bytes);
    memory.operation("buffer.copy_range", &[writer.clone(), reader.clone(),
        scalar(8193), scalar(8193), scalar(0)]).unwrap();
    memory.operation("loan.end", &[writer]).unwrap();
    memory.operation("loan.end", &[reader]).unwrap();
    memory.operation("owner.drop", &[destination]).unwrap();
    memory.operation("owner.drop", &[source]).unwrap();
    assert!(memory.is_clean());
}

#[test]
fn overlapping_move_is_memmove_and_failed_ranges_do_not_partially_mutate() {
    for (dst, src, expected) in [(1, 0, vec![1, 1, 2, 3, 4]),
                                 (0, 1, vec![2, 3, 4, 5, 5])] {
        let mut memory = ByteMemory::new(5, None);
        let owner = memory.new_owner(vec![1, 2, 3, 4, 5]);
        let root = memory.storage(&owner).unwrap();
        let writer = memory.operation("borrow.mut", std::slice::from_ref(&owner)).unwrap().remove(0);
        memory.operation("buffer.move_within", &[writer.clone(), scalar(dst),
            scalar(src), scalar(4)]).unwrap();
        assert_eq!(memory.owners[&root], expected);
        for (op, args) in [
            ("buffer.move_within", vec![writer.clone(), scalar(0), scalar(4), scalar(2)]),
            ("buffer.fill_range", vec![writer.clone(), scalar(4), scalar(2), scalar(99)]),
            ("buffer.swap", vec![writer.clone(), scalar(0), scalar(u64::MAX)]),
        ] {
            assert!(matches!(memory.operation(op, &args), Err(Halt::Trap("bounds"))));
            assert_eq!(memory.owners[&root], expected);
        }
        memory.operation("loan.end", &[writer]).unwrap();
        memory.operation("owner.drop", &[owner]).unwrap();
        assert!(memory.is_clean());
    }
}

#[test]
fn head_reborrow_keeps_shape_frozen_and_pop_recovers_exact_payload() {
    let mut memory = ByteMemory::new(25, None);
    let payload = memory.operation("buffer.new", &[scalar(1)]).unwrap().remove(0);
    let empty = memory.operation("chain.empty", &[]).unwrap().remove(0);
    let pushed = memory.operation("chain.try_push", &[empty, payload.clone()]).unwrap();
    let chain = pushed[0].clone();
    memory.operation("owner.drop", &[pushed[1].clone()]).unwrap();
    let parent = memory.operation("chain.head_mut", std::slice::from_ref(&chain)).unwrap().remove(0);
    let child = memory.operation("borrow.read", std::slice::from_ref(&parent)).unwrap().remove(0);
    for operation in ["owner.move", "chain.pop"] {
        assert!(matches!(memory.operation(operation, std::slice::from_ref(&chain)), Err(Halt::Internal)));
    }
    assert!(matches!(memory.begin_chain_drop(&chain), Err(Halt::Internal)));
    assert!(matches!(memory.operation("loan.end", std::slice::from_ref(&parent)), Err(Halt::Internal)));
    memory.operation("loan.end", &[child]).unwrap();
    memory.operation("buffer.store", &[parent.clone(), scalar(0), scalar(42)]).unwrap();
    memory.operation("loan.end", &[parent]).unwrap();
    let popped = memory.operation("chain.pop", &[chain]).unwrap();
    assert_eq!(memory.root(&popped[1]).unwrap(), memory.root(&payload).unwrap());
    assert_eq!(memory.owners[&memory.storage(&popped[1]).unwrap()], vec![42]);
    assert_eq!(memory.report(true)["chain_nodes_dropped"], 1);
    assert_eq!(memory.report(true)["live_bytes"], 1);
    memory.operation("owner.drop", &[popped[1].clone()]).unwrap();
    assert!(memory.begin_chain_drop(&popped[0]).unwrap().is_none());
    assert!(memory.is_clean());
}

#[test]
fn numeric_chain_and_byte_ids_never_alias_provenance_or_payload_extent() {
    let mut memory = ByteMemory::new(64, None);
    let empty = memory.operation("chain.empty", &[]).unwrap().remove(0);
    let payload = memory.operation("buffer.new", &[scalar(3)]).unwrap().remove(0);
    let independent = memory.operation("buffer.new", &[scalar(7)]).unwrap().remove(0);
    let pushed = memory.operation("chain.try_push", &[empty, payload]).unwrap();
    let chain = pushed[0].clone();
    assert!(matches!(chain, RuntimeValue::Chain(2)));
    assert!(matches!(independent, RuntimeValue::Owner(2)));
    memory.operation("owner.drop", &[pushed[1].clone()]).unwrap();
    let head = memory.operation("chain.head_mut", std::slice::from_ref(&chain)).unwrap().remove(0);
    let reader = memory.operation("borrow.read", std::slice::from_ref(&independent)).unwrap().remove(0);
    assert_ne!(memory.root(&head).unwrap(), memory.root(&reader).unwrap());
    assert_eq!(memory.operation("buffer.len", std::slice::from_ref(&head)).unwrap()[0].scalar().unwrap(), &json!(3));
    assert_eq!(memory.operation("buffer.len", std::slice::from_ref(&reader)).unwrap()[0].scalar().unwrap(), &json!(7));
    memory.operation("buffer.copy", &[head.clone(), reader.clone(), scalar(3)]).unwrap();
    assert!(matches!(memory.operation("buffer.len", std::slice::from_ref(&chain)), Err(Halt::Internal)));
    assert!(matches!(memory.begin_chain_drop(&chain), Err(Halt::Internal)));
    memory.operation("loan.end", &[reader]).unwrap();
    memory.operation("owner.drop", &[independent]).unwrap();
    memory.operation("loan.end", &[head]).unwrap();
    let node = memory.begin_chain_drop(&chain).unwrap().unwrap();
    assert!(memory.drop_chain_node(node).unwrap().is_none());
    assert!(memory.is_clean());
}

#[test]
fn formal_forward_and_direct_child_rebind_to_actual_without_counter_inflation() {
    for direct in [false, true] {
        let mut memory = ByteMemory::new(8, None);
        let owner = memory.operation("buffer.new", &[scalar(1)]).unwrap().remove(0);
        let parent = memory.operation("borrow.mut", std::slice::from_ref(&owner)).unwrap().remove(0);
        let params = json!([{"name":"input","type":"mutbuf"}]);
        let (outer, outer_scope) = memory.enter_call(&params, vec![parent.clone()]).unwrap();
        let (inner, inner_scope) = memory.enter_call(&params, vec![outer[0].clone()]).unwrap();
        assert_eq!(memory.report(false)["loans_started"], 1);
        assert_eq!(memory.report(false)["live_local_loans"], 1);
        let child = if direct {
            memory.operation("borrow.mut", &[inner[0].clone()]).unwrap().remove(0)
        } else { inner[0].clone() };
        let returned = memory.return_loan(&child, &inner[0], true).unwrap();
        memory.leave_call(&inner_scope).unwrap();
        let returned = memory.return_loan(&returned, &outer[0], true).unwrap();
        memory.leave_call(&outer_scope).unwrap();
        assert_eq!(memory.report(false)["loans_started"], 2);
        assert_eq!(memory.report(false)["live_local_loans"], 2);
        assert!(matches!(memory.operation("loan.end", std::slice::from_ref(&parent)), Err(Halt::Internal)));
        memory.operation("buffer.store", &[returned.clone(), scalar(0), scalar(73)]).unwrap();
        memory.operation("loan.end", &[returned]).unwrap();
        assert_eq!(memory.operation("buffer.load", &[parent.clone(), scalar(0)]).unwrap()[0].scalar().unwrap(), &json!(73));
        memory.operation("loan.end", &[parent]).unwrap();
        memory.operation("owner.drop", &[owner]).unwrap();
        assert!(memory.is_clean());
    }
}
