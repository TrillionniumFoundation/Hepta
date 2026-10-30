//! Optional finite byte storage for the existing execution Machine.
//! Static linear/loan admission belongs to the existing ownership verifier.
use std::collections::{BTreeMap, BTreeSet};
use serde_json::{json, Value};
use super::{AllocationFailureIndex, Exec, Halt, RuntimeValue};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Root { Owner(u64), Chain(u64) }

struct Loan {
    parent: RuntimeValue,
    // A chain and a byte owner can have equal numeric IDs. Provenance belongs
    // to the typed language root; byte access belongs to its payload storage.
    root: Root,
    storage: u64,
    mutable: bool,
    // Call formals are distinct scope witnesses, not source borrow events.
    external: bool,
}

// Flat identities avoid recursive host destruction when a finite-step stop
// leaves a long chain partially destroyed. Node storage and payloads remain
// ordinary byte owners in the shared ledger, exactly as in canonical Core.
#[derive(Clone, Copy)]
struct ChainNode {
    storage: u64,
    payload: u64,
    tail: Option<u64>,
}

const CHAIN_NODE_BYTES: u64 = 24;

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(n: u64) -> RuntimeValue { RuntimeValue::Scalar(json!(n)) }

    #[test]
    fn shared_call_alias_reads_do_not_enable_parent_writes_or_early_end() {
        let mut memory = ByteMemory::new(8, None);
        let owner = memory.operation("buffer.new", &[scalar(1)]).unwrap().remove(0);
        let parent = memory.operation("borrow.mut", &[owner.clone()]).unwrap().remove(0);
        let params = json!([{"name":"left","type":"readbuf"},{"name":"right","type":"readbuf"}]);
        let (formal, scope) = memory.enter_call(&params, vec![parent.clone(), parent.clone()]).unwrap();
        let shared = memory.operation("borrow.read", &[formal[0].clone()]).unwrap().remove(0);
        let read = memory.operation("buffer.load", &[formal[1].clone(), scalar(0)]).unwrap();
        assert_eq!(read[0].scalar().unwrap(), &json!(0));
        assert!(matches!(memory.operation("buffer.load", &[formal[0].clone(), scalar(0)]),
                         Err(Halt::Internal)));
        assert!(matches!(memory.operation("buffer.store", &[parent.clone(), scalar(0), scalar(42)]),
                         Err(Halt::Internal)));
        assert!(matches!(memory.operation("loan.end", &[parent.clone()]), Err(Halt::Internal)));
        assert!(matches!(memory.operation("borrow.mut", &[shared.clone()]), Err(Halt::Internal)));
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
        let parent = memory.operation("borrow.mut", &[owner.clone()]).unwrap().remove(0);
        let child = memory.operation("borrow.mut", &[parent.clone()]).unwrap().remove(0);
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
        let reader = memory.operation("borrow.read", &[source.clone()]).unwrap().remove(0);
        let writer = memory.operation("borrow.mut", &[destination.clone()]).unwrap().remove(0);
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
            let writer = memory.operation("borrow.mut", &[owner.clone()]).unwrap().remove(0);
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
        let parent = memory.operation("chain.head_mut", &[chain.clone()]).unwrap().remove(0);
        let child = memory.operation("borrow.read", &[parent.clone()]).unwrap().remove(0);
        for operation in ["owner.move", "chain.pop"] {
            assert!(matches!(memory.operation(operation, &[chain.clone()]), Err(Halt::Internal)));
        }
        assert!(matches!(memory.begin_chain_drop(&chain), Err(Halt::Internal)));
        assert!(matches!(memory.operation("loan.end", &[parent.clone()]), Err(Halt::Internal)));
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
        let head = memory.operation("chain.head_mut", &[chain.clone()]).unwrap().remove(0);
        let reader = memory.operation("borrow.read", &[independent.clone()]).unwrap().remove(0);
        assert_ne!(memory.root(&head).unwrap(), memory.root(&reader).unwrap());
        assert_eq!(memory.operation("buffer.len", &[head.clone()]).unwrap()[0].scalar().unwrap(), &json!(3));
        assert_eq!(memory.operation("buffer.len", &[reader.clone()]).unwrap()[0].scalar().unwrap(), &json!(7));
        memory.operation("buffer.copy", &[head.clone(), reader.clone(), scalar(3)]).unwrap();
        assert!(matches!(memory.operation("buffer.len", &[chain.clone()]), Err(Halt::Internal)));
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
            let parent = memory.operation("borrow.mut", &[owner.clone()]).unwrap().remove(0);
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
            assert!(matches!(memory.operation("loan.end", &[parent.clone()]), Err(Halt::Internal)));
            memory.operation("buffer.store", &[returned.clone(), scalar(0), scalar(73)]).unwrap();
            memory.operation("loan.end", &[returned]).unwrap();
            assert_eq!(memory.operation("buffer.load", &[parent.clone(), scalar(0)]).unwrap()[0].scalar().unwrap(), &json!(73));
            memory.operation("loan.end", &[parent]).unwrap();
            memory.operation("owner.drop", &[owner]).unwrap();
            assert!(memory.is_clean());
        }
    }
}

pub(super) struct ByteMemory {
    owners: BTreeMap<u64, Vec<u8>>,
    loans: BTreeMap<u64, Loan>,
    chains: BTreeMap<u64, Option<u64>>,
    chain_nodes: BTreeMap<u64, ChainNode>,
    chains_created: u64,
    chains_consumed: u64,
    chain_nodes_created: u64,
    chain_nodes_dropped: u64,
    max_heap: u64,
    fail_at: Option<AllocationFailureIndex>,
    attempts: u64,
    allocations: u64,
    frees: u64,
    owners_created: u64,
    owners_dropped: u64,
    loans_started: u64,
    loans_ended: u64,
    next_loan: u64,
    live_bytes: u64,
    peak_bytes: u64,
}

impl ByteMemory {
    pub(super) fn new(max_heap: u64, fail_at: Option<AllocationFailureIndex>) -> Self {
        Self { owners: BTreeMap::new(), loans: BTreeMap::new(), max_heap, fail_at,
            chains: BTreeMap::new(), chain_nodes: BTreeMap::new(),
            chains_created: 0, chains_consumed: 0,
            chain_nodes_created: 0, chain_nodes_dropped: 0,
            attempts: 0, allocations: 0, frees: 0, owners_created: 0,
            owners_dropped: 0, loans_started: 0, loans_ended: 0, next_loan: 0,
            live_bytes: 0, peak_bytes: 0 }
    }

    pub(super) fn supports(op: &str) -> bool {
        matches!(op, "buffer.new" | "buffer.try_new" | "buffer.len" |
            "borrow.read" | "borrow.mut" | "loan.end" |
            "owner.move" | "owner.drop" | "buffer.load" | "buffer.store")
            || Self::extended(op)
    }

    pub(super) fn extended(op: &str) -> bool {
        matches!(op, "buffer.fill" | "buffer.copy" | "buffer.move_within" |
            "buffer.fill_range" | "buffer.copy_range" | "buffer.swap" |
            "chain.empty" | "chain.try_push" | "chain.pop" | "chain.is_empty" |
            "chain.head_read" | "chain.head_mut")
    }

    pub(super) fn chain_operation(op: &str) -> bool { op.starts_with("chain.") }

    pub(super) fn live_chain(&self, id: u64) -> bool {
        self.chains.contains_key(&id)
    }

    fn chain_id(&self, value: &RuntimeValue) -> Exec<u64> {
        match value {
            RuntimeValue::Chain(id) if self.chains.contains_key(id) => Ok(*id),
            _ => Err(Halt::Internal),
        }
    }

    fn new_chain(&mut self, head: Option<u64>) -> RuntimeValue {
        self.chains_created += 1;
        self.chains.insert(self.chains_created, head);
        RuntimeValue::Chain(self.chains_created)
    }

    fn unborrowed_owner(&self, id: u64) -> Exec<()> {
        if !self.owners.contains_key(&id) || self.loans.values().any(|loan| loan.storage == id) {
            return Err(Halt::Internal);
        }
        Ok(())
    }

    fn unborrowed_chain(&self, id: u64) -> Exec<()> {
        if !self.chains.contains_key(&id)
            || self.loans.values().any(|loan| loan.root == Root::Chain(id)) {
            return Err(Halt::Internal);
        }
        Ok(())
    }

    fn consume_chain(&mut self, id: u64) -> Exec<Option<u64>> {
        self.unborrowed_chain(id)?;
        let head = self.chains.remove(&id).ok_or(Halt::Internal)?;
        self.chains_consumed += 1;
        Ok(head)
    }

    pub(super) fn begin_chain_drop(&mut self, value: &RuntimeValue) -> Exec<Option<u64>> {
        let id = self.chain_id(value)?;
        self.consume_chain(id)
    }

    pub(super) fn drop_chain_node(&mut self, id: u64) -> Exec<Option<u64>> {
        let node = *self.chain_nodes.get(&id).ok_or(Halt::Internal)?;
        self.drop_owner(node.payload)?;
        self.drop_owner(node.storage)?;
        self.chain_nodes.remove(&id).ok_or(Halt::Internal)?;
        self.chain_nodes_dropped += 1;
        Ok(node.tail)
    }

    fn drop_owner(&mut self, id: u64) -> Exec<()> {
        self.unborrowed_owner(id)?;
        let bytes = self.owners.remove(&id).ok_or(Halt::Internal)?;
        self.owners_dropped += 1;
        if !bytes.is_empty() { self.frees += 1; }
        self.live_bytes -= bytes.len() as u64;
        Ok(())
    }

    pub(super) fn loan_type(&self, id: u64) -> Option<&'static str> {
        self.loans.get(&id).map(|loan| if loan.mutable { "mutbuf" } else { "readbuf" })
    }

    pub(super) fn return_loan(&mut self, value: &RuntimeValue, parent: &RuntimeValue,
                             mutable: bool) -> Exec<RuntimeValue> {
        let (RuntimeValue::Loan(id), RuntimeValue::Loan(parent_id)) = (value, parent) else {
            return Err(Halt::Internal);
        };
        self.root(value)?;
        self.root(parent)?;
        let loan = self.loans.get(id).ok_or(Halt::Internal)?;
        let input = self.loans.get(parent_id).ok_or(Halt::Internal)?;
        if mutable && (!loan.mutable || !input.mutable) { return Err(Halt::Internal); }
        if self.child_exists(*id) { return Err(Halt::Internal); }
        if !input.external { return Err(Halt::Internal); }
        let caller = input.parent.clone();
        if id == parent_id {
            // Materialize this previously uncounted formal witness as a fresh
            // source child of the actual caller. It is already distinct from
            // the caller's loan; forwarding adds exactly one borrow event.
            let output = self.loans.get_mut(id).ok_or(Halt::Internal)?;
            output.external = false;
            output.mutable = mutable;
            self.loans_started += 1;
            return Ok(value.clone());
        }
        if loan.external || !matches!(loan.parent, RuntimeValue::Loan(id) if id == *parent_id) {
            return Err(Halt::Internal);
        }
        // A callee-created direct child transfers exactly once, with no extra
        // allocation, tick or started-loan event. Remove only its call-scope
        // parent, retaining the selected actual and its typed logical root.
        self.loans.get_mut(id).ok_or(Halt::Internal)?.parent = caller;
        Ok(value.clone())
    }

    fn root(&self, value: &RuntimeValue) -> Exec<Root> {
        let mut current = value;
        let mut traversed = 0;
        let mut expected = None;
        loop {
            match current {
                RuntimeValue::Owner(id) if self.owners.contains_key(id) => {
                    let root = Root::Owner(*id);
                    return if expected.is_none_or(|r| r == root) { Ok(root) } else { Err(Halt::Internal) };
                }
                RuntimeValue::Chain(id) if self.chains.contains_key(id) => {
                    let root = Root::Chain(*id);
                    return if expected.is_none_or(|r| r == root) { Ok(root) } else { Err(Halt::Internal) };
                }
                RuntimeValue::Loan(id) => {
                    let loan = self.loans.get(id).ok_or(Halt::Internal)?;
                    // Parent handles are immutable and point only to an
                    // already-live ancestor; the bound also refuses a bug
                    // that would fabricate a cyclic runtime graph.
                    traversed += 1;
                    if traversed > self.loans.len() || !self.owners.contains_key(&loan.storage)
                        || expected.is_some_and(|r| r != loan.root) {
                        return Err(Halt::Internal);
                    }
                    expected = Some(loan.root);
                    current = &loan.parent;
                }
                _ => return Err(Halt::Internal),
            }
        }
    }

    fn storage(&self, value: &RuntimeValue) -> Exec<u64> {
        self.root(value)?;
        match value {
            RuntimeValue::Owner(id) => Ok(*id),
            RuntimeValue::Loan(id) => Ok(self.loans.get(id).ok_or(Halt::Internal)?.storage),
            _ => Err(Halt::Internal),
        }
    }

    fn borrow(&mut self, parent: &RuntimeValue, mutable: bool, head: bool) -> Exec<RuntimeValue> {
        let root = self.root(parent)?;
        let storage = if head {
            let id = self.chain_id(parent)?;
            let node = self.chains[&id].ok_or(Halt::Trap("bounds"))?;
            self.chain_nodes.get(&node).ok_or(Halt::Internal)?.payload
        } else { self.storage(parent)? };
        let mut ancestors = BTreeSet::new();
        let mut current = parent;
        while let RuntimeValue::Loan(id) = current {
            if !ancestors.insert(*id) { return Err(Halt::Internal); }
            let loan = self.loans.get(id).ok_or(Halt::Internal)?;
            if mutable && !loan.mutable { return Err(Halt::Internal); }
            current = &loan.parent;
        }
        if self.loans.iter().any(|(id, loan)| loan.root == root
            && !ancestors.contains(id) && (mutable || loan.mutable)) {
            return Err(Halt::Internal);
        }
        self.next_loan += 1;
        self.loans_started += 1;
        self.loans.insert(self.next_loan, Loan { root, storage, mutable,
            parent: parent.clone(), external: false });
        Ok(RuntimeValue::Loan(self.next_loan))
    }

    pub(super) fn enter_call(&mut self, params: &Value, mut values: Vec<RuntimeValue>)
        -> Exec<(Vec<RuntimeValue>, Vec<u64>)> {
        let params = params.as_array().ok_or(Halt::Internal)?;
        if params.len() != values.len() { return Err(Halt::Internal); }
        // Check every actual before creating witnesses. A local child of one
        // readonly formal must not suspend a distinct aliased readonly formal.
        let mut views = Vec::new();
        for (param, value) in params.iter().zip(&values) {
            if !matches!(param["type"].as_str(), Some("readbuf" | "mutbuf")) { continue; }
            let mutable = param["type"] == "mutbuf";
            self.access(value, mutable)?;
            let root = self.root(value)?;
            if views.iter().any(|(other, exclusive)| *other == root && (*exclusive || mutable)) {
                return Err(Halt::Internal);
            }
            views.push((root, mutable));
        }
        let mut formals = Vec::new();
        for (param, value) in params.iter().zip(&mut values) {
            if !matches!(param["type"].as_str(), Some("readbuf" | "mutbuf")) { continue; }
            let root = self.root(value)?;
            let storage = self.storage(value)?;
            let mutable = param["type"] == "mutbuf";
            self.next_loan += 1;
            let id = self.next_loan;
            self.loans.insert(id, Loan { root, storage, mutable, parent: value.clone(), external: true });
            *value = RuntimeValue::Loan(id);
            formals.push(id);
        }
        Ok((values, formals))
    }

    pub(super) fn leave_call(&mut self, formals: &[u64]) -> Exec<()> {
        for id in formals {
            let loan = self.loans.get(id).ok_or(Halt::Internal)?;
            // A forwarded result materialized this witness into a local child.
            if !loan.external { continue; }
            if self.child_exists(*id) { return Err(Halt::Internal); }
            self.loans.remove(id).ok_or(Halt::Internal)?;
        }
        Ok(())
    }

    fn new_owner(&mut self, bytes: Vec<u8>) -> RuntimeValue {
        self.owners_created += 1;
        if !bytes.is_empty() { self.allocations += 1; }
        self.live_bytes += bytes.len() as u64;
        self.peak_bytes = self.peak_bytes.max(self.live_bytes);
        self.owners.insert(self.owners_created, bytes);
        RuntimeValue::Owner(self.owners_created)
    }

    fn allocate(&mut self, size: u64, optional: bool) -> Exec<(RuntimeValue, bool)> {
        // Match the canonical object-size, budget, and failure ordering.
        // Logical empty owners never call the allocator or consume fail_at.
        if size == 0 { return Ok((self.new_owner(Vec::new()), true)); }
        if size > i64::MAX as u64 {
            return if optional { Ok((self.new_owner(Vec::new()), false)) }
                else { Err(Halt::Trap("allocation")) };
        }
        if size > self.max_heap.saturating_sub(self.live_bytes) {
            return Err(Halt::Budget("heap"));
        }
        self.attempts += 1;
        if !self.fail_at.as_ref().is_some_and(|index| index.equals_counter(self.attempts)) {
            let length = usize::try_from(size).map_err(|_| Halt::Internal)?;
            let mut bytes = Vec::new();
            if bytes.try_reserve_exact(length).is_ok() {
                bytes.resize(length, 0);
                return Ok((self.new_owner(bytes), true));
            }
        }
        if optional { Ok((self.new_owner(Vec::new()), false)) }
        else { Err(Halt::Trap("allocation")) }
    }

    fn child_exists(&self, id: u64) -> bool {
        self.loans.values().any(|loan| matches!(loan.parent, RuntimeValue::Loan(parent) if parent == id))
    }

    fn access(&self, value: &RuntimeValue, mutable: bool) -> Exec<u64> {
        let RuntimeValue::Loan(id) = value else { return Err(Halt::Internal); };
        let loan = self.loans.get(id).ok_or(Halt::Internal)?;
        if mutable && !loan.mutable || self.child_exists(*id) {
            return Err(Halt::Internal);
        }
        self.storage(value)
    }

    fn unsigned(value: &RuntimeValue) -> Exec<u64> {
        value.scalar()?.as_u64().ok_or(Halt::Internal)
    }

    fn range(&self, root: u64, offset: u64, count: u64) -> Exec<std::ops::Range<usize>> {
        let length = self.owners.get(&root).ok_or(Halt::Internal)?.len() as u64;
        // Check by subtraction before converting, adding, slicing or writing.
        // Empty extents at the end are valid; an offset beyond the end is not.
        if offset > length || count > length - offset { return Err(Halt::Trap("bounds")); }
        let start = usize::try_from(offset).map_err(|_| Halt::Internal)?;
        let count = usize::try_from(count).map_err(|_| Halt::Internal)?;
        Ok(start..start + count)
    }

    fn copy_distinct(&mut self, destination: u64, source: u64,
                     dst_offset: u64, src_offset: u64, count: u64) -> Exec<()> {
        // Even a zero-length copy must not erase the distinct-owner contract.
        if destination == source { return Err(Halt::Internal); }
        let dst = self.range(destination, dst_offset, count)?;
        let src = self.range(source, src_offset, count)?;
        // A bounded stack scratch avoids a host allocation proportional to the
        // copy size and does not fabricate a language-level allocation event.
        // Both ranges are checked before the first observable byte changes.
        let mut scratch = [0_u8; 4096];
        let mut copied = 0;
        while copied < src.len() {
            let chunk = (src.len() - copied).min(scratch.len());
            scratch[..chunk].copy_from_slice(
                &self.owners.get(&source).ok_or(Halt::Internal)?[src.start + copied..src.start + copied + chunk]);
            self.owners.get_mut(&destination).ok_or(Halt::Internal)?
                [dst.start + copied..dst.start + copied + chunk].copy_from_slice(&scratch[..chunk]);
            copied += chunk;
        }
        Ok(())
    }

    pub(super) fn operation(&mut self, op: &str, args: &[RuntimeValue]) -> Exec<Vec<RuntimeValue>> {
        if op == "chain.empty" { return Ok(vec![self.new_chain(None)]); }
        let first = args.first().ok_or(Halt::Internal)?;
        match op {
            "buffer.new" | "buffer.try_new" => {
                let (owner, success) = self.allocate(Self::unsigned(first)?, op == "buffer.try_new")?;
                let mut result = vec![owner];
                if op == "buffer.try_new" { result.push(RuntimeValue::Scalar(json!(success))); }
                Ok(result)
            }
            "buffer.len" => {
                let root = self.storage(first)?;
                Ok(vec![RuntimeValue::Scalar(json!(self.owners[&root].len()))])
            }
            "borrow.read" | "borrow.mut" => {
                Ok(vec![self.borrow(first, op == "borrow.mut", false)?])
            }
            "loan.end" => {
                self.root(first)?;
                let RuntimeValue::Loan(id) = first else { return Err(Halt::Internal); };
                if self.child_exists(*id) || self.loans[id].external { return Err(Halt::Internal); }
                self.loans.remove(id).ok_or(Halt::Internal)?;
                self.loans_ended += 1;
                Ok(vec![])
            }
            "owner.move" => {
                if let RuntimeValue::Chain(id) = first {
                    self.unborrowed_chain(*id)?;
                    return Ok(vec![first.clone()]);
                }
                let RuntimeValue::Owner(id) = first else { return Err(Halt::Internal); };
                self.root(first)?;
                self.unborrowed_owner(*id)?;
                Ok(vec![first.clone()])
            }
            "owner.drop" => {
                let RuntimeValue::Owner(id) = first else { return Err(Halt::Internal); };
                self.drop_owner(*id)?;
                Ok(vec![])
            }
            "chain.try_push" => {
                let chain = self.chain_id(first)?;
                self.unborrowed_chain(chain)?;
                let RuntimeValue::Owner(payload) = args.get(1).ok_or(Halt::Internal)?
                    else { return Err(Halt::Internal); };
                self.unborrowed_owner(*payload)?;
                let head = self.chains[&chain];
                let (storage, success) = self.allocate(CHAIN_NODE_BYTES, true)?;
                let RuntimeValue::Owner(storage) = storage else { return Err(Halt::Internal); };
                if success {
                    self.chain_nodes_created += 1;
                    self.chain_nodes.insert(self.chain_nodes_created,
                        ChainNode { storage, payload: *payload, tail: head });
                    let fallback = self.new_owner(Vec::new());
                    self.consume_chain(chain)?;
                    let new_chain = self.new_chain(Some(self.chain_nodes_created));
                    Ok(vec![new_chain, fallback, RuntimeValue::Scalar(json!(true))])
                } else {
                    self.drop_owner(storage)?;
                    self.consume_chain(chain)?;
                    let new_chain = self.new_chain(head);
                    Ok(vec![new_chain, RuntimeValue::Owner(*payload), RuntimeValue::Scalar(json!(false))])
                }
            }
            "chain.pop" => {
                let chain = self.chain_id(first)?;
                let head = self.consume_chain(chain)?;
                if let Some(id) = head {
                    let node = self.chain_nodes.remove(&id).ok_or(Halt::Internal)?;
                    self.drop_owner(node.storage)?;
                    self.chain_nodes_dropped += 1;
                    Ok(vec![self.new_chain(node.tail), RuntimeValue::Owner(node.payload),
                            RuntimeValue::Scalar(json!(true))])
                } else {
                    let chain = self.new_chain(None);
                    let empty = self.new_owner(Vec::new());
                    Ok(vec![chain, empty, RuntimeValue::Scalar(json!(false))])
                }
            }
            "chain.is_empty" => {
                let chain = self.chain_id(first)?;
                Ok(vec![RuntimeValue::Scalar(json!(self.chains[&chain].is_none()))])
            }
            "chain.head_read" | "chain.head_mut" => {
                Ok(vec![self.borrow(first, op == "chain.head_mut", true)?])
            }
            "buffer.load" | "buffer.store" => {
                let root = self.access(first, op == "buffer.store")?;
                let index = Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?;
                let data = self.owners.get_mut(&root).ok_or(Halt::Internal)?;
                if index >= data.len() as u64 { return Err(Halt::Trap("bounds")); }
                let index = usize::try_from(index).map_err(|_| Halt::Internal)?;
                if op == "buffer.store" {
                    let byte = Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?;
                    data[index] = u8::try_from(byte).map_err(|_| Halt::Internal)?;
                    Ok(vec![])
                } else { Ok(vec![RuntimeValue::Scalar(json!(data[index]))]) }
            }
            "buffer.fill" | "buffer.fill_range" => {
                let root = self.access(first, true)?;
                let (range, byte_index) = if op == "buffer.fill" {
                    (0..self.owners.get(&root).ok_or(Halt::Internal)?.len(), 1)
                } else {
                    (self.range(root, Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?,
                                Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?)?, 3)
                };
                let byte = u8::try_from(Self::unsigned(args.get(byte_index).ok_or(Halt::Internal)?)?)
                    .map_err(|_| Halt::Internal)?;
                self.owners.get_mut(&root).ok_or(Halt::Internal)?[range].fill(byte);
                Ok(vec![])
            }
            "buffer.copy" | "buffer.copy_range" => {
                let destination = self.access(first, true)?;
                let source = self.access(args.get(1).ok_or(Halt::Internal)?, false)?;
                let (dst, src, count) = if op == "buffer.copy" {
                    (0, 0, Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?)
                } else {
                    (Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?,
                     Self::unsigned(args.get(3).ok_or(Halt::Internal)?)?,
                     Self::unsigned(args.get(4).ok_or(Halt::Internal)?)?)
                };
                self.copy_distinct(destination, source, dst, src, count)?;
                Ok(vec![])
            }
            "buffer.move_within" => {
                let root = self.access(first, true)?;
                let dst = Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?;
                let src = Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?;
                let count = Self::unsigned(args.get(3).ok_or(Halt::Internal)?)?;
                let destination = self.range(root, dst, count)?;
                let source = self.range(root, src, count)?;
                self.owners.get_mut(&root).ok_or(Halt::Internal)?.copy_within(source, destination.start);
                Ok(vec![])
            }
            "buffer.swap" => {
                let root = self.access(first, true)?;
                let left = Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?;
                let right = Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?;
                let left = self.range(root, left, 1)?.start;
                let right = self.range(root, right, 1)?.start;
                self.owners.get_mut(&root).ok_or(Halt::Internal)?.swap(left, right);
                Ok(vec![])
            }
            _ => Err(Halt::Internal),
        }
    }

    pub(super) fn is_clean(&self) -> bool {
        self.owners.is_empty() && self.loans.is_empty() && self.live_bytes == 0
            && self.chains.is_empty() && self.chain_nodes.is_empty()
            && self.chains_created == self.chains_consumed
            && self.chain_nodes_created == self.chain_nodes_dropped
            && self.loans_started == self.loans_ended
    }

    pub(super) fn report(&self, v7: bool) -> Value {
        let mut report = json!({
            "allocations": self.allocations, "frees": self.frees,
            "allocation_attempts": self.attempts,
            "owners_created": self.owners_created, "owners_dropped": self.owners_dropped,
            "live_owners": self.owners.len(), "live_bytes": self.live_bytes,
            "peak_bytes": self.peak_bytes, "loans_started": self.loans_started,
            "loans_ended": self.loans_ended,
            "live_local_loans": self.loans.values().filter(|loan| !loan.external).count()
        });
        if v7 {
            report["chains_created"] = json!(self.chains_created);
            report["chains_consumed"] = json!(self.chains_consumed);
            report["live_chains"] = json!(self.chains.len());
            report["chain_nodes_created"] = json!(self.chain_nodes_created);
            report["chain_nodes_dropped"] = json!(self.chain_nodes_dropped);
            report["live_chain_nodes"] = json!(self.chain_nodes.len());
        }
        report
    }
}
