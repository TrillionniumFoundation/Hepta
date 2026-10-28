//! Optional finite byte storage for the existing execution Machine.
//! Static linear/loan admission belongs to the existing ownership verifier.
use std::collections::BTreeMap;
use serde_json::{json, Value};
use super::{Exec, Halt, RuntimeValue};

struct Loan {
    parent: RuntimeValue,
    root: u64,
    mutable: bool,
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
        let shared = memory.operation("borrow.read", &[parent.clone()]).unwrap().remove(0);
        let read = memory.operation("buffer.load", &[parent.clone(), scalar(0)]).unwrap();
        assert_eq!(read[0].scalar().unwrap(), &json!(0));
        assert!(matches!(memory.operation("buffer.store", &[parent.clone(), scalar(0), scalar(42)]),
                         Err(Halt::Internal)));
        assert!(matches!(memory.operation("loan.end", &[parent.clone()]), Err(Halt::Internal)));
        assert!(matches!(memory.operation("borrow.mut", &[shared.clone()]), Err(Halt::Internal)));
        memory.operation("loan.end", &[shared]).unwrap();
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
    fn all_bulk_bounds_are_checked_before_writes_and_copy_crosses_scratch_chunks() {
        let mut memory = ByteMemory::new(20_000, None);
        let source_bytes: Vec<u8> = (0..8193).map(|i| (i % 251) as u8).collect();
        let source = memory.new_owner(source_bytes.clone());
        let destination = memory.new_owner(vec![97; 8193]);
        let source_id = memory.root(&source).unwrap();
        let destination_id = memory.root(&destination).unwrap();
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
            let root = memory.root(&owner).unwrap();
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
        assert_eq!(memory.owners[&memory.root(&popped[1]).unwrap()], vec![42]);
        assert_eq!(memory.report(true)["chain_nodes_dropped"], 1);
        assert_eq!(memory.report(true)["live_bytes"], 1);
        memory.operation("owner.drop", &[popped[1].clone()]).unwrap();
        assert!(memory.begin_chain_drop(&popped[0]).unwrap().is_none());
        assert!(memory.is_clean());
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
    fail_at: Option<u64>,
    attempts: u64,
    allocations: u64,
    frees: u64,
    owners_created: u64,
    owners_dropped: u64,
    loans_started: u64,
    loans_ended: u64,
    live_bytes: u64,
    peak_bytes: u64,
}

impl ByteMemory {
    pub(super) fn new(max_heap: u64, fail_at: Option<u64>) -> Self {
        Self { owners: BTreeMap::new(), loans: BTreeMap::new(), max_heap, fail_at,
            chains: BTreeMap::new(), chain_nodes: BTreeMap::new(),
            chains_created: 0, chains_consumed: 0,
            chain_nodes_created: 0, chain_nodes_dropped: 0,
            attempts: 0, allocations: 0, frees: 0, owners_created: 0,
            owners_dropped: 0, loans_started: 0, loans_ended: 0,
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
        if !self.owners.contains_key(&id) || self.loans.values().any(|loan| loan.root == id) {
            return Err(Halt::Internal);
        }
        Ok(())
    }

    fn unborrowed_chain(&self, id: u64) -> Exec<()> {
        if let Some(head) = self.chains.get(&id).ok_or(Halt::Internal)? {
            // Only the head payload can have an exposed loan. Any shape
            // change requires it ended; tail payloads were enclosed with no
            // live loans and cannot be addressed through a chain capability.
            self.unborrowed_owner(self.chain_nodes.get(head).ok_or(Halt::Internal)?.payload)?;
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

    pub(super) fn return_loan(&mut self, parent: &RuntimeValue, value: &RuntimeValue,
                             mutable: bool) -> Exec<RuntimeValue> {
        let (RuntimeValue::Loan(parent_id), RuntimeValue::Loan(value_id)) = (parent, value)
            else { return Err(Halt::Internal); };
        self.root(parent)?;
        self.root(value)?;
        if parent_id == value_id {
            // A returned incoming parameter is a NEW child of the caller's
            // argument; ending it cannot consume the original caller loan.
            return self.operation(if mutable { "borrow.mut" } else { "borrow.read" },
                                  &[parent.clone()])?.pop().ok_or(Halt::Internal);
        }
        let loan = self.loans.get(value_id).ok_or(Halt::Internal)?;
        if !matches!(&loan.parent, RuntimeValue::Loan(id) if id == parent_id) ||
            loan.mutable != mutable || self.child_exists(*value_id) {
            return Err(Halt::Internal);
        }
        Ok(value.clone())
    }

    fn root(&self, value: &RuntimeValue) -> Exec<u64> {
        let mut current = value;
        let mut traversed = 0;
        loop {
            match current {
                RuntimeValue::Owner(id) if self.owners.contains_key(id) => return Ok(*id),
                RuntimeValue::Loan(id) => {
                    let loan = self.loans.get(id).ok_or(Halt::Internal)?;
                    // Parent handles are immutable and point only to an
                    // already-live ancestor; the bound also refuses a bug
                    // that would fabricate a cyclic runtime graph.
                    traversed += 1;
                    if traversed > self.loans.len() || !self.owners.contains_key(&loan.root) {
                        return Err(Halt::Internal);
                    }
                    current = &loan.parent;
                }
                _ => return Err(Halt::Internal),
            }
        }
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
        if self.fail_at != Some(self.attempts) {
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
        if mutable {
            if !loan.mutable || self.child_exists(*id) { return Err(Halt::Internal); }
        } else if self.loans.values().any(|child| child.mutable &&
            matches!(child.parent, RuntimeValue::Loan(parent) if parent == *id)) {
            return Err(Halt::Internal);
        }
        // Two read-only formal parameters may alias one caller loan. A shared
        // reborrow through one formal must not disable reads through the other.
        // Writes still require exclusivity. A mutable descendant must start
        // with a mutable child: shared loans can never be upgraded to mutable.
        // Static per-SSA suspension rules remain enforced by verify_owned.
        self.root(value)
    }

    fn unsigned(value: &RuntimeValue) -> Exec<u64> {
        value.scalar()?.as_u64().ok_or(Halt::Internal)
    }

    fn argument(args: &[RuntimeValue], index: usize) -> Exec<u64> {
        Self::unsigned(args.get(index).ok_or(Halt::Internal)?)
    }

    fn range(&self, root: u64, offset: u64, size: u64) -> Exec<(usize, usize)> {
        let length = self.owners.get(&root).ok_or(Halt::Internal)?.len() as u64;
        if offset > length || size > length - offset { return Err(Halt::Trap("bounds")); }
        Ok((usize::try_from(offset).map_err(|_| Halt::Internal)?,
            usize::try_from(size).map_err(|_| Halt::Internal)?))
    }

    fn copy_range(&mut self, destination: u64, source: u64,
                  dst_offset: u64, src_offset: u64, size: u64) -> Exec<()> {
        if destination == source { return Err(Halt::Internal); }
        // Validate BOTH complete ranges before the first write. Use fixed
        // scratch rather than allocating another size-proportional buffer.
        let (dst_offset, size) = self.range(destination, dst_offset, size)?;
        let (src_offset, _) = self.range(source, src_offset, size as u64)?;
        let mut scratch = [0_u8; 4096];
        let mut copied = 0;
        while copied < size {
            let count = (size - copied).min(scratch.len());
            scratch[..count].copy_from_slice(
                &self.owners[&source][src_offset + copied..src_offset + copied + count]);
            self.owners.get_mut(&destination).ok_or(Halt::Internal)?[
                dst_offset + copied..dst_offset + copied + count].copy_from_slice(&scratch[..count]);
            copied += count;
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
                let root = self.root(first)?;
                Ok(vec![RuntimeValue::Scalar(json!(self.owners[&root].len()))])
            }
            "borrow.read" | "borrow.mut" => {
                let root = self.root(first)?;
                let mutable = op == "borrow.mut";
                if let RuntimeValue::Loan(id) = first {
                    if mutable && !self.loans[id].mutable { return Err(Halt::Internal); }
                }
                self.loans_started += 1;
                self.loans.insert(self.loans_started, Loan { root, mutable, parent: first.clone() });
                Ok(vec![RuntimeValue::Loan(self.loans_started)])
            }
            "loan.end" => {
                self.root(first)?;
                let RuntimeValue::Loan(id) = first else { return Err(Halt::Internal); };
                if self.child_exists(*id) { return Err(Halt::Internal); }
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
                if self.loans.values().any(|loan| loan.root == *id) { return Err(Halt::Internal); }
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
                let chain = self.chain_id(first)?;
                let head = self.chains[&chain].ok_or(Halt::Trap("bounds"))?;
                let root = self.chain_nodes.get(&head).ok_or(Halt::Internal)?.payload;
                let mutable = op == "chain.head_mut";
                if self.loans.values().any(|loan| loan.root == root && (mutable || loan.mutable)) {
                    return Err(Halt::Internal);
                }
                self.loans_started += 1;
                self.loans.insert(self.loans_started,
                    Loan { root, mutable, parent: RuntimeValue::Owner(root) });
                Ok(vec![RuntimeValue::Loan(self.loans_started)])
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
                let (offset, size, value) = if op == "buffer.fill" {
                    (0, self.owners[&root].len() as u64, Self::argument(args, 1)?)
                } else {
                    (Self::argument(args, 1)?, Self::argument(args, 2)?, Self::argument(args, 3)?)
                };
                let (offset, size) = self.range(root, offset, size)?;
                let value = u8::try_from(value).map_err(|_| Halt::Internal)?;
                self.owners.get_mut(&root).ok_or(Halt::Internal)?[offset..offset + size].fill(value);
                Ok(vec![])
            }
            "buffer.copy" | "buffer.copy_range" => {
                let destination = self.access(first, true)?;
                let source = self.access(args.get(1).ok_or(Halt::Internal)?, false)?;
                let (dst_offset, src_offset, size) = if op == "buffer.copy" {
                    (0, 0, Self::argument(args, 2)?)
                } else {
                    (Self::argument(args, 2)?, Self::argument(args, 3)?, Self::argument(args, 4)?)
                };
                self.copy_range(destination, source, dst_offset, src_offset, size)?;
                Ok(vec![])
            }
            "buffer.move_within" => {
                let root = self.access(first, true)?;
                let destination = Self::argument(args, 1)?;
                let source = Self::argument(args, 2)?;
                let size = Self::argument(args, 3)?;
                let (destination, size) = self.range(root, destination, size)?;
                let (source, _) = self.range(root, source, size as u64)?;
                self.owners.get_mut(&root).ok_or(Halt::Internal)?
                    .copy_within(source..source + size, destination);
                Ok(vec![])
            }
            "buffer.swap" => {
                let root = self.access(first, true)?;
                let left = Self::argument(args, 1)?;
                let right = Self::argument(args, 2)?;
                let (left, _) = self.range(root, left, 1)?;
                let (right, _) = self.range(root, right, 1)?;
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
            "loans_ended": self.loans_ended, "live_local_loans": self.loans.len()
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
