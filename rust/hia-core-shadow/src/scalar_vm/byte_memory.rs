//! Optional finite byte storage for the existing execution Machine.
//! Static linear/loan admission belongs to the existing ownership verifier.
use std::collections::{BTreeMap, BTreeSet};
use serde_json::{json, Value};
use super::{Exec, Halt, RuntimeValue};

struct Loan {
    parent: RuntimeValue,
    root: u64,
    mutable: bool,
    // Call-formal witnesses are not source borrow instructions.
    external: bool,
}

// Explicit arena links avoid a host-stack-recursive destructor. Node storage
// and payloads remain ordinary owners in the shared allocation ledger.
struct ChainNode {
    storage: u64,
    payload: u64,
    tail: Option<u64>,
}

const CHAIN_NODE_BYTES: u64 = 24;

pub(super) struct ByteMemory {
    owners: BTreeMap<u64, Vec<u8>>,
    loans: BTreeMap<u64, Loan>,
    chains: BTreeMap<u64, Option<u64>>,
    nodes: BTreeMap<u64, ChainNode>,
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
    next_loan_id: u64,
    live_bytes: u64,
    peak_bytes: u64,
}

impl ByteMemory {
    pub(super) fn new(max_heap: u64, fail_at: Option<u64>) -> Self {
        Self { owners: BTreeMap::new(), loans: BTreeMap::new(), max_heap, fail_at,
            chains: BTreeMap::new(), nodes: BTreeMap::new(),
            chains_created: 0, chains_consumed: 0, chain_nodes_created: 0,
            chain_nodes_dropped: 0,
            attempts: 0, allocations: 0, frees: 0, owners_created: 0,
            owners_dropped: 0, loans_started: 0, loans_ended: 0, next_loan_id: 0,
            live_bytes: 0, peak_bytes: 0 }
    }

    pub(super) fn supports(op: &str) -> bool {
        matches!(op, "buffer.new" | "buffer.try_new" | "buffer.len" |
            "borrow.read" | "borrow.mut" | "loan.end" |
            "owner.move" | "owner.drop" | "buffer.load" | "buffer.store" |
            "buffer.fill" | "buffer.copy" | "buffer.move_within" |
            "buffer.swap" | "buffer.copy_range" | "buffer.fill_range" |
            "chain.empty" | "chain.try_push" | "chain.pop" |
            "chain.is_empty" | "chain.head_read" | "chain.head_mut")
    }

    pub(super) fn loan_type(&self, id: u64) -> Option<&'static str> {
        self.loans.get(&id).map(|loan| if loan.mutable { "mutbuf" } else { "readbuf" })
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

    pub(super) fn free_owner(&self, value: &RuntimeValue) -> Exec<u64> {
        let RuntimeValue::Owner(id) = value else { return Err(Halt::Internal); };
        self.root(value)?;
        if self.loans.values().any(|loan| loan.root == *id) { return Err(Halt::Internal); }
        Ok(*id)
    }

    pub(super) fn free_owned(&self, value: &RuntimeValue) -> Exec<()> {
        match value {
            RuntimeValue::Owner(_) => { self.free_owner(value)?; }
            RuntimeValue::Chain(_) => {
                // A live chain exposes only its current head. Popping or
                // transferring the chain is forbidden until all such loans
                // (including their call-formal/reborrow descendants) end.
                if let Some(head) = self.chain_head(value)? {
                    let node = self.nodes.get(&head).ok_or(Halt::Internal)?;
                    self.free_owner(&RuntimeValue::Owner(node.payload))?;
                }
            }
            _ => return Err(Halt::Internal),
        }
        Ok(())
    }

    fn drop_owner(&mut self, value: &RuntimeValue) -> Exec<()> {
        let id = self.free_owner(value)?;
        let bytes = self.owners.remove(&id).ok_or(Halt::Internal)?;
        self.owners_dropped += 1;
        if !bytes.is_empty() { self.frees += 1; }
        self.live_bytes -= bytes.len() as u64;
        Ok(())
    }

    fn new_chain(&mut self, head: Option<u64>) -> RuntimeValue {
        self.chains_created += 1;
        self.chains.insert(self.chains_created, head);
        RuntimeValue::Chain(self.chains_created)
    }

    fn chain_head(&self, value: &RuntimeValue) -> Exec<Option<u64>> {
        let RuntimeValue::Chain(id) = value else { return Err(Halt::Internal); };
        self.chains.get(id).copied().ok_or(Halt::Internal)
    }

    pub(super) fn consume_chain(&mut self, value: &RuntimeValue) -> Exec<Option<u64>> {
        self.free_owned(value)?;
        let RuntimeValue::Chain(id) = value else { return Err(Halt::Internal); };
        let head = self.chains.remove(id).ok_or(Halt::Internal)?;
        self.chains_consumed += 1;
        Ok(head)
    }

    // The Machine charges one tick BEFORE each call. On a budget stop the
    // chain has been consumed, but all unvisited nodes/owners stay in the
    // stopped ledger. Host cleanup never masquerades as language destruction.
    pub(super) fn drop_chain_node(&mut self, id: u64) -> Exec<Option<u64>> {
        let node = self.nodes.remove(&id).ok_or(Halt::Internal)?;
        self.drop_owner(&RuntimeValue::Owner(node.payload))?;
        self.drop_owner(&RuntimeValue::Owner(node.storage))?;
        self.chain_nodes_dropped += 1;
        Ok(node.tail)
    }

    fn push_chain(&mut self, chain: &RuntimeValue, payload: &RuntimeValue)
        -> Exec<Vec<RuntimeValue>> {
        self.free_owned(chain)?;
        let head = self.chain_head(chain)?;
        let payload_id = self.free_owner(payload)?;
        // Heap admission precedes failure injection, just as for buffers.
        // On failure allocate() creates a logical empty owner; dispose that
        // internal placeholder and return the original payload unchanged.
        let (storage, success) = self.allocate(CHAIN_NODE_BYTES, true)?;
        let (next_head, fallback) = if success {
            let storage_id = self.free_owner(&storage)?;
            self.chain_nodes_created += 1;
            let id = self.chain_nodes_created;
            self.nodes.insert(id, ChainNode { storage: storage_id, payload: payload_id, tail: head });
            (Some(id), self.new_owner(Vec::new()))
        } else {
            self.drop_owner(&storage)?;
            (head, payload.clone())
        };
        self.consume_chain(chain)?;
        Ok(vec![self.new_chain(next_head), fallback, RuntimeValue::Scalar(json!(success))])
    }

    fn pop_chain(&mut self, chain: &RuntimeValue) -> Exec<Vec<RuntimeValue>> {
        let head = self.consume_chain(chain)?;
        if let Some(id) = head {
            let node = self.nodes.remove(&id).ok_or(Halt::Internal)?;
            self.drop_owner(&RuntimeValue::Owner(node.storage))?;
            self.chain_nodes_dropped += 1;
            Ok(vec![self.new_chain(node.tail), RuntimeValue::Owner(node.payload),
                    RuntimeValue::Scalar(json!(true))])
        } else {
            Ok(vec![self.new_chain(None), self.new_owner(Vec::new()),
                    RuntimeValue::Scalar(json!(false))])
        }
    }

    fn borrow(&mut self, value: &RuntimeValue, mutable: bool) -> Exec<RuntimeValue> {
        let root = self.root(value)?;
        let mut ancestors = BTreeSet::new();
        let mut current = value;
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
        self.loans_started += 1;
        self.next_loan_id += 1;
        let id = self.next_loan_id;
        self.loans.insert(id, Loan { root, mutable, parent: value.clone(), external: false });
        Ok(RuntimeValue::Loan(id))
    }

    pub(super) fn enter_call(&mut self, params: &Value, mut values: Vec<RuntimeValue>)
        -> Exec<(Vec<RuntimeValue>, Vec<u64>)> {
        let parameters = params.as_array().ok_or(Halt::Internal)?;
        if parameters.len() != values.len() { return Err(Halt::Internal); }
        // Validate all actual loans before installing any formal witnesses:
        // two shared formals may legally alias the same mutable caller loan.
        let mut views = Vec::new();
        for (parameter, value) in parameters.iter().zip(&values) {
            if !matches!(parameter["type"].as_str(), Some("readbuf" | "mutbuf")) { continue; }
            let mutable = parameter["type"] == "mutbuf";
            let root = self.access(value, mutable)?;
            if views.iter().any(|(other_root, exclusive)|
                *other_root == root && (*exclusive || mutable)) { return Err(Halt::Internal); }
            views.push((root, mutable));
        }
        let mut formals = Vec::new();
        for (parameter, value) in parameters.iter().zip(&mut values) {
            if !matches!(parameter["type"].as_str(), Some("readbuf" | "mutbuf")) { continue; }
            let root = self.root(value)?;
            self.next_loan_id += 1;
            let id = self.next_loan_id;
            // A child of `left` must not suspend an aliased readonly `right`.
            self.loans.insert(id, Loan { root, parent: value.clone(),
                mutable: parameter["type"] == "mutbuf", external: true });
            *value = RuntimeValue::Loan(id);
            formals.push(id);
        }
        Ok((values, formals))
    }

    pub(super) fn leave_call(&mut self, formals: &[u64]) -> Exec<()> {
        for id in formals {
            let loan = self.loans.get(id).ok_or(Halt::Internal)?;
            if !loan.external || self.child_exists(*id) { return Err(Halt::Internal); }
            self.loans.remove(id).ok_or(Halt::Internal)?;
        }
        Ok(())
    }

    fn access(&self, value: &RuntimeValue, mutable: bool) -> Exec<u64> {
        let RuntimeValue::Loan(id) = value else { return Err(Halt::Internal); };
        let loan = self.loans.get(id).ok_or(Halt::Internal)?;
        if (mutable && !loan.mutable) || self.child_exists(*id) { return Err(Halt::Internal); }
        self.root(value)
    }

    fn unsigned(value: &RuntimeValue) -> Exec<u64> {
        value.scalar()?.as_u64().ok_or(Halt::Internal)
    }

    fn range(offset: u64, count: u64, extent: usize) -> Exec<std::ops::Range<usize>> {
        let size = extent as u64;
        // Check even empty ranges: len..len is valid, (len + 1).. is not.
        // No addition or subtraction may overflow before the bounds trap.
        if offset > size || count > size - offset { return Err(Halt::Trap("bounds")); }
        let start = usize::try_from(offset).map_err(|_| Halt::Internal)?;
        let length = usize::try_from(count).map_err(|_| Halt::Internal)?;
        Ok(start..start + length)
    }

    fn copy(&mut self, destination: u64, source: u64,
            destination_offset: u64, source_offset: u64, count: u64) -> Exec<()> {
        if destination == source { return Err(Halt::Internal); }
        let destination_size = self.owners.get(&destination).ok_or(Halt::Internal)?.len();
        let source_size = self.owners.get(&source).ok_or(Halt::Internal)?.len();
        let dst = Self::range(destination_offset, count, destination_size)?;
        let src = Self::range(source_offset, count, source_size)?;
        if count == 0 { return Ok(()); }

        // The static loan checker requires distinct live owner roots. A
        // BTreeMap double-ended mutable iterator yields disjoint references
        // without unsafe pointers, moving owners, or O(count) scratch storage.
        let mut owners = self.owners.range_mut(destination.min(source)..=destination.max(source));
        let (first_id, first) = owners.next().ok_or(Halt::Internal)?;
        let (_, last) = owners.next_back().ok_or(Halt::Internal)?;
        if *first_id == destination {
            first[dst].copy_from_slice(&last[src]);
        } else {
            last[dst].copy_from_slice(&first[src]);
        }
        Ok(())
    }

    pub(super) fn operation(&mut self, op: &str, args: &[RuntimeValue]) -> Exec<Vec<RuntimeValue>> {
        if op == "chain.empty" {
            if !args.is_empty() { return Err(Halt::Internal); }
            return Ok(vec![self.new_chain(None)]);
        }
        let first = args.first().ok_or(Halt::Internal)?;
        match op {
            "chain.try_push" => self.push_chain(first, args.get(1).ok_or(Halt::Internal)?),
            "chain.pop" => self.pop_chain(first),
            "chain.is_empty" => Ok(vec![RuntimeValue::Scalar(json!(self.chain_head(first)?.is_none()))]),
            "chain.head_read" | "chain.head_mut" => {
                let head = self.chain_head(first)?.ok_or(Halt::Trap("bounds"))?;
                let node = self.nodes.get(&head).ok_or(Halt::Internal)?;
                let payload = RuntimeValue::Owner(node.payload);
                Ok(vec![self.borrow(&payload, op == "chain.head_mut")?])
            }
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
            "borrow.read" | "borrow.mut" => Ok(vec![self.borrow(first, op == "borrow.mut")?]),
            "loan.end" => {
                self.root(first)?;
                let RuntimeValue::Loan(id) = first else { return Err(Halt::Internal); };
                if self.loans.get(id).ok_or(Halt::Internal)?.external || self.child_exists(*id) {
                    return Err(Halt::Internal);
                }
                self.loans.remove(id).ok_or(Halt::Internal)?;
                self.loans_ended += 1;
                Ok(vec![])
            }
            "owner.move" => {
                self.free_owned(first)?;
                Ok(vec![first.clone()])
            }
            "owner.drop" => {
                // Chain destruction is handled in Machine so each node is
                // charged against the same global instruction-step budget.
                self.drop_owner(first)?;
                Ok(vec![])
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
                let data = self.owners.get_mut(&root).ok_or(Halt::Internal)?;
                let (range, value_index) = if op == "buffer.fill" {
                    (0..data.len(), 1)
                } else {
                    let offset = Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?;
                    let count = Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?;
                    (Self::range(offset, count, data.len())?, 3)
                };
                let byte = Self::unsigned(args.get(value_index).ok_or(Halt::Internal)?)?;
                data[range].fill(u8::try_from(byte).map_err(|_| Halt::Internal)?);
                Ok(vec![])
            }
            "buffer.copy" | "buffer.copy_range" => {
                let destination = self.access(first, true)?;
                let source = self.access(args.get(1).ok_or(Halt::Internal)?, false)?;
                let (destination_offset, source_offset, count) = if op == "buffer.copy" {
                    (0, 0, Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?)
                } else {
                    (Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?,
                     Self::unsigned(args.get(3).ok_or(Halt::Internal)?)?,
                     Self::unsigned(args.get(4).ok_or(Halt::Internal)?)?)
                };
                self.copy(destination, source, destination_offset, source_offset, count)?;
                Ok(vec![])
            }
            "buffer.move_within" => {
                let root = self.access(first, true)?;
                let destination = Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?;
                let source = Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?;
                let count = Self::unsigned(args.get(3).ok_or(Halt::Internal)?)?;
                let data = self.owners.get_mut(&root).ok_or(Halt::Internal)?;
                let dst = Self::range(destination, count, data.len())?;
                let src = Self::range(source, count, data.len())?;
                // copy_within has memmove semantics for both overlap directions.
                data.copy_within(src, dst.start);
                Ok(vec![])
            }
            "buffer.swap" => {
                let root = self.access(first, true)?;
                let left = Self::unsigned(args.get(1).ok_or(Halt::Internal)?)?;
                let right = Self::unsigned(args.get(2).ok_or(Halt::Internal)?)?;
                let data = self.owners.get_mut(&root).ok_or(Halt::Internal)?;
                if left >= data.len() as u64 || right >= data.len() as u64 {
                    return Err(Halt::Trap("bounds"));
                }
                data.swap(usize::try_from(left).map_err(|_| Halt::Internal)?,
                          usize::try_from(right).map_err(|_| Halt::Internal)?);
                Ok(vec![])
            }
            _ => Err(Halt::Internal),
        }
    }

    pub(super) fn is_clean(&self) -> bool {
        self.owners.is_empty() && self.loans.is_empty() && self.chains.is_empty()
            && self.nodes.is_empty() && self.live_bytes == 0
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
            report["live_chain_nodes"] = json!(self.nodes.len());
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> RuntimeValue { RuntimeValue::Scalar(json!(value)) }

    #[test]
    fn invalid_bulk_ranges_do_not_partially_write_storage() {
        let mut memory = ByteMemory::new(1024, None);
        let source = memory.new_owner(vec![1, 2, 3, 4]);
        let destination = memory.new_owner(vec![9, 8, 7, 6]);
        let reader = memory.borrow(&source, false).unwrap_or_else(|_| panic!("reader"));
        let writer = memory.borrow(&destination, true).unwrap_or_else(|_| panic!("writer"));
        let before = memory.owners.clone();
        for (opcode, operands) in [
            ("buffer.copy", vec![writer.clone(), reader.clone(), scalar(5)]),
            ("buffer.copy_range", vec![writer.clone(), reader.clone(), scalar(1), scalar(2), scalar(3)]),
            ("buffer.move_within", vec![writer.clone(), scalar(0), scalar(3), scalar(2)]),
            ("buffer.fill_range", vec![writer.clone(), scalar(3), scalar(2), scalar(0)]),
            ("buffer.swap", vec![writer.clone(), scalar(0), scalar(u64::MAX)]),
        ] {
            assert!(matches!(memory.operation(opcode, &operands), Err(Halt::Trap("bounds"))));
            assert_eq!(memory.owners, before, "{opcode} wrote before validating every range");
        }
    }

    #[test]
    fn copy_uses_selected_roots_without_touching_intervening_owner() {
        let mut memory = ByteMemory::new(1024, None);
        let first = memory.new_owner(vec![1, 2, 3, 4]);
        let middle = memory.new_owner(vec![91, 92]);
        let last = memory.new_owner(vec![5, 6, 7, 8]);
        let a = memory.root(&first).unwrap_or_else(|_| panic!("first"));
        let b = memory.root(&last).unwrap_or_else(|_| panic!("last"));
        let untouched = memory.root(&middle).unwrap_or_else(|_| panic!("middle"));
        memory.copy(b, a, 1, 0, 3).unwrap_or_else(|_| panic!("ascending copy"));
        assert_eq!(memory.owners[&b], [5, 1, 2, 3]);
        memory.copy(a, b, 0, 1, 3).unwrap_or_else(|_| panic!("descending copy"));
        assert_eq!(memory.owners[&a], [1, 2, 3, 4]);
        assert_eq!(memory.owners[&untouched], [91, 92]);
        assert!(matches!(memory.copy(a, a, 0, 0, 0), Err(Halt::Internal)));
    }

    #[test]
    fn chain_head_loans_block_consumption_until_all_descendants_end() {
        let mut memory = ByteMemory::new(100, None);
        let empty = memory.new_chain(None);
        let payload = memory.new_owner(vec![1, 2]);
        let pushed = memory.push_chain(&empty, &payload).unwrap_or_else(|_| panic!("push"));
        let chain = &pushed[0];
        memory.drop_owner(&pushed[1]).unwrap_or_else(|_| panic!("fallback"));
        let parent = memory.operation("chain.head_mut", &[chain.clone()])
            .unwrap_or_else(|_| panic!("head"))[0].clone();
        let child = memory.borrow(&parent, false).unwrap_or_else(|_| panic!("child"));
        assert!(matches!(memory.consume_chain(chain), Err(Halt::Internal)));
        assert!(matches!(memory.pop_chain(chain), Err(Halt::Internal)));
        assert!(matches!(memory.operation("loan.end", &[parent.clone()]), Err(Halt::Internal)));
        memory.operation("loan.end", &[child]).unwrap_or_else(|_| panic!("end child"));
        assert!(matches!(memory.consume_chain(chain), Err(Halt::Internal)));
        memory.operation("loan.end", &[parent]).unwrap_or_else(|_| panic!("end parent"));
        let head = memory.consume_chain(chain).unwrap_or_else(|_| panic!("consume"))
            .unwrap_or_else(|| panic!("node"));
        assert!(memory.drop_chain_node(head).unwrap_or_else(|_| panic!("drop")).is_none());
        assert!(memory.is_clean());
        assert_eq!(memory.report(true)["chain_nodes_dropped"], 1);
    }

    #[test]
    fn failed_node_allocation_returns_same_payload_without_an_extra_allocation() {
        let mut memory = ByteMemory::new(100, Some(2));
        let (payload, _) = memory.allocate(3, false).unwrap_or_else(|_| panic!("payload"));
        let payload_id = memory.free_owner(&payload).unwrap_or_else(|_| panic!("owner"));
        memory.owners.get_mut(&payload_id).unwrap().copy_from_slice(&[9, 8, 7]);
        let empty = memory.new_chain(None);
        let pushed = memory.push_chain(&empty, &payload).unwrap_or_else(|_| panic!("push"));
        assert!(matches!(pushed[1], RuntimeValue::Owner(id) if id == payload_id));
        assert_eq!(pushed[2].scalar().unwrap_or_else(|_| panic!("status")), &json!(false));
        assert_eq!(memory.owners[&payload_id], [9, 8, 7]);
        let ledger = memory.report(true);
        assert_eq!(ledger["allocation_attempts"], 2);
        assert_eq!(ledger["allocations"], 1);
        assert_eq!(ledger["owners_created"], 2);
        assert_eq!(ledger["owners_dropped"], 1);
        assert_eq!(ledger["chain_nodes_created"], 0);
        assert!(memory.consume_chain(&pushed[0]).unwrap_or_else(|_| panic!("consume")).is_none());
        memory.drop_owner(&pushed[1]).unwrap_or_else(|_| panic!("drop payload"));
        assert!(memory.is_clean());
    }
}
