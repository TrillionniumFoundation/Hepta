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
}

pub(super) struct ByteMemory {
    owners: BTreeMap<u64, Vec<u8>>,
    loans: BTreeMap<u64, Loan>,
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
            attempts: 0, allocations: 0, frees: 0, owners_created: 0,
            owners_dropped: 0, loans_started: 0, loans_ended: 0,
            live_bytes: 0, peak_bytes: 0 }
    }

    pub(super) fn supports(op: &str) -> bool {
        matches!(op, "buffer.new" | "buffer.try_new" | "buffer.len" |
            "borrow.read" | "borrow.mut" | "loan.end" |
            "owner.move" | "owner.drop" | "buffer.load" | "buffer.store" |
            "buffer.fill" | "buffer.copy" | "buffer.move_within" | "buffer.swap" |
            "buffer.copy_range" | "buffer.fill_range")
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
        if id == parent_id {
            // A forwarded formal retains the caller's handle. Its result must
            // be a fresh child so consuming the result cannot end that parent.
            let op = if mutable { "borrow.mut" } else { "borrow.read" };
            return Ok(self.operation(op, &[parent.clone()])?.remove(0));
        }
        if !matches!(loan.parent, RuntimeValue::Loan(id) if id == *parent_id) {
            return Err(Halt::Internal);
        }
        // A callee-created direct child transfers exactly once, with no extra
        // allocation, tick or started-loan event at the return boundary.
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
                let RuntimeValue::Owner(id) = first else { return Err(Halt::Internal); };
                self.root(first)?;
                if self.loans.values().any(|loan| loan.root == *id) { return Err(Halt::Internal); }
                Ok(vec![first.clone()])
            }
            "owner.drop" => {
                let RuntimeValue::Owner(id) = first else { return Err(Halt::Internal); };
                if self.loans.values().any(|loan| loan.root == *id) { return Err(Halt::Internal); }
                let bytes = self.owners.remove(id).ok_or(Halt::Internal)?;
                self.owners_dropped += 1;
                if !bytes.is_empty() { self.frees += 1; }
                self.live_bytes -= bytes.len() as u64;
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
            // The v7 Python ledger includes chain counters even in a program
            // with no chain opcode. This execution profile never admits one.
            for field in ["chains_created", "chains_consumed", "live_chains",
                          "chain_nodes_created", "chain_nodes_dropped", "live_chain_nodes"] {
                report[field] = json!(0);
            }
        }
        report
    }
}
