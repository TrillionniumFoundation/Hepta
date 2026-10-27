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
    next_loan_id: u64,
    live_bytes: u64,
    peak_bytes: u64,
}

impl ByteMemory {
    pub(super) fn new(max_heap: u64, fail_at: Option<u64>) -> Self {
        Self { owners: BTreeMap::new(), loans: BTreeMap::new(), max_heap, fail_at,
            attempts: 0, allocations: 0, frees: 0, owners_created: 0,
            owners_dropped: 0, loans_started: 0, loans_ended: 0, next_loan_id: 0,
            live_bytes: 0, peak_bytes: 0 }
    }

    pub(super) fn supports(op: &str) -> bool {
        matches!(op, "buffer.new" | "buffer.try_new" | "buffer.len" |
            "borrow.read" | "borrow.mut" | "loan.end" |
            "owner.move" | "owner.drop" | "buffer.load" | "buffer.store")
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
                self.free_owner(first)?;
                Ok(vec![first.clone()])
            }
            "owner.drop" => {
                let id = self.free_owner(first)?;
                let bytes = self.owners.remove(&id).ok_or(Halt::Internal)?;
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
            "loans_ended": self.loans_ended,
            "live_local_loans": self.loans.values().filter(|loan| !loan.external).count()
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
