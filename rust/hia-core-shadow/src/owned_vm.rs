//! Independent finite execution of the existing v1-v7 resource ISA.
//! This is a development oracle, never the production admission authority.
//! There is no Python invocation, native execution, source replay, raw pointer,
//! borrowed return, concurrency or acceptance of unknown resource ISA versions.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};

use super::scalar_vm::{opcode_results, Exec, Halt};
use super::{decode_hia, failure, valid_constant, verify_owned, R};

const MAX_STEPS: u64 = 1_000_000;
const MAX_HEAP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CALL_DEPTH: u32 = 32;
const CHAIN_NODE_BYTES: u64 = 24;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OwnedOptions {
    pub max_steps: u64,
    pub max_heap_bytes: u64,
    pub allocation_fail_at: Option<u64>,
}

impl Default for OwnedOptions {
    fn default() -> Self {
        Self { max_steps: 100_000, max_heap_bytes: 16 * 1024 * 1024,
               allocation_fail_at: None }
    }
}

// Identities refer to this machine's allocations/loans, never host pointers.
// Cloning an environment value does not create a new ownership capability:
// consume/move/call operations remove the old SSA binding, and the static
// verifier additionally checks every path, including paths not executed here.
#[derive(Clone)]
enum RuntimeValue {
    Scalar(Value),
    Owner(u64),
    Chain(u64),
    View { id: u64, mutable: bool },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Root { Owner(u64), Chain(u64) }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent { Root(Root), View(u64) }

// A head loan has chain provenance but accesses its head payload's storage.
// Keeping those identities separate prevents treating a chain as a byte buffer
// or moving its root while an otherwise valid payload view remains live.
struct Loan { root: Root, storage: u64, parent: Parent, mutable: bool, external: bool }

struct ChainNode { storage: u64, payload: u64, tail: Option<u64> }

type Environment = BTreeMap<String, RuntimeValue>;

fn scalar(value: &RuntimeValue) -> Exec<&Value> {
    match value { RuntimeValue::Scalar(v) => Ok(v), _ => Err(Halt::Internal) }
}

fn integer(value: &RuntimeValue) -> Exec<u64> {
    scalar(value)?.as_u64().ok_or(Halt::Internal)
}

fn lookup(env: &Environment, name: &Value) -> Exec<RuntimeValue> {
    env.get(name.as_str().ok_or(Halt::Internal)?).cloned().ok_or(Halt::Internal)
}

fn resolve(env: &Environment, names: &Value) -> Exec<Vec<RuntimeValue>> {
    names.as_array().ok_or(Halt::Internal)?.iter().map(|n| lookup(env, n)).collect()
}

fn bind(params: &Value, values: Vec<RuntimeValue>) -> Exec<Environment> {
    let params = params.as_array().ok_or(Halt::Internal)?;
    if params.len() != values.len() { return Err(Halt::Internal); }
    let mut env = Environment::new();
    for (param, value) in params.iter().zip(values) {
        env.insert(param["name"].as_str().ok_or(Halt::Internal)?.into(), value);
    }
    Ok(env)
}

struct Machine<'a> {
    functions: BTreeMap<&'a str, &'a Value>,
    options: OwnedOptions,
    steps: u64,
    owners: BTreeMap<u64, Vec<u8>>,
    loans: BTreeMap<u64, Loan>,
    chains: BTreeMap<u64, Option<u64>>,
    nodes: BTreeMap<u64, ChainNode>,
    recursive_chain: bool,
    chains_created: u64,
    chains_consumed: u64,
    chain_nodes_created: u64,
    chain_nodes_dropped: u64,
    owner_count: u64,
    drops: u64,
    allocations: u64,
    frees: u64,
    allocation_attempts: u64,
    live_bytes: u64,
    peak_bytes: u64,
    loans_started: u64,
    loans_ended: u64,
    next_loan_id: u64,
}

impl<'a> Machine<'a> {
    fn new(functions: BTreeMap<&'a str, &'a Value>, options: OwnedOptions,
           recursive_chain: bool) -> Self {
        Self { functions, options, steps: 0, owners: BTreeMap::new(),
               loans: BTreeMap::new(), owner_count: 0, drops: 0,
               chains: BTreeMap::new(), nodes: BTreeMap::new(), recursive_chain,
               chains_created: 0, chains_consumed: 0,
               chain_nodes_created: 0, chain_nodes_dropped: 0,
               allocations: 0, frees: 0, allocation_attempts: 0,
               live_bytes: 0, peak_bytes: 0, loans_started: 0, loans_ended: 0,
               next_loan_id: 0 }
    }

    fn tick(&mut self) -> Exec<()> {
        self.steps += 1;
        if self.steps > self.options.max_steps { Err(Halt::Budget("steps")) }
        else { Ok(()) }
    }

    fn new_owner(&mut self, bytes: Vec<u8>) -> RuntimeValue {
        self.owner_count += 1;
        if !bytes.is_empty() { self.allocations += 1; }
        self.live_bytes += bytes.len() as u64;
        self.peak_bytes = self.peak_bytes.max(self.live_bytes);
        self.owners.insert(self.owner_count, bytes);
        RuntimeValue::Owner(self.owner_count)
    }

    fn allocate(&mut self, size: u64, optional: bool) -> Exec<(RuntimeValue, bool)> {
        // A zero-size owner is a real linear value, but not an allocator call.
        if size == 0 { return Ok((self.new_owner(Vec::new()), true)); }
        if size > i64::MAX as u64 {
            return if optional { Ok((self.new_owner(Vec::new()), false)) }
                   else { Err(Halt::Trap("allocation")) };
        }
        if size > self.options.max_heap_bytes - self.live_bytes {
            return Err(Halt::Budget("heap"));
        }
        self.allocation_attempts += 1;
        let mut bytes = Vec::new();
        let failed = self.options.allocation_fail_at == Some(self.allocation_attempts)
            || bytes.try_reserve_exact(size as usize).is_err();
        if failed {
            return if optional { Ok((self.new_owner(Vec::new()), false)) }
                   else { Err(Halt::Trap("allocation")) };
        }
        bytes.resize(size as usize, 0);
        Ok((self.new_owner(bytes), true))
    }

    fn drop_bytes(&mut self, id: u64) -> Exec<()> {
        if self.loans.values().any(|loan| loan.storage == id) {
            return Err(Halt::Internal);
        }
        let bytes = self.owners.remove(&id).ok_or(Halt::Internal)?;
        if !bytes.is_empty() { self.frees += 1; }
        self.live_bytes -= bytes.len() as u64;
        self.drops += 1;
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

    fn consume_chain(&mut self, value: &RuntimeValue) -> Exec<Option<u64>> {
        let Root::Chain(id) = self.free_owner(value)? else { return Err(Halt::Internal); };
        let head = self.chains.remove(&id).ok_or(Halt::Internal)?;
        self.chains_consumed += 1;
        Ok(head)
    }

    fn drop_chain(&mut self, value: &RuntimeValue) -> Exec<()> {
        // Consume the root before charging destruction, as specified by Core.
        // If a tick stops us, the remaining nodes/storage stay in the ledger;
        // dropping this oracle's host maps is not source-program cleanup.
        let mut head = self.consume_chain(value)?;
        while let Some(id) = head {
            self.tick()?;
            let node = self.nodes.remove(&id).ok_or(Halt::Internal)?;
            self.drop_bytes(node.payload)?;
            self.drop_bytes(node.storage)?;
            self.chain_nodes_dropped += 1;
            head = node.tail;
        }
        Ok(())
    }

    fn range(extent: usize, offset: u64, size: u64) -> Exec<std::ops::Range<usize>> {
        // Check subtraction before forming an endpoint or host slice index.
        // Even a zero-size operation must have an in-range offset.
        if offset > extent as u64 || size > extent as u64 - offset {
            return Err(Halt::Trap("bounds"));
        }
        Ok(offset as usize..(offset + size) as usize)
    }

    fn copy_bytes(&mut self, destination: u64, source: u64,
                  dst_offset: u64, src_offset: u64, size: u64) -> Exec<()> {
        if destination == source { return Err(Halt::Internal); }
        let dst = Self::range(self.owners.get(&destination).ok_or(Halt::Internal)?.len(),
                              dst_offset, size)?;
        let src = Self::range(self.owners.get(&source).ok_or(Halt::Internal)?.len(),
                              src_offset, size)?;
        // Move a Vec handle, never clone bytes or allocate count-sized scratch.
        // All fallible guards precede removal; source and destination are
        // distinct, so the checked source remains present until reinsertion.
        let mut bytes = self.owners.remove(&destination).ok_or(Halt::Internal)?;
        bytes[dst].copy_from_slice(&self.owners[&source][src]);
        self.owners.insert(destination, bytes);
        Ok(())
    }

    fn root(&self, value: &RuntimeValue) -> Exec<Root> {
        let root = match value {
            RuntimeValue::Owner(id) => Root::Owner(*id),
            RuntimeValue::Chain(id) => Root::Chain(*id),
            RuntimeValue::View { id, .. } => {
                let mut current = *id;
                loop {
                    let loan = self.loans.get(&current).ok_or(Halt::Internal)?;
                    match loan.parent {
                        Parent::Root(root) => break root,
                        Parent::View(parent) => current = parent,
                    }
                }
            }
            RuntimeValue::Scalar(_) => return Err(Halt::Internal),
        };
        let alive = match root {
            Root::Owner(id) => self.owners.contains_key(&id),
            Root::Chain(id) => self.chains.contains_key(&id),
        };
        if !alive { return Err(Halt::Internal); }
        Ok(root)
    }

    fn byte_owner(&self, value: &RuntimeValue) -> Exec<u64> {
        let root = self.root(value)?;
        let storage = match value {
            RuntimeValue::Owner(id) => *id,
            RuntimeValue::View { id, .. } => {
                let loan = self.loans.get(id).ok_or(Halt::Internal)?;
                if loan.root != root { return Err(Halt::Internal); }
                loan.storage
            }
            _ => return Err(Halt::Internal),
        };
        if !self.owners.contains_key(&storage) { return Err(Halt::Internal); }
        Ok(storage)
    }

    fn free_owner(&self, value: &RuntimeValue) -> Exec<Root> {
        if !matches!(value, RuntimeValue::Owner(_) | RuntimeValue::Chain(_)) {
            return Err(Halt::Internal);
        }
        let root = self.root(value)?;
        if self.loans.values().any(|l| l.root == root) {
            return Err(Halt::Internal);
        }
        Ok(root)
    }

    fn borrow(&mut self, value: &RuntimeValue, mutable: bool, head: bool)
        -> Exec<RuntimeValue> {
        let root = self.root(value)?;
        let storage = if head {
            let node = self.chain_head(value)?.ok_or(Halt::Trap("bounds"))?;
            self.nodes.get(&node).ok_or(Halt::Internal)?.payload
        } else { self.byte_owner(value)? };
        if !self.owners.contains_key(&storage) { return Err(Halt::Internal); }
        let mut ancestors = BTreeSet::new();
        let parent = match value {
            RuntimeValue::Owner(_) | RuntimeValue::Chain(_) => Parent::Root(root),
            RuntimeValue::View { id, mutable: permitted } => {
                if mutable && !permitted { return Err(Halt::Internal); }
                let mut current = *id;
                loop {
                    if !ancestors.insert(current) { return Err(Halt::Internal); }
                    match self.loans.get(&current).ok_or(Halt::Internal)?.parent {
                        Parent::Root(_) => break,
                        Parent::View(previous) => current = previous,
                    }
                }
                Parent::View(*id)
            }
            RuntimeValue::Scalar(_) => return Err(Halt::Internal),
        };
        if self.loans.iter().any(|(id, loan)| loan.root == root
                && !ancestors.contains(id) && (mutable || loan.mutable)) {
            return Err(Halt::Internal);
        }
        self.loans_started += 1;
        self.next_loan_id += 1;
        let id = self.next_loan_id;
        self.loans.insert(id, Loan { root, storage, parent, mutable, external: false });
        Ok(RuntimeValue::View { id, mutable })
    }

    fn access(&self, value: &RuntimeValue, mutable: bool) -> Exec<u64> {
        let RuntimeValue::View { id, mutable: permitted } = value
            else { return Err(Halt::Internal); };
        if mutable && !permitted
            || self.loans.values().any(|l| l.parent == Parent::View(*id)) {
            return Err(Halt::Internal);
        }
        self.byte_owner(value)
    }

    fn enter_call(&mut self, params: &Value, mut values: Vec<RuntimeValue>)
        -> Exec<(Environment, Vec<u64>)> {
        let parameters = params.as_array().ok_or(Halt::Internal)?;
        if parameters.len() != values.len() { return Err(Halt::Internal); }
        // Check all actual arguments BEFORE adding any call-formal loans:
        // two readbuf formals may refer to one caller loan. Its first formal
        // must not make the second argument look suspended during binding.
        let mut views = Vec::new();
        for (param, value) in parameters.iter().zip(&values) {
            if matches!(param["type"].as_str(), Some("readbuf" | "mutbuf")) {
                let mutable = param["type"] == "mutbuf";
                self.access(value, mutable)?;
                let root = self.root(value)?;
                if views.iter().any(|(other_root, exclusive)| {
                    *other_root == root && (*exclusive || mutable)
                }) { return Err(Halt::Internal); }
                views.push((root, mutable));
            }
        }
        let mut formals = Vec::new();
        for (param, value) in parameters.iter().zip(&mut values) {
            if !matches!(param["type"].as_str(), Some("readbuf" | "mutbuf")) { continue; }
            let root = self.root(value)?;
            let storage = self.byte_owner(value)?;
            let RuntimeValue::View { id: parent, .. } = value else { return Err(Halt::Internal); };
            let mutable = param["type"] == "mutbuf";
            self.next_loan_id += 1;
            let id = self.next_loan_id;
            // Distinct identities match the Core's distinct formal loans.
            // A local child of `left` suspends `left`, not another readonly
            // formal `right` sharing its root. Retain the real parent/root
            // for conflict checks, and never upgrade the caller permission.
            self.loans.insert(id, Loan { root, storage, parent: Parent::View(*parent),
                                        mutable, external: true });
            *value = RuntimeValue::View { id, mutable };
            formals.push(id);
        }
        Ok((bind(params, values)?, formals))
    }

    fn leave_call(&mut self, formals: &[u64]) -> Exec<()> {
        for id in formals {
            let loan = self.loans.get(id).ok_or(Halt::Internal)?;
            if !loan.external || self.loans.values().any(|l| l.parent == Parent::View(*id)) {
                return Err(Halt::Internal);
            }
            self.loans.remove(id).ok_or(Halt::Internal)?;
        }
        // Call-formal loans are scope witnesses, not source borrow/end
        // instructions, so they never change program resource counters.
        Ok(())
    }

    fn operation(&mut self, op: &Value, env: &mut Environment, depth: u32)
        -> Exec<()> {
        let opcode = op["op"].as_str().ok_or(Halt::Internal)?;
        let operands = resolve(env, &op["args"])?;
        let get = |n: usize| operands.get(n).ok_or(Halt::Internal);
        let consume = |env: &mut Environment, n: usize| -> Exec<()> {
            let name = op["args"][n].as_str().ok_or(Halt::Internal)?;
            env.remove(name).ok_or(Halt::Internal)?;
            Ok(())
        };
        let outputs = match opcode {
            "buffer.new" | "buffer.try_new" => {
                let (owner, succeeded) = self.allocate(integer(get(0)?)?, opcode == "buffer.try_new")?;
                let mut result = vec![owner];
                if opcode == "buffer.try_new" { result.push(RuntimeValue::Scalar(json!(succeeded))); }
                result
            }
            "buffer.len" => {
                let storage = self.byte_owner(get(0)?)?;
                vec![RuntimeValue::Scalar(json!(self.owners[&storage].len() as u64))]
            }
            "chain.empty" => vec![self.new_chain(None)],
            "chain.try_push" => {
                let head = self.chain_head(get(0)?)?;
                self.free_owner(get(0)?)?;
                let Root::Owner(payload) = self.free_owner(get(1)?)?
                    else { return Err(Halt::Internal); };
                let (storage, succeeded) = self.allocate(CHAIN_NODE_BYTES, true)?;
                let RuntimeValue::Owner(storage) = storage else { return Err(Halt::Internal); };
                let (head, fallback) = if succeeded {
                    self.chain_nodes_created += 1;
                    let id = self.chain_nodes_created;
                    self.nodes.insert(id, ChainNode { storage, payload, tail: head });
                    (Some(id), self.new_owner(Vec::new()))
                } else {
                    // Optional allocation made a real empty owner. Its
                    // internal release must count, without a free(NULL).
                    self.drop_bytes(storage)?;
                    (head, RuntimeValue::Owner(payload))
                };
                self.consume_chain(get(0)?)?;
                let chain = self.new_chain(head);
                consume(env, 0)?;
                consume(env, 1)?;
                vec![chain, fallback, RuntimeValue::Scalar(json!(succeeded))]
            }
            "chain.pop" => {
                let head = self.consume_chain(get(0)?)?;
                let (tail, payload, present) = if let Some(id) = head {
                    let node = self.nodes.remove(&id).ok_or(Halt::Internal)?;
                    self.drop_bytes(node.storage)?;
                    self.chain_nodes_dropped += 1;
                    (self.new_chain(node.tail), RuntimeValue::Owner(node.payload), true)
                } else {
                    let tail = self.new_chain(None);
                    (tail, self.new_owner(Vec::new()), false)
                };
                consume(env, 0)?;
                vec![tail, payload, RuntimeValue::Scalar(json!(present))]
            }
            "chain.is_empty" => vec![RuntimeValue::Scalar(json!(self.chain_head(get(0)?)?.is_none()))],
            "chain.head_read" | "chain.head_mut" =>
                vec![self.borrow(get(0)?, opcode == "chain.head_mut", true)?],
            "borrow.read" | "borrow.mut" =>
                vec![self.borrow(get(0)?, opcode == "borrow.mut", false)?],
            "loan.end" => {
                let RuntimeValue::View { id, .. } = get(0)? else { return Err(Halt::Internal); };
                self.root(get(0)?)?;
                if self.loans.get(id).ok_or(Halt::Internal)?.external
                    || self.loans.values().any(|l| l.parent == Parent::View(*id)) {
                    return Err(Halt::Internal);
                }
                self.loans.remove(id).ok_or(Halt::Internal)?;
                self.loans_ended += 1;
                consume(env, 0)?;
                vec![]
            }
            "owner.move" => {
                self.free_owner(get(0)?)?;
                consume(env, 0)?;
                vec![get(0)?.clone()]
            }
            "owner.drop" => {
                match self.free_owner(get(0)?)? {
                    Root::Owner(id) => self.drop_bytes(id)?,
                    Root::Chain(_) => self.drop_chain(get(0)?)?,
                }
                consume(env, 0)?;
                vec![]
            }
            "buffer.load" | "buffer.store" => {
                let root = self.access(get(0)?, opcode == "buffer.store")?;
                let index = integer(get(1)?)?;
                let bytes = self.owners.get_mut(&root).ok_or(Halt::Internal)?;
                if index >= bytes.len() as u64 { return Err(Halt::Trap("bounds")); }
                if opcode == "buffer.store" {
                    bytes[index as usize] = u8::try_from(integer(get(2)?)?).map_err(|_| Halt::Internal)?;
                    vec![]
                } else {
                    vec![RuntimeValue::Scalar(json!(bytes[index as usize]))]
                }
            }
            "buffer.fill" | "buffer.fill_range" => {
                let storage = self.access(get(0)?, true)?;
                let bytes = self.owners.get_mut(&storage).ok_or(Halt::Internal)?;
                let (range, byte) = if opcode == "buffer.fill" {
                    (0..bytes.len(), integer(get(1)?)?)
                } else {
                    (Self::range(bytes.len(), integer(get(1)?)?, integer(get(2)?)?)?,
                     integer(get(3)?)?)
                };
                bytes[range].fill(u8::try_from(byte).map_err(|_| Halt::Internal)?);
                vec![]
            }
            "buffer.copy" | "buffer.copy_range" => {
                let destination = self.access(get(0)?, true)?;
                let source = self.access(get(1)?, false)?;
                if self.root(get(0)?)? == self.root(get(1)?)? { return Err(Halt::Internal); }
                let (dst_offset, src_offset, size) = if opcode == "buffer.copy" {
                    (0, 0, integer(get(2)?)?)
                } else { (integer(get(2)?)?, integer(get(3)?)?, integer(get(4)?)?) };
                self.copy_bytes(destination, source, dst_offset, src_offset, size)?;
                vec![]
            }
            "buffer.move_within" => {
                let storage = self.access(get(0)?, true)?;
                let bytes = self.owners.get_mut(&storage).ok_or(Halt::Internal)?;
                let (dst, src, size) = (integer(get(1)?)?, integer(get(2)?)?, integer(get(3)?)?);
                let dst = Self::range(bytes.len(), dst, size)?;
                let src = Self::range(bytes.len(), src, size)?;
                // copy_within is overlap-safe without allocating a temporary.
                bytes.copy_within(src, dst.start);
                vec![]
            }
            "buffer.swap" => {
                let storage = self.access(get(0)?, true)?;
                let bytes = self.owners.get_mut(&storage).ok_or(Halt::Internal)?;
                let (left, right) = (integer(get(1)?)?, integer(get(2)?)?);
                if left >= bytes.len() as u64 || right >= bytes.len() as u64 {
                    return Err(Halt::Trap("bounds"));
                }
                bytes.swap(left as usize, right as usize);
                vec![]
            }
            "call" => {
                let name = op["attrs"]["function"].as_str().ok_or(Halt::Internal)?;
                let callee = *self.functions.get(name).ok_or(Halt::Internal)?;
                for (n, param) in callee["params"].as_array().ok_or(Halt::Internal)?.iter().enumerate() {
                    if matches!(param["type"].as_str(), Some("buffer" | "chain")) {
                        self.free_owner(get(n)?)?;
                        consume(env, n)?;
                    }
                }
                self.invoke(name, operands, depth + 1)?
            }
            _ => {
                // Share the independent Rust scalar arithmetic semantics,
                // never the Python VM. Verification has already checked the
                // declared ISA in the whole module, including dead callees.
                let values = operands.iter().map(|v| scalar(v).cloned()).collect::<Exec<Vec<_>>>()?;
                opcode_results(op, &values)?.into_iter().map(RuntimeValue::Scalar).collect()
            }
        };
        let params = op["out"].as_array().ok_or(Halt::Internal)?;
        if outputs.len() != params.len() { return Err(Halt::Internal); }
        for (param, value) in params.iter().zip(outputs) {
            if let RuntimeValue::Scalar(ref v) = value {
                if !param["type"].as_str().is_some_and(|ty| valid_constant(ty, v)) {
                    return Err(Halt::Internal);
                }
            }
            env.insert(param["name"].as_str().ok_or(Halt::Internal)?.into(), value);
        }
        Ok(())
    }

    fn invoke(&mut self, name: &str, args: Vec<RuntimeValue>, depth: u32)
        -> Exec<Vec<RuntimeValue>> {
        if depth >= MAX_CALL_DEPTH { return Err(Halt::Budget("calls")); }
        self.tick()?;
        let function = *self.functions.get(name).ok_or(Halt::Internal)?;
        let blocks = function["blocks"].as_array().ok_or(Halt::Internal)?;
        let by_name: BTreeMap<&str, &Value> = blocks.iter()
            .map(|b| (b["id"].as_str().unwrap_or(""), b)).collect();
        let mut current = function["entry"].as_str().ok_or(Halt::Internal)?;
        let (mut env, formals) = self.enter_call(&function["params"], args)?;
        loop {
            let block = *by_name.get(current).ok_or(Halt::Internal)?;
            for op in block["ops"].as_array().ok_or(Halt::Internal)? {
                self.tick()?;
                self.operation(op, &mut env, depth)?;
            }
            self.tick()?;
            let term = &block["term"];
            match term["op"].as_str().ok_or(Halt::Internal)? {
                "ret" => {
                    let values = resolve(&env, &term["values"])?;
                    self.leave_call(&formals)?;
                    return Ok(values);
                }
                "trap" => return Err(Halt::Trap(match term["code"].as_str() {
                    Some("user") => "user", Some("overflow") => "overflow",
                    Some("division_by_zero") => "division_by_zero",
                    Some("bounds") => "bounds", Some("allocation") => "allocation",
                    _ => return Err(Halt::Internal),
                })),
                "jump" | "branch" => {
                    let edge = if term["op"] == "jump" { term }
                        else if scalar(&lookup(&env, &term["cond"])?)?.as_bool().ok_or(Halt::Internal)? {
                            &term["then"]
                        } else { &term["else"] };
                    let values = resolve(&env, &edge["args"])?;
                    current = edge["target"].as_str().ok_or(Halt::Internal)?;
                    // Snapshot all arguments before rebinding any phi slot.
                    env = bind(&by_name.get(current).ok_or(Halt::Internal)?["params"], values)?;
                }
                _ => return Err(Halt::Internal),
            }
        }
    }

    fn resources(&self) -> Value {
        let mut result = json!({"allocations": self.allocations, "frees": self.frees,
            "allocation_attempts": self.allocation_attempts,
            "owners_created": self.owner_count, "owners_dropped": self.drops,
            "live_owners": self.owners.len(), "live_bytes": self.live_bytes,
            "peak_bytes": self.peak_bytes, "loans_started": self.loans_started,
            "loans_ended": self.loans_ended,
            "live_local_loans": self.loans.values().filter(|loan| !loan.external).count()});
        // Old input profiles retain their original byte-resource ledger.
        if self.recursive_chain {
            result["chains_created"] = json!(self.chains_created);
            result["chains_consumed"] = json!(self.chains_consumed);
            result["live_chains"] = json!(self.chains.len());
            result["chain_nodes_created"] = json!(self.chain_nodes_created);
            result["chain_nodes_dropped"] = json!(self.chain_nodes_dropped);
            result["live_chain_nodes"] = json!(self.nodes.len());
        }
        result
    }
}

/// Execute an independently verified, closed v1-v7 resource program.
/// This finite oracle is not a proof or an alternative production verifier.
/// Core traps/budget stops retain their stopped logical resource state;
/// Rust releasing oracle host memory is not represented as program cleanup.
pub fn execute_owned(input: &[u8], function: &str, arguments: &[Value],
                     options: OwnedOptions) -> R<Value> {
    if !(1..=MAX_STEPS).contains(&options.max_steps)
        || options.max_heap_bytes > MAX_HEAP_BYTES
        || options.allocation_fail_at == Some(0) {
        return failure("E_HIA_BUDGET_POLICY", "owned oracle options outside finite limits");
    }
    let (document, _) = decode_hia(input)?;
    // An explicit closed version list: neither unknown versions nor nominal
    // inputs inherit primitive execution authority from a similar entry body.
    if !matches!(document["schema"].as_str(), Some(
        "hepta.hia.program.v1" | "hepta.hia.program.v2" | "hepta.hia.program.v3" |
        "hepta.hia.program.v4" | "hepta.hia.program.v5" | "hepta.hia.program.v6" |
        "hepta.hia.program.v7"
    )) {
        return failure("E_HIA_RUST_UNSUPPORTED", "owned execution supports primitive HIA v1-v7");
    }
    let verification = verify_owned(input)?;
    let functions = document["functions"].as_array().ok_or_else(|| super::VerifyError {
        code: "E_HIA_FORMAT", detail: "missing verified function inventory".into(),
    })?;
    let by_name: BTreeMap<&str, &Value> = functions.iter()
        .map(|f| (f["name"].as_str().unwrap_or(""), f)).collect();
    let Some(entry) = by_name.get(function) else {
        return failure("E_HIA_INPUT", "unknown owned-oracle entry");
    };
    if document.get("exports").is_some_and(|exports| {
        !exports.as_array().is_some_and(|values| values.iter().any(|v| v.as_str() == Some(function)))
    }) {
        return failure("E_HIA_INPUT", "function is not an exported scalar entry");
    }
    let params = entry["params"].as_array().ok_or_else(|| super::VerifyError {
        code: "E_HIA_INPUT", detail: "invalid entry signature".into(),
    })?;
    if params.len() != arguments.len() || params.iter().zip(arguments).any(|(p, v)| {
        !p["type"].as_str().is_some_and(|ty| valid_constant(ty, v))
    }) || entry["returns"].as_array().is_none_or(|types| types.iter().any(|ty| {
        matches!(ty.as_str(), Some("buffer" | "readbuf" | "mutbuf" | "chain"))
    })) {
        return failure("E_HIA_INPUT", "public entry must use exactly typed scalar arguments and returns");
    }
    let mut machine = Machine::new(by_name, options, document["schema"] == "hepta.hia.program.v7");
    let args = arguments.iter().cloned().map(RuntimeValue::Scalar).collect();
    let result = machine.invoke(function, args, 0);
    let mut report = json!({
        "schema": "hepta.hia.rust-owned-execution.v2", "status": "unknown",
        "program_schema": document["schema"],
        "function": function, "program_sha256": verification["program_sha256"],
        "steps": machine.steps, "max_steps": machine.options.max_steps,
        "max_call_depth": MAX_CALL_DEPTH, "max_heap_bytes": machine.options.max_heap_bytes,
        "resources": machine.resources(), "word_bits": 64,
        "claims": {"finite_primitive_resource_execution": true,
            "primitive_v1_v7_resource_execution": true,
            "recursive_buffer_chains_supported": true, "source_replayed": false,
            "production_admission_authorized": false, "whole_language_soundness_proved": false,
            "general_memory_provenance_proved": false, "native_backend_refinement_proved": false,
            "abi_or_hardware_qualified": false}
    });
    match result {
        Ok(values) => {
            if !machine.owners.is_empty() || !machine.loans.is_empty()
                || !machine.chains.is_empty() || !machine.nodes.is_empty() {
                return failure("E_HIA_RUST_RUNTIME", "successful scalar entry retained owner/chain/loan state");
            }
            let scalars = values.iter().map(|v| scalar(v).cloned()).collect::<Exec<Vec<_>>>()
                .map_err(|_| super::VerifyError { code: "E_HIA_RUST_RUNTIME",
                    detail: "resource escaped scalar entry".into() })?;
            report["status"] = json!("returned");
            report["values"] = json!(scalars);
        }
        Err(Halt::Trap(code)) => {
            report["status"] = json!("trapped");
            report["error"] = json!({"code": code});
        }
        Err(Halt::Budget(code)) => {
            report["status"] = json!("budget_exceeded");
            report["error"] = json!({"code": code});
        }
        Err(Halt::Internal) => return failure("E_HIA_RUST_RUNTIME", "resource oracle invariant failed"),
    }
    Ok(report)
}
