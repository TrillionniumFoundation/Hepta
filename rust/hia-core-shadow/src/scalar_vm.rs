//! Independent, bounded HIA execution oracle with explicit finite profiles.
//! IMPORTANT: this is a development shadow, NOT native final-use authorization.
//! Scalar mode retains its resource-free ISA. The opt-in byte-owner mode uses
//! the existing Owner/Loan verifier plus a whole-module execution whitelist.
use std::collections::BTreeMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use super::{decode_hia, failure, int_bits, valid_constant, verify, verify_owned, R};

mod byte_memory;
use byte_memory::ByteMemory;

const MAX_STEPS: u64 = 1_000_000;
const MAX_CALL_DEPTH: u32 = 32;
const MAX_OWNED_HEAP_BYTES: u64 = 16 * 1024 * 1024;
const V3_MAX_STEPS: u64 = 10_000_000;
const V3_MAX_CALL_DEPTH: u32 = 256;
const V3_MAX_OWNED_HEAP_BYTES: u64 = 1024 * 1024 * 1024;

// Failure injection only compares a positive integer with the allocation
// counter; no big-integer arithmetic is needed. Wide retains every canonical
// hexadecimal digit and denotes an integer strictly greater than u64::MAX.
// It is not the absent-injection policy and is never clamped or truncated.
#[derive(Clone)]
enum AllocationFailureIndex {
    Word(u64),
    Wide(String),
}

impl AllocationFailureIndex {
    fn from_hex(value: &Value) -> R<Self> {
        let Some(encoded) = value.as_str() else {
            return failure("E_HIA_BUDGET_POLICY", "v4 failure index must be null or canonical positive hex");
        };
        let Some(digits) = encoded.strip_prefix("0x") else {
            return failure("E_HIA_BUDGET_POLICY", "v4 failure index requires lowercase 0x prefix");
        };
        if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        }) {
            return failure("E_HIA_BUDGET_POLICY", "v4 failure index must be positive canonical lowercase hex");
        }
        if digits.len() <= 16 {
            u64::from_str_radix(digits, 16).map(Self::Word).map_err(|_| super::VerifyError {
                code: "E_HIA_BUDGET_POLICY", detail: "invalid hexadecimal failure index".into(),
            })
        } else {
            Ok(Self::Wide(encoded.to_owned()))
        }
    }

    fn equals_counter(&self, attempt: u64) -> bool {
        match self {
            Self::Word(index) => *index == attempt,
            // Canonical positive values with more than 16 hex digits are
            // strictly above every u64 counter value. This is exact integer
            // equality, not a replacement by None or a budget projection.
            Self::Wide(_) => false,
        }
    }

    fn report_value(&self) -> Value {
        match self {
            Self::Word(index) => json!(index),
            Self::Wide(encoded) => json!(encoded),
        }
    }
}

#[derive(Debug)]
enum Halt {
    Trap(&'static str),
    Budget(&'static str),
    Internal,
}
type Exec<T> = Result<T, Halt>;

// Capabilities never cross the public JSON argument/result boundary. Cloning
// an internal handle while reading operands does not duplicate language
// ownership: the existing verifier checks linear use and consumed SSA names
// are removed after the corresponding operation succeeds.
#[derive(Clone)]
enum RuntimeValue {
    Scalar(Value),
    Owner(u64),
    Loan(u64),
    Chain(u64),
}
impl RuntimeValue {
    fn scalar(&self) -> Exec<&Value> {
        match self { Self::Scalar(value) => Ok(value), _ => Err(Halt::Internal) }
    }
}

fn integer(v: &Value) -> Exec<i128> {
    v.as_i64().map(i128::from)
        .or_else(|| v.as_u64().map(i128::from))
        .ok_or(Halt::Internal)
}
fn typed_integer(value: i128, ty: &str, wrapping: bool) -> Exec<Value> {
    let Some((signed, width)) = int_bits(ty) else { return Err(Halt::Internal); };
    let n = if wrapping {
        let mask = (1_i128 << width) - 1;
        let word = value & mask;
        if signed && word >= (1_i128 << (width - 1)) {
            word - (1_i128 << width)
        } else { word }
    } else {
        let (low, high) = if signed {
            (-(1_i128 << (width - 1)), (1_i128 << (width - 1)) - 1)
        } else { (0, (1_i128 << width) - 1) };
        if value < low || value > high {
            return Err(Halt::Trap("overflow"));
        }
        value
    };
    if signed {
        let bounded = i64::try_from(n).map_err(|_| Halt::Internal)?;
        Ok(Value::Number(bounded.into()))
    } else {
        let bounded = u64::try_from(n).map_err(|_| Halt::Internal)?;
        Ok(Value::Number(bounded.into()))
    }
}
fn boolean(v: &Value) -> Exec<bool> { v.as_bool().ok_or(Halt::Internal) }
fn elem<'a>(a: &'a [Value], index: usize) -> Exec<&'a Value> {
    a.get(index).ok_or(Halt::Internal)
}
fn binary(a: &[Value]) -> Exec<(i128, i128)> {
    Ok((integer(elem(a, 0)?)?, integer(elem(a, 1)?)?))
}
fn opcode_results(v: &Value, values: &[Value]) -> Exec<Vec<Value>> {
    let opcode = v["op"].as_str().ok_or(Halt::Internal)?;
    let outputs = v["out"].as_array().ok_or(Halt::Internal)?;
    let ty = outputs.first().and_then(|x| x["type"].as_str()).unwrap_or("unit");
    let attrs = &v["attrs"];
    let result = match opcode {
        "const" => vec![attrs.get("value").ok_or(Halt::Internal)?.clone()],
        "int.add.checked" | "int.sub.checked" | "int.mul.checked"
        | "int.add.wrap" | "int.sub.wrap" | "int.mul.wrap" => {
            let (a, b) = binary(values)?;
            let operation = opcode.split('.').nth(1).ok_or(Halt::Internal)?;
            let product = match operation {
                "add" => Some(a + b),
                "sub" => Some(a - b),
                "mul" => a.checked_mul(b),
                _ => None,
            };
            let wrap = opcode.ends_with(".wrap");
            let n = match product {
                Some(n) => n,
                None if wrap => a.wrapping_mul(b),
                None => return Err(Halt::Trap("overflow")),
            };
            vec![typed_integer(n, ty, wrap)?]
        }
        "int.div.checked" | "int.rem.checked" => {
            let (a, b) = binary(values)?;
            if b == 0 { return Err(Halt::Trap("division_by_zero")); }
            // The HIA ISA traps signed MIN / -1 for BOTH quotient and
            // remainder. Computing the remainder in i128 would otherwise
            // yield zero and silently disagree with Python and native LLVM.
            let (signed, width) = int_bits(ty).ok_or(Halt::Internal)?;
            if signed && a == -(1_i128 << (width - 1)) && b == -1 {
                return Err(Halt::Trap("overflow"));
            }
            let quotient = a / b; // i128 division truncates toward zero.
            let n = if opcode == "int.div.checked" { quotient } else { a - quotient * b };
            vec![typed_integer(n, ty, false)?]
        }
        "int.shl.checked" | "int.shr.checked" => {
            let (a, b) = binary(values)?;
            let width = int_bits(ty).ok_or(Halt::Internal)?.1;
            if b < 0 || b >= i128::from(width) { return Err(Halt::Trap("overflow")); }
            let n = if opcode == "int.shl.checked" { a << (b as u32) }
                    else { a >> (b as u32) };
            vec![typed_integer(n, ty, opcode == "int.shl.checked")?]
        }
        "int.neg.checked" => {
            vec![typed_integer(-integer(elem(values, 0)?)?, ty, false)?]
        }
        "bit.and" | "bit.or" | "bit.xor" => {
            let (a, b) = binary(values)?;
            let n = match opcode {
                "bit.and" => a & b, "bit.or" => a | b, _ => a ^ b,
            };
            vec![typed_integer(n, ty, true)?]
        }
        "bit.not" => vec![typed_integer(!integer(elem(values, 0)?)?, ty, true)?],
        "compare.eq" | "compare.ne" => {
            let a = elem(values, 0)?;
            let b = elem(values, 1)?;
            vec![Value::Bool(if opcode == "compare.eq" { a == b } else { a != b })]
        }
        "compare.lt" | "compare.le" | "compare.gt" | "compare.ge" => {
            let (a, b) = binary(values)?;
            let yes = match opcode {
                "compare.lt" => a < b, "compare.le" => a <= b,
                "compare.gt" => a > b, _ => a >= b,
            };
            vec![Value::Bool(yes)]
        }
        "bool.not" => vec![Value::Bool(!boolean(elem(values, 0)?)?)],
        "bool.and" | "bool.or" => {
            let a = boolean(elem(values, 0)?)?;
            let b = boolean(elem(values, 1)?)?;
            vec![Value::Bool(if opcode == "bool.and" { a && b } else { a || b })]
        }
        "int.cast" => {
            let n = integer(elem(values, 0)?)?;
            let mode = attrs["mode"].as_str().ok_or(Halt::Internal)?;
            vec![typed_integer(n, ty, mode == "wrap")?]
        }
        "select" => {
            let chosen = if boolean(elem(values, 0)?)? { 1 } else { 2 };
            vec![elem(values, chosen)?.clone()]
        }
        _ => return Err(Halt::Internal),
    };
    if result.len() != outputs.len() {
        return Err(Halt::Internal);
    }
    if result.iter().zip(outputs).any(|(value, out)| {
        !out["type"].as_str().is_some_and(|t| valid_constant(t, value))
    }) {
        return Err(Halt::Internal);
    }
    Ok(result)
}
fn lookup(env: &BTreeMap<String, RuntimeValue>, name: &Value) -> Exec<RuntimeValue> {
    env.get(name.as_str().ok_or(Halt::Internal)?)
        .cloned().ok_or(Halt::Internal)
}
fn resolve(env: &BTreeMap<String, RuntimeValue>, names: &Value) -> Exec<Vec<RuntimeValue>> {
    names.as_array().ok_or(Halt::Internal)?
        .iter().map(|v| lookup(env, v)).collect()
}
fn bind(params: &Value, values: Vec<RuntimeValue>) -> Exec<BTreeMap<String, RuntimeValue>> {
    let params = params.as_array().ok_or(Halt::Internal)?;
    if params.len() != values.len() { return Err(Halt::Internal); }
    let mut env = BTreeMap::new();
    for (param, value) in params.iter().zip(values) {
        env.insert(param["name"].as_str().ok_or(Halt::Internal)?.to_owned(), value);
    }
    Ok(env)
}
struct Machine<'a> {
    functions: BTreeMap<&'a str, &'a Value>,
    steps: u64,
    limit: u64,
    max_call_depth: u32,
    memory: Option<ByteMemory>,
}
// Language calls live in an explicit stack. A larger language depth must not
// consume one Rust host frame per call, including in unoptimized/test builds.
// Dropping a suspended frame only drops handles: stopped execution retains
// the actual owners, loans and chain nodes in the Machine's one memory ledger.
struct Frame<'a> {
    function: &'a Value,
    blocks: BTreeMap<&'a str, &'a Value>,
    current: &'a str,
    next_operation: usize,
    env: BTreeMap<String, RuntimeValue>,
    formals: Vec<u64>,
    return_bindings: BTreeMap<&'a str, RuntimeValue>,
    pending_call: Option<&'a Value>,
}
impl<'a> Machine<'a> {
    fn tick(&mut self) -> Exec<()> {
        self.steps += 1;
        if self.steps > self.limit { Err(Halt::Budget("steps")) } else { Ok(()) }
    }
    fn enter_frame(&mut self, name: &str, args: Vec<RuntimeValue>, depth: usize) -> Exec<Frame<'a>> {
        // Canonical Python uses a zero-based depth and a root-inclusive
        // frame limit: depth >= max_call_depth rejects BEFORE its entry tick.
        // The legacy policy admits exactly 32 frames (depth 0..31), not 33.
        // All versioned policies use the same entry and lifecycle rules.
        if depth >= self.max_call_depth as usize { return Err(Halt::Budget("calls")); }
        // Copy the lifetime-qualified reference, never clone an 8 MiB function
        // at each recursive call. The source document lives for this Machine.
        let function: &'a Value = *self.functions.get(name).ok_or(Halt::Internal)?;
        self.tick()?; // one call-entry tick, same convention as Python VM.
        let blocks = function["blocks"].as_array().ok_or(Halt::Internal)?;
        let by_name: BTreeMap<&str, &Value> = blocks.iter()
            .map(|b| (b["id"].as_str().unwrap_or(""), b)).collect();
        let current = function["entry"].as_str().ok_or(Halt::Internal)?;
        let (args, formals) = if let Some(memory) = self.memory.as_mut() {
            memory.enter_call(&function["params"], args)?
        } else { (args, Vec::new()) };
        let return_bindings: BTreeMap<&str, RuntimeValue> = if function["returns"]
            .as_array().ok_or(Halt::Internal)?.iter()
            .any(|ty| matches!(ty.as_str(), Some("readbuf" | "mutbuf"))) {
            function["params"].as_array().ok_or(Halt::Internal)?.iter().zip(&args)
                .filter(|(p, _)| matches!(p["type"].as_str(), Some("readbuf" | "mutbuf")))
                .map(|(p, value)| Ok((p["name"].as_str().ok_or(Halt::Internal)?, value.clone())))
                .collect::<Exec<_>>()?
        } else { BTreeMap::new() };
        let env = bind(&function["params"], args)?;
        Ok(Frame { function, blocks: by_name, current, next_operation: 0,
            env, formals, return_bindings, pending_call: None })
    }

    fn finish_operation(&self, frame: &mut Frame<'a>, op: &Value,
                        outputs: Vec<RuntimeValue>) -> Exec<()> {
        let op_name = op["op"].as_str().ok_or(Halt::Internal)?;
        let parameters = op["out"].as_array().ok_or(Halt::Internal)?;
        if parameters.len() != outputs.len() { return Err(Halt::Internal); }
        if matches!(op_name, "owner.move" | "owner.drop" | "loan.end") {
            let consumed = op["args"][0].as_str().ok_or(Halt::Internal)?;
            frame.env.remove(consumed).ok_or(Halt::Internal)?;
        }
        if matches!(op_name, "chain.try_push" | "chain.pop") {
            for name in op["args"].as_array().ok_or(Halt::Internal)? {
                frame.env.remove(name.as_str().ok_or(Halt::Internal)?).ok_or(Halt::Internal)?;
            }
        }
        for (parameter, value) in parameters.iter().zip(outputs) {
            let ty = parameter["type"].as_str().ok_or(Halt::Internal)?;
            match &value {
                RuntimeValue::Scalar(v) if valid_constant(ty, v) => {}
                RuntimeValue::Owner(_) if ty == "buffer" => {}
                RuntimeValue::Chain(id) if ty == "chain" && self.memory.as_ref()
                    .is_some_and(|m| m.live_chain(*id)) => {}
                RuntimeValue::Loan(id) if self.memory.as_ref()
                    .is_some_and(|m| m.loan_type(*id) == Some(ty)) => {}
                _ => return Err(Halt::Internal),
            }
            frame.env.insert(parameter["name"].as_str().ok_or(Halt::Internal)?.into(), value);
        }
        Ok(())
    }

    fn invoke(&mut self, name: &str, args: Vec<RuntimeValue>) -> Exec<Vec<RuntimeValue>> {
        let mut frame = self.enter_frame(name, args, 0)?;
        let mut suspended: Vec<Frame<'a>> = Vec::new();
        loop {
            let block = *frame.blocks.get(frame.current).ok_or(Halt::Internal)?;
            let operations = block["ops"].as_array().ok_or(Halt::Internal)?;
            if let Some(op) = operations.get(frame.next_operation) {
                self.tick()?;
                frame.next_operation += 1;
                let op_name = op["op"].as_str().ok_or(Halt::Internal)?;
                let operands = resolve(&frame.env, &op["args"])?;
                if op_name == "call" {
                    let callee = op["attrs"]["function"].as_str().ok_or(Halt::Internal)?;
                    // Transfer owning arguments before entering the callee,
                    // exactly as the canonical VM does. Borrowed arguments
                    // remain live in the caller and keep their runtime root.
                    // A trapped/budget-stopped call never fabricates cleanup.
                    for (name, value) in op["args"].as_array().ok_or(Halt::Internal)?
                        .iter().zip(&operands) {
                        if matches!(value, RuntimeValue::Owner(_) | RuntimeValue::Chain(_)) {
                            frame.env.remove(name.as_str().ok_or(Halt::Internal)?)
                                .ok_or(Halt::Internal)?;
                        }
                    }
                    let child = self.enter_frame(callee, operands, suspended.len() + 1)?;
                    frame.pending_call = Some(op);
                    suspended.push(frame);
                    frame = child;
                    continue;
                }
                let outputs = if op_name == "owner.drop" && matches!(operands.first(), Some(RuntimeValue::Chain(_))) {
                    // Canonical destruction consumes the chain descriptor
                    // before ticking once for each node. A stopped destructor
                    // retains the remaining byte owners/nodes in the ledger.
                    let mut node = self.memory.as_mut().ok_or(Halt::Internal)?
                        .begin_chain_drop(&operands[0])?;
                    while let Some(id) = node {
                        self.tick()?;
                        node = self.memory.as_mut().ok_or(Halt::Internal)?.drop_chain_node(id)?;
                    }
                    vec![]
                } else if ByteMemory::supports(op_name) {
                    self.memory.as_mut().ok_or(Halt::Internal)?.operation(op_name, &operands)?
                } else {
                    let scalars = operands.iter().map(|v| v.scalar().cloned())
                        .collect::<Exec<Vec<_>>>()?;
                    opcode_results(op, &scalars)?.into_iter().map(RuntimeValue::Scalar).collect()
                };
                self.finish_operation(&mut frame, op, outputs)?;
                continue;
            }
            self.tick()?;
            let term = &block["term"];
            match term["op"].as_str().ok_or(Halt::Internal)? {
                "ret" => {
                    let mut values = resolve(&frame.env, &term["values"])?;
                    if !frame.return_bindings.is_empty() {
                        let origins = frame.function["return_loans"].as_array().ok_or(Halt::Internal)?;
                        for ((ty, origin), value) in frame.function["returns"].as_array()
                            .ok_or(Halt::Internal)?.iter().zip(origins).zip(&mut values) {
                            if matches!(ty.as_str(), Some("readbuf" | "mutbuf")) {
                                let parent = frame.return_bindings.get(origin.as_str().ok_or(Halt::Internal)?)
                                    .ok_or(Halt::Internal)?;
                                *value = self.memory.as_mut().ok_or(Halt::Internal)?
                                    .return_loan(value, parent, ty == "mutbuf")?;
                            }
                        }
                    }
                    if let Some(memory) = self.memory.as_mut() {
                        memory.leave_call(&frame.formals)?;
                    }
                    let Some(mut caller) = suspended.pop() else { return Ok(values); };
                    let call = caller.pending_call.take().ok_or(Halt::Internal)?;
                    self.finish_operation(&mut caller, call, values)?;
                    frame = caller;
                }
                "trap" => {
                    let code = term["code"].as_str().ok_or(Halt::Internal)?;
                    return match code {
                        "user" => Err(Halt::Trap("user")),
                        "overflow" => Err(Halt::Trap("overflow")),
                        "division_by_zero" => Err(Halt::Trap("division_by_zero")),
                        "bounds" => Err(Halt::Trap("bounds")),
                        "allocation" => Err(Halt::Trap("allocation")),
                        _ => Err(Halt::Internal),
                    };
                }
                "jump" | "branch" => {
                    let edge = if term["op"] == "jump" { term }
                        else if boolean(lookup(&frame.env, &term["cond"])?.scalar()?)? {
                            &term["then"]
                        } else { &term["else"] };
                    let values = resolve(&frame.env, &edge["args"])?;
                    let target = edge["target"].as_str().ok_or(Halt::Internal)?;
                    let destination = *frame.blocks.get(target).ok_or(Halt::Internal)?;
                    // Simultaneously assign all block arguments, including
                    // loop backedge values. No stale SSA values can leak in.
                    frame.env = bind(&destination["params"], values)?;
                    frame.current = target;
                    frame.next_operation = 0;
                }
                _ => return Err(Halt::Internal),
            }
        }
    }
}
/// Finite Rust interpreter for independently verified scalar HIA programs.
/// The canonical Python verifier remains mandatory for production admission.
/// This is NOT an alternative native final-use authorization or refinement proof.
pub fn execute_scalar(input: &[u8], function: &str, arguments: &[Value],
                      max_steps: u64) -> R<Value> {
    execute(input, function, arguments, max_steps, None, MAX_CALL_DEPTH, MAX_STEPS)
}

/// Opt-in finite byte-owner execution in the SAME Machine as scalar execution.
/// Verified CFG/loops and internal scalar/owner/loan calls share one ledger.
/// Public entry/return remains scalar. v7/v8 chains, bulk operations and v8
/// parameter-bound loan returns share one ledger and one execution Machine.
/// Static ownership admission still comes from the existing verify_owned.
pub fn execute_owned(input: &[u8], function: &str, arguments: &[Value],
                     max_steps: u64, max_heap_bytes: u64,
                     allocation_fail_at: Option<u64>) -> R<Value> {
    if max_heap_bytes > MAX_OWNED_HEAP_BYTES || allocation_fail_at == Some(0) {
        return failure("E_HIA_BUDGET_POLICY", "owned heap/failure policy outside finite profile");
    }
    execute(input, function, arguments, max_steps,
            Some((max_heap_bytes, allocation_fail_at.map(AllocationFailureIndex::Word))),
            MAX_CALL_DEPTH, MAX_STEPS)
}

/// Bind one actual independent execution to its complete caller request.
///
/// This opt-in transport envelope uses the SAME verifier and Machine as
/// execute_owned. Legacy execution reports are unchanged. The hash binds
/// canonical Core, entry, scalar arguments and all finite execution limits;
/// it authenticates neither the binary nor a third-party report producer.
pub fn execute_owned_bound(input: &[u8], function: &str, arguments: &[Value],
                           max_steps: u64, max_heap_bytes: u64,
                           allocation_fail_at: Option<u64>) -> R<Value> {
    check_bound_arguments(arguments)?;
    let execution = execute_owned(input, function, arguments, max_steps,
                                  max_heap_bytes, allocation_fail_at)?;
    bind_execution(execution, function, arguments, max_heap_bytes, json!(allocation_fail_at), 1)
}

/// Explicit bounded policy for the same Machine; no legacy policy upgrade.
/// All four JSON policy fields are mandatory, with exact integer/null types.
/// The existing bounded/duplicate-safe decoder runs before any VM execution.
pub fn execute_owned_bound_v2(input: &[u8], function: &str, arguments: &[Value],
                              policy_input: &[u8]) -> R<Value> {
    execute_owned_bound_policy(input, function, arguments, policy_input, 2,
        MAX_STEPS, MAX_OWNED_HEAP_BYTES, MAX_CALL_DEPTH)
}

/// Opt-in production-sized evaluator budgets on the same explicit-frame
/// Machine. This does not grant production admission or upgrade v1/v2 limits.
pub fn execute_owned_bound_v3(input: &[u8], function: &str, arguments: &[Value],
                              policy_input: &[u8]) -> R<Value> {
    execute_owned_bound_policy(input, function, arguments, policy_input, 3,
        V3_MAX_STEPS, V3_MAX_OWNED_HEAP_BYTES, V3_MAX_CALL_DEPTH)
}

/// Exact positive failure indices beyond u64, with the same bounded Machine.
/// The v4 wire uses canonical hexadecimal strings and keeps the finite policy
/// byte limit. Legacy v1/v2/v3 integer policies and report shapes are unchanged.
pub fn execute_owned_bound_v4(input: &[u8], function: &str, arguments: &[Value],
                              policy_input: &[u8]) -> R<Value> {
    execute_owned_bound_policy(input, function, arguments, policy_input, 4,
        V3_MAX_STEPS, V3_MAX_OWNED_HEAP_BYTES, V3_MAX_CALL_DEPTH)
}

fn execute_owned_bound_policy(input: &[u8], function: &str, arguments: &[Value],
                              policy_input: &[u8], version: u8,
                              step_ceiling: u64, heap_ceiling: u64,
                              depth_ceiling: u32) -> R<Value> {
    const MAX_POLICY_BYTES: usize = 1024;
    if policy_input.len() > MAX_POLICY_BYTES {
        return failure("E_HIA_BUDGET_POLICY", format!("bound v{version} policy exceeds 1024 bytes"));
    }
    let (policy, _) = decode_hia(policy_input)?;
    let fields = super::object(&policy,
        &["max_steps", "max_heap_bytes", "allocation_fail_at", "max_call_depth"],
        &format!("bound v{version} policy"))?;
    let integer = |name: &str| fields[name].as_u64().ok_or_else(|| super::VerifyError {
        code: "E_HIA_BUDGET_POLICY", detail: format!("{name} must be an exact unsigned integer"),
    });
    let max_steps = integer("max_steps")?;
    let max_heap_bytes = integer("max_heap_bytes")?;
    let max_call_depth = integer("max_call_depth")?;
    let allocation_fail_at = if fields["allocation_fail_at"].is_null() {
        None
    } else if version == 4 {
        Some(AllocationFailureIndex::from_hex(&fields["allocation_fail_at"])?)
    } else {
        Some(AllocationFailureIndex::Word(integer("allocation_fail_at")?))
    };
    if !(1..=step_ceiling).contains(&max_steps) || max_heap_bytes > heap_ceiling
        || !(1..=u64::from(depth_ceiling)).contains(&max_call_depth)
        || matches!(allocation_fail_at.as_ref(), Some(AllocationFailureIndex::Word(0))) {
        return failure("E_HIA_BUDGET_POLICY", format!("bound v{version} policy outside existing finite limits"));
    }
    check_bound_arguments(arguments)?;
    let mut execution = execute(input, function, arguments, max_steps,
        Some((max_heap_bytes, allocation_fail_at)), max_call_depth as u32, step_ceiling)?;
    if version == 4 {
        // The versioned report makes the exact hexadecimal policy type
        // explicit; v1 report consumers are never silently upgraded.
        execution["schema"] = json!("hepta.hia.rust-byte-owner-execution.v2");
        execution["allocation_fail_at"] = fields["allocation_fail_at"].clone();
    }
    bind_execution(execution, function, arguments, max_heap_bytes,
                   fields["allocation_fail_at"].clone(), version)
}

fn check_bound_arguments(arguments: &[Value]) -> R<()> {
    if arguments.len() > super::MAX_SCALAR_ARGS || arguments.iter().any(|value| {
        !matches!(value, Value::Number(_) | Value::Bool(_) | Value::Null)
    }) {
        return failure("E_HIA_INPUT", "bound execution requires bounded scalar arguments");
    }
    let encoded_arguments = serde_json::to_vec(arguments).map_err(|error| super::VerifyError {
        code: "E_HIA_INPUT", detail: error.to_string(),
    })?;
    if encoded_arguments.len() > super::MAX_SCALAR_ARGS_BYTES {
        return failure("E_HIA_INPUT", "bound execution arguments exceed the wire budget");
    }
    Ok(())
}

fn bind_execution(execution: Value, function: &str, arguments: &[Value],
                  max_heap_bytes: u64, allocation_fail_at: Value, version: u8) -> R<Value> {
    let request = json!({
        "schema": format!("hepta.hia.rust-execution-request.v{version}"),
        "program_sha256": execution["program_sha256"],
        "function": function,
        "arguments": arguments,
        "mode": "owned",
        "policy": {
            "max_steps": execution["max_steps"],
            "max_heap_bytes": max_heap_bytes,
            "allocation_fail_at": allocation_fail_at,
            "max_call_depth": execution["max_call_depth"],
        },
    });
    let canonical_request = serde_json::to_vec(&request).map_err(|error| super::VerifyError {
        code: "E_HIA_INPUT", detail: error.to_string(),
    })?;
    Ok(json!({
        "schema": format!("hepta.hia.rust-bound-execution.v{version}"),
        "request_sha256": format!("{:x}", Sha256::digest(canonical_request)),
        "request": request,
        "execution": execution,
    }))
}

fn owned_execution_profile(document: &Value) -> R<bool> {
    // This is an execution capability boundary, not a second verifier. The
    // entire document has already passed verify_owned. Reject an unsupported
    // operation even if a preceding allocation failure/trap would hide it.
    let functions = document["functions"].as_array().ok_or_else(|| super::VerifyError {
        code: "E_HIA_RUST_UNSUPPORTED", detail: "missing function inventory".into(),
    })?;
    // Check every function, including nonexported helpers that this execution
    // would not call. No hidden unsupported signature or opcode suffix can be
    // laundered through an early return, failure injection, or small budget.
    let mut chain = false;
    for function in functions {
        let mut types: Vec<&Value> = function["params"].as_array().unwrap()
            .iter().map(|p| &p["type"]).collect();
        types.extend(function["returns"].as_array().unwrap());
        for block in function["blocks"].as_array().unwrap() {
            types.extend(block["params"].as_array().unwrap().iter().map(|p| &p["type"]));
            if !matches!(block["term"]["op"].as_str(), Some("ret" | "trap" | "jump" | "branch")) {
                return failure("E_HIA_RUST_UNSUPPORTED", "unsupported byte-owner CFG terminator");
            }
            for op in block["ops"].as_array().unwrap() {
                types.extend(op["out"].as_array().unwrap().iter().map(|p| &p["type"]));
                let opcode = op["op"].as_str().unwrap();
                chain |= ByteMemory::chain_operation(opcode);
                let scalar = matches!(opcode,
                    "const" | "int.add.checked" | "int.sub.checked" | "int.mul.checked" |
                    "int.add.wrap" | "int.sub.wrap" | "int.mul.wrap" | "int.div.checked" |
                    "int.rem.checked" | "int.shl.checked" | "int.shr.checked" | "int.neg.checked" |
                    "bit.and" | "bit.or" | "bit.xor" | "bit.not" | "compare.eq" | "compare.ne" |
                    "compare.lt" | "compare.le" | "compare.gt" | "compare.ge" | "bool.not" |
                    "bool.and" | "bool.or" | "int.cast" | "select");
                if !scalar && opcode != "call" && !ByteMemory::supports(opcode) {
                    return failure("E_HIA_RUST_UNSUPPORTED", format!("byte-owner execution refuses {opcode}"));
                }
            }
        }
        for ty in types {
            chain |= ty == "chain";
            if !matches!(ty.as_str(), Some("buffer" | "readbuf" | "mutbuf" | "chain")) {
                super::scalar(ty)?;
            }
        }
    }
    Ok(chain)
}

fn execute(input: &[u8], function: &str, arguments: &[Value], max_steps: u64,
           owned_policy: Option<(u64, Option<AllocationFailureIndex>)>, max_call_depth: u32,
           step_ceiling: u64) -> R<Value> {
    if !(1..=step_ceiling).contains(&max_steps) {
        return failure("E_HIA_BUDGET_POLICY", "max_steps outside bounded Rust oracle profile");
    }
    let verification = if owned_policy.is_some() { verify_owned(input)? } else { verify(input)? };
    let (document, _) = decode_hia(input)?;
    let chain = if owned_policy.is_some() { owned_execution_profile(&document)? } else { false };
    let functions = document["functions"].as_array().ok_or_else(|| super::VerifyError {
        code: "E_HIA_FORMAT", detail: "missing verified function inventory".into(),
    })?;
    let by_name: BTreeMap<&str, &Value> = functions.iter()
        .map(|f| (f["name"].as_str().unwrap_or(""), f)).collect();
    // Full-module verify already checked exact export name/shape/uniqueness.
    // A private scalar helper may be called internally but cannot be
    // invoked directly from the external Rust-shadow entrypoint.
    if let Some(exports) = document.get("exports") {
        let Some(export_list) = exports.as_array() else {
            return failure("E_HIA_INPUT", "malformed explicit scalar exports");
        };
        if !export_list.iter().any(|value| value.as_str() == Some(function)) {
            return failure("E_HIA_INPUT", "function is not an exported scalar entry");
        }
    }
    let Some(entry) = by_name.get(function) else {
        return failure("E_HIA_INPUT", "unknown public scalar entry");
    };
    let Some(parameters) = entry["params"].as_array() else {
        return failure("E_HIA_INPUT", "invalid entry signature");
    };
    // Without an explicit exports list, resource helpers are still internal.
    // Refuse resource results BEFORE running a scalar-argument constructor;
    // a later cleanliness/result check would already have executed its effects.
    if parameters.iter().any(|p| super::scalar(&p["type"]).is_err()) ||
       entry["returns"].as_array().unwrap().iter().any(|ty| super::scalar(ty).is_err()) {
        return failure("E_HIA_INPUT", "public evaluator boundary cannot carry capabilities");
    }
    if parameters.len() != arguments.len() || parameters.iter().zip(arguments).any(|(p, v)| {
        !p["type"].as_str().is_some_and(|ty| valid_constant(ty, v))
    }) {
        return failure("E_HIA_INPUT", "entry arguments do not match exact scalar types");
    }
    let mut machine = Machine { functions: by_name, steps: 0, limit: max_steps, max_call_depth,
        memory: owned_policy.as_ref().map(|(heap, fail)| ByteMemory::new(*heap, fail.clone())) };
    let result = machine.invoke(function,
        arguments.iter().cloned().map(RuntimeValue::Scalar).collect());
    let mut report = json!({
        "schema": "hepta.hia.rust-scalar-execution.v1",
        "status": "unknown",
        "function": function,
        "program_sha256": verification["program_sha256"],
        "steps": machine.steps,
        "max_steps": max_steps,
        "max_call_depth": max_call_depth,
        "claims": {
            "finite_scalar_execution": true,
            "all_owner_and_memory_opcodes_refused": true,
            "production_admission_authorized": false,
            "whole_language_soundness_proved": false,
            "native_backend_refinement_proved": false,
            "abi_or_hardware_qualified": false
        }
    });
    if let Some(memory) = machine.memory.as_ref() {
        report["schema"] = json!("hepta.hia.rust-byte-owner-execution.v1");
        let loan_returns = document["schema"] == "hepta.hia.program.v8";
        report["profile"] = json!(if chain {
            "bounded-cfg-owned-memory-v5"
        } else if loan_returns {
            "bounded-cfg-byte-owner-loan-returns-v4"
        } else { "bounded-cfg-byte-owner-bulk-v3" });
        report["resources"] = memory.report(loan_returns || document["schema"] == "hepta.hia.program.v7");
        report["max_heap_bytes"] = json!(owned_policy.as_ref().unwrap().0);
        report["allocation_fail_at"] = owned_policy.as_ref().unwrap().1.as_ref()
            .map_or(Value::Null, AllocationFailureIndex::report_value);
        report["claims"] = json!({
            "finite_scalar_execution": true,
            "finite_byte_owner_execution": true,
            "single_block_scalar_entry_only": false,
            "scalar_public_entry_and_results_only": true,
            "verified_resource_cfg_execution": true,
            "interprocedural_byte_owner_and_loan_execution": true,
            "chain_and_bulk_execution": false,
            "versioned_bulk_byte_execution": true,
            "chain_execution": false,
            "general_resource_execution": false,
            "production_admission_authorized": false,
            "whole_language_soundness_proved": false,
            "native_backend_refinement_proved": false,
            "abi_or_hardware_qualified": false
        });
        if loan_returns {
            report["claims"]["parameter_bound_returned_loans_execution"] = json!(true);
        }
        if chain {
            report["claims"]["chain_and_bulk_execution"] = json!(true);
            report["claims"]["chain_execution"] = json!(true);
            report["claims"]["interprocedural_chain_execution"] = json!(true);
            report["claims"]["separate_logical_and_storage_identities"] = json!(true);
            report["claims"]["distinct_call_formal_loan_identities"] = json!(true);
        }
    }
    match result {
        Ok(values) => {
            if machine.memory.as_ref().is_some_and(|memory| !memory.is_clean()) {
                return failure("E_HIA_RUST_RUNTIME", "successful scalar entry retained resources");
            }
            let scalars: Vec<Value> = values.iter().map(|value| value.scalar().cloned())
                .collect::<Exec<_>>().map_err(|_| super::VerifyError {
                    code: "E_HIA_RUST_RUNTIME", detail: "resource cannot escape scalar entry".into(),
                })?;
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
        Err(Halt::Internal) => return failure(
            "E_HIA_RUST_RUNTIME", "verified HIA instruction could not be interpreted"),
    };
    Ok(report)
}
