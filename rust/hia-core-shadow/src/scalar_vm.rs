//! Independent, bounded, resource-free scalar HIA execution oracle.
//! IMPORTANT: this is a development shadow, NOT native final-use authorization.
//! Every input is rechecked by the existing Rust scalar verifier. Rust may
//! execute only operations from the verified, closed numeric/boolean ISA.
//! Invalid programs and resource instructions never gain an execution path.
use std::collections::BTreeMap;
use serde_json::{json, Value};
use super::{decode_hia, failure, int_bits, valid_constant, verify, R};

const MAX_STEPS: u64 = 1_000_000;
const MAX_CALL_DEPTH: u32 = 32;

#[derive(Debug)]
enum Halt {
    Trap(&'static str),
    Budget(&'static str),
    Internal,
}
type Exec<T> = Result<T, Halt>;

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
fn lookup(env: &BTreeMap<String, Value>, name: &Value) -> Exec<Value> {
    env.get(name.as_str().ok_or(Halt::Internal)?)
        .cloned().ok_or(Halt::Internal)
}
fn resolve(env: &BTreeMap<String, Value>, names: &Value) -> Exec<Vec<Value>> {
    names.as_array().ok_or(Halt::Internal)?
        .iter().map(|v| lookup(env, v)).collect()
}
fn bind(params: &Value, values: Vec<Value>) -> Exec<BTreeMap<String, Value>> {
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
}
impl<'a> Machine<'a> {
    fn tick(&mut self) -> Exec<()> {
        self.steps += 1;
        if self.steps > self.limit { Err(Halt::Budget("steps")) } else { Ok(()) }
    }
    fn invoke(&mut self, name: &str, args: Vec<Value>, depth: u32) -> Exec<Vec<Value>> {
        // Match the canonical root-inclusive Python dynamic budget:
        // 32 live frames at depths 0..31; depth 32 refuses before its tick.
        // Infinite one-call recursion therefore stops after 64 ticks.
        if depth >= MAX_CALL_DEPTH { return Err(Halt::Budget("calls")); }
        // Copy the lifetime-qualified reference, never clone an 8 MiB function
        // at each recursive call. The source document lives for this Machine.
        let function: &'a Value = *self.functions.get(name).ok_or(Halt::Internal)?;
        self.tick()?; // one call-entry tick, same convention as Python VM.
        let blocks = function["blocks"].as_array().ok_or(Halt::Internal)?;
        let by_name: BTreeMap<&str, &Value> = blocks.iter()
            .map(|b| (b["id"].as_str().unwrap_or(""), b)).collect();
        let mut current = function["entry"].as_str().ok_or(Halt::Internal)?;
        let mut env = bind(&function["params"], args)?;
        loop {
            let block = *by_name.get(current).ok_or(Halt::Internal)?;
            for op in block["ops"].as_array().ok_or(Halt::Internal)? {
                self.tick()?;
                let op_name = op["op"].as_str().ok_or(Halt::Internal)?;
                let operands = resolve(&env, &op["args"])?;
                let outputs = if op_name == "call" {
                    let callee = op["attrs"]["function"].as_str().ok_or(Halt::Internal)?;
                    self.invoke(callee, operands, depth + 1)?
                } else {
                    opcode_results(op, &operands)?
                };
                for (parameter, value) in op["out"].as_array().ok_or(Halt::Internal)?
                    .iter().zip(outputs) {
                    env.insert(parameter["name"].as_str().ok_or(Halt::Internal)?.into(), value);
                }
            }
            self.tick()?;
            let term = &block["term"];
            match term["op"].as_str().ok_or(Halt::Internal)? {
                "ret" => return resolve(&env, &term["values"]),
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
                        else if boolean(&lookup(&env, &term["cond"])?)? {
                            &term["then"]
                        } else { &term["else"] };
                    let values = resolve(&env, &edge["args"])?;
                    let target = edge["target"].as_str().ok_or(Halt::Internal)?;
                    let destination = *by_name.get(target).ok_or(Halt::Internal)?;
                    // Simultaneously assign all block arguments, including
                    // loop backedge values. No stale SSA values can leak in.
                    env = bind(&destination["params"], values)?;
                    current = target;
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
    if !(1..=MAX_STEPS).contains(&max_steps) {
        return failure("E_HIA_BUDGET_POLICY", "max_steps outside bounded Rust oracle profile");
    }
    let verification = verify(input)?; // whole-module scalar SSA gate, no resource fallback
    let (document, _) = decode_hia(input)?;
    let functions = document["functions"].as_array().ok_or_else(|| super::VerifyError {
        code: "E_HIA_FORMAT", detail: "missing verified function inventory".into(),
    })?;
    let by_name: BTreeMap<&str, &Value> = functions.iter()
        .map(|f| (f["name"].as_str().unwrap_or(""), f)).collect();
    let Some(entry) = by_name.get(function) else {
        return failure("E_HIA_INPUT", "unknown public scalar entry");
    };
    let Some(parameters) = entry["params"].as_array() else {
        return failure("E_HIA_INPUT", "invalid entry signature");
    };
    if parameters.len() != arguments.len() || parameters.iter().zip(arguments).any(|(p, v)| {
        !p["type"].as_str().is_some_and(|ty| valid_constant(ty, v))
    }) {
        return failure("E_HIA_INPUT", "entry arguments do not match exact scalar types");
    }
    let mut machine = Machine { functions: by_name, steps: 0, limit: max_steps };
    let result = machine.invoke(function, arguments.to_vec(), 0);
    let mut report = json!({
        "schema": "hepta.hia.rust-scalar-execution.v1",
        "status": "unknown",
        "function": function,
        "program_sha256": verification["program_sha256"],
        "steps": machine.steps,
        "max_steps": max_steps,
        "max_call_depth": MAX_CALL_DEPTH,
        "claims": {
            "finite_scalar_execution": true,
            "all_owner_and_memory_opcodes_refused": true,
            "production_admission_authorized": false,
            "whole_language_soundness_proved": false,
            "native_backend_refinement_proved": false,
            "abi_or_hardware_qualified": false
        }
    });
    match result {
        Ok(values) => {
            report["status"] = json!("returned");
            report["values"] = json!(values);
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
