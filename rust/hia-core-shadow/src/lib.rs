//! Conservative Rust shadow checker for the existing standalone HIA Program ISA.
//! This crate is NOT the language admission authority: the canonical Python
//! verify_program remains mandatory until semantic refinement is demonstrated.
//! The default profile is resource-free scalar SSA; the explicit owned profile
//! independently checks finite byte/chain graphs and v8 parameter loan returns.
//! The opt-in execution Machine has explicit finite byte-owner/chain profiles.
//! Every unsupported feature rejects instead of being interpreted as safe.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 262_144;
const MAX_DEPTH: usize = 64;
const MAX_FUNCTIONS: usize = 1024;
const MAX_BLOCKS: usize = 4096;

#[derive(Debug)]
pub struct VerifyError {
    pub code: &'static str,
    pub detail: String,
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}
impl std::error::Error for VerifyError {}
type R<T> = Result<T, VerifyError>;

fn failure<T>(code: &'static str, detail: impl Into<String>) -> R<T> {
    Err(VerifyError { code, detail: detail.into() })
}

// Charge every value before deserializing it, using one global budget across
// the entire tree. Per-subtree totals checked after next_element/next_value
// could allocate another large sibling subtree after the global budget was
// already exhausted. structure() remains a separate post-parse assertion.
struct UniqueJson {
    value: Value,
}
impl UniqueJson {
    fn leaf(value: Value) -> Self {
        Self { value }
    }
}
struct UniqueSeed<'a> {
    visited: &'a mut usize,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for UniqueSeed<'_> {
    type Value = UniqueJson;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        if *self.visited >= MAX_NODES || self.depth > MAX_DEPTH {
            return Err(de::Error::custom("HIA_DECODE_LIMIT: node/depth budget exceeded"));
        }
        *self.visited += 1;
        d.deserialize_any(UniqueVisitor { visited: self.visited, depth: self.depth })
    }
}
struct UniqueVisitor<'a> {
    visited: &'a mut usize,
    depth: usize,
}
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut visited = 0;
        UniqueSeed { visited: &mut visited, depth: 0 }.deserialize(d)
    }
}
impl<'de> Visitor<'de> for UniqueVisitor<'_> {
    type Value = UniqueJson;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("finite JSON without duplicate keys or floating values")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::Number(v.into())))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::Number(v.into())))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(E::custom("HIA does not admit floating JSON numbers"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::String(v.to_owned())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::String(v)))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::Null))
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson::leaf(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(next) = seq.next_element_seed(UniqueSeed {
            visited: &mut *self.visited, depth: self.depth + 1,
        })? {
            values.push(next.value);
        }
        Ok(UniqueJson { value: Value::Array(values) })
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut values = Map::new();
        // Refuse duplicate keys before even parsing the duplicate value.
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let next = map.next_value_seed(UniqueSeed {
                visited: &mut *self.visited, depth: self.depth + 1,
            })?;
            values.insert(key, next.value);
        }
        Ok(UniqueJson { value: Value::Object(values) })
    }
}

fn object<'a>(v: &'a Value, keys: &[&str], context: &str) -> R<&'a Map<String, Value>> {
    let Some(o) = v.as_object() else {
        return failure("E_HIA_FORMAT", format!("{context}: expected object"));
    };
    if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) {
        return failure("E_HIA_FORMAT", format!("{context}: unknown/missing keys"));
    }
    Ok(o)
}
fn array<'a>(v: &'a Value, context: &str) -> R<&'a [Value]> {
    v.as_array().map(Vec::as_slice).ok_or_else(|| VerifyError {
        code: "E_HIA_FORMAT", detail: format!("{context}: expected array"),
    })
}
fn string<'a>(v: &'a Value, context: &str) -> R<&'a str> {
    v.as_str().ok_or_else(|| VerifyError {
        code: "E_HIA_FORMAT", detail: format!("{context}: expected string"),
    })
}
fn ident(v: &Value) -> R<String> {
    let name = string(v, "identifier")?;
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 || name.starts_with("__hia_")
        || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || bytes[1..].iter().any(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
    {
        return failure("E_HIA_NAME", "invalid or reserved ASCII identifier");
    }
    Ok(name.to_owned())
}
fn scalar(v: &Value) -> R<String> {
    let ty = string(v, "type")?;
    if !matches!(ty, "i8" | "i16" | "i32" | "i64" | "isize"
        | "u8" | "u16" | "u32" | "u64" | "usize" | "bool" | "unit")
    {
        return failure("E_HIA_RUST_UNSUPPORTED", "Rust shadow checker only supports scalar values");
    }
    Ok(ty.to_owned())
}
fn int_bits(ty: &str) -> Option<(bool, u32)> {
    match ty {
        "i8" => Some((true, 8)), "i16" => Some((true, 16)),
        "i32" => Some((true, 32)), "i64" | "isize" => Some((true, 64)),
        "u8" => Some((false, 8)), "u16" => Some((false, 16)),
        "u32" => Some((false, 32)), "u64" | "usize" => Some((false, 64)),
        _ => None,
    }
}
fn valid_constant(ty: &str, v: &Value) -> bool {
    if ty == "bool" { return v.is_boolean(); }
    if ty == "unit" { return v.is_null(); }
    let Some((signed, bits)) = int_bits(ty) else { return false; };
    let n: i128 = match v.as_i64() {
        Some(n) => n as i128,
        None => match v.as_u64() {
            Some(n) => n as i128,
            None => return false,
        },
    };
    if signed {
        n >= -(1_i128 << (bits - 1)) && n < (1_i128 << (bits - 1))
    } else {
        n >= 0 && n < (1_i128 << bits)
    }
}
fn structure(v: &Value) -> R<()> {
    let mut nodes = 0_usize;
    let mut pending = vec![(v, 0_usize)];
    while let Some((node, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH {
            return failure("E_HIA_LIMIT", "JSON structure exceeds depth or node budget");
        }
        match node {
            Value::Array(a) => pending.extend(a.iter().map(|v| (v, depth + 1))),
            Value::Object(o) => pending.extend(o.values().map(|v| (v, depth + 1))),
            Value::Number(n) if !n.is_i64() && !n.is_u64() => {
                return failure("E_HIA_FORMAT", "noninteger JSON number");
            }
            _ => {}
        }
    }
    Ok(())
}
#[derive(Clone, PartialEq, Eq)]
struct Param { name: String, ty: String }
fn params(v: &Value) -> R<Vec<Param>> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for value in array(v, "parameters")? {
        let o = object(value, &["name", "type"], "parameter")?;
        let name = ident(&o["name"])?;
        if !seen.insert(name.clone()) {
            return failure("E_HIA_SSA", "duplicate parameter");
        }
        result.push(Param { name, ty: scalar(&o["type"])? });
    }
    Ok(result)
}
fn names(v: &Value) -> R<Vec<String>> {
    array(v, "values")?.iter().map(ident).collect()
}
fn returns(v: &Value) -> R<Vec<String>> {
    array(v, "returns")?.iter().map(scalar).collect()
}
fn effects(v: &Value) -> R<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for e in array(v, "effects")? {
        let e = string(e, "effect")?;
        if !matches!(e, "alloc" | "read" | "write" | "trap") || !out.insert(e.to_owned()) {
            return failure("E_HIA_EFFECT", "unknown or duplicated effect");
        }
    }
    Ok(out)
}
#[derive(Clone)]
struct Signature {
    params: Vec<Param>,
    returns: Vec<String>,
    effects: BTreeSet<String>,
}
#[derive(Clone)]
struct Edge { target: String, args: Vec<String> }
fn parse_edge(v: &Value) -> R<Edge> {
    let o = object(v, &["target", "args"], "CFG edge")?;
    Ok(Edge { target: ident(&o["target"])?, args: names(&o["args"])? })
}
fn term_edges(v: &Value) -> R<Vec<Edge>> {
    let Some(o) = v.as_object() else { return failure("E_HIA_CFG", "missing terminator"); };
    match o.get("op").and_then(Value::as_str) {
        Some("jump") => {
            object(v, &["op", "target", "args"], "jump")?;
            Ok(vec![Edge { target: ident(&o["target"])?, args: names(&o["args"])? }])
        }
        Some("branch") => {
            object(v, &["op", "cond", "then", "else"], "branch")?;
            ident(&o["cond"])?;
            Ok(vec![parse_edge(&o["then"])?, parse_edge(&o["else"])?])
        }
        Some("ret") => {
            object(v, &["op", "values"], "return")?;
            names(&o["values"])?;
            Ok(vec![])
        }
        Some("trap") => {
            object(v, &["op", "code"], "trap")?;
            let code = string(&o["code"], "trap code")?;
            if !matches!(code, "user" | "overflow" | "division_by_zero" | "bounds" | "allocation") {
                return failure("E_HIA_CFG", "unknown trap code");
            }
            Ok(vec![])
        }
        _ => failure("E_HIA_CFG", "unknown terminator"),
    }
}
fn matching(actual: &[String], expected: &[String], what: &str) -> R<()> {
    if actual != expected {
        return failure("E_HIA_TYPE", format!("{what}: type/arity mismatch"));
    }
    Ok(())
}
fn instruction(
    ins: &Value,
    env: &mut BTreeMap<String, String>,
    functions: &BTreeMap<String, Signature>,
    required: &mut BTreeSet<String>,
) -> R<()> {
    let o = object(ins, &["op", "args", "out", "attrs"], "instruction")?;
    let op = string(&o["op"], "opcode")?;
    let args = names(&o["args"])?;
    let output = params(&o["out"])?;
    let attrs = o["attrs"].as_object().ok_or_else(|| VerifyError {
        code: "E_HIA_FORMAT", detail: "attributes must be an object".into(),
    })?;
    let mut actual = Vec::new();
    for arg in &args {
        let Some(ty) = env.get(arg) else {
            return failure("E_HIA_SSA", format!("{op}: undefined/nonlocal value {arg}"));
        };
        actual.push(ty.clone());
    }
    let out_types: Vec<String> = output.iter().map(|x| x.ty.clone()).collect();
    let expect_empty_attrs = !matches!(op, "const" | "int.cast" | "call");
    if expect_empty_attrs && !attrs.is_empty() {
        return failure("E_HIA_FORMAT", "unsupported instruction attributes");
    }
    let expected: Vec<String> = match op {
        "const" => {
            object(&o["attrs"], &["value"], "const attrs")?;
            if !args.is_empty() || output.len() != 1 || !valid_constant(&output[0].ty, &attrs["value"]) {
                return failure("E_HIA_TYPE", "invalid exactly typed constant");
            }
            out_types.clone()
        }
        "int.add.checked" | "int.sub.checked" | "int.mul.checked"
        | "int.add.wrap" | "int.sub.wrap" | "int.mul.wrap"
        | "int.div.checked" | "int.rem.checked"
        | "int.shl.checked" | "int.shr.checked"
        | "bit.and" | "bit.or" | "bit.xor" => {
            if actual.len() != 2 || actual[0] != actual[1] || int_bits(&actual[0]).is_none() {
                return failure("E_HIA_TYPE", "integer binary operation type mismatch");
            }
            if op.ends_with(".checked") { required.insert("trap".into()); }
            vec![actual[0].clone()]
        }
        "bit.not" | "int.neg.checked" => {
            if actual.len() != 1 || int_bits(&actual[0]).is_none() {
                return failure("E_HIA_TYPE", "integer unary operation type mismatch");
            }
            if op == "int.neg.checked" { required.insert("trap".into()); }
            actual
        }
        "compare.eq" | "compare.ne" | "compare.lt" | "compare.le"
        | "compare.gt" | "compare.ge" => {
            if actual.len() != 2 || actual[0] != actual[1]
                || (int_bits(&actual[0]).is_none()
                    && !(actual[0] == "bool" && matches!(op, "compare.eq" | "compare.ne")))
            {
                return failure("E_HIA_TYPE", "comparison type mismatch");
            }
            vec!["bool".into()]
        }
        "bool.not" | "bool.and" | "bool.or" => {
            let arity = if op == "bool.not" { 1 } else { 2 };
            if actual.len() != arity || actual.iter().any(|ty| ty != "bool") {
                return failure("E_HIA_TYPE", "boolean operation type mismatch");
            }
            vec!["bool".into()]
        }
        "int.cast" => {
            object(&o["attrs"], &["mode"], "cast attrs")?;
            if actual.len() != 1 || output.len() != 1
                || int_bits(&actual[0]).is_none() || int_bits(&out_types[0]).is_none()
            {
                return failure("E_HIA_TYPE", "cast type mismatch");
            }
            let mode = string(&attrs["mode"], "cast mode")?;
            if !matches!(mode, "checked" | "wrap") {
                return failure("E_HIA_TYPE", "unknown cast mode");
            }
            if mode == "checked" { required.insert("trap".into()); }
            out_types.clone()
        }
        "select" => {
            if actual.len() != 3 || actual[0] != "bool" || actual[1] != actual[2] {
                return failure("E_HIA_TYPE", "select type mismatch");
            }
            vec![actual[1].clone()]
        }
        "call" => {
            object(&o["attrs"], &["function"], "call attrs")?;
            let callee = ident(&attrs["function"])?;
            let Some(sig) = functions.get(&callee) else {
                return failure("E_HIA_CALL", "unknown callee");
            };
            matching(&actual, &sig.params.iter().map(|p| p.ty.clone()).collect::<Vec<_>>(), "call")?;
            required.extend(sig.effects.iter().cloned());
            sig.returns.clone()
        }
        _ => return failure("E_HIA_RUST_UNSUPPORTED",
            format!("unsupported/resource opcode {op}; canonical Python verifier remains required")),
    };
    matching(&out_types, &expected, op)?;
    for p in output {
        if env.insert(p.name, p.ty).is_some() {
            return failure("E_HIA_SSA", "SSA value redefined in block");
        }
    }
    Ok(())
}
fn check_function(fn_value: &Value, sig: &Signature, functions: &BTreeMap<String, Signature>) -> R<usize> {
    let f = object(fn_value, &["name", "params", "returns", "effects", "entry", "blocks"], "function")?;
    let entry = ident(&f["entry"])?;
    let blocks = array(&f["blocks"], "blocks")?;
    if blocks.is_empty() || blocks.len() > MAX_BLOCKS {
        return failure("E_HIA_CFG", "invalid block count");
    }
    let mut by_id = BTreeMap::<String, &Value>::new();
    let mut definitions = BTreeSet::new();
    let mut block_params = BTreeMap::<String, Vec<Param>>::new();
    for b in blocks {
        let bobj = object(b, &["id", "params", "ops", "term"], "block")?;
        let id = ident(&bobj["id"])?;
        if by_id.insert(id.clone(), b).is_some() {
            return failure("E_HIA_CFG", "duplicate block");
        }
        let ps = params(&bobj["params"])?;
        for p in &ps {
            if !definitions.insert(p.name.clone()) {
                return failure("E_HIA_SSA", "SSA name redefined in function");
            }
        }
        for ins in array(&bobj["ops"], "operations")? {
            let io = object(ins, &["op", "args", "out", "attrs"], "instruction")?;
            string(&io["op"], "opcode")?;
            names(&io["args"])?;
            if !io["attrs"].is_object() {
                return failure("E_HIA_FORMAT", "invalid attributes");
            }
            for p in params(&io["out"])? {
                if !definitions.insert(p.name) {
                    return failure("E_HIA_SSA", "SSA name redefined in function");
                }
            }
        }
        term_edges(&bobj["term"])?;
        block_params.insert(id, ps);
    }
    if block_params.get(&entry) != Some(&sig.params) {
        return failure("E_HIA_CFG", "entry params must match function signature");
    }
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for (id, b) in &by_id {
        let mut outgoing = Vec::new();
        for edge in term_edges(&b["term"])? {
            let Some(target) = block_params.get(&edge.target) else {
                return failure("E_HIA_CFG", "edge to missing block");
            };
            if edge.target == entry || edge.args.len() != target.len() {
                return failure("E_HIA_CFG", "entry edge or edge arity mismatch");
            }
            outgoing.push(edge.target);
        }
        graph.insert(id.clone(), outgoing);
    }
    let mut reached = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(block) = pending.pop() {
        if reached.insert(block.clone()) {
            pending.extend(graph[&block].iter().cloned());
        }
    }
    if reached.len() != blocks.len() {
        return failure("E_HIA_CFG", "unreachable block");
    }
    for (id, block) in &by_id {
        let mut env: BTreeMap<String, String> = block_params[id]
            .iter().map(|p| (p.name.clone(), p.ty.clone())).collect();
        let mut required = BTreeSet::new();
        for ins in array(&block["ops"], "operations")? {
            instruction(ins, &mut env, functions, &mut required)?;
        }
        let term = &block["term"];
        let op = string(&term["op"], "terminator")?;
        if op == "branch" {
            let cond = ident(&term["cond"])?;
            if env.get(&cond).map(String::as_str) != Some("bool") {
                return failure("E_HIA_CFG", "branch requires a local bool");
            }
        }
        if op == "ret" {
            let values = names(&term["values"])?;
            let actual: R<Vec<String>> = values.iter().map(|name| {
                env.get(name).cloned().ok_or_else(|| VerifyError {
                    code: "E_HIA_SSA", detail: "return references nonlocal SSA".into(),
                })
            }).collect();
            matching(&actual?, &sig.returns, "return")?;
        }
        if op == "trap" { required.insert("trap".into()); }
        for edge in term_edges(term)? {
            let target = &block_params[&edge.target];
            for (name, expected) in edge.args.iter().zip(target) {
                if env.get(name) != Some(&expected.ty) {
                    return failure("E_HIA_CFG", "edge references absent or wrong-typed SSA");
                }
            }
        }
        if !required.is_subset(&sig.effects) {
            return failure("E_HIA_EFFECT", "function is missing required effect");
        }
    }
    Ok(blocks.len())
}
mod ownership;
mod scalar_vm;
pub use scalar_vm::{execute_owned, execute_owned_bound, execute_owned_bound_v2, execute_scalar};

// serde_json reports the JSON integer token -0 through visit_f64, although
// the Core JSON contract (and its Python decoder) treats that token as integer
// zero. Mask only its minus sign, outside strings and at complete value-token
// boundaries, before the same bounded/duplicate-safe decoder runs. Keeping the
// byte count and all other bytes unchanged preserves error offsets and budgets.
// Float spellings (-0.0, -0e0) and malformed numbers (-00, --0) are untouched.
fn integer_negative_zero(input: &[u8]) -> Cow<'_, [u8]> {
    let mut output = Cow::Borrowed(input);
    let (mut quoted, mut escaped) = (false, false);
    for (index, &byte) in input.iter().enumerate() {
        if quoted {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { quoted = false; }
            continue;
        }
        if byte == b'"' { quoted = true; continue; }
        if byte == b'-' && input.get(index + 1) == Some(&b'0')
            && (index == 0 || matches!(input[index - 1], b'[' | b':' | b',' | b' ' | b'\t' | b'\r' | b'\n'))
            && (index + 2 == input.len()
                || matches!(input[index + 2], b']' | b'}' | b',' | b' ' | b'\t' | b'\r' | b'\n'))
        {
            output.to_mut()[index] = b' ';
        }
    }
    output
}

fn decode_hia(input: &[u8]) -> R<(Value, Vec<u8>)> {
    if input.len() > MAX_BYTES {
        return failure("E_HIA_LIMIT", "encoded HIA program exceeds 8 MiB");
    }
    let integer_input = integer_negative_zero(input);
    let mut d = serde_json::Deserializer::from_slice(&integer_input);
    let parsed = UniqueJson::deserialize(&mut d).map_err(|e| {
        let detail = e.to_string();
        VerifyError {
            code: if detail.starts_with("HIA_DECODE_LIMIT:") {
                "E_HIA_LIMIT"
            } else {
                "E_HIA_FORMAT"
            },
            detail,
        }
    })?;
    d.end().map_err(|e| VerifyError { code: "E_HIA_FORMAT", detail: e.to_string() })?;
    let doc = parsed.value;
    structure(&doc)?;
    let canonical = serde_json::to_vec(&doc).map_err(|e| VerifyError {
        code: "E_HIA_FORMAT", detail: e.to_string(),
    })?;
    if canonical.len() > MAX_BYTES {
        return failure("E_HIA_LIMIT", "canonical HIA program exceeds 8 MiB");
    }
    Ok((doc, canonical))
}

/// Bounded untrusted CLI argument decoder for the existing scalar oracle.
///
/// Reuses the SAME depth/node/duplicate-key-safe deserializer as HIA Core
/// source. No Value tree is allocated for a payload over the byte budget.
/// Scalar *type* and arity remain independently checked by execute_scalar.
pub const MAX_SCALAR_ARGS_BYTES: usize = 128 * 1024;
pub const MAX_SCALAR_ARGS: usize = 8_192;
pub fn decode_scalar_arguments(text: &str) -> R<Vec<Value>> {
    if text.len() > MAX_SCALAR_ARGS_BYTES {
        return failure("E_HIA_INPUT", "scalar argument text exceeds the 128 KiB cap");
    }
    // This is a syntax/value-shape parser, NOT the HIA program validator.
    // decode_hia already rejects deep/dense JSON and duplicate object keys
    // before constructing an unrestricted serde_json::Value graph.
    let (value, _) = decode_hia(text.as_bytes())?;
    let Value::Array(arguments) = value else {
        return failure("E_HIA_INPUT", "scalar arguments must be a JSON array");
    };
    if arguments.len() > MAX_SCALAR_ARGS || arguments.iter().any(|item| {
        !matches!(item, Value::Number(_) | Value::Bool(_) | Value::Null)
    }) {
        return failure("E_HIA_INPUT", "scalar arguments exceed count/type profile");
    }
    Ok(arguments)
}


/// Independently check a conservative HIA v1 Owner/Loan CFG subset.
/// This is never a source/native admission or proof authorization.
pub fn verify_owned(input: &[u8]) -> R<Value> {
    ownership::verify_owned(input)
}

/// Fail-closed scalar shadow verification. A successful report is NOT a
/// substitute for hepta.hia_program.verify_program, LLVM/refinement proof,
/// or production final-use authorization.
pub fn verify(input: &[u8]) -> R<Value> {
    let (doc, _canonical_bytes) = decode_hia(input)?;
    // A verified standalone scalar program may explicitly restrict the
    // public entrypoints. This field is part of executable Core identity,
    // not an untrusted producer permission or a second schema authority.
    let top_keys: &[&str] = if doc.get("exports").is_some() {
        &["schema", "module", "functions", "exports"]
    } else {
        &["schema", "module", "functions"]
    };
    let top = object(&doc, top_keys, "program")?;
    let schema = string(&top["schema"], "schema")?;
    if !matches!(schema, "hepta.hia.program.v1" | "hepta.hia.program.v2"
        | "hepta.hia.program.v3" | "hepta.hia.program.v4"
        | "hepta.hia.program.v5" | "hepta.hia.program.v6"
        | "hepta.hia.program.v7")
    {
        return failure("E_HIA_SCHEMA", "unrecognized or ambiguous HIA schema");
    }
    // Version 7 extends the RESOURCE ISA, not the scalar machine. Every
    // function (including unused ones) is still fully checked by scalar()
    // and instruction(): Chain/Owner/Loan and any unknown opcode fail closed.
    // This does NOT authorize v7 resource verification or native final-use.

    ident(&top["module"])?;
    let fs = array(&top["functions"], "functions")?;
    if fs.is_empty() || fs.len() > MAX_FUNCTIONS {
        return failure("E_HIA_FORMAT", "invalid function count");
    }
    let mut signatures = BTreeMap::<String, Signature>::new();
    for f in fs {
        let o = object(f, &["name", "params", "returns", "effects", "entry", "blocks"], "function")?;
        let name = ident(&o["name"])?;
        if matches!(name.as_str(), "abort" | "calloc" | "malloc" | "free"
            | "memcpy" | "memmove" | "memset")
        {
            return failure("E_HIA_NAME", "function collides with native runtime symbol");
        }
        let sig = Signature {
            params: params(&o["params"])?,
            returns: returns(&o["returns"])?,
            effects: effects(&o["effects"])?,
        };
        if signatures.insert(name, sig).is_some() {
            return failure("E_HIA_NAME", "duplicate function name");
        }
    }
    // Match canonical verify_program's explicit scalar-export contract.
    // The whole Rust shadow module is scalar-only; exported names must still
    // be unique, existing and valid. An empty list exports nothing.
    if let Some(export_list) = top.get("exports") {
        let exports = array(export_list, "explicit scalar exports")?;
        let mut seen = BTreeSet::new();
        for entry in exports {
            let name = ident(entry)?;
            if !signatures.contains_key(&name) {
                return failure("E_HIA_CALL", "export references a missing function");
            }
            if !seen.insert(name) {
                return failure("E_HIA_NAME", "duplicate explicit scalar export");
            }
        }
    }
    let mut blocks_checked = 0;
    for f in fs {
        let name = string(&f["name"], "function name")?;
        blocks_checked += check_function(f, &signatures[name], &signatures)?;
    }
    let canonical = serde_json::to_vec(&doc).map_err(|e| VerifyError {
        code: "E_HIA_FORMAT", detail: e.to_string(),
    })?;
    if canonical.len() > MAX_BYTES {
        return failure("E_HIA_LIMIT", "canonical program exceeds 8 MiB");
    }
    let digest = Sha256::digest(&canonical);
    Ok(serde_json::json!({
        "schema": "hepta.hia.rust-scalar-shadow.v1",
        "ok": true,
        "program_sha256": format!("{digest:x}"),
        "functions_checked": fs.len(),
        "blocks_checked": blocks_checked,
        "source_required": false,
        "claims": {
            "scalar_ssa_and_cfg_checked": true,
            "v7_scalar_only_checked": schema == "hepta.hia.program.v7",
            "v7_chain_resources_supported": false,
            "resource_provenance_verified": false,
            "full_hia_verifier_replaced": false,
            "whole_language_soundness_proved": false,
            "backend_refinement_proved": false,
            "ffi_supported": false,
            "native_executed": false
        }
    }))
}
