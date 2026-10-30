//! Explicit, finite raw composite.v1 Copy-record candidate.
//!
//! Nominal identities are checked BEFORE erasure, including zero-width values.
//! The result is the existing primitive v6 Core, rechecked by verify_owned and
//! executed only by the existing Machine. No receipt imports or Python calls.
use std::collections::{BTreeMap, BTreeSet};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use super::{array, failure, ident, object, string, R};

const MAX_DEFINITIONS: usize = 128;
const MAX_FIELDS: usize = 64;
const MAX_TYPE_DEPTH: usize = 32;
const MAX_FLAT_FIELDS: usize = 512;
const MAX_GENERATED_NAMES: usize = 8192;
const MAX_VALUE_SLOTS: usize = 32768;
const PREFIX: &str = "h2internal_";
const PROFILE: &str = "monomorphic-copy-records-over-primitive-v6-v1";

fn name(value: &Value) -> R<String> {
    let result = ident(value)?;
    if result.starts_with(PREFIX) {
        return failure("E_HIA_NAME", "identifier uses the nominal elaborator namespace");
    }
    Ok(result)
}

#[derive(Clone, PartialEq, Eq)]
enum Type { Primitive(String), Record(String) }

impl Type {
    fn linear(&self) -> bool {
        matches!(self, Self::Primitive(t) if matches!(t.as_str(), "buffer" | "readbuf" | "mutbuf"))
    }
    fn owns(&self) -> bool { matches!(self, Self::Primitive(t) if t == "buffer") }
    fn loan(&self) -> bool {
        matches!(self, Self::Primitive(t) if matches!(t.as_str(), "readbuf" | "mutbuf"))
    }
    fn public_scalar(&self) -> bool {
        matches!(self, Self::Primitive(t) if !matches!(t.as_str(), "buffer" | "readbuf" | "mutbuf"))
    }
}

#[derive(Clone)]
struct Layout { fields: Vec<(String, Type)>, flat: Vec<String>, depth: usize }

struct Types {
    definitions: BTreeMap<String, Vec<(String, Type)>>,
    layouts: BTreeMap<String, Layout>,
}

impl Types {
    fn new(raw: &Value) -> R<Self> {
        let declarations = array(raw, "record declarations")?;
        if declarations.len() > MAX_DEFINITIONS {
            return failure("E_HIA_LIMIT", "nominal declaration budget exceeded");
        }
        let mut result = Self { definitions: BTreeMap::new(), layouts: BTreeMap::new() };
        for declaration in declarations {
            let fields = object(declaration, &["name", "params", "kind", "fields"], "Copy record declaration")?;
            if fields["kind"] != "record" || !array(&fields["params"], "type parameters")?.is_empty() {
                return failure("E_HIA_RUST_UNSUPPORTED", "candidate accepts only monomorphic Copy records");
            }
            let n = name(&fields["name"])?;
            if super::scalar(&fields["name"]).is_ok() || matches!(n.as_str(), "buffer" | "readbuf" | "mutbuf")
                || result.definitions.insert(n, Vec::new()).is_some() {
                return failure("E_HIA_TYPE", "duplicate or reserved nominal declaration");
            }
        }
        for declaration in declarations {
            let fields = array(&declaration["fields"], "record fields")?;
            if fields.len() > MAX_FIELDS { return failure("E_HIA_LIMIT", "record field budget exceeded"); }
            let mut seen = BTreeSet::new();
            let mut selected = Vec::new();
            for field in fields {
                let item = object(field, &["name", "type"], "record field")?;
                let n = name(&item["name"])?;
                if !seen.insert(n.clone()) { return failure("E_HIA_TYPE", "duplicate record field"); }
                let ty = result.resolve(&item["type"])?;
                if ty.linear() {
                    return failure("E_HIA_RUST_UNSUPPORTED", "resource fields are outside the Copy-record candidate");
                }
                selected.push((n, ty));
            }
            result.definitions.insert(name(&declaration["name"])?, selected);
        }
        // Validate every declaration, including unused cyclic or excessive
        // layouts. Check width before extending a flattened representation.
        for n in result.definitions.keys().cloned().collect::<Vec<_>>() {
            result.layout(&n, &mut BTreeSet::new())?;
        }
        Ok(result)
    }

    fn resolve(&self, raw: &Value) -> R<Type> {
        if let Some(text) = raw.as_str() {
            if super::scalar(raw).is_ok() || matches!(text, "buffer" | "readbuf" | "mutbuf") {
                return Ok(Type::Primitive(text.to_owned()));
            }
        }
        let selected = if raw.is_string() { name(raw)? } else {
            let fields = object(raw, &["name", "args"], "concrete record reference")?;
            if !array(&fields["args"], "type arguments")?.is_empty() {
                return failure("E_HIA_RUST_UNSUPPORTED", "generic instantiation is outside the record candidate");
            }
            name(&fields["name"])?
        };
        if !self.definitions.contains_key(&selected) {
            return failure("E_HIA_TYPE", "unknown nominal type or unsupported primitive type");
        }
        Ok(Type::Record(selected))
    }

    fn layout(&mut self, n: &str, active: &mut BTreeSet<String>) -> R<Layout> {
        if let Some(found) = self.layouts.get(n) { return Ok(found.clone()); }
        if !active.insert(n.to_owned()) { return failure("E_HIA_TYPE", "recursive by-value record declarations"); }
        if active.len() > MAX_TYPE_DEPTH + 1 {
            return failure("E_HIA_LIMIT", "nominal layout nesting exceeds budget");
        }
        let fields = self.definitions[n].clone();
        let mut flat = Vec::new();
        let mut depth = 0;
        for (_, ty) in &fields {
            let (child, child_depth) = match ty {
                Type::Primitive(part) => (vec![part.clone()], 0),
                Type::Record(record) => { let value = self.layout(record, active)?; (value.flat, value.depth) },
            };
            depth = depth.max(child_depth + 1);
            if depth > MAX_TYPE_DEPTH || child.len() > MAX_FLAT_FIELDS - flat.len() {
                return failure("E_HIA_LIMIT", "nominal layout depth/width exceeds budget");
            }
            flat.extend(child);
        }
        active.remove(n);
        let layout = Layout { fields, flat, depth };
        self.layouts.insert(n.to_owned(), layout.clone());
        Ok(layout)
    }

    fn flat(&self, ty: &Type) -> Vec<String> {
        match ty {
            Type::Primitive(t) => vec![t.clone()],
            Type::Record(n) => self.layouts[n].flat.clone(),
        }
    }

    fn width(&self, ty: &Type) -> usize {
        match ty { Type::Primitive(_) => 1, Type::Record(n) => self.layouts[n].flat.len() }
    }

    fn parameters(&self, raw: &Value) -> R<Vec<(String, Type)>> {
        let mut seen = BTreeSet::new();
        array(raw, "nominal parameters")?.iter().map(|param| {
            let item = object(param, &["name", "type"], "nominal parameter")?;
            let n = name(&item["name"])?;
            if !seen.insert(n.clone()) { return failure("E_HIA_SSA", "duplicate nominal parameter"); }
            Ok((n, self.resolve(&item["type"])?))
        }).collect()
    }
}

#[derive(Clone)]
struct Binding { ty: Type, names: Vec<String>, consumed: bool, external: bool }
type Environment = BTreeMap<String, Binding>;

#[derive(Clone)]
struct Signature { params: Vec<(String, Type)>, returns: Vec<Type> }

struct Lower {
    types: Types,
    signatures: BTreeMap<String, Signature>,
    serial: usize,
    value_slots: usize,
    emitted_slots: usize,
}

fn names(raw: &Value) -> R<Vec<String>> { array(raw, "nominal names")?.iter().map(name).collect() }

fn value<'a>(env: &'a Environment, n: &str) -> R<&'a Binding> {
    let Some(item) = env.get(n) else { return failure("E_HIA_SSA", "undefined or nonlocal nominal value"); };
    if item.consumed { return failure("E_HIA_RESOURCE", "use of consumed nominal value"); }
    Ok(item)
}

fn consume(env: &mut Environment, n: &str) -> R<()> {
    value(env, n)?;
    let binding = env.get_mut(n).unwrap();
    if binding.ty.linear() { binding.consumed = true; }
    Ok(())
}

fn live(env: &Environment) -> BTreeSet<String> {
    env.iter().filter(|(_, b)| b.ty.linear() && !b.consumed && !b.external)
        .map(|(n, _)| n.clone()).collect()
}

fn output_types(declared: &[(String, Type)], expected: &[Type]) -> R<()> {
    if declared.iter().map(|(_, t)| t).ne(expected.iter()) {
        return failure("E_HIA_TYPE", "nominal output type/arity mismatch before erasure");
    }
    Ok(())
}

impl Lower {
    fn new(document: &Value) -> R<Self> {
        let top = object(document, &["schema", "module", "types", "functions"], "raw Copy-record candidate")?;
        if top["schema"] != "hepta.hia.composite.v1" {
            return failure("E_HIA_SCHEMA", "Copy-record candidate requires explicit composite.v1");
        }
        name(&top["module"])?;
        let types = Types::new(&top["types"])?;
        let functions = array(&top["functions"], "nominal functions")?;
        if functions.is_empty() || functions.len() > super::MAX_FUNCTIONS {
            return failure("E_HIA_FORMAT", "invalid nominal function inventory");
        }
        let mut signatures = BTreeMap::new();
        for function in functions {
            let fields = object(function, &["name", "params", "returns", "effects", "entry", "blocks"], "nominal function")?;
            let n = name(&fields["name"])?;
            let params = types.parameters(&fields["params"])?;
            let returns = array(&fields["returns"], "nominal return types")?.iter()
                .map(|t| types.resolve(t)).collect::<R<Vec<_>>>()?;
            if returns.iter().any(Type::loan) {
                return failure("E_HIA_LOAN", "composite.v1 loans cannot escape a function");
            }
            super::effects(&fields["effects"])?;
            if signatures.insert(n, Signature { params, returns }).is_some() {
                return failure("E_HIA_NAME", "duplicate nominal function");
            }
        }
        Ok(Self { types, signatures, serial: 0, value_slots: 0, emitted_slots: 0 })
    }

    fn fresh(&mut self) -> R<String> {
        if self.serial >= MAX_GENERATED_NAMES { return failure("E_HIA_LIMIT", "nominal generated-name budget exceeded"); }
        self.serial += 1;
        Ok(format!("{PREFIX}{}", self.serial))
    }

    fn reserve_values(&mut self, params: &[(String, Type)]) -> R<()> {
        for (_, ty) in params {
            let count = self.types.width(ty);
            if count > MAX_VALUE_SLOTS - self.value_slots {
                return failure("E_HIA_LIMIT", "nominal elaborated value-slot budget exceeded");
            }
            self.value_slots += count;
        }
        Ok(())
    }

    fn reserve_emitted(&mut self, count: usize) -> R<()> {
        // Every emitted scalar reference occupies at least one Core JSON
        // node. This necessary Core bound also prevents argument fan-out from
        // allocating an enormous erased module before final Core admission.
        if count > super::MAX_NODES - self.emitted_slots {
            return failure("E_HIA_LIMIT", "erased scalar-reference expansion exceeds Core node budget");
        }
        self.emitted_slots += count;
        Ok(())
    }

    fn counted_widths(&self, widths: impl IntoIterator<Item = usize>) -> R<usize> {
        let remaining = super::MAX_NODES - self.emitted_slots;
        let mut count = 0usize;
        for width in widths {
            let Some(next) = count.checked_add(width).filter(|next| *next <= remaining) else {
                return failure("E_HIA_LIMIT", "erased scalar-reference expansion exceeds Core node budget");
            };
            count = next;
        }
        Ok(count)
    }

    fn flatten(&mut self, bindings: &[&Binding]) -> R<Vec<String>> {
        let count = self.counted_widths(bindings.iter().map(|b| b.names.len()))?;
        self.reserve_emitted(count)?;
        Ok(bindings.iter().flat_map(|b| b.names.iter().cloned()).collect())
    }

    fn flat_parameters(&mut self, params: &[(String, Type)]) -> R<(Vec<Value>, Environment)> {
        let mut flat = Vec::new();
        let mut env = Environment::new();
        for (n, ty) in params {
            self.reserve_emitted(self.types.width(ty))?;
            let parts = self.types.flat(ty);
            let selected = if matches!(ty, Type::Primitive(_)) { vec![n.clone()] }
                else { (0..parts.len()).map(|_| self.fresh()).collect::<R<Vec<_>>>()? };
            flat.extend(selected.iter().zip(parts).map(|(n, t)| json!({"name":n,"type":t})));
            env.insert(n.clone(), Binding { ty: ty.clone(), names: selected, consumed: false, external: ty.loan() });
        }
        Ok((flat, env))
    }

    fn edge(&mut self, raw: &Value, env: &Environment,
            signatures: &BTreeMap<String, Vec<(String, Type)>>) -> R<Value> {
        let fields = object(raw, &["target", "args"], "nominal edge")?;
        let target = name(&fields["target"])?;
        let Some(params) = signatures.get(&target) else { return failure("E_HIA_CFG", "missing nominal edge target"); };
        let args = names(&fields["args"])?;
        let mut moved = BTreeSet::new();
        let actual = args.iter().map(|n| {
            let binding = value(env, n)?;
            if binding.ty.linear() && !moved.insert(n.clone()) {
                return failure("E_HIA_RESOURCE", "nominal linear value duplicated on edge");
            }
            Ok(binding)
        }).collect::<R<Vec<_>>>()?;
        if !live(env).is_subset(&moved) { return failure("E_HIA_RESOURCE", "edge drops a live nominal value"); }
        if actual.iter().map(|b| &b.ty).ne(params.iter().map(|(_, t)| t)) {
            return failure("E_HIA_TYPE", "nominal edge types differ before erasure");
        }
        Ok(json!({"target":target, "args":self.flatten(&actual)?}))
    }

    fn function(&mut self, function: &Value) -> R<Value> {
        let fn_name = name(&function["name"])?;
        let signature = self.signatures[&fn_name].clone();
        let blocks = array(&function["blocks"], "nominal blocks")?;
        if blocks.is_empty() || blocks.len() > super::MAX_BLOCKS { return failure("E_HIA_CFG", "invalid nominal block count"); }
        let mut signatures = BTreeMap::new();
        let mut flat_blocks = BTreeMap::new();
        let mut definitions = BTreeSet::new();
        for block in blocks {
            let fields = object(block, &["id", "params", "ops", "term"], "nominal block")?;
            let n = name(&fields["id"])?;
            let params = self.types.parameters(&fields["params"])?;
            if signatures.insert(n.clone(), params.clone()).is_some() { return failure("E_HIA_CFG", "duplicate nominal block"); }
            self.reserve_values(&params)?;
            flat_blocks.insert(n, self.flat_parameters(&params)?);
            let mut current = params.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
            for instruction in array(&fields["ops"], "nominal operations")? {
                let item = object(instruction, &["op", "args", "out", "attrs"], "nominal instruction")?;
                let op = string(&item["op"], "nominal opcode")?;
                if !item["attrs"].is_object() { return failure("E_HIA_FORMAT", "instruction attributes must be an object"); }
                if (op.starts_with("record.") && !matches!(op, "record.make" | "record.get" | "record.unpack"))
                    || op.starts_with("enum.") || op.starts_with("task.") {
                    return failure("E_HIA_RUST_UNSUPPORTED", "operation is outside the Copy-record candidate");
                }
                names(&item["args"])?;
                let outputs = self.types.parameters(&item["out"])?;
                self.reserve_values(&outputs)?;
                current.extend(outputs.into_iter().map(|(n, _)| n));
            }
            for n in current {
                if !definitions.insert(n) { return failure("E_HIA_SSA", "nominal SSA value defined twice"); }
            }
        }
        let entry = name(&function["entry"])?;
        if signatures.get(&entry) != Some(&signature.params) {
            return failure("E_HIA_CFG", "nominal entry parameters differ from function signature");
        }
        self.reserve_emitted(flat_blocks[&entry].0.len())?;
        let function_params = flat_blocks[&entry].0.clone();
        let mut lowered = Vec::new();
        for block in blocks {
            let id = name(&block["id"])?;
            let (parameters, mut env) = flat_blocks.remove(&id).unwrap();
            let mut ops = Vec::new();
            for instruction in array(&block["ops"], "nominal operations")? {
                let op = string(&instruction["op"], "nominal opcode")?;
                let args = names(&instruction["args"])?;
                // Keep references until widths have been admitted. Cloning a
                // wide binding per repeated source argument would expand the
                // program before flatten() gets a chance to refuse it.
                let actual = args.iter().map(|n| value(&env, n)).collect::<R<Vec<_>>>()?;
                let declared = self.types.parameters(&instruction["out"])?;
                let attrs = &instruction["attrs"];
                match op {
                    "record.make" => {
                        object(attrs, &[], op)?;
                        let [(out, Type::Record(record))] = declared.as_slice() else {
                            return failure("E_HIA_TYPE", "record.make requires one nominal record output");
                        };
                        let fields = &self.types.layouts[record].fields;
                        if actual.iter().map(|b| &b.ty).ne(fields.iter().map(|(_, t)| t)) {
                            return failure("E_HIA_TYPE", "record.make nominal fields differ before erasure");
                        }
                        env.insert(out.clone(), Binding { ty: Type::Record(record.clone()),
                            names: actual.iter().flat_map(|b| b.names.iter().cloned()).collect(),
                            consumed: false, external: false });
                    }
                    "record.unpack" | "record.get" => {
                        object(attrs, if op == "record.get" { &["field"] } else { &[] }, op)?;
                        let [binding] = actual.as_slice() else { return failure("E_HIA_TYPE", "record access requires one record"); };
                        let Type::Record(record) = &binding.ty else { return failure("E_HIA_TYPE", "record access requires a nominal record"); };
                        let fields = &self.types.layouts[record].fields;
                        let field = if op == "record.get" { Some(name(&attrs["field"])?) } else { None };
                        let mut offset = 0;
                        let mut selected = Vec::new();
                        for (n, ty) in fields {
                            let width = self.types.width(ty);
                            if field.as_ref().is_none_or(|f| f == n) {
                                selected.push((ty.clone(), binding.names[offset..offset + width].to_vec()));
                            }
                            offset += width;
                        }
                        if field.is_some() && selected.is_empty() { return failure("E_HIA_TYPE", "unknown nominal field"); }
                        output_types(&declared, &selected.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>())?;
                        for ((out, _), (ty, selected_names)) in declared.iter().zip(selected) {
                            env.insert(out.clone(), Binding { ty, names: selected_names, consumed: false, external: false });
                        }
                    }
                    "call" => {
                        object(attrs, &["function"], op)?;
                        let callee = name(&attrs["function"])?;
                        let Some(called) = self.signatures.get(&callee).cloned() else { return failure("E_HIA_CALL", "unknown nominal callee"); };
                        if actual.iter().map(|b| &b.ty).ne(called.params.iter().map(|(_, t)| t)) {
                            return failure("E_HIA_CALL", "nominal call arguments differ before erasure");
                        }
                        output_types(&declared, &called.returns)?;
                        let flat_args = self.flatten(&actual)?;
                        let consumed = args.iter().zip(&actual).filter(|(_, binding)| binding.ty.owns())
                            .map(|(n, _)| n.clone()).collect::<Vec<_>>();
                        drop(actual);
                        for n in consumed { consume(&mut env, &n)?; }
                        let (flat_out, outputs) = self.flat_parameters(&declared)?;
                        env.extend(outputs.into_iter().map(|(n, mut b)| { b.external = false; (n, b) }));
                        ops.push(json!({"op":"call", "args":flat_args, "out":flat_out, "attrs":{"function":callee}}));
                    }
                    _ => {
                        if actual.iter().any(|b| matches!(b.ty, Type::Record(_)))
                            || declared.iter().any(|(_, t)| matches!(t, Type::Record(_))) {
                            return failure("E_HIA_TYPE", "primitive operation cannot reinterpret a nominal value");
                        }
                        let flat_args = self.flatten(&actual)?;
                        drop(actual);
                        if matches!(op, "owner.move" | "owner.drop" | "loan.end") {
                            for n in &args { consume(&mut env, n)?; }
                        }
                        let (flat_out, outputs) = self.flat_parameters(&declared)?;
                        env.extend(outputs.into_iter().map(|(n, mut b)| { b.external = false; (n, b) }));
                        ops.push(json!({"op":op,"args":flat_args,"out":flat_out,"attrs":attrs}));
                    }
                }
            }
            let term = &block["term"];
            let lowered_term = match string(&term["op"], "nominal terminator")? {
                "jump" => {
                    object(term, &["op", "target", "args"], "nominal jump")?;
                    let edge = self.edge(&json!({"target":term["target"], "args":term["args"]}), &env, &signatures)?;
                    json!({"op":"jump", "target":edge["target"], "args":edge["args"]})
                }
                "branch" => {
                    object(term, &["op", "cond", "then", "else"], "nominal branch")?;
                    let cond = value(&env, &name(&term["cond"])?)?;
                    if cond.ty != Type::Primitive("bool".into()) { return failure("E_HIA_CFG", "nominal branch condition must be bool"); }
                    json!({"op":"branch", "cond":cond.names[0],
                        "then":self.edge(&term["then"], &env, &signatures)?,
                        "else":self.edge(&term["else"], &env, &signatures)?})
                }
                "ret" => {
                    object(term, &["op", "values"], "nominal return")?;
                    let selected = names(&term["values"])?;
                    let actual = selected.iter().map(|n| value(&env, n)).collect::<R<Vec<_>>>()?;
                    if actual.iter().map(|b| &b.ty).ne(signature.returns.iter()) {
                        return failure("E_HIA_TYPE", "nominal return types differ before erasure");
                    }
                    let flat_returns = self.flatten(&actual)?;
                    drop(actual);
                    for n in selected { consume(&mut env, &n)?; }
                    if !live(&env).is_empty() { return failure("E_HIA_RESOURCE", "return leaves a live nominal value"); }
                    json!({"op":"ret", "values":flat_returns})
                }
                "trap" => { object(term, &["op", "code"], "nominal trap")?; term.clone() }
                _ => return failure("E_HIA_RUST_UNSUPPORTED", "terminator is outside the Copy-record candidate"),
            };
            lowered.push(json!({"id":id,"params":parameters,"ops":ops,"term":lowered_term}));
        }
        let return_count = self.counted_widths(signature.returns.iter().map(|t| self.types.width(t)))?;
        self.reserve_emitted(return_count)?;
        let returns = signature.returns.iter().flat_map(|t| self.types.flat(t)).collect::<Vec<_>>();
        Ok(json!({"name":fn_name,"params":function_params,"returns":returns,
            "effects":function["effects"],"entry":entry,"blocks":lowered}))
    }

    fn lower(&mut self, document: &Value) -> R<Value> {
        let functions = array(&document["functions"], "functions")?.iter()
            .map(|f| self.function(f)).collect::<R<Vec<_>>>()?;
        let exports = self.signatures.iter().filter(|(_, signature)|
            signature.params.iter().all(|(_, t)| t.public_scalar()) && signature.returns.iter().all(Type::public_scalar))
            .map(|(n, _)| n.clone()).collect::<Vec<_>>();
        Ok(json!({"schema":"hepta.hia.program.v6","module":document["module"],"exports":exports,"functions":functions}))
    }
}

struct Normalized { input_sha256: String, core: Value, bytes: Vec<u8>, core_sha256: String }

fn checked_core(input: &[u8]) -> R<Normalized> {
    let (document, canonical) = super::decode_hia(input)?;
    let core = Lower::new(&document)?.lower(&document)?;
    let bytes = serde_json::to_vec(&core).map_err(|error| super::VerifyError {
        code: "E_HIA_FORMAT", detail: error.to_string(),
    })?;
    // No nominal output or execution can escape without the same existing
    // full-module primitive ownership/CFG/effect checker accepting the bytes.
    let verified = super::verify_owned(&bytes)?;
    Ok(Normalized { input_sha256: format!("{:x}", Sha256::digest(&canonical)), core, bytes,
        core_sha256: verified["program_sha256"].as_str().unwrap().to_owned() })
}

fn claims() -> Value {
    json!({"raw_monomorphic_copy_records_checked":true,"same_primitive_core_reverified":true,
        "python_normalizer_or_runtime_used":false,"general_composite_input_supported":false,
        "rust_is_production_admission_authority":false,"whole_language_soundness_proved":false,
        "native_backend_refinement_proved":false})
}

/// Normalize only the explicit monomorphic Copy-record input candidate.
/// Returned JSON is descriptive; no API imports it as admission authority.
pub fn normalize_composite_records(input: &[u8]) -> R<Value> {
    let normalized = checked_core(input)?;
    Ok(json!({"schema":"hepta.hia.rust-copy-record-normalization.v1", "profile":PROFILE,
        "input_sha256":normalized.input_sha256,"program_sha256":normalized.core_sha256,
        "core":normalized.core,"claims":claims()}))
}

/// Read raw nominal input, check/erase it here, and invoke the same bound-v4
/// primitive Machine. The new outer request also binds the nominal origin.
pub fn execute_composite_records_bound(input: &[u8], function: &str, arguments: &[Value], policy: &[u8]) -> R<Value> {
    let normalized = checked_core(input)?;
    let primitive = super::execute_owned_bound_v4(&normalized.bytes, function, arguments, policy)?;
    let request = json!({"schema":"hepta.hia.rust-copy-record-request.v1","profile":PROFILE,
        "input_sha256":normalized.input_sha256,"program_sha256":normalized.core_sha256,
        "function":function,"arguments":arguments,"policy":primitive["request"]["policy"]});
    let encoded = serde_json::to_vec(&request).map_err(|error| super::VerifyError {
        code:"E_HIA_FORMAT",detail:error.to_string(),
    })?;
    Ok(json!({"schema":"hepta.hia.rust-copy-record-bound-execution.v1",
        "request_sha256":format!("{:x}",Sha256::digest(&encoded)),"request":request,
        "execution":primitive["execution"],"claims":claims()}))
}
