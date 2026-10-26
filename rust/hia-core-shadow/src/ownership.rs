//! Conservative Rust shadow of HIA v1 Owner/Loan control-flow semantics.
//! The existing Python verify_program is still the sole admission authority.
//! This shadow refuses interprocedural owners, arbitrary pointers, SIMD,
//! unknown instructions and all v2-v6 bulk-memory extensions.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{array, effects, failure, ident, names, object, string, term_edges,
            instruction as scalar_instruction, R, Signature, VerifyError};

fn is_cap(t: &str) -> bool { matches!(t, "buffer" | "readbuf" | "mutbuf") }
fn valid_type(v: &Value) -> R<String> {
    let t = string(v, "type")?;
    if is_cap(t) || matches!(t, "i8"|"i16"|"i32"|"i64"|"isize"|
       "u8"|"u16"|"u32"|"u64"|"usize"|"bool"|"unit") {
        Ok(t.into())
    } else { failure("E_HIA_TYPE", "unsupported type") }
}
#[derive(Clone, PartialEq, Eq)]
struct Param { name: String, ty: String }
fn params(v: &Value) -> R<Vec<Param>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for x in array(v, "parameters")? {
        let p = object(x, &["name", "type"], "parameter")?;
        let n = ident(&p["name"])?;
        if !seen.insert(n.clone()) { return failure("E_HIA_SSA", "duplicate parameter"); }
        out.push(Param { name: n, ty: valid_type(&p["type"])? });
    }
    Ok(out)
}
#[derive(Clone, PartialEq, Eq)]
struct Cap { ty: String, root: String, parent: Option<String>, external: bool }
type Caps = BTreeMap<String, Cap>;
struct Flow {
    vars: BTreeMap<String, String>,
    caps: Caps,
    required: BTreeSet<String>,
}
impl Flow {
    fn new(parameters: &[Param], caps: Caps) -> Self {
        Self {
            vars: parameters.iter().map(|p| (p.name.clone(), p.ty.clone())).collect(),
            caps, required: BTreeSet::new(),
        }
    }
    fn ty(&self, name: &str) -> R<String> {
        let Some(t) = self.vars.get(name) else {
            return failure("E_HIA_SSA", "value is not local to its block");
        };
        if is_cap(t) && !self.caps.contains_key(name) {
            return failure("E_HIA_RESOURCE", "use after move/end/drop");
        }
        Ok(t.clone())
    }
    fn cap(&self, name: &str) -> R<&Cap> {
        self.caps.get(name).ok_or_else(|| VerifyError {
            code: "E_HIA_RESOURCE", detail: "resource is not live".into()
        })
    }
    fn has_child(&self, name: &str) -> bool {
        self.caps.values().any(|c| c.parent.as_deref() == Some(name))
    }
    fn owner_free(&self, name: &str) -> R<()> {
        if self.ty(name)? != "buffer" {
            return failure("E_HIA_TYPE", "move/drop/return requires owner");
        }
        if self.caps.iter().any(|(other, c)| other.as_str() != name && c.root == name) {
            return failure("E_HIA_LOAN", "owner still has live loans");
        }
        Ok(())
    }
    fn access(&self, name: &str, mutable: bool) -> R<()> {
        let ty = self.ty(name)?;
        if (mutable && ty != "mutbuf") ||
           (!mutable && !matches!(ty.as_str(), "readbuf" | "mutbuf")) {
            return failure("E_HIA_TYPE", "read/write requires correct loan");
        }
        if self.has_child(name) { return failure("E_HIA_LOAN", "parent is suspended"); }
        Ok(())
    }
    fn borrow(&mut self, name: &str, output: &str, mutable: bool) -> R<()> {
        let ty = self.ty(name)?;
        if (mutable && !matches!(ty.as_str(), "buffer" | "mutbuf"))
            || (!mutable && !is_cap(&ty)) {
            return failure("E_HIA_LOAN", "invalid loan permission");
        }
        let root = self.cap(name)?.root.clone();
        let mut ancestors = BTreeSet::from([name.to_owned()]);
        let mut parent = self.cap(name)?.parent.clone();
        while let Some(n) = parent {
            if !ancestors.insert(n.clone()) {
                return failure("E_HIA_LOAN", "cyclic loan ancestry");
            }
            parent = self.cap(&n)?.parent.clone();
        }
        if self.caps.iter().any(|(n, cap)| {
            cap.root == root && !ancestors.contains(n) &&
            (mutable || cap.ty == "mutbuf")
        }) {
            return failure("E_HIA_LOAN", "overlapping incompatible loans");
        }
        self.caps.insert(output.into(), Cap {
            ty: if mutable { "mutbuf" } else { "readbuf" }.into(),
            root, parent: Some(name.into()), external: false,
        });
        Ok(())
    }
    fn instr(&mut self, v: &Value, version: u8) -> R<()> {
        let o = object(v, &["op", "args", "out", "attrs"], "instruction")?;
        let op = string(&o["op"], "opcode")?;
        let args = names(&o["args"])?;
        let output = params(&o["out"])?;
        if !matches!(op, "buffer.new" | "buffer.try_new" | "buffer.len" |
            "borrow.read" | "borrow.mut" | "loan.end" | "owner.move" |
            "owner.drop" | "buffer.load" | "buffer.store" |
            "buffer.fill" | "buffer.copy" | "buffer.move_within" |
            "buffer.swap" | "buffer.copy_range" | "buffer.fill_range") {
            // Reuse, rather than reimplement, exact scalar instruction checks.
            // Calls, foreign resources and unknown extensions remain unsupported.
            if op == "call" {
                return failure("E_HIA_RUST_UNSUPPORTED", "resource calls not yet modeled");
            }
            let empty = BTreeMap::<String, Signature>::new();
            return scalar_instruction(v, &mut self.vars, &empty, &mut self.required);
        }
        object(&o["attrs"], &[], "resource attributes")?;
        if ((matches!(op, "buffer.fill" | "buffer.copy") && version < 2)
            || (op == "buffer.move_within" && version < 3)
            || (op == "buffer.swap" && version < 4)
            || (op == "buffer.copy_range" && version < 5)
            || (op == "buffer.fill_range" && version < 6)) {
            return failure("E_HIA_OPCODE", "memory opcode outside declared ISA version");
        }
        let actual: Vec<String> = args.iter().map(|n| self.ty(n)).collect::<R<_>>()?;
        let actual: Vec<&str> = actual.iter().map(String::as_str).collect();
        let expected: Vec<&str> = match op {
            "buffer.new" | "buffer.try_new" => {
                if actual.as_slice() != ["usize"] { return failure("E_HIA_TYPE", "size must be usize"); }
                self.required.insert("alloc".into());
                if op == "buffer.new" {
                    self.required.insert("trap".into());
                    vec!["buffer"]
                } else { vec!["buffer", "bool"] }
            }
            "buffer.len" => {
                if actual.len() != 1 || !is_cap(actual[0]) {
                    return failure("E_HIA_TYPE", "buffer.len needs live resource");
                }
                vec!["usize"]
            }
            "borrow.read" | "borrow.mut" => {
                if actual.len() != 1 { return failure("E_HIA_TYPE", "borrow arity"); }
                if (op == "borrow.mut" && !matches!(actual[0], "buffer"|"mutbuf"))
                    || (op == "borrow.read" && !is_cap(actual[0])) {
                    return failure("E_HIA_LOAN", "borrow type mismatch");
                }
                vec![if op == "borrow.read" { "readbuf" } else { "mutbuf" }]
            }
            "loan.end" => {
                if actual.len() != 1 || !matches!(actual[0], "readbuf"|"mutbuf") {
                    return failure("E_HIA_TYPE", "loan.end type/arity");
                }
                if self.cap(&args[0])?.external {
                    return failure("E_HIA_LOAN", "cannot end foreign caller loan");
                }
                if self.has_child(&args[0]) {
                    return failure("E_HIA_LOAN", "child loan must end first");
                }
                vec![]
            }
            "owner.move" | "owner.drop" => {
                if actual.len() != 1 { return failure("E_HIA_TYPE", "owner arity"); }
                self.owner_free(&args[0])?;
                if op == "owner.drop" {
                    self.required.insert("alloc".into());
                    vec![]
                } else { vec!["buffer"] }
            }
            "buffer.load" => {
                if actual.len() != 2 || actual[1] != "usize" {
                    return failure("E_HIA_TYPE", "load type/arity");
                }
                self.access(&args[0], false)?;
                self.required.extend(["read".into(), "trap".into()]);
                vec!["u8"]
            }
            "buffer.store" => {
                if actual.len() != 3 || actual[1] != "usize" || actual[2] != "u8" {
                    return failure("E_HIA_TYPE", "store type/arity");
                }
                self.access(&args[0], true)?;
                self.required.extend(["write".into(), "trap".into()]);
                vec![]
            }
            "buffer.fill" => {
                if actual.as_slice() != ["mutbuf", "u8"] {
                    return failure("E_HIA_TYPE", "fill requires mutable view and u8");
                }
                self.access(&args[0], true)?;
                self.required.insert("write".into());
                vec![]
            }
            "buffer.copy" => {
                if actual.as_slice() != ["mutbuf", "readbuf", "usize"] {
                    return failure("E_HIA_TYPE", "copy requires mutable/read views and usize");
                }
                self.access(&args[0], true)?;
                self.access(&args[1], false)?;
                if self.cap(&args[0])?.root.as_str() == self.cap(&args[1])?.root.as_str() {
                    return failure("E_HIA_LOAN", "memcpy requires distinct owner roots");
                }
                self.required.extend(["read".into(), "write".into(), "trap".into()]);
                vec![]
            }
            "buffer.move_within" => {
                if actual.as_slice() != ["mutbuf", "usize", "usize", "usize"] {
                    return failure("E_HIA_TYPE", "move_within requires mutable view and three usize");
                }
                self.access(&args[0], true)?;
                self.required.extend(["read".into(), "write".into(), "trap".into()]);
                vec![]
            }
            "buffer.swap" => {
                if actual.as_slice() != ["mutbuf", "usize", "usize"] {
                    return failure("E_HIA_TYPE", "swap requires mutable view and two usize");
                }
                self.access(&args[0], true)?;
                self.required.extend(["read".into(), "write".into(), "trap".into()]);
                vec![]
            }
            "buffer.copy_range" => {
                if actual.as_slice() != ["mutbuf", "readbuf", "usize", "usize", "usize"] {
                    return failure("E_HIA_TYPE", "copy_range typed operands mismatch");
                }
                self.access(&args[0], true)?;
                self.access(&args[1], false)?;
                if self.cap(&args[0])?.root.as_str() == self.cap(&args[1])?.root.as_str() {
                    return failure("E_HIA_LOAN", "copy_range requires distinct owner roots");
                }
                self.required.extend(["read".into(), "write".into(), "trap".into()]);
                vec![]
            }
            "buffer.fill_range" => {
                if actual.as_slice() != ["mutbuf", "usize", "usize", "u8"] {
                    return failure("E_HIA_TYPE", "fill_range typed operands mismatch");
                }
                self.access(&args[0], true)?;
                self.required.extend(["write".into(), "trap".into()]);
                vec![]
            }
            _ => return failure("E_HIA_RUST_UNSUPPORTED", "unqualified resource opcode"),
        };
        if output.iter().map(|p| p.ty.as_str()).collect::<Vec<_>>() != expected {
            return failure("E_HIA_TYPE", "resource opcode result mismatch");
        }
        for p in &output {
            if self.vars.insert(p.name.clone(), p.ty.clone()).is_some() {
                return failure("E_HIA_SSA", "SSA name reused");
            }
        }
        match op {
            "buffer.new" | "buffer.try_new" => {
                let n = output[0].name.clone();
                self.caps.insert(n.clone(), Cap {
                    ty: "buffer".into(), root: n, parent: None, external: false,
                });
            }
            "borrow.read" | "borrow.mut" => {
                self.borrow(&args[0], &output[0].name, op == "borrow.mut")?;
            }
            "loan.end" | "owner.drop" => { self.caps.remove(&args[0]); }
            "owner.move" => {
                self.caps.remove(&args[0]);
                let n = output[0].name.clone();
                self.caps.insert(n.clone(), Cap {
                    ty: "buffer".into(), root: n, parent: None, external: false,
                });
            }
            _ => {}
        }
        Ok(())
    }
    fn finish(&mut self, term: &Value, results: &[String],
              declared: &BTreeSet<String>) -> R<()> {
        let op = string(&term["op"], "terminator")?;
        if op == "branch" && self.ty(&ident(&term["cond"])?)? != "bool" {
            return failure("E_HIA_CFG", "branch condition is not bool");
        }
        if op == "ret" {
            let vals = names(&term["values"])?;
            let types: Vec<String> = vals.iter().map(|n| self.ty(n)).collect::<R<_>>()?;
            if types.as_slice() != results { return failure("E_HIA_TYPE", "return mismatch"); }
            let mut consumed = BTreeSet::new();
            for (n, t) in vals.iter().zip(&types) {
                if t == "buffer" {
                    if !consumed.insert(n.clone()) {
                        return failure("E_HIA_RESOURCE", "owner returned twice");
                    }
                    self.owner_free(n)?;
                }
            }
            for n in consumed { self.caps.remove(&n); }
            if self.caps.values().any(|c| !c.external) {
                return failure("E_HIA_RESOURCE", "normal return leaks local resource");
            }
        }
        if op == "trap" { self.required.insert("trap".into()); }
        if !self.required.is_subset(declared) {
            return failure("E_HIA_EFFECT", "missing required effects");
        }
        Ok(())
    }
    fn forward(&self, args: &[String], target: &[Param]) -> R<Caps> {
        if args.len() != target.len() { return failure("E_HIA_CFG", "edge arity"); }
        let types: Vec<String> = args.iter().map(|n| self.ty(n)).collect::<R<_>>()?;
        if types != target.iter().map(|p| p.ty.clone()).collect::<Vec<_>>() {
            return failure("E_HIA_CFG", "edge type mismatch");
        }
        let resources: Vec<&String> = args.iter().zip(&types)
            .filter_map(|(n, t)| is_cap(t).then_some(n)).collect();
        let forwarded_names: BTreeSet<String> = resources.iter().map(|n| n.as_str().to_owned()).collect();
        if forwarded_names.len() != resources.len() {
            return failure("E_HIA_RESOURCE", "duplicate linear edge argument");
        }
        for (n, c) in &self.caps {
            if !c.external && !forwarded_names.contains(n) {
                return failure("E_HIA_RESOURCE", "CFG edge silently drops owner/loan");
            }
        }
        let mapping: BTreeMap<String, String> = args.iter().zip(target)
            .filter(|(_, p)| is_cap(&p.ty))
            .map(|(n, p)| (n.clone(), p.name.clone())).collect();
        let mut caps = BTreeMap::new();
        for (name, p) in args.iter().zip(target).filter(|(_, p)| is_cap(&p.ty)) {
            let cap = self.cap(name)?;
            let Some(root) = mapping.get(&cap.root) else {
                return failure("E_HIA_LOAN", "borrow root not forwarded");
            };
            let parent = match &cap.parent {
                None => None,
                Some(x) => Some(mapping.get(x).ok_or_else(|| VerifyError {
                    code: "E_HIA_LOAN", detail: "borrow parent not forwarded".into()
                })?.clone())
            };
            caps.insert(p.name.clone(), Cap {
                ty: cap.ty.clone(), root: root.clone(), parent, external: cap.external,
            });
        }
        Ok(caps)
    }
}
fn check_function(f: &Value, version: u8) -> R<usize> {
    let function = object(f, &["name", "params", "returns", "effects", "entry", "blocks"], "function")?;
    let n = ident(&function["name"])?;
    if matches!(n.as_str(), "abort"|"calloc"|"malloc"|"free"|"memcpy"|"memmove"|"memset") {
        return failure("E_HIA_NAME", "reserved native symbol");
    }
    let formal = params(&function["params"])?;
    let mut results = Vec::new();
    for v in array(&function["returns"], "returns")? {
        let t = valid_type(v)?;
        if matches!(t.as_str(), "readbuf"|"mutbuf") {
            return failure("E_HIA_LOAN", "escaping loan unsupported");
        }
        results.push(t);
    }
    let declared = effects(&function["effects"])?;
    let entry = ident(&function["entry"])?;
    let blocks = array(&function["blocks"], "blocks")?;
    if blocks.is_empty() || blocks.len() > super::MAX_BLOCKS {
        return failure("E_HIA_CFG", "invalid block inventory");
    }
    let mut by_id: BTreeMap<String, &Value> = BTreeMap::new();
    let mut ps: BTreeMap<String, Vec<Param>> = BTreeMap::new();
    let mut definitions = BTreeSet::new();
    for block in blocks {
        let b = object(block, &["id", "params", "ops", "term"], "block")?;
        let id = ident(&b["id"])?;
        if by_id.insert(id.clone(), block).is_some() {
            return failure("E_HIA_CFG", "duplicate block");
        }
        let parameters = params(&b["params"])?;
        for p in &parameters {
            if !definitions.insert(p.name.clone()) {
                return failure("E_HIA_SSA", "globally duplicated parameter");
            }
        }
        for v in array(&b["ops"], "ops")? {
            let o = object(v, &["op", "args", "out", "attrs"], "instruction")?;
            string(&o["op"], "opcode")?;
            names(&o["args"])?;
            if !o["attrs"].is_object() {
                return failure("E_HIA_FORMAT", "attrs is not object");
            }
            for p in params(&o["out"])? {
                if !definitions.insert(p.name) {
                    return failure("E_HIA_SSA", "globally duplicated result");
                }
            }
        }
        term_edges(&b["term"])?;
        ps.insert(id, parameters);
    }
    if ps.get(&entry) != Some(&formal) {
        return failure("E_HIA_CFG", "entry signature mismatch");
    }
    let mut graph: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (id, b) in &by_id {
        let mut successors = Vec::new();
        for e in term_edges(&b["term"])? {
            let Some(target) = ps.get(&e.target) else {
                return failure("E_HIA_CFG", "unknown target");
            };
            if e.target == entry || e.args.len() != target.len() {
                return failure("E_HIA_CFG", "entry edge/arity mismatch");
            }
            successors.push(e.target);
        }
        graph.insert(id.clone(), successors);
    }
    let mut reachable = BTreeSet::new();
    let mut work = vec![entry.clone()];
    while let Some(n) = work.pop() {
        if reachable.insert(n.clone()) {
            work.extend(graph[&n].iter().cloned());
        }
    }
    if reachable.len() != by_id.len() {
        return failure("E_HIA_CFG", "unreachable basic block");
    }
    let initial: Caps = formal.iter().filter(|p| is_cap(&p.ty))
        .map(|p| (p.name.clone(), Cap {
            ty: p.ty.clone(), root: p.name.clone(),
            parent: None, external: p.ty != "buffer"
        })).collect();
    let mut incoming: BTreeMap<String, Caps> = BTreeMap::from([(entry.clone(), initial)]);
    let mut pending = VecDeque::from([entry]);
    let mut processed = BTreeSet::new();
    while let Some(n) = pending.pop_front() {
        if !processed.insert(n.clone()) { continue; }
        let b = by_id[&n];
        let mut flow = Flow::new(&ps[&n], incoming[&n].clone());
        for instr in array(&b["ops"], "operations")? {
            flow.instr(instr, version)?;
        }
        flow.finish(&b["term"], &results, &declared)?;
        for e in term_edges(&b["term"])? {
            let new = flow.forward(&e.args, &ps[&e.target])?;
            if let Some(prior) = incoming.get(&e.target) {
                if prior != &new {
                    return failure("E_HIA_LOAN", "incompatible loan/root CFG join");
                }
            } else {
                incoming.insert(e.target.clone(), new);
                pending.push_back(e.target);
            }
        }
    }
    if processed.len() != blocks.len() {
        return failure("E_HIA_CFG", "unvalidated block");
    }
    Ok(blocks.len())
}
pub(super) fn verify_owned(input: &[u8]) -> R<Value> {
    let (doc, canonical) = super::decode_hia(input)?;
    let top = object(&doc, &["schema", "module", "functions"], "program")?;
    let schema = string(&top["schema"], "schema")?;
    if !matches!(schema, "hepta.hia.program.v1" | "hepta.hia.program.v2" |
        "hepta.hia.program.v3" | "hepta.hia.program.v4" |
        "hepta.hia.program.v5" | "hepta.hia.program.v6") {
        return failure("E_HIA_SCHEMA", "unsupported/ambiguous ISA version");
    }
    let version = match schema {
        "hepta.hia.program.v1" => 1,
        "hepta.hia.program.v2" => 2,
        "hepta.hia.program.v3" => 3,
        "hepta.hia.program.v4" => 4,
        "hepta.hia.program.v5" => 5,
        "hepta.hia.program.v6" => 6,
        _ => return failure("E_HIA_SCHEMA", "unsupported ISA version"),
    };
    ident(&top["module"])?;
    let fs = array(&top["functions"], "functions")?;
    if fs.is_empty() || fs.len() > super::MAX_FUNCTIONS {
        return failure("E_HIA_FORMAT", "invalid function count");
    }
    let mut function_names = BTreeSet::new();
    let mut count = 0;
    for f in fs {
        let n = ident(&object(f, &["name", "params", "returns", "effects", "entry", "blocks"], "function")?["name"])?;
        if !function_names.insert(n) {
            return failure("E_HIA_NAME", "duplicate function");
        }
        count += check_function(f, version)?;
    }
    let digest = Sha256::digest(&canonical);
    Ok(json!({
        "schema": "hepta.hia.rust-owner-shadow.v1",
        "ok": true,
        "program_sha256": format!("{digest:x}"),
        "functions_checked": fs.len(), "blocks_checked": count,
        "claims": {
            "finite_owner_loan_cfg_checked": true,
            "cross_block_owner_loan_state_checked": true,
            "v2_v6_bulk_byte_opcode_types_loans_and_effects_checked": true,
            "interprocedural_resource_calls_checked": false,
            "general_memory_provenance_proved": false,
            "full_source_to_core_refinement_proved": false,
            "llvm_backend_refinement_proved": false,
            "whole_language_soundness_proved": false,
            "native_execution_qualified": false,
            "rust_is_production_admission_authority": false
        }
    }))
}
