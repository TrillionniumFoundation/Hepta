//! Independent structural upper bounds over the existing checked byte-owner Core.
//!
//! The complete module is checked before graph analysis. This optional profile
//! accepts only audited primitive v1-v8 byte operations and acyclic call/CFG
//! graphs. Each metric is a separate conservative maximum; their maxima need
//! not occur on one feasible execution. Ticks are VM events, never native time.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{array, decode_hia, failure, string, term_edges, verify_owned, R};

const PROFILE: &str = "acyclic-byte-owner-v1-v8-u64-bounds";

#[derive(Clone, Copy, Default)]
struct Bound {
    allocator: u64,
    ticks: u64,
    depth: u64,
}

fn add(a: u64, b: u64) -> R<u64> {
    a.checked_add(b).ok_or_else(|| super::VerifyError {
        code: "E_HIA_BUDGET_OVERFLOW",
        detail: "finite bound exceeds the explicit u64 analysis profile".into(),
    })
}

pub(super) fn topological(edges: &BTreeMap<String, BTreeSet<String>>, context: &str) -> R<Vec<String>> {
    let mut incoming: BTreeMap<String, usize> = edges.keys().map(|name| (name.clone(), 0)).collect();
    for targets in edges.values() {
        for target in targets {
            let Some(degree) = incoming.get_mut(target) else {
                return failure("E_HIA_BUDGET_GRAPH", "unknown graph dependency");
            };
            *degree += 1;
        }
    }
    let mut ready: VecDeque<String> = incoming.iter()
        .filter(|(_, degree)| **degree == 0).map(|(name, _)| name.clone()).collect();
    let mut result = Vec::new();
    while let Some(name) = ready.pop_front() {
        result.push(name.clone());
        for target in &edges[&name] {
            let degree = incoming.get_mut(target).ok_or_else(|| super::VerifyError {
                code: "E_HIA_BUDGET_GRAPH", detail: "missing graph dependency".into(),
            })?;
            *degree -= 1;
            if *degree == 0 { ready.push_back(target.clone()); }
        }
    }
    if result.len() != edges.len() {
        return failure("E_HIA_BUDGET_UNBOUNDED", format!("{context}: cycles need a separate invariant"));
    }
    Ok(result)
}

fn audited_type(ty: &Value) -> R<()> {
    if !matches!(string(ty, "static budget type")?,
        "i8" | "i16" | "i32" | "i64" | "isize" |
        "u8" | "u16" | "u32" | "u64" | "usize" |
        "bool" | "unit" | "buffer" | "readbuf" | "mutbuf") {
        return failure("E_HIA_BUDGET_PROFILE", "unreviewed or recursive-chain type in byte-only budget");
    }
    Ok(())
}

fn audited_parameters(params: &Value) -> R<()> {
    for parameter in array(params, "static budget parameters")? {
        audited_type(&parameter["type"])?;
    }
    Ok(())
}

fn audit_module(functions: &[Value]) -> R<()> {
    for function in functions {
        audited_parameters(&function["params"])?;
        for ty in array(&function["returns"], "static budget returns")? { audited_type(ty)?; }
        for block in array(&function["blocks"], "static budget blocks")? {
            audited_parameters(&block["params"])?;
            for instruction in array(&block["ops"], "static budget instructions")? {
                audited_parameters(&instruction["out"])?;
                if !matches!(string(&instruction["op"], "static budget opcode")?,
                    "const" | "int.cast" | "int.neg.checked" | "select" |
                    "bool.not" | "bool.and" | "bool.or" |
                    "bit.and" | "bit.or" | "bit.xor" | "bit.not" |
                    "compare.eq" | "compare.ne" | "compare.lt" | "compare.le" | "compare.gt" | "compare.ge" |
                    "int.add.checked" | "int.sub.checked" | "int.mul.checked" |
                    "int.add.wrap" | "int.sub.wrap" | "int.mul.wrap" |
                    "int.div.checked" | "int.rem.checked" | "int.shl.checked" | "int.shr.checked" |
                    "buffer.new" | "buffer.try_new" | "buffer.len" | "borrow.read" | "borrow.mut" |
                    "loan.end" | "owner.move" | "owner.drop" | "buffer.load" | "buffer.store" |
                    "buffer.fill" | "buffer.copy" | "buffer.move_within" | "buffer.swap" |
                    "buffer.copy_range" | "buffer.fill_range" | "call") {
                    return failure("E_HIA_BUDGET_PROFILE", "unreviewed opcode in byte-only budget");
                }
            }
        }
    }
    Ok(())
}

fn bound_function(function: &Value, calculated: &BTreeMap<String, Bound>) -> R<Bound> {
    let mut blocks = BTreeMap::<String, &Value>::new();
    let mut edges = BTreeMap::<String, BTreeSet<String>>::new();
    for block in array(&function["blocks"], "static budget blocks")? {
        let name = string(&block["id"], "block name")?.to_owned();
        let targets = term_edges(&block["term"])?.into_iter().map(|edge| edge.target).collect();
        blocks.insert(name.clone(), block);
        edges.insert(name, targets);
    }
    let order = topological(&edges, "control flow")?;
    let mut values = BTreeMap::<String, Bound>::new();
    for name in order.into_iter().rev() {
        let block = blocks[&name];
        let operations = array(&block["ops"], "static budget instructions")?;
        let mut local = Bound { ticks: add(operations.len() as u64, 1)?, depth: 1, allocator: 0 };
        for instruction in operations {
            let opcode = string(&instruction["op"], "static budget opcode")?;
            if matches!(opcode, "buffer.new" | "buffer.try_new" | "owner.drop") {
                local.allocator = add(local.allocator, 1)?;
            }
            if opcode == "call" {
                let name = string(&instruction["attrs"]["function"], "callee")?;
                let Some(child) = calculated.get(name) else {
                    return failure("E_HIA_BUDGET_GRAPH", "callee bound is unavailable");
                };
                local.allocator = add(local.allocator, child.allocator)?;
                local.ticks = add(local.ticks, child.ticks)?;
                local.depth = local.depth.max(add(1, child.depth)?);
            }
        }
        // Alternatives use independent maxima. Sequential calls add cost;
        // mutually exclusive branches are not summed into an exact path claim.
        let mut suffix = Bound::default();
        for target in &edges[&name] {
            let Some(next) = values.get(target) else {
                return failure("E_HIA_BUDGET_GRAPH", "successor bound is unavailable");
            };
            suffix.allocator = suffix.allocator.max(next.allocator);
            suffix.ticks = suffix.ticks.max(next.ticks);
            suffix.depth = suffix.depth.max(next.depth);
        }
        local.allocator = add(local.allocator, suffix.allocator)?;
        local.ticks = add(local.ticks, suffix.ticks)?;
        local.depth = local.depth.max(suffix.depth);
        values.insert(name, local);
    }
    let entry = string(&function["entry"], "function entry")?;
    let Some(mut result) = values.get(entry).copied() else {
        return failure("E_HIA_BUDGET_GRAPH", "entry bound is unavailable");
    };
    result.ticks = add(result.ticks, 1)?; // one function-entry event
    Ok(result)
}

/// Recheck an entire primitive module and bound each byte-only acyclic invocation.
/// This does not execute code, accept a producer receipt, or grant native use.
pub fn analyze_static_budget(input: &[u8]) -> R<Value> {
    verify_owned(input)?;
    let (document, canonical) = decode_hia(input)?;
    let functions = array(&document["functions"], "functions")?;
    audit_module(functions)?;
    let mut named = BTreeMap::<String, &Value>::new();
    let mut calls = BTreeMap::<String, BTreeSet<String>>::new();
    for function in functions {
        let name = string(&function["name"], "function name")?.to_owned();
        let mut callees = BTreeSet::new();
        for block in array(&function["blocks"], "blocks")? {
            for instruction in array(&block["ops"], "instructions")? {
                if instruction["op"] == "call" {
                    callees.insert(string(&instruction["attrs"]["function"], "callee")?.to_owned());
                }
            }
        }
        named.insert(name.clone(), function);
        calls.insert(name, callees);
    }
    let mut calculated = BTreeMap::new();
    for name in topological(&calls, "call graph")?.into_iter().rev() {
        calculated.insert(name.clone(), bound_function(named[&name], &calculated)?);
    }
    let mut rows = Vec::new();
    for function in functions {
        let name = string(&function["name"], "function name")?;
        let bound = calculated[name];
        rows.push(json!({"function": name, "max_allocator_interactions": bound.allocator,
                         "max_vm_ticks": bound.ticks, "max_call_depth": bound.depth}));
    }
    Ok(json!({
        "schema": "hepta.hia.rust-static-budget.v1", "profile": PROFILE,
        "status": "conservative_structural_upper_bounds_not_authority",
        "program_sha256": format!("{:x}", Sha256::digest(&canonical)),
        "core_schema": document["schema"], "functions": rows,
        "claims": {"whole_module_independently_checked": true,
            "byte_only_acyclic_cfg_and_call_graph_checked": true,
            "per_metric_conservative_upper_bounds": true,
            "exact_feasible_path_maxima_proved": false,
            "u64_bound_overflow_rejected": true,
            "live_heap_or_process_rss_bounded": false,
            "native_time_or_stack_bytes_bounded": false,
            "recursive_chain_costs_bounded": false,
            "rust_is_production_admission_authority": false,
            "whole_language_soundness_proved": false,
            "native_backend_refinement_proved": false}
    }))
}
