use hia_core_shadow::{execute_owned, OwnedOptions};
use serde_json::{json, Value};

fn program() -> Value {
    json!({
        "schema":"hepta.hia.program.v1", "module":"owned_oracle",
        "functions":[{
            "name":"exercise", "params":[{"name":"size","type":"usize"}],
            "returns":["u8"], "effects":["alloc","write","read","trap"],
            "entry":"entry", "blocks":[{
                "id":"entry", "params":[{"name":"size","type":"usize"}],
                "ops":[
                    {"op":"buffer.new","args":["size"],"out":[{"name":"owner","type":"buffer"}],"attrs":{}},
                    {"op":"borrow.mut","args":["owner"],"out":[{"name":"view","type":"mutbuf"}],"attrs":{}},
                    {"op":"const","args":[],"out":[{"name":"zero","type":"usize"}],"attrs":{"value":0}},
                    {"op":"const","args":[],"out":[{"name":"byte","type":"u8"}],"attrs":{"value":41}},
                    {"op":"buffer.store","args":["view","zero","byte"],"out":[],"attrs":{}},
                    {"op":"buffer.load","args":["view","zero"],"out":[{"name":"answer","type":"u8"}],"attrs":{}},
                    {"op":"loan.end","args":["view"],"out":[],"attrs":{}},
                    {"op":"owner.move","args":["owner"],"out":[{"name":"moved","type":"buffer"}],"attrs":{}},
                    {"op":"owner.drop","args":["moved"],"out":[],"attrs":{}}
                ],
                "term":{"op":"ret","values":["answer"]}
            }]
        }]
    })
}

fn run(program: &Value, size: u64, options: OwnedOptions) -> Value {
    execute_owned(&serde_json::to_vec(program).unwrap(), "exercise",
                  &[json!(size)], options).unwrap()
}

#[test]
fn reads_writes_and_moves_execute_with_exact_cleanup() {
    let result = run(&program(), 7, OwnedOptions::default());
    assert_eq!(result["schema"], "hepta.hia.rust-owned-execution.v2");
    assert_eq!(result["program_schema"], "hepta.hia.program.v1");
    assert_eq!(result["claims"]["primitive_v1_v7_resource_execution"], true);
    assert!(result["claims"].get("finite_v1_byte_resource_execution").is_none());
    assert_eq!(result["status"], "returned");
    assert_eq!(result["values"], json!([41]));
    assert_eq!(result["steps"], 11);
    assert_eq!(result["resources"], json!({
        "allocations":1,"frees":1,"allocation_attempts":1,
        "owners_created":1,"owners_dropped":1,"live_owners":0,
        "live_bytes":0,"peak_bytes":7,"loans_started":1,
        "loans_ended":1,"live_local_loans":0,
    }));
    assert_eq!(result["claims"]["production_admission_authorized"], false);
    assert_eq!(result["claims"]["native_backend_refinement_proved"], false);
}

#[test]
fn bounds_trap_and_host_budget_do_not_fabricate_resource_cleanup() {
    let result = run(&program(), 0, OwnedOptions::default());
    assert_eq!(result["status"], "trapped");
    assert_eq!(result["error"]["code"], "bounds");
    assert_eq!(result["resources"]["allocation_attempts"], 0);
    assert_eq!(result["resources"]["live_owners"], 1);
    assert_eq!(result["resources"]["live_local_loans"], 1);
    assert_eq!(result["resources"]["owners_dropped"], 0);

    let result = run(&program(), 7, OwnedOptions { max_steps: 4, ..OwnedOptions::default() });
    assert_eq!(result["status"], "budget_exceeded");
    assert_eq!(result["error"]["code"], "steps");
    assert_eq!(result["steps"], 5);
    assert_eq!(result["resources"]["live_bytes"], 7);
    assert_eq!(result["resources"]["live_local_loans"], 1);
    assert_eq!(result["resources"]["frees"], 0);
}

#[test]
fn allocation_refusal_differs_from_host_heap_budget() {
    let result = run(&program(), 7, OwnedOptions {
        allocation_fail_at: Some(1), ..OwnedOptions::default()
    });
    assert_eq!(result["status"], "trapped");
    assert_eq!(result["error"]["code"], "allocation");
    assert_eq!(result["resources"]["allocation_attempts"], 1);
    assert_eq!(result["resources"]["owners_created"], 0);

    let result = run(&program(), 7, OwnedOptions { max_heap_bytes: 6, ..OwnedOptions::default() });
    assert_eq!(result["status"], "budget_exceeded");
    assert_eq!(result["error"]["code"], "heap");
    assert_eq!(result["resources"]["allocation_attempts"], 0);
    // Oversized objects follow HIA's allocation refusal, before host budget.
    let result = run(&program(), u64::MAX, OwnedOptions::default());
    assert_eq!(result["status"], "trapped");
    assert_eq!(result["error"]["code"], "allocation");
    assert_eq!(result["resources"]["allocation_attempts"], 0);
}

#[test]
fn known_versions_execute_but_unknown_isa_and_dangling_views_refuse() {
    let mut document = program();
    for version in 1..=7 {
        document["schema"] = json!(format!("hepta.hia.program.v{version}"));
        assert_eq!(run(&document, 7, OwnedOptions::default())["values"], json!([41]));
    }
    for schema in ["hepta.hia.program.v0", "hepta.hia.program.v8", "hepta.hia.composite.v2"] {
        document["schema"] = json!(schema);
        let error = execute_owned(&serde_json::to_vec(&document).unwrap(), "exercise",
                                  &[json!(7)], OwnedOptions::default()).unwrap_err();
        assert_eq!(error.code, "E_HIA_RUST_UNSUPPORTED");
    }
    let mut document = program();
    let ops = document["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap();
    ops.insert(4, json!({"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}));
    let error = execute_owned(&serde_json::to_vec(&document).unwrap(), "exercise",
                              &[json!(7)], OwnedOptions::default()).unwrap_err();
    assert_eq!(error.code, "E_HIA_LOAN");
}

fn op(name: &str, args: &[&str], output: &[(&str, &str)]) -> Value {
    json!({"op":name,"args":args,"attrs":{},
        "out":output.iter().map(|(n,t)| json!({"name":n,"type":t})).collect::<Vec<_>>()})
}

fn constant(name: &str, typ: &str, value: u64) -> Value {
    let mut instruction = op("const", &[], &[(name, typ)]);
    instruction["attrs"] = json!({"value":value});
    instruction
}

fn small_chain() -> Value {
    json!({"schema":"hepta.hia.program.v7", "module":"chain_oracle", "functions":[{
        "name":"exercise","params":[],"returns":["bool","bool","usize"],
        "effects":["alloc","read","write","trap"],"entry":"entry","blocks":[{
            "id":"entry","params":[],"ops":[
                constant("size", "usize", 2),
                op("buffer.new", &["size"], &[("payload","buffer")]),
                op("borrow.mut", &["payload"], &[("writer","mutbuf")]),
                constant("zero", "usize", 0), constant("byte", "u8", 73),
                op("buffer.store", &["writer","zero","byte"], &[]),
                op("loan.end", &["writer"], &[]),
                op("chain.empty", &[], &[("tail","chain")]),
                op("chain.try_push", &["tail","payload"],
                   &[("head","chain"),("fallback","buffer"),("ok","bool")]),
                op("owner.drop", &["fallback"], &[]),
                op("chain.pop", &["head"],
                   &[("rest","chain"),("item","buffer"),("present","bool")]),
                op("buffer.len", &["item"], &[("length","usize")]),
                op("owner.drop", &["item"], &[]), op("owner.drop", &["rest"], &[])
            ],"term":{"op":"ret","values":["ok","present","length"]}
        }]
    }]})
}

fn chain_run(document: &Value, options: OwnedOptions) -> Value {
    execute_owned(&serde_json::to_vec(document).unwrap(), "exercise", &[], options).unwrap()
}

#[test]
fn push_pop_and_failed_header_have_independent_exact_ledgers() {
    for (fail, answer, allocations, peak, nodes) in [
        (None, json!([true,true,2]), 2, 26, 1),
        (Some(2), json!([false,false,0]), 1, 2, 0),
    ] {
        let report = chain_run(&small_chain(), OwnedOptions {
            allocation_fail_at: fail, ..OwnedOptions::default()
        });
        assert_eq!(report["status"], "returned");
        assert_eq!(report["values"], answer);
        assert_eq!(report["steps"], 16);
        assert_eq!(report["resources"], json!({
            "allocations":allocations,"frees":allocations,"allocation_attempts":2,
            "owners_created":3,"owners_dropped":3,"live_owners":0,
            "live_bytes":0,"peak_bytes":peak,"loans_started":1,"loans_ended":1,
            "live_local_loans":0,"chains_created":3,"chains_consumed":3,"live_chains":0,
            "chain_nodes_created":nodes,"chain_nodes_dropped":nodes,"live_chain_nodes":0
        }));
    }
    let stopped = chain_run(&small_chain(), OwnedOptions {
        max_heap_bytes: 25, ..OwnedOptions::default()
    });
    assert_eq!(stopped["error"]["code"], "heap");
    assert_eq!(stopped["resources"]["allocation_attempts"], 1);
    assert_eq!(stopped["resources"]["chains_consumed"], 0);
    assert_eq!(stopped["resources"]["live_bytes"], 2);
}

#[test]
fn chain_head_reads_payload_and_nil_head_traps_before_creating_loan() {
    let mut document = small_chain();
    let body = &mut document["functions"][0]["blocks"][0];
    let ops = body["ops"].as_array_mut().unwrap();
    ops.splice(9..9, [
        op("chain.head_read", &["head"], &[("view","readbuf")]),
        op("borrow.read", &["view"], &[("child","readbuf")]),
        op("buffer.load", &["child","zero"], &[("observed","u8")]),
        op("loan.end", &["child"], &[]), op("loan.end", &["view"], &[]),
    ]);
    body["term"]["values"] = json!(["observed"]);
    document["functions"][0]["returns"] = json!(["u8"]);
    let report = chain_run(&document, OwnedOptions::default());
    assert_eq!(report["values"], json!([73]));
    assert_eq!(report["resources"]["loans_started"], 3);
    assert_eq!(report["resources"]["loans_ended"], 3);
    let stopped = chain_run(&document, OwnedOptions {
        allocation_fail_at: Some(2), ..OwnedOptions::default()
    });
    assert_eq!(stopped["status"], "trapped");
    assert_eq!(stopped["error"]["code"], "bounds");
    assert_eq!(stopped["resources"]["loans_started"], 1);
    assert_eq!(stopped["resources"]["live_local_loans"], 0);
    assert_eq!(stopped["resources"]["live_bytes"], 2);
}

#[test]
fn chain_destructor_ticks_before_each_payload_and_header_release() {
    let mut document = small_chain();
    let body = &mut document["functions"][0]["blocks"][0];
    body["ops"].as_array_mut().unwrap().truncate(10);
    body["ops"].as_array_mut().unwrap().push(op("owner.drop", &["head"], &[]));
    body["term"]["values"] = json!(["ok"]);
    document["functions"][0]["returns"] = json!(["bool"]);
    let stopped = chain_run(&document, OwnedOptions { max_steps: 12, ..OwnedOptions::default() });
    assert_eq!(stopped["status"], "budget_exceeded");
    assert_eq!(stopped["steps"], 13);
    assert_eq!(stopped["resources"]["live_chains"], 0);
    assert_eq!(stopped["resources"]["live_chain_nodes"], 1);
    assert_eq!(stopped["resources"]["live_bytes"], 26);
    assert_eq!(stopped["resources"]["owners_dropped"], 1); // empty fallback only
    assert_eq!(stopped["resources"]["frees"], 0);
    let finished = chain_run(&document, OwnedOptions::default());
    assert_eq!(finished["steps"], 14);
    assert_eq!(finished["resources"]["frees"], 2);
    assert_eq!(finished["resources"]["live_chain_nodes"], 0);
}

#[test]
fn single_owner_bulk_operations_keep_their_exact_version_gates() {
    for (version, operation) in [
        (2, op("buffer.fill", &["view","byte"], &[])),
        (3, op("buffer.move_within", &["view","zero","zero","size"], &[])),
        (4, op("buffer.swap", &["view","zero","zero"], &[])),
        (6, op("buffer.fill_range", &["view","zero","size","byte"], &[])),
    ] {
        let mut document = program();
        document["schema"] = json!(format!("hepta.hia.program.v{version}"));
        document["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().insert(5, operation);
        let report = run(&document, 7, OwnedOptions::default());
        assert_eq!(report["values"], json!([41]));
        assert_eq!(report["steps"], 12);
        assert_eq!(report["resources"]["allocations"], 1);
        assert_eq!(report["resources"]["frees"], 1);
        for old in 1..version {
            document["schema"] = json!(format!("hepta.hia.program.v{old}"));
            let error = execute_owned(&serde_json::to_vec(&document).unwrap(), "exercise",
                                      &[json!(7)], OwnedOptions::default()).unwrap_err();
            assert_eq!(error.code, "E_HIA_OPCODE");
        }
    }
}

#[test]
fn cross_owner_copy_uses_bytes_without_new_allocation_events() {
    for (version, operation) in [
        (2, op("buffer.copy", &["destination","source","size"], &[])),
        (5, op("buffer.copy_range", &["destination","source","zero","zero","size"], &[])),
    ] {
        let mut document = program();
        document["schema"] = json!(format!("hepta.hia.program.v{version}"));
        let ops = document["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap();
        ops.truncate(5);
        ops.extend([
            op("loan.end", &["view"], &[]),
            op("borrow.read", &["owner"], &[("source","readbuf")]),
            op("buffer.new", &["size"], &[("other","buffer")]),
            op("borrow.mut", &["other"], &[("destination","mutbuf")]), operation,
            op("buffer.load", &["destination","zero"], &[("answer","u8")]),
            op("loan.end", &["source"], &[]), op("loan.end", &["destination"], &[]),
            op("owner.drop", &["owner"], &[]), op("owner.drop", &["other"], &[]),
        ]);
        let report = run(&document, 7, OwnedOptions::default());
        assert_eq!(report["values"], json!([41]));
        assert_eq!(report["resources"]["allocation_attempts"], 2);
        assert_eq!(report["resources"]["owners_created"], 2);
        assert_eq!(report["resources"]["frees"], 2);
        assert_eq!(report["resources"]["peak_bytes"], 14);
    }
}

#[test]
fn public_scalar_boundary_and_invalid_budgets_refuse() {
    let mut document = program();
    let raw = serde_json::to_vec(&document).unwrap();
    assert!(execute_owned(&raw, "exercise", &[json!(true)], OwnedOptions::default()).is_err());
    assert!(execute_owned(&raw, "exercise", &[json!(7)], OwnedOptions {
        allocation_fail_at: Some(0), ..OwnedOptions::default()
    }).is_err());
    document["exports"] = json!([]);
    assert!(execute_owned(&serde_json::to_vec(&document).unwrap(), "exercise",
                          &[json!(7)], OwnedOptions::default()).is_err());
}

#[test]
fn readonly_formal_child_does_not_suspend_its_aliased_sibling() {
    let mut document = program();
    document["functions"][0]["blocks"][0]["ops"][5] = json!({
        "op":"call","args":["view","view"],
        "out":[{"name":"answer","type":"u8"}],"attrs":{"function":"reader"}
    });
    document["functions"].as_array_mut().unwrap().push(json!({
        "name":"reader", "params":[{"name":"left","type":"readbuf"},{"name":"right","type":"readbuf"}],
        "returns":["u8"], "effects":["read","trap"], "entry":"entry",
        "blocks":[{
            "id":"entry", "params":[{"name":"left","type":"readbuf"},{"name":"right","type":"readbuf"}],
            "ops":[
                {"op":"const","args":[],"out":[{"name":"index","type":"usize"}],"attrs":{"value":0}},
                {"op":"borrow.read","args":["left"],"out":[{"name":"child","type":"readbuf"}],"attrs":{}},
                {"op":"buffer.load","args":["child","index"],"out":[{"name":"a","type":"u8"}],"attrs":{}},
                {"op":"buffer.load","args":["right","index"],"out":[{"name":"b","type":"u8"}],"attrs":{}},
                {"op":"loan.end","args":["child"],"out":[],"attrs":{}},
                {"op":"int.add.checked","args":["a","b"],"out":[{"name":"sum","type":"u8"}],"attrs":{}}
            ],
            "term":{"op":"ret","values":["sum"]}
        }]
    }));
    let report = run(&document, 1, OwnedOptions::default());
    assert_eq!(report["values"], json!([82]));
    assert_eq!(report["resources"]["loans_started"], 2);
    assert_eq!(report["resources"]["loans_ended"], 2);
    assert_eq!(report["resources"]["live_local_loans"], 0);
    assert_eq!(report["resources"]["frees"], 1);
    // The parent itself remains suspended; this must still be a verifier
    // denial, rather than making all suspended parent reads permissible.
    document["functions"][1]["blocks"][0]["ops"][3]["args"][0] = json!("left");
    assert!(execute_owned(&serde_json::to_vec(&document).unwrap(), "exercise",
                          &[json!(1)], OwnedOptions::default()).is_err());
}
