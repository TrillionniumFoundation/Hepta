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
fn newer_isa_and_dangling_view_programs_are_rejected_before_execution() {
    let mut document = program();
    for schema in ["hepta.hia.program.v2", "hepta.hia.program.v7"] {
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
