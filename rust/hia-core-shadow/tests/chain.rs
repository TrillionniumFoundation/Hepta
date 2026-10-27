//! v7 Chain owner/loan/CFG shadow: genuine byte-exact authoritative Core fixtures.
//! These are acceptance inputs; without cargo execution they are not pass evidence.
use hia_core_shadow::verify_owned;
use serde_json::{json, Value};

fn source() -> Value {
    json!({
        "schema": "hepta.hia.program.v7", "module": "chain_rust_shadow",
        "functions": [{
            "name": "work", "params": [], "returns": [],
            "effects": ["alloc", "read", "trap"], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [],
                "ops": [
                    {"op":"chain.empty", "args":[],
                     "out":[{"name":"tail","type":"chain"}], "attrs":{}},
                    {"op":"const", "args":[],
                     "out":[{"name":"zero","type":"usize"}], "attrs":{"value":0}},
                    {"op":"buffer.new", "args":["zero"],
                     "out":[{"name":"bytes","type":"buffer"}], "attrs":{}},
                    {"op":"chain.try_push", "args":["tail","bytes"],
                     "out":[{"name":"built","type":"chain"},
                            {"name":"unused","type":"buffer"},
                            {"name":"pushed","type":"bool"}], "attrs":{}},
                    {"op":"chain.is_empty", "args":["built"],
                     "out":[{"name":"empty","type":"bool"}], "attrs":{}},
                    {"op":"chain.head_read", "args":["built"],
                     "out":[{"name":"head","type":"readbuf"}], "attrs":{}},
                    {"op":"loan.end", "args":["head"], "out":[], "attrs":{}},
                    {"op":"chain.pop", "args":["built"],
                     "out":[{"name":"remaining","type":"chain"},
                            {"name":"item","type":"buffer"},
                            {"name":"popped","type":"bool"}], "attrs":{}},
                    {"op":"owner.drop", "args":["unused"], "out":[], "attrs":{}},
                    {"op":"owner.drop", "args":["item"], "out":[], "attrs":{}},
                    {"op":"owner.drop", "args":["remaining"], "out":[], "attrs":{}}
                ], "term":{"op":"ret", "values":[]}
            }]
        }]
    })
}
fn accepted(source: &Value) -> bool {
    verify_owned(&serde_json::to_vec(source).unwrap()).is_ok()
}
#[test]
fn v7_resource_profile_is_strictly_opt_in_and_safety_claims_remain_false() {
    let report = verify_owned(&serde_json::to_vec(&source()).unwrap()).unwrap();
    assert_eq!(report["claims"]["v7_chain_owner_loan_cfg_checked"], true);
    assert_eq!(report["claims"]["v7_chain_native_semantics_proved"], false);
    assert_eq!(report["claims"]["rust_is_production_admission_authority"], false);
    assert_eq!(report["claims"]["general_memory_provenance_proved"], false);
    for v in 1..=6 {
        let mut older = source();
        older["schema"] = json!(format!("hepta.hia.program.v{v}"));
        assert!(!accepted(&older), "v{v} must refuse chain vocabulary");
    }
    let mut unknown = source();
    unknown["functions"][0]["blocks"][0]["ops"][0]["op"] = json!("chain.new_unchecked");
    assert!(!accepted(&unknown));
}
#[test]
fn real_recursive_chain_project_fixture_is_accepted_as_single_closed_module() {
    // Imported directly from the repository's canonical executable Core fixture.
    // Includes nested chain/buffer calls, failure branches, loops, head borrows,
    // dynamic owners and recursive-node lifecycle; no source-level shortcuts.
    let fixture = include_bytes!("../../../examples/hia_recursive_chain/core_v7.json");
    let report = verify_owned(fixture).unwrap();
    assert_eq!(report["functions_checked"], 9);
    assert_eq!(report["claims"]["v7_chain_owner_loan_cfg_checked"], true);
}
#[test]
fn chain_descriptor_cannot_masquerade_as_raw_byte_owner() {
    let mut doc = source();
    let ops = doc["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap();
    ops[4]["op"] = json!("buffer.len");
    ops[4]["out"][0]["type"] = json!("usize");
    assert!(!accepted(&doc));
    doc = source();
    let ops = doc["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap();
    ops[5]["op"] = json!("borrow.read");
    assert!(!accepted(&doc));
}
#[test]
fn head_loan_blocks_move_pop_drop_and_additional_mutable_head() {
    for replacement in ["owner.drop", "owner.move", "chain.pop", "chain.head_mut"] {
        let mut doc = source();
        let ops = doc["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap();
        ops[6] = match replacement {
            "owner.drop" => json!({"op":"owner.drop","args":["built"],"out":[],"attrs":{}}),
            "owner.move" => json!({"op":"owner.move","args":["built"],
                "out":[{"name":"moved","type":"chain"}],"attrs":{}}),
            "chain.pop" => json!({"op":"chain.pop","args":["built"],
                "out":[{"name":"tail2","type":"chain"},
                       {"name":"item2","type":"buffer"},
                       {"name":"ok2","type":"bool"}],"attrs":{}}),
            _ => json!({"op":"chain.head_mut","args":["built"],
                "out":[{"name":"other","type":"mutbuf"}],"attrs":{}})
        };
        assert!(!accepted(&doc), "{replacement} bypassed live read loan");
    }
}
#[test]
fn chain_drop_is_linear_and_effects_are_explicit() {
    let mut doc = source();
    doc["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().push(json!({
        "op":"owner.drop","args":["remaining"],"out":[],"attrs":{}
    }));
    assert!(!accepted(&doc));
    doc = source();
    doc["functions"][0]["effects"] = json!(["read","trap"]); // missing alloc
    assert!(!accepted(&doc));
    doc = source();
    doc["functions"][0]["effects"] = json!(["alloc","trap"]); // missing read
    assert!(!accepted(&doc));
    doc = source();
    doc["functions"][0]["blocks"][0]["ops"][3]["out"][0]["type"] = json!("buffer");
    assert!(!accepted(&doc));
}
#[test]
fn branch_join_preserves_only_owner_identity_not_predecessor_names() {
    let doc = json!({
        "schema":"hepta.hia.program.v7", "module":"joined_chains",
        "functions":[{
            "name":"join", "params":[{"name":"condition","type":"bool"}],
            "returns":[], "effects":["alloc"], "entry":"entry",
            "blocks":[
                {"id":"entry","params":[{"name":"condition","type":"bool"}],
                 "ops":[{"op":"chain.empty","args":[],
                         "out":[{"name":"original","type":"chain"}],"attrs":{}}],
                 "term":{"op":"branch","cond":"condition",
                         "then":{"target":"yes","args":["original"]},
                         "else":{"target":"no","args":["original"]}}},
                {"id":"yes","params":[{"name":"left","type":"chain"}],
                 "ops":[{"op":"owner.move","args":["left"],
                         "out":[{"name":"moved_left","type":"chain"}],"attrs":{}}],
                 "term":{"op":"jump","target":"join","args":["moved_left"]}},
                {"id":"no","params":[{"name":"right","type":"chain"}],
                 "ops":[{"op":"owner.move","args":["right"],
                         "out":[{"name":"moved_right","type":"chain"}],"attrs":{}}],
                 "term":{"op":"jump","target":"join","args":["moved_right"]}},
                {"id":"join","params":[{"name":"merged","type":"chain"}],
                 "ops":[{"op":"owner.drop","args":["merged"],"out":[],"attrs":{}}],
                 "term":{"op":"ret","values":[]}}
            ]
        }]
    });
    assert!(accepted(&doc));
    let mut bad = doc;
    bad["functions"][0]["blocks"][2]["term"]["args"] = json!([]);
    assert!(!accepted(&bad)); // missing linear owner on one predecessor
}
#[test]
fn chain_across_internal_calls_and_scalar_only_exports() {
    let mut doc = json!({
        "schema":"hepta.hia.program.v7", "module":"chain_calls",
        "exports":["run"],
        "functions":[
            {"name":"bounce","params":[{"name":"input","type":"chain"}],
             "returns":["chain"],"effects":[],"entry":"bounce_entry",
             "blocks":[{"id":"bounce_entry","params":[{"name":"input","type":"chain"}],
                 "ops":[{"op":"owner.move","args":["input"],
                         "out":[{"name":"returned","type":"chain"}],"attrs":{}}],
                 "term":{"op":"ret","values":["returned"]}}]},
            {"name":"run","params":[],"returns":[],"effects":["alloc"],"entry":"run_entry",
             "blocks":[{"id":"run_entry","params":[],"ops":[
                 {"op":"chain.empty","args":[],
                  "out":[{"name":"start","type":"chain"}],"attrs":{}},
                 {"op":"call","args":["start"],
                  "out":[{"name":"back","type":"chain"}],"attrs":{"function":"bounce"}},
                 {"op":"owner.drop","args":["back"],"out":[],"attrs":{}}
             ],"term":{"op":"ret","values":[]}}]}
        ]
    });
    assert!(accepted(&doc));
    doc["exports"] = json!(["run","bounce"]); // foreign ABI cannot export chain
    assert!(!accepted(&doc));
    doc["exports"] = json!(["run","run"]); // duplicate export
    assert!(!accepted(&doc));
    doc["exports"] = json!(["unknown"]); // missing function
    assert!(!accepted(&doc));
}
