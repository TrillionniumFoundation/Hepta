//! Genuine Rust-only cross-block Owner/Loan negative controls (no Python mock).
use hia_core_shadow::verify_owned;
use serde_json::{json, Value};

fn owned() -> Value {
    json!({
        "schema":"hepta.hia.program.v1", "module":"owned_rust",
        "functions":[{
            "name":"read_zero", "params":[{"name":"n","type":"usize"}],
            "returns":["u8"], "effects":["alloc","read","trap"],
            "entry":"entry",
            "blocks":[
                {"id":"entry",
                 "params":[{"name":"n","type":"usize"}],
                 "ops":[
                    {"op":"buffer.new","args":["n"],
                     "out":[{"name":"b","type":"buffer"}],"attrs":{}},
                    {"op":"borrow.read","args":["b"],
                     "out":[{"name":"v","type":"readbuf"}],"attrs":{}},
                    {"op":"const","args":[],"out":[{"name":"zero","type":"usize"}],
                     "attrs":{"value":0}}
                 ],
                 "term":{"op":"jump","target":"next","args":["b","v","zero"]}},
                {"id":"next",
                 "params":[{"name":"owner","type":"buffer"},
                           {"name":"view","type":"readbuf"},
                           {"name":"index","type":"usize"}],
                 "ops":[
                    {"op":"buffer.load","args":["view","index"],
                     "out":[{"name":"byte","type":"u8"}],"attrs":{}},
                    {"op":"loan.end","args":["view"],"out":[],"attrs":{}},
                    {"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}
                 ],
                 "term":{"op":"ret","values":["byte"]}}
            ]
        }]
    })
}
fn checked(doc: &Value) -> bool {
    verify_owned(&serde_json::to_vec(doc).unwrap()).is_ok()
}
#[test]
fn real_owner_and_loan_can_cross_cfg_block() {
    let report = verify_owned(&serde_json::to_vec(&owned()).unwrap()).unwrap();
    assert_eq!(report["claims"]["cross_block_owner_loan_state_checked"], true);
    assert_eq!(report["claims"]["rust_is_production_admission_authority"], false);
    assert_eq!(report["claims"]["general_memory_provenance_proved"], false);
}
#[test]
fn duplicate_keys_and_unknown_proof_claim_reject() {
    let raw = br#"{"schema":"hepta.hia.program.v1","schema":"hepta.hia.program.v6","module":"m","functions":[]}"#;
    assert!(verify_owned(raw).is_err());
    let mut d = owned();
    d["whole_language_soundness_proved"] = json!(false);
    assert!(!checked(&d));
}
#[test]
fn double_drop_and_reborrow_after_end_reject() {
    let mut d = owned();
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().push(json!({
      "op":"owner.drop","args":["owner"],"out":[],"attrs":{}
    }));
    assert!(!checked(&d));
    d = owned();
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().insert(2,json!({
      "op":"borrow.read","args":["view"],
      "out":[{"name":"use_after_end","type":"readbuf"}],"attrs":{}
    }));
    assert!(!checked(&d));
}
#[test]
fn cannot_drop_root_with_live_loan() {
    let mut d = owned();
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().remove(1);
    assert!(!checked(&d));
}
#[test]
fn cannot_duplicate_owner_across_block_edge() {
    let mut d = owned();
    d["functions"][0]["blocks"][0]["term"]["args"] = json!(["b","b","zero"]);
    assert!(!checked(&d));
}
#[test]
fn cannot_access_suspended_parent_loan() {
    let mut d = owned();
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().insert(0,json!({
        "op":"borrow.read","args":["view"],
        "out":[{"name":"child","type":"readbuf"}],"attrs":{}
    }));
    assert!(!checked(&d));
}
#[test]
fn absent_effect_rejects() {
    let mut d = owned();
    d["functions"][0]["effects"] = json!(["alloc","trap"]);
    assert!(!checked(&d));
}
#[test]
fn versioned_bulk_memory_requires_live_mutable_loan_and_declared_effects() {
    let mut d = owned();
    d["schema"] = json!("hepta.hia.program.v2");
    d["functions"][0]["effects"] = json!(["alloc", "read", "write", "trap"]);
    d["functions"][0]["blocks"][0]["ops"][1]["op"] = json!("borrow.mut");
    d["functions"][0]["blocks"][0]["ops"][1]["out"][0]["type"] = json!("mutbuf");
    d["functions"][0]["blocks"][1]["params"][1]["type"] = json!("mutbuf");
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().insert(0,json!({
        "op":"const","args":[],"out":[{"name":"value","type":"u8"}],
        "attrs":{"value":7}
    }));
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().insert(1,json!({
        "op":"buffer.fill","args":["view","value"],"out":[],"attrs":{}
    }));
    assert!(checked(&d)); // HIA v2 typed memset
    d["schema"] = json!("hepta.hia.program.v1");
    assert!(!checked(&d)); // old version may not silently gain the opcode
    d["schema"] = json!("hepta.hia.program.v6");
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().insert(2,json!({
        "op":"buffer.fill_range",
        "args":["view","index","index","value"],"out":[],"attrs":{}
    }));
    assert!(checked(&d));
    d["schema"] = json!("hepta.hia.program.v5");
    assert!(!checked(&d));
    d["schema"] = json!("hepta.hia.program.v6");
    d["functions"][0]["effects"] = json!(["alloc", "read", "trap"]);
    assert!(!checked(&d)); // write effect is mandatory
}
#[test]
fn v5_range_copy_proves_distinct_roots_before_admission() {
    let mut d = owned();
    d["schema"] = json!("hepta.hia.program.v5");
    d["functions"][0]["effects"] = json!(["alloc","read","write","trap"]);
    let entry = &mut d["functions"][0]["blocks"][0];
    entry["ops"].as_array_mut().unwrap().insert(1,json!({
        "op":"buffer.new","args":["n"],
        "out":[{"name":"other","type":"buffer"}],"attrs":{}
    }));
    // Put unique mutable destination and shared source in the same block.
    entry["ops"][2]["op"] = json!("borrow.mut");
    entry["ops"][2]["out"][0]["type"] = json!("mutbuf");
    entry["ops"].as_array_mut().unwrap().insert(3,json!({
        "op":"borrow.read","args":["other"],
        "out":[{"name":"source","type":"readbuf"}],"attrs":{}
    }));
    entry["ops"].as_array_mut().unwrap().insert(5,json!({
        "op":"buffer.copy_range",
        "args":["v","source","zero","zero","zero"],"out":[],"attrs":{}
    }));
    entry["ops"].as_array_mut().unwrap().insert(6,json!({
        "op":"loan.end","args":["source"],"out":[],"attrs":{}
    }));
    entry["term"]["args"] = json!(["b","v","zero","other"]);
    let next = &mut d["functions"][0]["blocks"][1];
    next["params"].as_array_mut().unwrap().push(json!({
        "name":"other_owner","type":"buffer"
    }));
    next["params"][1]["type"] = json!("mutbuf");
    next["ops"].as_array_mut().unwrap().push(json!({
        "op":"owner.drop","args":["other_owner"],"out":[],"attrs":{}
    }));
    assert!(checked(&d));
    d["schema"] = json!("hepta.hia.program.v4");
    assert!(!checked(&d));
    d["schema"] = json!("hepta.hia.program.v5");
    d["functions"][0]["blocks"][0]["ops"][5]["args"][1] = json!("v"); // same owner alias
    assert!(!checked(&d));
}

#[test]
fn type_correct_cfg_join_cannot_change_loan_root() {
    let mut d = owned();
    // Add a second independently allocated owner, then forward both through
    // either predecessor order. The read view always originates from "b".
    d["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().insert(1,json!({
        "op":"buffer.new","args":["n"],
        "out":[{"name":"other","type":"buffer"}],"attrs":{}
    }));
    d["functions"][0]["blocks"][0]["term"]["op"] = json!("branch");
    d["functions"][0]["blocks"][0]["term"] = json!({
        "op":"branch",
        "cond":"choose",
        "then":{"target":"next","args":["b","other","v","zero"]},
        "else":{"target":"next","args":["other","b","v","zero"]}
    });
    d["functions"][0]["params"].as_array_mut().unwrap().push(
        json!({"name":"choose","type":"bool"}));
    d["functions"][0]["blocks"][0]["params"].as_array_mut().unwrap().push(
        json!({"name":"choose","type":"bool"}));
    d["functions"][0]["blocks"][1]["params"].as_array_mut().unwrap().insert(1,
        json!({"name":"second","type":"buffer"}));
    d["functions"][0]["blocks"][1]["ops"].as_array_mut().unwrap().insert(3,json!({
        "op":"owner.drop","args":["second"],"out":[],"attrs":{}
    }));
    assert!(!checked(&d));
}
