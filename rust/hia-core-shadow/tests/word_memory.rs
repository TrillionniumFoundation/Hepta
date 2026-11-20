//! Independent v9 checker/VM conformance; expected endian values are Rust bytes.
use hia_core_shadow::{analyze_finite_entry_heap, analyze_static_budget, execute_owned, verify_owned};
use serde_json::{json, Value};

fn program(store: &str, load: &str) -> Value {
    let params = json!([{"name":"n","type":"usize"},{"name":"offset","type":"usize"},
                       {"name":"value","type":"u64"}]);
    json!({"schema":"hepta.hia.program.v9","module":"word_memory",
           "exports":["probe"],"functions":[{
        "name":"probe","params":params,"returns":["u64"],"effects":["alloc","read","write","trap"],
        "entry":"entry","blocks":[{"id":"entry","params":params,
            "ops":[
                {"op":"buffer.new","args":["n"],"out":[{"name":"owner","type":"buffer"}],"attrs":{}},
                {"op":"borrow.mut","args":["owner"],"out":[{"name":"view","type":"mutbuf"}],"attrs":{}},
                {"op":store,"args":["view","offset","value"],"out":[],"attrs":{}},
                {"op":load,"args":["view","offset"],"out":[{"name":"answer","type":"u64"}],"attrs":{}},
                {"op":"loan.end","args":["view"],"out":[],"attrs":{}},
                {"op":"owner.drop","args":["owner"],"out":[],"attrs":{}}
            ],"term":{"op":"ret","values":["answer"]}}]}]})
}

#[test]
fn actual_vm_preserves_unsigned_values_alignment_and_byte_order() {
    for store in ["buffer.store.u64.le", "buffer.store.u64.be"] {
        for load in ["buffer.load.u64.le", "buffer.load.u64.be"] {
            let source = serde_json::to_vec(&program(store, load)).unwrap();
            for n in [8_u64, 9, 17, 64] {
                for offset in [0, (n - 8).min(1), n - 8] {
                    for value in [0_u64, 0x0123_4567_89AB_CDEF, u64::MAX] {
                        let result = execute_owned(&source, "probe",
                            &[json!(n), json!(offset), json!(value)], 100, 100, None).unwrap();
                        let expected = if store.ends_with("le") == load.ends_with("le") {
                            value
                        } else { value.swap_bytes() };
                        assert_eq!(result["status"], "returned");
                        assert_eq!(result["values"], json!([expected]));
                        assert_eq!(result["resources"]["live_owners"], 0);
                        assert_eq!(result["resources"]["live_local_loans"], 0);
                        let bound = analyze_static_budget(&source).unwrap();
                        assert_eq!(bound["functions"][0]["max_vm_ticks"], result["steps"]);
                        assert_eq!(bound["functions"][0]["max_allocator_interactions"], 2);
                    }
                }
            }
        }
    }
}

#[test]
fn both_word_operations_trap_on_short_or_high_offsets() {
    for read_only in [false, true] {
        for suffix in ["le", "be"] {
            let mut doc = program(&format!("buffer.store.u64.{suffix}"),
                                  &format!("buffer.load.u64.{suffix}"));
            if read_only {
                doc["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().remove(2);
            }
            let source = serde_json::to_vec(&doc).unwrap();
            let cases = (0..8).map(|n| (n, 0)).chain([
                (8, 1), (9, 2), (17, 10), (17, 17), (17, 18),
                (32, 1 << 32), (32, (1 << 32) + 1), (32, 1 << 63), (32, u64::MAX),
            ]);
            for (n, offset) in cases {
                let result = execute_owned(&source, "probe",
                    &[json!(n), json!(offset), json!(9)], 100, 100, None).unwrap();
                assert_eq!(result["status"], "trapped");
                assert_eq!(result["error"]["code"], "bounds");
                assert_eq!(result["resources"]["owners_dropped"], 0);
            }
        }
    }
}

#[test]
fn declared_version_permissions_types_and_effects_are_mandatory() {
    let source = program("buffer.store.u64.le", "buffer.load.u64.be");
    assert!(verify_owned(&serde_json::to_vec(&source).unwrap()).is_ok());
    for version in 1..=8 {
        let mut bad = source.clone();
        bad["schema"] = json!(format!("hepta.hia.program.v{version}"));
        assert!(verify_owned(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for mutation in ["effect", "readonly", "offset", "attribute", "result"] {
        let mut bad = source.clone();
        let f = &mut bad["functions"][0];
        match mutation {
            "effect" => f["effects"] = json!(["alloc", "read", "write"]),
            "readonly" => {
                f["blocks"][0]["ops"][1]["op"] = json!("borrow.read");
                f["blocks"][0]["ops"][1]["out"][0]["type"] = json!("readbuf");
            }
            "offset" => f["blocks"][0]["ops"][2]["args"][1] = json!("value"),
            "attribute" => f["blocks"][0]["ops"][2]["attrs"] = json!({"unchecked":true}),
            "result" => f["blocks"][0]["ops"][3]["out"][0]["type"] = json!("u8"),
            _ => unreachable!(),
        }
        assert!(verify_owned(&serde_json::to_vec(&bad).unwrap()).is_err(), "{mutation}");
    }
}

#[test]
fn finite_resource_admission_counts_words_without_trusting_loaded_sizes() {
    let document = program("buffer.store.u64.le", "buffer.load.u64.le");
    let source = serde_json::to_vec(&document).unwrap();
    let arguments = [json!(17), json!(1), json!(8)];
    let policy = serde_json::to_vec(&json!({"max_live_heap_bytes":17})).unwrap();
    let bound = analyze_finite_entry_heap(&source, "probe", &arguments, &policy).unwrap();
    assert_eq!(bound["schema"], "hepta.hia.rust-finite-entry-heap.v2");
    assert_eq!(bound["peak_bound_bytes"], 17);
    assert_eq!(bound["max_allocator_interactions"], 2);
    assert_eq!(bound["claims"]["execution_used_to_establish_bound"], false);
    let lower = serde_json::to_vec(&json!({"max_live_heap_bytes":16})).unwrap();
    assert_eq!(analyze_finite_entry_heap(&source, "probe", &arguments, &lower)
               .unwrap_err().code, "E_HIA_BUDGET_EXCEEDED");

    let mut document = document;
    document["functions"][0]["blocks"][0]["ops"].as_array_mut().unwrap().splice(4..4, [
        json!({"op":"int.cast","args":["answer"],"out":[{"name":"requested","type":"usize"}],"attrs":{"mode":"wrap"}}),
        json!({"op":"buffer.new","args":["requested"],"out":[{"name":"extra","type":"buffer"}],"attrs":{}}),
        json!({"op":"owner.drop","args":["extra"],"out":[],"attrs":{}}),
    ]);
    let source = serde_json::to_vec(&document).unwrap();
    let observed = execute_owned(&source, "probe", &arguments, 100, 100, None).unwrap();
    assert_eq!(observed["values"], json!([8]));
    assert_eq!(observed["resources"]["peak_bytes"], 25);
    let policy = serde_json::to_vec(&json!({"max_live_heap_bytes":25})).unwrap();
    assert_eq!(analyze_finite_entry_heap(&source, "probe", &arguments, &policy)
               .unwrap_err().code, "E_HIA_BUDGET_UNBOUNDED");
}
