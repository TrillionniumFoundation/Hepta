//! Raw lexical integer cases must reach the independent Rust decoder unchanged.
use hia_core_shadow::{decode_scalar_arguments, execute_owned, verify, verify_owned};
use serde_json::{json, Value};

fn source(version: u8, token: &str) -> Vec<u8> {
    let value = json!({
        "schema":format!("hepta.hia.program.v{version}"), "module":"raw_integer",
        "functions":[{"name":"run", "params":[], "returns":["i64"],
            "effects":[], "entry":"entry", "blocks":[{"id":"entry", "params":[],
            "ops":[{"op":"const", "args":[], "out":[{"name":"zero", "type":"i64"}],
                    "attrs":{"value":"RAW_TOKEN"}}], "term":{"op":"ret", "values":["zero"]}}]}]
    });
    serde_json::to_string(&value).unwrap().replace("\"RAW_TOKEN\"", token).into_bytes()
}

#[test]
fn negative_zero_is_integer_zero_in_each_primitive_schema() {
    for version in 1..=8 {
        let negative = source(version, "-0");
        let zero = source(version, "0");
        assert_eq!(verify_owned(&negative).unwrap(), verify_owned(&zero).unwrap());
        if version < 8 {
            assert_eq!(verify(&negative).unwrap(), verify(&zero).unwrap());
        }
        let result = execute_owned(&negative, "run", &[], 20, 0, None).unwrap();
        assert_eq!(result["status"], "returned");
        assert_eq!(result["values"], json!([0]));
    }
}

#[test]
fn float_and_malformed_spellings_still_reject_in_raw_core() {
    for token in ["-0.0", "0e0", "-0e0", "-0E+0", "-00", "00", "--0",
                  "+0", "- 0", "-0false", "-0:0", "-0 0", "0-0", "\"-0\""] {
        for version in [1, 8] {
            let raw = source(version, token);
            assert!(verify_owned(&raw).is_err(), "{version}: {token}");
        }
    }
}

#[test]
fn scalar_argument_tokens_use_the_same_integer_contract() {
    for text in ["[-0]", "[ -0 , -0\n,\t-0\r]", "[-0,1,-1,true,null]"] {
        let values = decode_scalar_arguments(text).unwrap();
        assert_eq!(values[0], json!(0));
        assert!(values.iter().all(|v| !matches!(v, Value::Number(n) if n.is_f64())));
    }
    for text in ["[-0.0]", "[0e0]", "[-0e0]", "[-00]", "[--0]", "[+0]",
                 "[- 0]", "[-0 false]", "[-0 0]", "[0-0]", "[\"-0\"]",
                 r#"["escaped\" -0",-0]"#, r#"["escaped\\",-0]"#] {
        assert!(decode_scalar_arguments(text).is_err(), "{text}");
    }
}

#[test]
fn negative_zero_never_waives_duplicate_or_depth_admission() {
    let duplicate = br#"{"k":-0,"k":0}"#;
    let error = verify_owned(duplicate).unwrap_err();
    assert_eq!(error.code, "E_HIA_FORMAT");
    assert!(error.detail.contains("duplicate JSON object key"));
    let deep = format!("{}-0{}", "[".repeat(65), "]".repeat(65));
    assert_eq!(verify_owned(deep.as_bytes()).unwrap_err().code, "E_HIA_LIMIT");
}
