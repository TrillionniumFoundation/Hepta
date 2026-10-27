//! Untrusted-input budget controls for the shared HIA Rust JSON decoder.
//! They exercise the real parser before scalar, owned or execution admission.
//! Passing does NOT qualify arbitrary program semantics or native final-use.
use hia_core_shadow::{execute_scalar, verify, verify_owned};

#[test]
fn rejects_node_budget_during_untrusted_deserialization() {
    // 262144 scalar children + one array root exceeds MAX_NODES, while the
    // JSON text stays well below the 8 MiB input limit.
    let dense = format!("[{}]", vec!["null"; 262_144].join(","));
    assert!(dense.len() < 8 * 1024 * 1024);
    let error = verify(dense.as_bytes()).unwrap_err();
    assert_eq!(error.code, "E_HIA_LIMIT");
    assert!(error.detail.contains("HIA_DECODE_LIMIT:"));
    assert_eq!(verify_owned(dense.as_bytes()).unwrap_err().code, "E_HIA_LIMIT");
    assert_eq!(execute_scalar(dense.as_bytes(), "entry", &[], 100)
        .unwrap_err().code, "E_HIA_LIMIT");
}

#[test]
fn rejects_depth_before_constructing_full_value_graph() {
    // Nesting is under serde_json's generic depth limit, but beyond HIA's
    // own 64-edge budget. An exactly 64-deep input reaches later schema
    // validation; 65 is rejected by the decoder itself.
    let inside = format!("{}null{}", "[".repeat(64), "]".repeat(64));
    let at_limit = verify(inside.as_bytes()).unwrap_err();
    assert_eq!(at_limit.code, "E_HIA_FORMAT");
    let over = format!("{}null{}", "[".repeat(65), "]".repeat(65));
    let error = verify(over.as_bytes()).unwrap_err();
    assert_eq!(error.code, "E_HIA_LIMIT");
    assert!(error.detail.contains("HIA_DECODE_LIMIT:"));
}

#[test]
fn rejects_byte_budget_and_duplicate_fields_independently() {
    let too_large = vec![b' '; 8 * 1024 * 1024 + 1];
    assert_eq!(verify(&too_large).unwrap_err().code, "E_HIA_LIMIT");
    let duplicate = br#"{"module":"old","module":"new","schema":"hepta.hia.program.v1","functions":[]}"#;
    let error = verify(duplicate).unwrap_err();
    assert_eq!(error.code, "E_HIA_FORMAT");
    assert!(error.detail.contains("duplicate JSON object key"));
}

#[test]
fn rejects_wrong_shape_without_confusing_it_with_resource_exhaustion() {
    let small = br#"[null,42,true,{"flag":false}]"#;
    let error = verify(small).unwrap_err();
    assert_eq!(error.code, "E_HIA_FORMAT");
}
