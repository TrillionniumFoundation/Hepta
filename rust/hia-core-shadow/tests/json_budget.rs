//! Global, root-at-depth-zero admission before a nested suffix is decoded.
use hia_core_shadow::{verify, verify_owned};

const MAX_NODES: usize = 262_144;

fn both_reject_with(input: &[u8], code: &str) {
    assert_eq!(verify(input).unwrap_err().code, code);
    assert_eq!(verify_owned(input).unwrap_err().code, code);
}

#[test]
fn exact_node_limit_reaches_schema_check_but_next_value_never_decodes() {
    let exact = format!("[{}0]", "0,".repeat(MAX_NODES - 2));
    // A non-module JSON value reaches the schema check at exactly the limit.
    both_reject_with(exact.as_bytes(), "E_HIA_FORMAT");

    // The final float would fail scalar parsing if it were deserialized.
    // A global budget must stop before visiting that value, even though
    // its immediate parent contains only two children.
    let over = format!("[{}[0,1.5]]", "0,".repeat(MAX_NODES - 3));
    both_reject_with(over.as_bytes(), "E_HIA_LIMIT");
}

#[test]
fn nested_object_values_share_the_array_budget() {
    let over = format!("[{}{{\"tail\":[1.5]}}]", "0,".repeat(MAX_NODES - 3));
    both_reject_with(over.as_bytes(), "E_HIA_LIMIT");
}

#[test]
fn depth_is_checked_before_the_disallowed_leaf() {
    let exact = format!("{}0{}", "[".repeat(64), "]".repeat(64));
    both_reject_with(exact.as_bytes(), "E_HIA_FORMAT");
    let over = format!("{}1.5{}", "[".repeat(65), "]".repeat(65));
    both_reject_with(over.as_bytes(), "E_HIA_LIMIT");
}

#[test]
fn duplicate_keys_still_reject_before_their_value() {
    let duplicate = format!("{{\"k\":0,\"k\":{}0{}}}",
                            "[".repeat(65), "]".repeat(65));
    let error = verify(duplicate.as_bytes()).unwrap_err();
    assert_eq!(error.code, "E_HIA_FORMAT");
    assert!(error.detail.contains("duplicate JSON object key"));
}
