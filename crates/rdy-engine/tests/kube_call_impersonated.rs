//! The `impersonated` field of a `kube` action log entry in the result schema (M1-111, 02 Appendix B
//! rule 8): a boolean, and an entry with it passes. The probe test `an_impersonated_kube_call_is_marked`
//! checks that the entry is written.

#![allow(clippy::expect_used)]

use std::path::Path;

use serde_json::Value;

fn assert_matches_result_schema(report: &Value) {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("schema file"))
        .expect("schema json");
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(report)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the report fails the schema: {errors:#?}"
    );
}

#[test]
fn an_impersonated_field_that_is_not_a_boolean_fails_the_schema() {
    let sample = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/reports/not-ready-7.2.json"),
    )
    .expect("the fixture is in the repo");
    let mut json: Value = serde_json::from_str(&sample).expect("a report");
    let entry = serde_json::json!({
        "seq": 90, "check": "k8s.rbac", "at_ms": 1, "duration_ms": 1, "kind": "kube", "outcome": "ok",
        "method": "POST", "path": "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "status": 201, "impersonated": true
    });
    json["actions"]
        .as_array_mut()
        .expect("actions")
        .push(entry.clone());
    assert_matches_result_schema(&json);

    let mut bad = entry;
    bad["impersonated"] = Value::from("yes");
    json["actions"].as_array_mut().expect("actions").pop();
    json["actions"].as_array_mut().expect("actions").push(bad);
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("schema file"))
        .expect("schema json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("schema compiles");
    assert!(!validator.is_valid(&json));
}
