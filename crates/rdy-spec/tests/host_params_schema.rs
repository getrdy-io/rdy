//! The host parameter structs against `schema/spec.v1.schema.json`.
//!
//! For each entry, the JSON schema and `CheckSpec::decode_params` must agree: the schema accepts the
//! entry exactly when it decodes to a typed variant. So the schema, which writers of specs read, and
//! the structs, which rdy runs, cannot drift apart without this test failing.

use std::error::Error;
use std::path::Path;

use jsonschema::Validator;
use rdy_spec::check::CheckParams;
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn check_validator() -> TestResult<Validator> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/spec.v1.schema.json"),
    )?;
    let whole: Value = serde_json::from_str(&text)?;
    // Only the definitions a check entry uses. The `Bundle` definition has a pattern
    // (`^file:/[^\0]{0,1023}$`) that this validator refuses as a regex, so it is left out.
    let mut defs = whole["$defs"].clone();
    defs.as_object_mut()
        .ok_or("$defs is an object")?
        .remove("Bundle");
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/Check",
        "$defs": defs,
    });
    Ok(jsonschema::draft202012::options().build(&schema)?)
}

fn decodes(entry: &Value) -> TestResult<bool> {
    let spec: CheckSpec = serde_json::from_value(entry.clone())?;
    Ok(!matches!(
        spec.decode_params(),
        CheckParams::Unsupported { .. } | CheckParams::Unknown { .. }
    ))
}

fn agree(entries: &[Value], want: bool) -> TestResult {
    let validator = check_validator()?;
    for entry in entries {
        assert_eq!(validator.is_valid(entry), want, "schema, for {entry}");
        assert_eq!(decodes(entry)?, want, "decoder, for {entry}");
    }
    Ok(())
}

#[test]
fn entries_both_accept() -> TestResult {
    agree(
        &[
            json!({"id": "host.cpu", "min": 8}),
            json!({"id": "host.cpu", "arch": ["amd64", "aarch64"]}),
            json!({"id": "host.cpu", "flags": ["avx2", "x86-64-v3"], "recommended": 16}),
            json!({"id": "host.memory", "min": "32Gi"}),
            json!({"id": "host.memory", "min": 1_073_741_824, "swap": "forbid",
                "tolerance_percent": 0, "tolerance_result": "warn", "min_available": "8Gi"}),
            json!({"id": "host.memory", "min": "1Gi", "tolerance_percent": 20}),
            json!({"id": "host.disk", "path": "/var/lib", "min": "100Gi"}),
            json!({"id": "host.disk", "path": "C:\\", "min": "20Gi", "min_inodes": 0,
                "forbid_options": ["noexec", "nosuid", "nodev", "ro"], "forbid_fstypes": ["nfs"]}),
            json!({"id": "host.ports", "free": [80, {"port": 443}, {"port": 8443, "bind": "loopback"}]}),
            json!({"id": "host.ports", "udp_free": [53, 123], "allow_owner": ["acme"]}),
            json!({"id": "host.lsm"}),
            json!({"id": "host.lsm", "selinux": {"allow": ["permissive"], "denials_max": 0,
                "denials_window": "24h", "watch": ["container_t"]},
                "apparmor": {"allow": ["enabled", "disabled"], "require_profiles": ["acme"]}}),
            json!({"id": "host.security_agents"}),
            json!({"id": "host.security_agents", "forbid": ["a"], "allow": ["b"]}),
            json!({"id": "host.os"}),
            json!({"id": "host.os", "windows_min_build": 4_294_967_295_u64}),
            json!({"id": "host.disk", "path": "/srv/data \u{a0}ok", "min": "1Gi"}),
            json!({"id": "host.os", "supported": [{"id": "rhel", "versions": ["8", "9"]}, {"id": "ubuntu"}],
                "arch": ["x86_64"], "fips": "forbid", "windows_min_build": 20348}),
        ],
        true,
    )
}

#[test]
fn entries_both_refuse() -> TestResult {
    agree(
        &[
            // no threshold
            json!({"id": "host.cpu"}),
            json!({"id": "host.cpu", "recommended": 8}),
            json!({"id": "host.memory"}),
            json!({"id": "host.memory", "swap": "forbid"}),
            json!({"id": "host.disk"}),
            json!({"id": "host.disk", "path": "/"}),
            json!({"id": "host.disk", "min": "1Gi"}),
            json!({"id": "host.ports"}),
            json!({"id": "host.ports", "allow_owner": ["acme"]}),
            // unknown key
            json!({"id": "host.memory", "mn": "32Gi"}),
            json!({"id": "host.os", "like": "rhel"}),
            json!({"id": "host.lsm", "selinux": {"mode": "enforcing"}}),
            json!({"id": "host.ports", "free": [{"port": 80, "proto": "tcp"}]}),
            // a key with no value, at any depth
            json!({"id": "host.lsm", "selinux": {"allow": null}}),
            json!({"id": "host.lsm", "apparmor": {"require_profiles": null}}),
            json!({"id": "host.os", "supported": [{"id": "rhel", "versions": null}]}),
            // an empty list is no threshold
            json!({"id": "host.cpu", "flags": []}),
            json!({"id": "host.cpu", "arch": []}),
            json!({"id": "host.ports", "free": []}),
            json!({"id": "host.ports", "udp_free": []}),
            // control characters in a path, C0 and C1
            json!({"id": "host.disk", "path": "/a\nb", "min": "1Gi"}),
            json!({"id": "host.disk", "path": "/a\u{0}b", "min": "1Gi"}),
            json!({"id": "host.disk", "path": "/a\u{7f}b", "min": "1Gi"}),
            json!({"id": "host.disk", "path": "/a\u{85}b", "min": "1Gi"}),
            json!({"id": "host.disk", "path": "C:\\a\u{9f}", "min": "1Gi"}),
            // above u32
            json!({"id": "host.lsm", "selinux": {"denials_max": 4_294_967_296_u64}}),
            json!({"id": "host.os", "windows_min_build": 4_294_967_296_u64}),
            // bad values
            json!({"id": "host.cpu", "min": 0}),
            json!({"id": "host.cpu", "min": 4097}),
            json!({"id": "host.cpu", "arch": ["sparc"]}),
            json!({"id": "host.cpu", "arch": ["amd64", "amd64"]}),
            json!({"id": "host.cpu", "flags": ["AVX2"]}),
            json!({"id": "host.memory", "min": "32G"}),
            json!({"id": "host.memory", "min": "1Gi", "swap": "off"}),
            json!({"id": "host.memory", "min": "1Gi", "tolerance_percent": 21}),
            json!({"id": "host.memory", "min": "1Gi", "tolerance_percent": -1}),
            json!({"id": "host.memory", "min": "1Gi", "tolerance_result": "fail"}),
            json!({"id": "host.disk", "path": "relative", "min": "1Gi"}),
            json!({"id": "host.disk", "path": "/", "min": "1Gi", "forbid_options": ["exec"]}),
            json!({"id": "host.disk", "path": "/", "min": "1Gi", "forbid_fstypes": ["NFS"]}),
            json!({"id": "host.ports", "free": [0]}),
            json!({"id": "host.ports", "free": [65536]}),
            json!({"id": "host.ports", "udp_free": [53, 53]}),
            json!({"id": "host.ports", "free": [{"port": 80, "bind": "all"}]}),
            json!({"id": "host.lsm", "selinux": {"allow": ["strict"]}}),
            json!({"id": "host.lsm", "apparmor": {"allow": ["on"]}}),
            json!({"id": "host.os", "fips": "yes"}),
            json!({"id": "host.os", "supported": [{"versions": ["8"]}]}),
            json!({"id": "host.os", "supported": [{"id": "RHEL"}]}),
            json!({"id": "host.os", "windows_min_build": -1}),
        ],
        false,
    )
}
