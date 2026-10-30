//! The M1 redaction rules (M1-060, 04 Appendix B and D).
//!
//! The 23 positive inputs of Appendix D come out typed: each secret becomes `[REDACTED:<rule>:<tag>]`,
//! and quotes, keys, separators and the host of a URL stay. The negatives come out unchanged. Tags are
//! replaced with `~` before the comparison. Every secret here is synthetic, and the ones that look like
//! tokens are built from parts so that no scanner sees a whole token in the source.
//!
//! This is the rule test of the ticket. The 28-case corpus under `tests/fixtures/redaction` with its
//! gate is M1-063.

use rdy_engine::redact::{Redactor, TagKey, evidence_url};
use regex::Regex;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([9; 32]))
}

/// The text with every tag replaced by `~`.
fn normalized(text: &str) -> String {
    let tag = Regex::new(r"\[REDACTED:([a-z0-9_.]+):[0-9a-f]{8}\]")
        .unwrap_or_else(|e| panic!("the tag pattern is valid: {e}"));
    tag.replace_all(text, "[REDACTED:$1:~]").into_owned()
}

/// One positive case: the input, the secrets that must not survive, and the expected output.
struct Case {
    name: &'static str,
    input: String,
    secrets: Vec<String>,
    want: String,
}

fn case(name: &'static str, input: &str, secrets: &[&str], want: &str) -> Case {
    Case {
        name,
        input: input.to_owned(),
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        want: want.to_owned(),
    }
}

const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn positives() -> Vec<Case> {
    let jwt = [
        "eyJh",
        "bGciOiJSUzI1NiJ9.",
        "eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.",
        "c2lnbmF0dXJlLWNhbmFyeS0x",
    ]
    .concat();
    let session = ["IQoJb3Jp", "Z2luX2VjEXAMPLETOKEN9876"].concat();
    let share = ["rdy_st_", "Zk3v9Qx7canaryShareTok01"].concat();
    let kube_token = ["Zk3v9Qx7", "canaryKubeTokenAb012"].concat();
    let bearer = ["canary", "BearerCredential42"].concat();
    let basic = "dXNlcjpwYXNzd29yZC1jYW5hcnk=";
    let rsa = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n{}\n-----END RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEAcanaryRsaBody1111111111111111111111111111111", "cGVtLWNhbmFyeS1ib2R5LTI="
    );
    let pkcs8 = format!(
        "-----BEGIN PRIVATE KEY-----\\n{}\\n-----END PRIVATE KEY-----\\n",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAAcanaryPkcs8Body22222222222222"
    );
    vec![
        // url 3
        case(
            "url proxy",
            "HTTPS_PROXY=http://svc:pa55@proxy.acme.test:3128",
            &["svc:pa55", "pa55"],
            "HTTPS_PROXY=http://[REDACTED:url_userinfo:~]@proxy.acme.test:3128",
        ),
        case(
            "url postgres dsn",
            "DATABASE_URL=postgres://app:Zq9xK7mW2@db.acme.test:5432/app?sslmode=require",
            &["Zq9xK7mW2"],
            "DATABASE_URL=postgres://[REDACTED:url_userinfo:~]@db.acme.test:5432/app?sslmode=require",
        ),
        case(
            "url percent encoded",
            "proxy: http://svc:p%40ss%3Aw0rd-canary@proxy.acme.test:3128/",
            &["p%40ss%3Aw0rd-canary"],
            "proxy: http://[REDACTED:url_userinfo:~]@proxy.acme.test:3128/",
        ),
        // auth 4
        case(
            "auth bearer",
            &format!("Authorization: Bearer {bearer}"),
            &[&bearer],
            "Authorization: Bearer [REDACTED:auth_header:~]",
        ),
        case(
            "auth basic",
            &format!("authorization: Basic {basic}"),
            &[basic],
            "authorization: Basic [REDACTED:auth_header:~]",
        ),
        case(
            "auth proxy",
            &format!("Proxy-Authorization: Basic {basic}"),
            &[basic],
            "Proxy-Authorization: Basic [REDACTED:auth_header:~]",
        ),
        case(
            "auth x-api-key",
            "X-Api-Key: canary-api-key-0042",
            &["canary-api-key-0042"],
            "X-Api-Key: [REDACTED:api_key_header:~]",
        ),
        // aws 4
        case(
            "aws key id in a log line",
            &format!("ERROR request failed for access key {KEY_ID} (denied)"),
            &[KEY_ID],
            "ERROR request failed for access key [REDACTED:aws_access_key_id:~] (denied)",
        ),
        case(
            "aws secret in env",
            &format!("AWS_SECRET_ACCESS_KEY={SECRET_KEY}"),
            &[SECRET_KEY],
            "AWS_SECRET_ACCESS_KEY=[REDACTED:aws_secret_access_key:~]",
        ),
        case(
            "aws session json",
            &format!(
                "{{\n  \"AccessKeyId\": \"ASIAIOSFODNN7EXAMPLE\",\n  \"SessionToken\": \"{session}\",\n  \"Expiration\": \"2026-11-04T10:15:00Z\"\n}}"
            ),
            &["ASIAIOSFODNN7EXAMPLE", &session],
            "{\n  \"AccessKeyId\": \"[REDACTED:aws_access_key_id:~]\",\n  \"SessionToken\": \"[REDACTED:aws_session_token:~]\",\n  \"Expiration\": \"2026-11-04T10:15:00Z\"\n}",
        ),
        case(
            "aws credentials file",
            &format!(
                "[default]\naws_access_key_id = {KEY_ID}\naws_secret_access_key = {SECRET_KEY}\nregion = eu-west-1\n"
            ),
            &[KEY_ID, SECRET_KEY],
            "[default]\naws_access_key_id = [REDACTED:aws_access_key_id:~]\naws_secret_access_key = [REDACTED:aws_secret_access_key:~]\nregion = eu-west-1\n",
        ),
        // pem 2
        case(
            "pem rsa",
            &format!("key follows\n{rsa}\nafter the key\n"),
            &[
                "MIIEowIBAAKCAQEAcanaryRsaBody",
                "cGVtLWNhbmFyeS1ib2R5LTI=",
                "BEGIN RSA PRIVATE KEY",
            ],
            "key follows\n[REDACTED:pem_private_key:~]\nafter the key\n",
        ),
        case(
            "pem pkcs8 in json",
            &format!("{{\"tls\":\"{pkcs8}\",\"port\":8443}}"),
            &["MIIEvQIBADANBgkqhkiG9w0BAQEFAAcanaryPkcs8Body"],
            "{\"tls\":\"[REDACTED:pem_private_key:~]\\n\",\"port\":8443}",
        ),
        // kubeconfig 2
        case(
            "kubeconfig token",
            &format!("users:\n- name: admin\n  user:\n    token: {kube_token}\n"),
            &[&kube_token],
            "users:\n- name: admin\n  user:\n    token: [REDACTED:kubeconfig_credential:~]\n",
        ),
        case(
            "kubeconfig client key",
            "users:\n- name: admin\n  user:\n    client-certificate-data: Y2VydC1wdWJsaWM=\n    client-key-data: Y2FuYXJ5LWNsaWVudC1rZXktZGF0YQ==\n",
            &["Y2FuYXJ5LWNsaWVudC1rZXktZGF0YQ=="],
            "users:\n- name: admin\n  user:\n    client-certificate-data: Y2VydC1wdWJsaWM=\n    client-key-data: [REDACTED:kubeconfig_credential:~]\n",
        ),
        // rdy_token 1
        case(
            "rdy share token",
            &format!("share it with support: {share} (expires in 7 days)"),
            &[&share],
            "share it with support: [REDACTED:rdy_share_token:~] (expires in 7 days)",
        ),
        // key_name 5
        case(
            "key env",
            "DB_PASSWORD=hunter2",
            &["hunter2"],
            "DB_PASSWORD=[REDACTED:secret_by_key:~]",
        ),
        case(
            "key yaml",
            "db:\n  password: hunter2\n  host: db.acme.test\n",
            &["hunter2"],
            "db:\n  password: [REDACTED:secret_by_key:~]\n  host: db.acme.test\n",
        ),
        case(
            "key fake placeholder prefix",
            "password=[REDACTED:x:00000000]hunter2",
            &["hunter2"],
            "password=[REDACTED:secret_by_key:~]",
        ),
        case(
            "key flags",
            "mysql --password=hunter2 --host db\nmysql --password hunter3 --host db",
            &["hunter2", "hunter3"],
            "mysql --password=[REDACTED:secret_by_key:~]\nmysql --password [REDACTED:secret_by_key:~] --host db",
        ),
        case(
            "key json",
            "{\n  \"client_secret\": \"canary-client-secret\",\n  \"client_id\": \"rdy-cli\"\n}",
            &["canary-client-secret"],
            "{\n  \"client_secret\": \"[REDACTED:secret_by_key:~]\",\n  \"client_id\": \"rdy-cli\"\n}",
        ),
        // jwt 1
        case(
            "jwt in a kubernetes error",
            &format!("Unauthorized: invalid bearer token \"{jwt}\": token has expired"),
            &[&jwt, "c2lnbmF0dXJlLWNhbmFyeS0x"],
            "Unauthorized: invalid bearer token \"[REDACTED:jwt:~]\": token has expired",
        ),
        // hostile 1
        case(
            "ansi around a password",
            "\u{1b}[1mpassword\u{1b}[0m=hunter2\u{1b}[0m\nnext: line\n\u{1b}[31mtoken=hunter3\u{1b}[0m\n",
            &["hunter2", "hunter3"],
            "\u{1b}[1mpassword\u{1b}[0m=[REDACTED:secret_by_key:~]\u{1b}[0m\nnext: line\n\u{1b}[31mtoken=[REDACTED:secret_by_key:~]\u{1b}[0m\n",
        ),
    ]
}

#[test]
fn the_twenty_three_positive_inputs_come_out_typed_with_the_rest_kept() {
    let cases = positives();
    assert_eq!(cases.len(), 23, "04 Appendix D lists 23 positive inputs");
    let r = redactor();
    for c in &cases {
        let out = r.redact_str(&c.input);
        for secret in &c.secrets {
            assert!(
                !out.contains(secret.as_str()),
                "{}: {secret} survived in {}",
                c.name,
                *out
            );
        }
        assert_eq!(normalized(&out), c.want, "{}", c.name);
    }
}

#[test]
fn a_second_pass_changes_nothing() {
    let r = redactor();
    for c in positives() {
        let once = r.redact_str(&c.input);
        let twice = r.redact_str(&once);
        assert_eq!(*once, *twice, "{}", c.name);
    }
}

#[test]
fn equal_secrets_share_a_tag_whatever_rule_found_them() {
    let r = redactor();
    let out = r.redact_str("PROXY=http://svc:Zq9xK7mW2@h.test\nnote: http://svc:Zq9xK7mW2@h.test");
    let tags: Vec<&str> = out
        .match_indices("[REDACTED:url_userinfo:")
        .map(|(i, _)| &out[i + 23..i + 31])
        .collect();
    assert_eq!(tags.len(), 2, "{}", *out);
    assert_eq!(tags[0], tags[1]);
}

#[test]
fn the_negatives_come_out_unchanged() {
    let r = redactor();
    let cert = "-----BEGIN CERTIFICATE-----\nc3ludGhldGljLWNlcnRpZmljYXRlLWJvZHktbGluZS1vbmU=\nc3ludGhldGljLWNlcnRpZmljYXRlLWJvZHktbGluZS10d28=\n-----END CERTIFICATE-----";
    let public = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n-----END PUBLIC KEY-----";
    for text in [
        "secretName: acme-tls",
        "password: ${DB_PASSWORD}\nsecretName: acme-tls",
        "passed: 12\nauthor: alice",
        "commit: 9fceb02d0ae598e95dc970b74767f19372d61af8",
        "request id: 3f2b8c1e-5a47-4d0b-9c6e-1f7a2d4b8e90",
        "auth_method: oidc\ntokenType: Bearer\npasswordMode: file",
        "password: /run/secrets/db-pass",
        "see https://docs.acme.test/guide?page=2 and ssh to git.acme.test",
        "Bearer authentication failed; Bearer tokens expire",
        "WWW-Authenticate: Bearer realm=\"acme\"",
        cert,
        public,
    ] {
        assert_eq!(*r.redact_str(text), text, "{text}");
    }
}

#[test]
fn only_the_private_key_of_a_bundle_is_removed() {
    let r = redactor();
    let text = "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nQ0hBSU4=\n-----END CERTIFICATE-----\n";
    let out = normalized(&r.redact_str(text));
    assert_eq!(
        out,
        "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----\n[REDACTED:pem_private_key:~]\n-----BEGIN CERTIFICATE-----\nQ0hBSU4=\n-----END CERTIFICATE-----\n"
    );
}

#[test]
fn a_key_with_no_end_goes_to_the_end_of_the_text() {
    let r = redactor();
    let out =
        r.redact_str("log line\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nmore text");
    assert_eq!(normalized(&out), "log line\n[REDACTED:pem_private_key:~]");
}

#[test]
fn a_flag_with_a_secret_name_takes_the_next_word_only() {
    let r = redactor();
    for (text, want) in [
        (
            "run --token abc123def --verbose",
            "run --token [REDACTED:secret_by_key:~] --verbose",
        ),
        (
            "run --api-key 'abc 123' --verbose",
            "run --api-key '[REDACTED:secret_by_key:~]' --verbose",
        ),
        (
            "run --password $DB_PASSWORD --verbose",
            "run --password $DB_PASSWORD --verbose",
        ),
        (
            "run --password-file /etc/pw --verbose",
            "run --password-file /etc/pw --verbose",
        ),
        ("run --password --verbose", "run --password --verbose"),
    ] {
        assert_eq!(normalized(&r.redact_str(text)), want, "{text}");
    }
}

#[test]
fn an_all_quoted_env_file_loses_only_the_secret_lines() {
    let r = redactor();
    let text =
        "NAME=\"acme\"\nDB_PASSWORD=\"hunter2\"\nREGION=\"eu\"\nAPI_TOKEN='abc123'\nMODE='fast'\n";
    assert_eq!(
        normalized(&r.redact_str(text)),
        "NAME=\"acme\"\nDB_PASSWORD=\"[REDACTED:secret_by_key:~]\"\nREGION=\"eu\"\nAPI_TOKEN='[REDACTED:secret_by_key:~]'\nMODE='fast'\n"
    );
}

#[test]
fn a_commented_out_block_is_redacted_to_its_last_comment_line() {
    let r = redactor();
    let text = "# token: |\n#   hunter2\n#   more\n# next: 1\nkeep: me\n";
    let out = normalized(&r.redact_str(text));
    assert!(!out.contains("hunter2") && !out.contains("more"), "{out}");
    assert!(out.ends_with("# next: 1\nkeep: me\n"), "{out}");
    let pem =
        "# -----BEGIN PRIVATE KEY-----\n# S0VZLUNBTkFSWQ==\n# -----END PRIVATE KEY-----\nkeep\n";
    assert_eq!(
        normalized(&r.redact_str(pem)),
        "# [REDACTED:pem_private_key:~]\nkeep\n"
    );
}

#[test]
fn a_list_of_maps_ends_a_secret_at_the_next_item() {
    let r = redactor();
    let text = "items:\n- password: |\n    hunter2\n- name: second\n";
    let out = normalized(&r.redact_str(text));
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.ends_with("- name: second\n"), "{out}");
}

#[test]
fn evidence_urls_are_scheme_host_port_and_path() {
    let planted = ["pa55", "w0rd-canary"].concat();
    let token = "tok-canary-9";
    let url = format!("https://svc:{planted}@dl.acme.test:8443/pkg/a.tgz?token={token}&sig=1#top");
    let stored = evidence_url(&url).unwrap_or_default();
    assert_eq!(stored, "https://dl.acme.test:8443/pkg/a.tgz");
    assert!(!stored.contains(&planted) && !stored.contains(token));
    assert_eq!(evidence_url("not a url"), None);
}

/// The tags of every placeholder of `rule` in `text`.
fn tags_of<'a>(text: &'a str, rule: &str) -> Vec<&'a str> {
    let open = format!("[REDACTED:{rule}:");
    text.match_indices(&open)
        .map(|(i, _)| &text[i + open.len()..i + open.len() + 8])
        .collect()
}

#[test]
fn one_secret_has_one_tag_in_a_header_a_flag_and_a_bare_bearer() {
    let r = redactor();
    let token = ["canary", "SharedBearer77"].concat();
    let header = r.redact_str(&format!("Authorization: Bearer {token}"));
    let flag = r.redact_str(&format!("run --token {token}"));
    let bare = r.redact_str(&format!("got bearer {token} from the proxy"));
    let proxy = r.redact_str(&format!("Proxy-Authorization: Bearer {token}"));
    assert_eq!(
        normalized(&header),
        "Authorization: Bearer [REDACTED:auth_header:~]"
    );
    let want = tags_of(&header, "auth_header");
    assert_eq!(want.len(), 1, "{}", *header);
    assert_eq!(tags_of(&flag, "secret_by_key"), want, "{}", *flag);
    assert_eq!(tags_of(&bare, "auth_header"), want, "{}", *bare);
    assert_eq!(tags_of(&proxy, "auth_header"), want, "{}", *proxy);
}

#[test]
fn a_header_with_a_plain_word_is_left_alone() {
    let r = redactor();
    for text in [
        "authorization: true",
        "Authorization: null",
        "authorization: none",
    ] {
        assert_eq!(*r.redact_str(text), text);
    }
}

#[test]
fn a_raw_slash_in_a_url_password_is_still_userinfo() {
    let r = redactor();
    let out = r.redact_str("DATABASE_URL=postgres://app:K7x/9+Qa@db:5432/app");
    assert_eq!(
        normalized(&out),
        "DATABASE_URL=postgres://[REDACTED:url_userinfo:~]@db:5432/app"
    );
    let out = r.redact_str("see postgres://app:K7x?9#Qa@db:5432/app now");
    assert_eq!(
        normalized(&out),
        "see postgres://[REDACTED:url_userinfo:~]@db:5432/app now"
    );
    // A port, a scoped package and a digest are not userinfo.
    for text in [
        "https://h.test:8443/pkg/@scope/x",
        "https://registry.test/@scope/pkg",
        "docker://reg.test/app@sha256:0123456789abcdef",
        "https://dl.acme.test/pkg?email=a@b.test",
    ] {
        assert_eq!(*r.redact_str(text), text, "{text}");
    }
}

#[test]
fn an_evidence_url_with_an_at_sign_after_the_authority_stores_nothing() {
    for url in [
        "https://dl.acme.test/pkg?email=a@b.test",
        "docker://reg.test/app@sha256:0123456789abcdef",
        "https://registry.test/@scope/pkg",
        "https://h.test/v1?k=svc@Zk3v9TokenAbc",
        "https://u:K7x/9+Qa@db.test:5432/app",
    ] {
        assert_eq!(evidence_url(url), None, "{url}");
    }
}

#[test]
fn an_angle_bracket_placeholder_after_a_flag_is_a_fix_text_not_a_secret() {
    let r = redactor();
    // The fix text of the k8s.access check.
    let fix = "Log in with `rancher login <rancher-url> --token <bearer-token>` and run again.";
    assert_eq!(*r.redact_str(fix), fix);
    // A real value is still taken, and so is a bracketed word in a key rule.
    assert_eq!(
        normalized(&r.redact_str("rancher login --token abc123def")),
        "rancher login --token [REDACTED:secret_by_key:~]"
    );
    assert!(!r.redact_str("password: <hunter2>").contains("hunter2"));
    assert!(!r.redact_str("run --token <a>hunter2").contains("hunter2"));
}

#[test]
fn a_client_key_path_in_a_kubeconfig_stays() {
    let r = redactor();
    let text = "users:\n- name: admin\n  user:\n    client-key: /etc/kube/client.key\n";
    assert_eq!(*r.redact_str(text), text);
}
