//! The fix text of `k8s.access`, by cause (03 `k8s.access`, "Fix, by cause").
//!
//! The words are chosen from what rdy knows without asking: the credential plugin's file name, the shape
//! of the context name, the server host. Where it cannot tell which cloud a cluster is on, the text says
//! "the way you made this kubeconfig" and names no command that may not apply. A value rdy does not know
//! (a profile, a resource group, a principal) is an angle-bracket placeholder, never a guess.
//!
//! Every backtick span is a command the customer can copy. The tests run each text through
//! `rdy_engine::fixtext::check`.

use crate::client::{ConnectionFacts, Credential, KubeError};

/// The cloud a cluster appears to be on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Provider {
    Eks,
    Gke,
    Aks,
    OpenShift,
    Other,
}

/// What rdy can tell about the cluster from the kubeconfig alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Guess {
    pub(super) provider: Provider,
    /// The cluster name, when the context name gives it.
    pub(super) cluster: Option<String>,
    /// The region (EKS) or location (GKE), when the context name gives it.
    pub(super) region: Option<String>,
    /// The API server as the cluster line shows it.
    pub(super) server: String,
}

impl Guess {
    fn cluster(&self) -> &str {
        self.cluster.as_deref().unwrap_or("<cluster>")
    }

    fn region(&self) -> &str {
        self.region.as_deref().unwrap_or("<region>")
    }
}

/// Reads the provider, cluster and region from the plugin, the context name and the server host.
pub(super) fn guess(facts: Option<&ConnectionFacts>) -> Guess {
    let Some(facts) = facts else {
        return Guess {
            provider: Provider::Other,
            cluster: None,
            region: None,
            server: String::new(),
        };
    };
    let context = facts.line().context();
    let server = facts.line().server();
    let mut guess = Guess {
        provider: Provider::Other,
        cluster: None,
        region: None,
        server: server.to_owned(),
    };
    // `arn:aws:eks:<region>:<account>:cluster/<name>` is what `aws eks update-kubeconfig` writes.
    let parts: Vec<&str> = context.split(':').collect();
    if context.starts_with("arn:aws") && parts.len() == 6 && parts[2] == "eks" {
        guess.provider = Provider::Eks;
        guess.region = Some(parts[3].to_owned());
        guess.cluster = parts[5].strip_prefix("cluster/").map(str::to_owned);
    } else if let Some(rest) = context.strip_prefix("gke_") {
        // `gke_<project>_<location>_<cluster>`. A project id has no underscore.
        let fields: Vec<&str> = rest.split('_').collect();
        if fields.len() == 3 {
            guess.provider = Provider::Gke;
            guess.region = Some(fields[1].to_owned());
            guess.cluster = Some(fields[2].to_owned());
        }
    } else if is_oc_context(context) {
        guess.provider = Provider::OpenShift;
    }
    if guess.provider == Provider::Other {
        let host = server
            .split_once("://")
            .map_or(server, |(_, rest)| rest)
            .split(['/', ':'])
            .next()
            .unwrap_or("");
        if host.ends_with(".eks.amazonaws.com") || host.ends_with(".eks.amazonaws.com.cn") {
            guess.provider = Provider::Eks;
        } else if host.ends_with(".azmk8s.io") {
            guess.provider = Provider::Aks;
        } else if host.ends_with(".gke.goog") {
            guess.provider = Provider::Gke;
        }
    }
    // The plugin is the strongest signal, because it is what the cloud's own command wrote.
    for credential in facts.credentials() {
        if let Credential::Plugin { binary } = credential
            && let Some(provider) = plugin_provider(binary)
        {
            guess.provider = provider;
        }
    }
    // The cluster name of an AKS context is usually the cluster name.
    if guess.provider == Provider::Aks
        && guess.cluster.is_none()
        && !context.is_empty()
        && context
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        guess.cluster = Some(context.to_owned());
    }
    guess
}

/// `<namespace>/<api-host>:<port>/<user>`, the context name `oc login` writes.
fn is_oc_context(context: &str) -> bool {
    let parts: Vec<&str> = context.split('/').collect();
    parts.len() == 3 && parts[1].starts_with("api-") && parts[1].contains(':')
}

/// The provider a credential plugin's file name belongs to.
fn plugin_provider(binary: &str) -> Option<Provider> {
    let lower = binary.to_ascii_lowercase();
    let name = lower
        .strip_suffix(".exe")
        .or_else(|| lower.strip_suffix(".cmd"))
        .unwrap_or(&lower);
    match name {
        "aws" | "aws-iam-authenticator" | "aws-eks" => Some(Provider::Eks),
        "gke-gcloud-auth-plugin" | "gcloud" => Some(Provider::Gke),
        "kubelogin" => Some(Provider::Aks),
        "oc" => Some(Provider::OpenShift),
        _ => None,
    }
}

/// How to get fresh credentials for this cluster.
pub(super) fn login(guess: &Guess) -> String {
    match guess.provider {
        Provider::Eks => format!(
            "Refresh the kubeconfig with `aws eks update-kubeconfig --name {} --region {}`. If the AWS session expired, run `aws sso login --profile <profile>` first.",
            guess.cluster(),
            guess.region()
        ),
        Provider::Gke => format!(
            "Refresh the kubeconfig with `gcloud container clusters get-credentials {} --location {}`, and keep `gke-gcloud-auth-plugin` on PATH. If gcloud asks for a login, run `gcloud auth login` first.",
            guess.cluster(),
            guess
                .region
                .as_deref()
                .unwrap_or("<location>")
        ),
        Provider::Aks => format!(
            "Refresh the kubeconfig with `az aks get-credentials -g <resource-group> -n {}`, then `kubelogin convert-kubeconfig -l azurecli`. If az asks for a login, run `az login` first.",
            guess.cluster()
        ),
        Provider::OpenShift => format!("Log in again with `oc login {}`.", server_or_placeholder(guess)),
        Provider::Other => "Log in again the way you did when you made this kubeconfig, or ask the cluster admin for a new one.".to_owned(),
    }
}

fn server_or_placeholder(guess: &Guess) -> &str {
    if guess.server.is_empty() {
        "<server>"
    } else {
        &guess.server
    }
}

/// What to add when a 401 comes back after a good sign-in on EKS: the IAM principal is not mapped.
pub(super) fn eks_not_mapped(guess: &Guess) -> String {
    format!(
        "If the sign-in works and the server still says Unauthorized, the IAM principal is not mapped to the cluster. Add it with `aws eks create-access-entry --cluster-name {c} --principal-arn <principal-arn>` and `aws eks associate-access-policy --cluster-name {c} --principal-arn <principal-arn> --policy-arn <policy-arn> --access-scope type=cluster`, or edit `aws-auth` on an older cluster. Only the cluster creator is admin by default.",
        c = guess.cluster()
    )
}

/// The fix for a 401.
pub(super) fn unauthorized(guess: &Guess) -> String {
    let mut text = login(guess);
    if guess.provider == Provider::Eks {
        text.push(' ');
        text.push_str(&eks_not_mapped(guess));
    }
    text
}

/// The fix for an identity that the server treats as `system:anonymous`.
pub(super) fn anonymous(guess: &Guess, has_credentials: bool) -> String {
    let lead = if has_credentials {
        "The server did not accept the credentials in the kubeconfig and fell back to anonymous."
    } else {
        "The kubeconfig user has no token, client certificate or credential plugin."
    };
    format!("{lead} {}", login(guess))
}

/// The fix for a 403 on the identity review.
pub(super) fn review_forbidden(has_credentials: bool, guess: &Guess) -> String {
    if has_credentials {
        "Every logged-in user may ask who they are (the `system:basic-user` ClusterRole). Ask the cluster admin to check `kubectl get clusterrolebinding system:basic-user -o yaml` and any authorizer webhook that denies `selfsubjectreviews`.".to_owned()
    } else {
        format!(
            "The kubeconfig user has no credentials, so the server treats rdy as anonymous and refuses it. {}",
            login(guess)
        )
    }
}

/// The fix for a server that cannot be reached, by what the error chain said.
///
/// `route` is the phrase for the proxy route (`ProxyUse::describe`), when there is one.
pub(super) fn unreachable(guess: &Guess, cause: &str, route: Option<&str>) -> String {
    let mut text = if cause.contains("UnknownIssuer") {
        // The hint of `KubeError` covers both cases (a CA in the kubeconfig and none), so it is used as is
        // by `for_error`. This arm is for completeness.
        String::new()
    } else if cause.contains("NotValidForName") {
        "The address in the kubeconfig is not in the server certificate. Use the name the certificate has (`kubectl config view --minify` shows the server), or set `tls-server-name` on the cluster.".to_owned()
    } else if cause.contains("(Expired)") {
        "The API server's certificate has expired. The cluster admin must renew it (kubeadm clusters: kubeadm certs renew all, on each control-plane node). Managed clusters rotate it themselves, so check with the provider.".to_owned()
    } else if cause.contains("NotValidYet") {
        "The server certificate is not valid yet, so this machine's clock is probably behind. Check the time with `timedatectl`.".to_owned()
    } else if cause.contains("did not resolve") {
        "The server name does not resolve from this machine. Check DNS or the VPN, and the address in the kubeconfig (`kubectl config view --minify`).".to_owned()
    } else if cause.contains("asked for credentials") {
        "The proxy wants credentials. Put them in the proxy URL, `http://user:password@host:port`, in `proxy-url` or in HTTPS_PROXY.".to_owned()
    } else if cause.contains("refused to open a tunnel") {
        "The proxy refused the CONNECT to the API server. Ask the network team to allow it, or run rdy from a host that reaches the API server directly.".to_owned()
    } else if cause.contains("handshake") {
        format!(
            "The TLS handshake failed. A proxy or load balancer that does not speak TLS on this port can cause it. {}",
            no_reply(guess)
        )
    } else {
        no_reply(guess)
    };
    if let Some(route) = route
        && !text.is_empty()
        && !cause.contains("proxy")
    {
        if route.starts_with("through") {
            text.push_str(&format!(
                " The request went {route}: check that the proxy allows CONNECT to the API server's host and port."
            ));
        } else {
            text.push_str(&format!(" The request went {route}."));
        }
    }
    text
}

/// The 03 text for an API server that does not answer.
pub(super) fn no_reply(guess: &Guess) -> String {
    let server = if guess.server.is_empty() {
        "the server"
    } else {
        &guess.server
    };
    let endpoint = match guess.provider {
        Provider::Eks => "EKS: check `endpointPublicAccess` and `publicAccessCidrs`.",
        Provider::Gke => "GKE: check the master authorized networks.",
        Provider::Aks => "AKS: check `--api-server-authorized-ip-ranges`.",
        Provider::OpenShift | Provider::Other => {
            "EKS: check `endpointPublicAccess` and `publicAccessCidrs`. GKE: check the master authorized networks. AKS: check `--api-server-authorized-ip-ranges`."
        }
    };
    format!(
        "No reply from {server}. The API endpoint is probably private or limited to allowed networks. {endpoint} Run rdy from a host inside the network, or connect the VPN."
    )
}

/// The fix for a credential plugin that did not answer in time.
pub(super) fn plugin_timed_out(binary: &str, guess: &Guess) -> String {
    let login = match guess.provider {
        Provider::Eks => "`aws sso login --profile <profile>`",
        Provider::Gke => "`gcloud auth login`",
        Provider::Aks => "`az login`",
        Provider::OpenShift => "`oc login <server>`",
        Provider::Other => "the login your provider uses",
    };
    format!(
        "Run the login by hand first: {login}. Then run rdy again. Without a terminal on stdin and stderr rdy runs `{binary}` non-interactively, so a device-code or browser login cannot finish inside rdy."
    )
}

/// The fix for a credential that has ended or is about to.
pub(super) fn renew(guess: &Guess, kind: &Credential) -> String {
    match kind {
        Credential::ClientCertificate { .. } => format!(
            "Ask the cluster admin for a new client certificate (kubeadm clusters: kubeadm certs renew admin.conf). {}",
            login(guess)
        ),
        _ => login(guess),
    }
}

/// The fix for any `KubeError` that stopped the connection.
pub(super) fn for_error(
    error: &KubeError,
    facts: Option<&ConnectionFacts>,
    route: Option<&str>,
) -> String {
    let guess = guess(facts);
    match error {
        KubeError::Unauthorized { .. } => unauthorized(&guess),
        KubeError::Timeout { .. } => unreachable(&guess, "timed out", route),
        KubeError::Unreachable { cause, .. } if !cause.contains("UnknownIssuer") => {
            unreachable(&guess, cause, route)
        }
        KubeError::PluginFailed { .. } | KubeError::PluginOutputInvalid { .. } => {
            format!("{} {}", error.hint(), login(&guess))
        }
        KubeError::PluginNotStarted { plugin, .. }
            if plugin.starts_with("gke-gcloud-auth-plugin") =>
        {
            format!(
                "{} Install it with `gcloud components install gke-gcloud-auth-plugin`.",
                error.hint()
            )
        }
        // A 403 on `/version`, a missing kubeconfig, a bad context, an unknown issuer and the rest have a
        // hint that already says what to do.
        other => other.hint(),
    }
}

#[cfg(test)]
mod tests;
