//! Which proxy the kube client uses, and why (03 `k8s.access`, ADR 0037).
//!
//! kube takes a proxy only from the cluster's `proxy-url` and never reads `HTTPS_PROXY` on its own that
//! rdy would want (the load reads it and fails on a malformed value, so the client module keeps it away
//! from kube, ADR 0031 decision 6). `kubectl` honours both, so `kubectl` can work while `rdy` times out.
//! This module makes rdy choose the way `kubectl` does and says which rule applied:
//!
//! 1. The cluster entry's `proxy-url`. It applies to the cluster whatever `NO_PROXY` says.
//! 2. `HTTPS_PROXY`, else `https_proxy`, for an `https` API server, unless `NO_PROXY` (else `no_proxy`)
//!    covers the API host. Loopback hosts and `localhost` never use a proxy.
//! 3. No proxy.
//!
//! Only an `http://` proxy is used (a `CONNECT` tunnel). `https://`, `socks5://` and any other scheme are
//! refused with a hint, because kube checks an `https` proxy against the cluster's CA settings and the
//! SOCKS path is not tested here (ADR 0037 decision 2). The `NO_PROXY` rules are Go's `httpproxy`
//! rules, the ones `kubectl` follows: a name matches itself and its subdomains, a leading dot matches
//! subdomains only, `*.example.com` is the same as `.example.com`, `host:port` limits the entry to a
//! port, an IP and a CIDR match addresses, and `*` matches everything.
//!
//! The functions here are pure. They read the [`Env`] values the caller gathered and open nothing.

use std::net::IpAddr;
use std::str::FromStr;

use http::Uri;

use super::Env;
use super::error::KubeError;
use super::proxy_display;
use super::text::escape_capped;

/// The longest `NO_PROXY` entry shown in a report, in characters.
const SHOWN_ENTRY: usize = 64;

/// Which rule chose the route to the API server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyRule {
    /// No proxy is configured anywhere that applies.
    None,
    /// The cluster entry's `proxy-url` in the kubeconfig.
    KubeconfigProxyUrl,
    /// The environment variable of this name.
    Environment(&'static str),
    /// A proxy variable is set, but the API host is exempt, so the request goes direct.
    Bypassed {
        /// The variable that names the proxy.
        var: &'static str,
        /// Why: a fixed phrase, or the `NO_PROXY` entry that matched (escaped and cut).
        why: String,
    },
}

/// The route to the API server: the rule and the proxy it chose.
///
/// The proxy is shown as scheme, host and port. User info, path and query never appear, because the
/// user info is a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUse {
    rule: ProxyRule,
    proxy: Option<String>,
}

impl ProxyUse {
    /// No proxy.
    #[must_use]
    pub fn none() -> Self {
        Self {
            rule: ProxyRule::None,
            proxy: None,
        }
    }

    /// The rule that applied.
    #[must_use]
    pub fn rule(&self) -> &ProxyRule {
        &self.rule
    }

    /// The proxy as `scheme://host:port`, when the request goes through one.
    #[must_use]
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }

    /// True when the request goes through a proxy.
    #[must_use]
    pub fn is_proxied(&self) -> bool {
        self.proxy.is_some()
    }

    /// One phrase for a report or a fix, or `None` when no proxy is involved at all.
    ///
    /// `through the proxy http://proxy.acme.example:3128 (HTTPS_PROXY)` or `directly, although
    /// HTTPS_PROXY is set (NO_PROXY entry ".acme.example" covers the API host)`.
    #[must_use]
    pub fn describe(&self) -> Option<String> {
        match (&self.rule, &self.proxy) {
            (ProxyRule::KubeconfigProxyUrl, Some(proxy)) => Some(format!(
                "through the proxy {proxy} (proxy-url in the kubeconfig)"
            )),
            (ProxyRule::Environment(var), Some(proxy)) => {
                Some(format!("through the proxy {proxy} ({var})"))
            }
            (ProxyRule::Bypassed { var, why }, _) => {
                Some(format!("directly, although {var} is set ({why})"))
            }
            _ => None,
        }
    }
}

/// What [`resolve`] decided.
#[derive(Debug)]
pub(crate) struct Resolved {
    /// The proxy to put on the kube config. `None` for a direct request.
    pub(crate) uri: Option<Uri>,
    /// The route, for reports.
    pub(crate) used: ProxyUse,
    /// The user info of the proxy URL, whole and its password. They join the known-secret set.
    pub(crate) secrets: Vec<String>,
}

/// Picks the proxy for the API server at `server`.
///
/// `kubeconfig_proxy` is the cluster entry's `proxy-url` (empty counts as unset).
///
/// # Errors
///
/// [`KubeError::ProxyUnsupported`] when the rule that applies names a proxy rdy cannot use: not an `http`
/// URL, no host, or not a URL at all. A proxy variable that `NO_PROXY` exempts is not read, so a stale
/// value there never fails a run that does not use it.
pub(crate) fn resolve(
    kubeconfig_proxy: Option<&str>,
    env: &Env,
    server: &Uri,
) -> Result<Resolved, KubeError> {
    if let Some(raw) = kubeconfig_proxy.filter(|raw| !raw.is_empty()) {
        return use_proxy(
            raw,
            raw,
            "the proxy-url in the kubeconfig",
            ProxyRule::KubeconfigProxyUrl,
        );
    }
    let direct = |used| Resolved {
        uri: None,
        used,
        secrets: Vec::new(),
    };
    let (Some(raw), true) = (
        env.https_proxy.as_deref().filter(|raw| !raw.is_empty()),
        server.scheme_str() == Some("https"),
    ) else {
        return Ok(direct(ProxyUse::none()));
    };
    let var = env.https_proxy_name;
    let host = bare_host(server);
    let port = server.port_u16().unwrap_or(443);
    if is_loopback(&host) {
        return Ok(direct(bypassed(
            var,
            "loopback addresses never use a proxy",
        )));
    }
    if let Some(list) = env.no_proxy.as_deref()
        && let Some(entry) = no_proxy_entry(list, &host, port)
    {
        let why = if entry == "*" {
            "NO_PROXY is *".to_owned()
        } else {
            format!(
                "NO_PROXY entry \"{}\" covers the API host",
                escape_capped(&entry, SHOWN_ENTRY)
            )
        };
        return Ok(direct(bypassed(var, &why)));
    }
    // Go reads `host:port` as an http proxy. The kubeconfig field needs a scheme.
    // An error shows the value as it was written, so a malformed one reads "(not a valid URL)".
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("http://{raw}")
    };
    use_proxy(&candidate, raw, var, ProxyRule::Environment(var))
}

fn bypassed(var: &'static str, why: &str) -> ProxyUse {
    ProxyUse {
        rule: ProxyRule::Bypassed {
            var,
            why: why.to_owned(),
        },
        proxy: None,
    }
}

/// Checks `raw` is a proxy rdy can use, and describes the route through it.
fn use_proxy(
    raw: &str,
    written: &str,
    origin: &'static str,
    rule: ProxyRule,
) -> Result<Resolved, KubeError> {
    let unusable = || KubeError::ProxyUnsupported {
        proxy: proxy_display(written),
        origin,
    };
    let uri = Uri::from_str(raw).map_err(|_| unusable())?;
    let usable = uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        && uri.host().is_some_and(|host| !host.is_empty())
        && uri.query().is_none()
        && matches!(uri.path(), "" | "/");
    if !usable {
        return Err(unusable());
    }
    let secrets = uri
        .authority()
        .and_then(|authority| authority.as_str().rsplit_once('@'))
        .map(|(userinfo, _)| userinfo)
        .filter(|userinfo| !userinfo.is_empty())
        .map(|userinfo| {
            let mut secrets = vec![userinfo.to_owned()];
            if let Some((_, password)) = userinfo.split_once(':')
                && !password.is_empty()
            {
                secrets.push(password.to_owned());
            }
            secrets
        })
        .unwrap_or_default();
    Ok(Resolved {
        used: ProxyUse {
            rule,
            proxy: Some(proxy_display(raw)),
        },
        uri: Some(uri),
        secrets,
    })
}

/// The host of `server` in lower case, without the brackets of an IPv6 literal.
fn bare_host(server: &Uri) -> String {
    server
        .host()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// `localhost` and loopback addresses. Go never proxies them.
fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The first `NO_PROXY` entry that covers `host` and `port`, lower-cased.
///
/// `host` is lower case with no brackets.
pub(crate) fn no_proxy_entry(list: &str, host: &str, port: u16) -> Option<String> {
    let ip = host.parse::<IpAddr>().ok();
    for raw in list.split(',') {
        let entry = raw.trim().to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            return Some(entry);
        }
        if let Some((net, bits)) = entry.split_once('/') {
            if let (Some(ip), Ok(net), Ok(bits)) = (ip, net.parse::<IpAddr>(), bits.parse::<u8>())
                && cidr_contains(net, bits, ip)
            {
                return Some(entry);
            }
            continue;
        }
        let (name, entry_port) = split_port(&entry);
        if entry_port.is_some_and(|wanted| wanted != port) {
            continue;
        }
        if let Ok(listed) = name.parse::<IpAddr>() {
            if ip == Some(listed) {
                return Some(entry);
            }
            continue;
        }
        if name.is_empty() {
            continue;
        }
        // `*.acme.example` is `.acme.example`. A name with no leading dot matches itself too.
        let dotted = name
            .strip_prefix("*.")
            .map_or_else(|| name.to_owned(), |rest| format!(".{rest}"));
        let (suffix, itself) = if dotted.starts_with('.') {
            (dotted, false)
        } else {
            (format!(".{dotted}"), true)
        };
        if host.ends_with(&suffix) || (itself && host == &suffix[1..]) {
            return Some(entry);
        }
    }
    None
}

/// Splits `name:port`, `[v6]:port` and `[v6]`. An unbracketed IPv6 literal has no port.
fn split_port(entry: &str) -> (&str, Option<u16>) {
    if let Some(rest) = entry.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((name, after)) => (name, after.strip_prefix(':').and_then(|p| p.parse().ok())),
            None => (entry, None),
        };
    }
    if entry.matches(':').count() == 1
        && let Some((name, port)) = entry.split_once(':')
    {
        return match port.parse() {
            Ok(port) => (name, Some(port)),
            // `host:` or `host:abc` is not a port. Match the name alone, as Go does.
            Err(_) => (name, None),
        };
    }
    (entry, None)
}

/// Whether `ip` is inside the network `net`/`bits`. A family mismatch or a prefix too long is no match.
fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;
