//! The judgement of `net.proxy`: a pure function from what was read to a finding.
//!
//! It touches no machine. Every string it writes holds a proxy as `http://host:port`, a variable name, a
//! file path from the fixed list, or an entry of a `NO_PROXY` list the customer wrote. Never a user name
//! or password: [`Setting`] has none, and `NO_PROXY` holds none.
//!
//! **Levels (03).** Block: the proxy is not reachable; a required `NO_PROXY` entry is missing; a daemon
//! does not see the proxy and the spec sets `daemons_need_proxy`. Warn: a daemon does not see the proxy,
//! a PAC address, two spellings of one variable that differ, an unsupported scheme, a daemon whose
//! `NO_PROXY` lacks a required entry. Anything else is a note.

use rdy_engine::check::{Finding, Level, Need, Os, Partial};
use rdy_engine::probe::{EnvConflict, NoProxy, PROXY_ENV};
use serde_json::{Value, json};

use super::parse::Setting;
use crate::text::code;

/// The most names a sentence lists before "and N more".
const NAMED: usize = 4;

/// What the spec asks for.
#[derive(Debug, Clone, Default)]
pub(super) struct Rules {
    pub required_no_proxy: Vec<String>,
    pub daemons_need_proxy: bool,
}

/// What a daemon's own settings say.
#[derive(Debug, Clone, Default)]
pub(super) struct Daemon {
    pub unit: &'static str,
    pub present: bool,
    pub http: Option<Setting>,
    pub https: Option<Setting>,
    pub no_proxy: Option<NoProxy>,
    /// The files that set something, as paths from the fixed list.
    pub sources: Vec<String>,
    /// `EnvironmentFile=` targets, which rdy does not read.
    pub env_files: Vec<String>,
    /// A drop-in directory or file could not be read, so a missing proxy is not known to be missing.
    pub unread: bool,
}

impl Daemon {
    /// The usable proxy of the daemon, `https` first.
    fn proxy(&self) -> Option<&str> {
        self.https
            .as_ref()
            .and_then(Setting::origin)
            .or_else(|| self.http.as_ref().and_then(Setting::origin))
    }

    fn name(&self) -> &'static str {
        match self.unit {
            "docker" => "Docker",
            "containerd" => "containerd",
            _ => "kubelet",
        }
    }
}

/// Whether the proxy could be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Reach {
    /// The run has no proxy to test.
    NoProxy,
    /// Not tried, with the reason.
    NotTried(&'static str),
    /// A TCP connection opened and closed.
    Connected { origin: String, ms: u64 },
    /// No connection. `class` is a stable word, `why` a phrase for a sentence.
    Failed {
        origin: String,
        class: &'static str,
        why: &'static str,
    },
}

/// Everything the check read.
#[derive(Debug, Clone)]
pub(super) struct Facts {
    pub os: Os,
    /// The proxy variables that are set, in the order read. A PAC address in `auto_proxy` is one too.
    pub vars: Vec<(&'static str, Setting)>,
    pub no_proxy: Option<(&'static str, NoProxy)>,
    pub conflicts: Vec<EnvConflict>,
    pub daemons: Vec<Daemon>,
    pub reach: Reach,
    pub notes: Vec<String>,
    pub missing_network: bool,
    pub unread: Vec<String>,
}

/// The proxy the run's shell uses: the first usable one of `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`,
/// `http_proxy`, the order `ProbeHub::set_proxy_from_env` uses.
fn shell_proxy(facts: &Facts) -> Option<(&'static str, &str)> {
    PROXY_ENV.iter().find_map(|name| {
        facts
            .vars
            .iter()
            .find(|(var, _)| var == name)
            .and_then(|(var, setting)| setting.origin().map(|origin| (*var, origin)))
    })
}

fn credentials(facts: &Facts) -> bool {
    facts.vars.iter().any(|(_, s)| {
        matches!(
            s,
            Setting::Proxy {
                credentials: true,
                ..
            }
        )
    })
}

/// `a, b and N more`.
fn list(items: &[String]) -> String {
    let mut shown: Vec<String> = items.iter().take(NAMED).map(|i| code(i)).collect();
    if items.len() > NAMED {
        shown.push(format!("and {} more", items.len() - NAMED));
    }
    shown.join(", ")
}

/// The `NO_PROXY` text for a fix: the entries the shell has, then the required ones it lacks. Only entries
/// made of plain characters are copied, so the text is safe inside quotes.
fn no_proxy_text(facts: &Facts, rules: &Rules) -> String {
    let plain = |entry: &str| {
        !entry.is_empty()
            && entry.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '.' | ':' | '*' | '/' | '_' | '-' | '[' | ']')
            })
    };
    let mut entries: Vec<String> = facts
        .no_proxy
        .iter()
        .flat_map(|(_, list)| list.entries().map(str::to_owned))
        .filter(|entry| plain(entry))
        .collect();
    for required in &rules.required_no_proxy {
        let required = required.trim().to_ascii_lowercase();
        if plain(&required) && !entries.contains(&required) {
            entries.push(required);
        }
    }
    if entries.is_empty() {
        entries = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    }
    let text = entries.join(",");
    if text.chars().count() > 200 {
        "<your NO_PROXY list>".to_owned()
    } else {
        text
    }
}

/// The fix for a daemon that does not see the proxy (03 "net.proxy").
fn dropin_fix(daemon: &Daemon, proxy: &str, facts: &Facts, rules: &Rules) -> String {
    let unit = daemon.unit;
    let text = format!(
        "{} does not see the proxy. Create `/etc/systemd/system/{unit}.service.d/http-proxy.conf` with `[Service]` and `Environment=\"HTTP_PROXY={proxy}\" \"HTTPS_PROXY={proxy}\" \"NO_PROXY={}\"`, then run `systemctl daemon-reload && systemctl restart {unit}`.",
        daemon.name(),
        no_proxy_text(facts, rules),
    );
    text
}

/// Said once after the drop-in fixes, when the shell proxy URL has a user name and password.
const CREDENTIALS_ADVICE: &str = "The proxy URL of this shell has a user name and password. Add them to the URLs in the drop-in if the proxy needs them. rdy does not print them.";

// The result's `observed` may hold lists and objects two levels deep and nothing below that: a deeper one
// is cut to "[truncated]" when the report is written. So each value here is a scalar, a flat object, or a
// list of flat objects, and no key holds a word the redactor reads as a secret name (`credentials`,
// `bypass`, `auth`, `token`): a placeholder would replace its value.

/// One proxy variable or drop-in setting, flat. `has_user_info` is whether the URL had a user name.
fn setting_fields(setting: &Setting, out: &mut serde_json::Map<String, Value>) {
    match setting {
        Setting::Proxy {
            origin,
            credentials,
        } => {
            out.insert("state".to_owned(), json!("proxy"));
            out.insert("proxy".to_owned(), json!(origin));
            out.insert("has_user_info".to_owned(), json!(credentials));
        }
        Setting::Unsupported(scheme) => {
            out.insert("state".to_owned(), json!("unsupported_scheme"));
            out.insert("scheme".to_owned(), json!(scheme));
        }
        Setting::Pac(url) => {
            out.insert("state".to_owned(), json!("pac"));
            out.insert("url".to_owned(), json!(url));
        }
        Setting::Bad(error) => {
            out.insert("state".to_owned(), json!("not_usable"));
            out.insert(
                "why".to_owned(),
                json!(error.to_string().split(". Fix:").next().unwrap_or_default()),
            );
        }
    }
}

fn variable_json(var: &str, setting: &Setting) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("var".to_owned(), json!(var));
    setting_fields(setting, &mut out);
    Value::Object(out)
}

fn coverage(scope: &str, list: &NoProxy, rules: &Rules, out: &mut Vec<Value>) {
    for entry in &rules.required_no_proxy {
        let by = list.covers(entry);
        out.push(json!({
            "scope": scope,
            "entry": entry,
            "covered": by.is_some(),
            "by": by,
        }));
    }
}

fn no_proxy_json(facts: &Facts) -> Value {
    match &facts.no_proxy {
        Some((var, list)) => json!({
            "set": true,
            "var": var,
            "entries": list.len(),
            "truncated": list.truncated(),
        }),
        None => json!({ "set": false }),
    }
}

/// `NO_PROXY` coverage of each required entry: for the shell, then for each daemon that has a proxy.
fn coverage_json(facts: &Facts, rules: &Rules) -> Vec<Value> {
    let mut out = Vec::new();
    if rules.required_no_proxy.is_empty() {
        return out;
    }
    let none = NoProxy::default();
    let shell = facts.no_proxy.as_ref().map_or(&none, |(_, list)| list);
    coverage("shell", shell, rules, &mut out);
    for daemon in facts
        .daemons
        .iter()
        .filter(|d| d.present && d.proxy().is_some())
    {
        coverage(
            daemon.unit,
            daemon.no_proxy.as_ref().unwrap_or(&none),
            rules,
            &mut out,
        );
    }
    out
}

fn daemon_json(daemon: &Daemon) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("unit".to_owned(), json!(daemon.unit));
    out.insert("present".to_owned(), json!(daemon.present));
    // The usable proxy (`https` first), else the state of the setting that was written.
    match daemon.proxy() {
        Some(origin) => {
            out.insert("proxy".to_owned(), json!(origin));
        }
        None => {
            if let Some(setting) = daemon.https.as_ref().or(daemon.http.as_ref()) {
                let mut state = serde_json::Map::new();
                setting_fields(setting, &mut state);
                out.insert("proxy_state".to_owned(), state["state"].clone());
            }
        }
    }
    out.insert(
        "no_proxy_entries".to_owned(),
        json!(daemon.no_proxy.as_ref().map(NoProxy::len)),
    );
    out.insert("sources".to_owned(), json!(daemon.sources.join(", ")));
    out.insert(
        "environment_files_not_read".to_owned(),
        json!(daemon.env_files.join(", ")),
    );
    out.insert("unreadable".to_owned(), json!(daemon.unread));
    Value::Object(out)
}

fn reach_json(reach: &Reach) -> Value {
    match reach {
        Reach::NoProxy => json!({ "state": "no_proxy" }),
        Reach::NotTried(why) => json!({ "state": "not_tried", "why": why }),
        Reach::Connected { origin, ms } => {
            json!({ "state": "connected", "proxy": origin, "ms": ms })
        }
        Reach::Failed { origin, class, why } => {
            json!({ "state": "failed", "proxy": origin, "class": class, "why": why })
        }
    }
}

/// The finding for what was read.
pub(super) fn judge(facts: &Facts, rules: &Rules) -> Finding {
    let mut blocks: Vec<String> = Vec::new();
    let mut warns: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut notes: Vec<String> = facts.notes.clone();
    let shell = shell_proxy(facts);
    let daemon_has_proxy = facts
        .daemons
        .iter()
        .any(|d| d.present && d.proxy().is_some());

    // The proxy itself: reachable?
    if let Reach::Failed { origin, class, why } = &facts.reach {
        blocks.push(format!(
            "The proxy {} is not reachable ({why})",
            code(origin)
        ));
        if *class == "blackhole" {
            // The wording `M1-179` counts as a hang the check survived.
            notes.push("no reply within 3 s from the proxy address".to_owned());
        }
        let var = shell.map_or("HTTPS_PROXY", |(var, _)| var);
        let port = origin.rsplit(':').next().unwrap_or("the proxy port");
        fixes.push(match *class {
            "refused" => format!(
                "Nothing listens at the proxy {origin}. Check the host and port in {var}, and that the proxy is running."
            ),
            "dns" => format!(
                "The proxy name in {var} ({origin}) does not resolve on this machine. Fix the name in {var}, or use the proxy's IP address."
            ),
            _ => format!(
                "This machine cannot reach the proxy {origin}. Check the address in {var}. If it is right, ask the network team to allow tcp/{port} from this machine to the proxy."
            ),
        });
    }

    // PAC and WPAD: detected, never fetched.
    let mut pacs = 0;
    for (var, setting) in &facts.vars {
        if let Setting::Pac(url) = setting {
            pacs += 1;
            warns.push(format!(
                "{var} points at a PAC or WPAD script ({}), and rdy does not fetch or evaluate PAC",
                code(url)
            ));
        }
    }
    if pacs > 0 {
        fixes.push(
            "rdy cannot evaluate PAC. Set HTTPS_PROXY to the proxy that the PAC script returns for the product's hosts, or set via_proxy in the spec."
                .to_owned(),
        );
    }

    // Variables rdy cannot use.
    let mut unusable = false;
    for (var, setting) in &facts.vars {
        match setting {
            Setting::Unsupported(scheme) => {
                unusable = true;
                warns.push(format!(
                    "{var} uses {scheme}://, which rdy does not support in M1, so it was not probed"
                ));
            }
            Setting::Bad(error) => {
                unusable = true;
                let why = error.to_string();
                warns.push(format!(
                    "{var} is not a usable proxy URL ({})",
                    why.split(". Fix:").next().unwrap_or_default()
                ));
            }
            _ => {}
        }
    }
    if unusable {
        fixes.push(
            "Set the proxy variable to the proxy's http://host:port address, or ask the network team for one. rdy supports plain http:// proxies with Basic authentication."
                .to_owned(),
        );
    }

    // Two spellings that differ.
    for conflict in &facts.conflicts {
        warns.push(format!(
            "{} and {} are both set and differ",
            conflict.upper, conflict.lower
        ));
        fixes.push(format!(
            "Set only one of {} and {}, or make them equal.",
            conflict.upper, conflict.lower
        ));
    }
    if !facts.conflicts.is_empty() {
        fixes.push(
            "curl and Python read the lower-case name first and Go reads the upper-case name, so tools use different values today."
                .to_owned(),
        );
    }

    // NO_PROXY coverage of what the spec requires, for the shell.
    if !rules.required_no_proxy.is_empty() && shell.is_some() {
        let missing: Vec<String> = rules
            .required_no_proxy
            .iter()
            .filter(|entry| {
                facts
                    .no_proxy
                    .as_ref()
                    .is_none_or(|(_, list)| list.covers(entry).is_none())
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            blocks.push(format!("NO_PROXY does not cover {}", list(&missing)));
            fixes.push(format!(
                "Add {} to NO_PROXY in the environment of the product, so that traffic to them does not go through the proxy.",
                list(&missing)
            ));
        }
    }

    // Daemons.
    for daemon in facts.daemons.iter().filter(|d| d.present) {
        match (shell, daemon.proxy()) {
            (Some(_), None) if daemon.unread => {}
            (Some((_, proxy)), None) => {
                let message = format!(
                    "{} is installed and has no proxy in a systemd drop-in{}, so it does not see the proxy this shell uses",
                    daemon.name(),
                    if daemon.unit == "docker" {
                        " or daemon.json"
                    } else {
                        ""
                    }
                );
                if rules.daemons_need_proxy {
                    blocks.push(message);
                } else {
                    warns.push(message);
                }
                fixes.push(dropin_fix(daemon, proxy, facts, rules));
            }
            (Some((var, proxy)), Some(own)) if own != proxy => {
                notes.push(format!(
                    "{} uses the proxy {} and this shell uses {} from {var}.",
                    daemon.unit,
                    code(own),
                    code(proxy)
                ));
            }
            (None, Some(own)) => {
                notes.push(format!(
                    "{} has the proxy {}, and this shell has none, so rdy tested the endpoints direct.",
                    daemon.unit,
                    code(own)
                ));
            }
            _ => {}
        }
        if daemon.proxy().is_some()
            && !rules.required_no_proxy.is_empty()
            && let Some(missing) = daemon_gap(daemon, rules)
        {
            warns.push(format!(
                "the NO_PROXY of {} does not cover {}",
                daemon.unit,
                list(&missing)
            ));
            fixes.push(format!(
                "Add {} to the NO_PROXY of {} in its systemd drop-in, then run `systemctl daemon-reload && systemctl restart {}`.",
                list(&missing),
                daemon.unit,
                daemon.unit
            ));
        }
        for file in &daemon.env_files {
            notes.push(format!(
                "The unit of {} reads {} with EnvironmentFile=. rdy does not read it, so a proxy set there is not seen.",
                daemon.unit,
                code(file)
            ));
        }
    }

    if credentials(facts)
        && facts
            .daemons
            .iter()
            .any(|d| d.present && d.proxy().is_none() && !d.unread)
        && shell.is_some()
    {
        fixes.push(CREDENTIALS_ADVICE.to_owned());
    }

    // A proxy with no NO_PROXY sends every destination to the proxy. Said once.
    if shell.is_some() && facts.no_proxy.is_none() && rules.required_no_proxy.is_empty() {
        notes.push(
            "NO_PROXY is not set, so every destination, cluster-internal ones included, goes through the proxy."
                .to_owned(),
        );
    }

    let any_proxy = shell.is_some() || daemon_has_proxy || pacs > 0;
    let blocked = !blocks.is_empty();
    let mut parts = blocks;
    parts.extend(warns);
    let message = if parts.is_empty() {
        match (shell, &facts.reach) {
            (Some((var, origin)), Reach::Connected { .. }) => format!(
                "The proxy {} from {var} is reachable, and NO_PROXY and the daemons agree with it.",
                code(origin)
            ),
            (Some((var, origin)), _) => format!(
                "The proxy {} from {var} is set and nothing in the settings conflicts.",
                code(origin)
            ),
            _ if any_proxy => {
                "A proxy is configured for a daemon and nothing conflicts.".to_owned()
            }
            _ => "No proxy is configured for this shell, Docker, containerd or the kubelet."
                .to_owned(),
        }
    } else {
        parts.join("; ")
    };
    let level = if blocked {
        Level::Fail
    } else if parts.is_empty() {
        Level::Pass
    } else {
        Level::Warn
    };

    let observed = json!({
        "os": match facts.os {
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Windows => "windows",
            _ => "other",
        },
        "variables": facts
            .vars
            .iter()
            .map(|(var, s)| variable_json(var, s))
            .collect::<Vec<_>>(),
        "conflicts": facts
            .conflicts
            .iter()
            .map(|c| json!({ "upper": c.upper, "lower": c.lower }))
            .collect::<Vec<_>>(),
        "shell_proxy": shell.map(|(var, origin)| json!({ "var": var, "proxy": origin })),
        "no_proxy": no_proxy_json(facts),
        "no_proxy_coverage": coverage_json(facts, rules),
        "daemons": facts.daemons.iter().map(daemon_json).collect::<Vec<_>>(),
        "reach": reach_json(&facts.reach),
    });
    let expected = json!({
        "required_no_proxy": rules.required_no_proxy,
        "daemons_need_proxy": rules.daemons_need_proxy,
    });
    let mut finding = Finding::new(level, message)
        .with_observed(observed)
        .with_expected(expected);
    if !fixes.is_empty() {
        finding = finding.with_fix(fixes.join(" "));
    }
    for note in notes {
        finding = finding.with_note(note);
    }
    let mut unread = facts.unread.clone();
    if let Reach::NotTried(why) = &facts.reach {
        unread.push(format!("the proxy was not contacted: {why}"));
    }
    if !unread.is_empty() {
        let missing = if facts.missing_network {
            vec![Need::Network]
        } else {
            Vec::new()
        };
        finding = finding.with_partial(Partial::new(missing, unread.join("; ")));
    }
    finding
}

/// The required entries the daemon's `NO_PROXY` does not cover, or `None` when it covers all.
fn daemon_gap(daemon: &Daemon, rules: &Rules) -> Option<Vec<String>> {
    let empty = NoProxy::default();
    let own = daemon.no_proxy.as_ref().unwrap_or(&empty);
    let missing: Vec<String> = rules
        .required_no_proxy
        .iter()
        .filter(|entry| own.covers(entry).is_none())
        .cloned()
        .collect();
    (!missing.is_empty()).then_some(missing)
}
