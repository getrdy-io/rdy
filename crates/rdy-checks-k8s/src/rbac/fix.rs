//! The fix text of `k8s.rbac` (03, "Fix").
//!
//! The commands are built from the spec's words (verbs, resources, namespaces) and from the user name the
//! server reported. A user name is put in a command only when every character is plain; any other name
//! becomes `<user>` for the reader to fill in. Nothing here repeats a reason the server gave.

use super::ask::{Ask, Target};
use super::judge::{Gathered, Identity};

/// Who the permissions are for, as far as a command needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Who {
    /// The user name, when it is known and safe to put in a command.
    user: Option<String>,
    /// The groups of the identity, when the reviews ran as the identity itself.
    groups: Vec<String>,
}

impl Who {
    pub(super) fn of(gathered: &Gathered) -> Self {
        let (user, groups) = match (&gathered.as_user, &gathered.identity) {
            (Some(user), _) => (Some(user.clone()), Vec::new()),
            (None, Identity::Verified { user, groups }) => (Some(user.clone()), groups.clone()),
            (None, Identity::Unverified(_)) => (None, Vec::new()),
        };
        Self {
            user: user.filter(|name| plain(name)),
            groups,
        }
    }

    /// The service account as `(namespace, name)`, when the subject is one.
    fn service_account(&self) -> Option<(&str, &str)> {
        self.user
            .as_deref()?
            .strip_prefix("system:serviceaccount:")?
            .split_once(':')
    }

    /// The flag that names the subject of a binding.
    fn subject_flag(&self) -> String {
        match (self.service_account(), self.user.as_deref()) {
            (Some((namespace, name)), _) => format!("--serviceaccount={namespace}:{name}"),
            (None, Some(user)) => format!("--user={user}"),
            (None, None) => "--user=<user>".to_owned(),
        }
    }

    /// The OpenShift command that binds `rdy-installer` to the subject, in one step. `role_namespace` is the
    /// namespace of a `Role`, or `None` for a `ClusterRole`. `None` when no `oc adm policy` form fits: a
    /// service account of another namespace than the role's has no `-z` form (`-z` means the current
    /// namespace).
    fn openshift_bind(&self, role_namespace: Option<&str>) -> Option<String> {
        match (role_namespace, self.service_account(), self.user.as_deref()) {
            (None, Some((namespace, name)), _) => Some(format!(
                "oc adm policy add-cluster-role-to-user rdy-installer -z {name} -n {namespace}"
            )),
            (None, None, user) => Some(format!(
                "oc adm policy add-cluster-role-to-user rdy-installer {}",
                user.unwrap_or("<user>")
            )),
            (Some(role), Some((namespace, name)), _) if role == namespace => Some(format!(
                "oc adm policy add-role-to-user rdy-installer -z {name} -n {role} --role-namespace={role}"
            )),
            (Some(_), Some(_), _) => None,
            (Some(role), None, user) => Some(format!(
                "oc adm policy add-role-to-user rdy-installer {} -n {role} --role-namespace={role}",
                user.unwrap_or("<user>")
            )),
        }
    }
}

/// True for a name that is safe in a command line: letters, digits and `- . _ : @ /`.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '@' | '/'))
}

/// What the fix text is built from.
pub(super) struct Context<'a> {
    pub(super) who: Who,
    /// The permissions answered "not allowed": a role can grant them.
    pub(super) grantable: Vec<&'a Ask>,
    /// The permissions answered "denied": an authorizer refused them, and a role cannot override it.
    pub(super) denied: Vec<&'a Ask>,
    /// The implied `escalate` and `bind` asks answered no.
    pub(super) implied: Vec<&'a Ask>,
    /// The asks with an evaluation error.
    pub(super) unclear: Vec<&'a Ask>,
    /// Namespaces of denied items that do not exist.
    pub(super) missing_namespaces: Vec<&'a str>,
    /// True when the cluster is OpenShift: the binding is also given as an `oc adm policy` command.
    pub(super) openshift: bool,
}

/// The fix text. Empty when nothing needs fixing.
pub(super) fn text(context: &Context<'_>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for namespace in &context.missing_namespaces {
        if plain(namespace) {
            parts.push(format!(
                "Namespace `{namespace}` does not exist. Create it with `kubectl create namespace {namespace}`, or grant the identity `create namespaces`."
            ));
        }
    }
    if let Some(ask) = context.grantable.first() {
        parts.push(grant(
            ask,
            &context.who,
            context.openshift,
            "Ask the cluster admin to bind a role that grants the missing permissions to this identity.",
        ));
    }
    if let Some(ask) = context.denied.first() {
        parts.push(format!(
            "`{}` was refused by an authorizer other than RBAC, for example a webhook, and a role cannot override that. Ask the cluster admin which authorizer refused it.",
            ask.describe()
        ));
    }
    if let Some(ask) = context.unclear.first() {
        parts.push(format!(
            "An authorizer failed while it checked `{}`. Run `kubectl auth can-i {}` as the identity to see the answer, and check the authorizer's logs.",
            ask.describe(),
            can_i(ask)
        ));
    }
    if let Some(ask) = context.implied.first() {
        parts.push(grant(
            ask,
            &context.who,
            context.openshift,
            "To prove the identity may grant roles without holding every rule itself, give it `escalate` and `bind`.",
        ));
    }
    if !context.grantable.is_empty() {
        if !context.who.groups.is_empty() {
            parts.push(
                "A binding to one of the identity's groups works too (`--group=<name>`)."
                    .to_owned(),
            );
        }
        parts.push("On a throwaway test cluster only, `cluster-admin` works.".to_owned());
    }
    parts.join(" ")
}

/// `get pods/log` becomes `get pods --subresource=log`. The words come from the spec.
fn can_i(ask: &Ask) -> String {
    match &ask.target {
        Target::NonResource { path } => format!("{} {path}", ask.verb),
        Target::Resource {
            group,
            resource,
            subresource,
            namespace,
            ..
        } => {
            let mut text = format!("{} {resource}", ask.verb);
            if !group.is_empty() {
                text.push('.');
                text.push_str(group);
            }
            if let Some(subresource) = subresource {
                text.push_str(" --subresource=");
                text.push_str(subresource);
            }
            if let Some(namespace) = namespace {
                text.push_str(" -n ");
                text.push_str(namespace);
            }
            text
        }
    }
}

/// A shell word: quoted when it holds `*`.
fn word(value: &str) -> String {
    if value.contains('*') {
        format!("'{value}'")
    } else {
        value.to_owned()
    }
}

/// The two commands that grant `ask`, after `lead`.
fn grant(ask: &Ask, who: &Who, openshift: bool, lead: &str) -> String {
    let subject = who.subject_flag();
    let verb = word(&ask.verb);
    let role_namespace = match &ask.target {
        Target::Resource {
            namespace: Some(namespace),
            ..
        } => Some(namespace.as_str()),
        _ => None,
    };
    let (create, bind) = match &ask.target {
        Target::NonResource { path } => (
            format!(
                "kubectl create clusterrole rdy-installer --verb={verb} --non-resource-url={}",
                word(path)
            ),
            format!(
                "kubectl create clusterrolebinding rdy-installer --clusterrole=rdy-installer {subject}"
            ),
        ),
        Target::Resource {
            group,
            resource,
            subresource,
            namespace,
            name,
        } => {
            let mut resource_arg = resource.clone();
            if !group.is_empty() {
                resource_arg.push('.');
                resource_arg.push_str(group);
            }
            if let Some(subresource) = subresource {
                resource_arg.push('/');
                resource_arg.push_str(subresource);
            }
            let names = name
                .as_ref()
                .map_or_else(String::new, |name| format!(" --resource-name={name}"));
            match namespace {
                Some(namespace) => (
                    format!(
                        "kubectl create role rdy-installer -n {namespace} --verb={verb} --resource={}{names}",
                        word(&resource_arg)
                    ),
                    format!(
                        "kubectl create rolebinding rdy-installer -n {namespace} --role=rdy-installer {subject}"
                    ),
                ),
                None => (
                    format!(
                        "kubectl create clusterrole rdy-installer --verb={verb} --resource={}{names}",
                        word(&resource_arg)
                    ),
                    format!(
                        "kubectl create clusterrolebinding rdy-installer --clusterrole=rdy-installer {subject}"
                    ),
                ),
            }
        }
    };
    let mut text = format!(
        "{lead} For `{}`: `{create}`, then `{bind}`.",
        ask.describe()
    );
    if openshift && let Some(command) = who.openshift_bind(role_namespace) {
        text.push_str(&format!(
            " On OpenShift, `{command}` makes the binding once the role exists."
        ));
    }
    text.push_str(
        " For each other permission, add a `--verb` and `--resource` pair to the same role. A namespaced item needs its own role and rolebinding in its namespace, so repeat both commands per namespace. Cluster-scoped items and URLs go in a clusterrole.",
    );
    text
}
