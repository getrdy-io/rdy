//! Families and the registry (02 section "Checks, families and the run plan").
//!
//! A [`Family`] is a group of checks that share a prefix, such as `host`. It lists its checks as static
//! [`CheckInfo`]s and builds a check from a decoded spec entry. A [`Registry`] holds the families of
//! this build. The planner ([`Registry::plan`](crate::plan)) asks it which ids exist.
//!
//! Nothing here does I/O. [`Family::build`] is a pure function of the entry and the spec, so the plan
//! of a run is the same on every machine with the same OS.
//!
//! The probe hook of 02 (`Family::probe`, for needs only one family can test, such as `kube_context`)
//! arrives with the probe facade (M1-040) and the family probe ticket. The trait gains a method with a
//! default body then, so a family written now keeps compiling.

use std::collections::BTreeMap;

use rdy_spec::Target;
use rdy_spec::check::CheckParams;
use rdy_spec::spec::{CheckSpec, Spec};

use crate::check::{Check, CheckInfo};

#[cfg(test)]
pub(crate) mod tests;

/// The hosts one check may reach: its own `endpoints`, with derived defaults applied.
///
/// A check gets the hosts its spec entry names and nothing else. The network facade (M1-043 and later)
/// refuses any other peer (INV-12). The set keeps first-seen order and holds no duplicates, so two
/// spellings of the same target count once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostSet(Vec<Target>);

impl HostSet {
    /// A set with no hosts. Most checks have this.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A set of `targets`, in order, without duplicates.
    #[must_use]
    pub fn new(targets: impl IntoIterator<Item = Target>) -> Self {
        let mut set = Self::default();
        for target in targets {
            if !set.0.contains(&target) {
                set.0.push(target);
            }
        }
        set
    }

    /// The hosts, in the order they were first given.
    pub fn iter(&self) -> std::slice::Iter<'_, Target> {
        self.0.iter()
    }

    /// Whether `target` is in the set.
    #[must_use]
    pub fn contains(&self, target: &Target) -> bool {
        self.0.contains(target)
    }

    /// How many hosts the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a HostSet {
    type Item = &'a Target;
    type IntoIter = std::slice::Iter<'a, Target>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A check built from a spec entry, with the hosts it may reach.
#[non_exhaustive]
pub struct Built {
    /// The check, ready to run.
    pub check: Box<dyn Check>,
    /// The hosts it may reach, derived defaults included.
    pub hosts: HostSet,
}

impl Built {
    /// A built check that reaches no host.
    #[must_use]
    pub fn new(check: Box<dyn Check>) -> Self {
        Self {
            check,
            hosts: HostSet::empty(),
        }
    }

    /// Sets the hosts the check may reach.
    #[must_use]
    pub fn with_hosts(mut self, hosts: HostSet) -> Self {
        self.hosts = hosts;
        self
    }
}

impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Built")
            .field("check", &self.check.info().id)
            .field("hosts", &self.hosts)
            .finish()
    }
}

/// Why a family could not build a check from an entry that decoded.
///
/// The planner turns it into a skip with `skip_kind: unsupported_spec`. Nothing runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// The entry decoded, but this rdy cannot act on it. The text says why, in a short phrase. Do not
    /// put a value from the spec in it unless it is cut and escaped.
    #[error("rdy cannot use this entry: {0}")]
    Unsupported(String),
}

/// A group of checks with one id prefix.
///
/// Three families exist in M1 (`host`, `net`, `k8s`), which is why this is a trait.
pub trait Family: Send + Sync + 'static {
    /// The id prefix, such as `host`. Every check id of the family starts with `{name}.`.
    fn name(&self) -> &'static str;

    /// The static facts of every check this family builds.
    fn checks(&self) -> &'static [&'static CheckInfo];

    /// Builds the check for `entry`.
    ///
    /// `params` are the entry's decoded parameters, and always the variant of an id in
    /// [`Family::checks`]. `spec` is the whole spec, for defaults that come from another entry
    /// (`net.tls_intercept` defaults to the `net.egress` hosts). It must not do I/O.
    ///
    /// # Errors
    ///
    /// [`BuildError::Unsupported`] when the entry is well formed but this rdy cannot act on it.
    fn build(
        &self,
        entry: &CheckSpec,
        params: CheckParams,
        spec: &Spec,
    ) -> Result<Built, BuildError>;
}

/// Why [`Registry::register`] refused a family. These are programming errors in the build, not
/// something an operator can cause.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Two families have the same name.
    #[error("family '{0}' is registered twice; register each family once")]
    DuplicateFamily(&'static str),
    /// Two checks have the same id.
    #[error("check '{0}' is registered twice; every check id belongs to one family")]
    DuplicateCheck(&'static str),
    /// A check's `CheckInfo` does not match the family it is listed in.
    #[error(
        "check '{id}' is listed by family '{family}' but does not start with '{family}.' or names another family; fix its CheckInfo"
    )]
    Misfiled {
        /// The check id.
        id: &'static str,
        /// The family that lists it.
        family: &'static str,
    },
}

/// The families of this build and the checks they provide.
///
/// The registry is built once at startup and read-only after. Its iteration order is by check id, so
/// anything derived from it (a plan, the xtask listing) is stable.
#[derive(Default)]
pub struct Registry {
    families: Vec<Box<dyn Family>>,
    /// Check id to the index of its family and its static facts.
    checks: BTreeMap<&'static str, (usize, &'static CheckInfo)>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a family.
    ///
    /// # Errors
    ///
    /// [`RegistryError`] when the family name or a check id is already taken, or when a check's
    /// `CheckInfo` names another family. The registry is unchanged on error.
    pub fn register(&mut self, family: impl Family) -> Result<&mut Self, RegistryError> {
        let name = family.name();
        if self.families.iter().any(|f| f.name() == name) {
            return Err(RegistryError::DuplicateFamily(name));
        }
        let index = self.families.len();
        let mut added: BTreeMap<&'static str, (usize, &'static CheckInfo)> = BTreeMap::new();
        for info in family.checks() {
            let prefixed = info
                .id
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.') && rest.len() > 1);
            if !prefixed || info.family != name {
                return Err(RegistryError::Misfiled {
                    id: info.id,
                    family: name,
                });
            }
            if self.checks.contains_key(info.id) || added.insert(info.id, (index, info)).is_some() {
                return Err(RegistryError::DuplicateCheck(info.id));
            }
        }
        self.checks.extend(added);
        self.families.push(Box::new(family));
        Ok(self)
    }

    /// The family called `name`, if this build has it.
    #[must_use]
    pub fn family(&self, name: &str) -> Option<&dyn Family> {
        self.families
            .iter()
            .find(|f| f.name() == name)
            .map(|f| &**f)
    }

    /// The family and static facts of the check `id`, if this build has it.
    #[must_use]
    pub fn check(&self, id: &str) -> Option<(&dyn Family, &'static CheckInfo)> {
        let (index, info) = self.checks.get(id)?;
        Some((self.families.get(*index)?.as_ref(), info))
    }

    /// The static facts of every registered check, ordered by id.
    pub fn infos(&self) -> impl Iterator<Item = &'static CheckInfo> + '_ {
        self.checks.values().map(|(_, info)| *info)
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field(
                "families",
                &self.families.iter().map(|f| f.name()).collect::<Vec<_>>(),
            )
            .field("checks", &self.checks.keys().collect::<Vec<_>>())
            .finish()
    }
}
