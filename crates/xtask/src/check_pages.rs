//! The check family pages: `checks/host.md`, `checks/network.md` and `checks/kubernetes.md`, written by
//! `cargo xtask docs` (docs/plan/09-docs-site.md, sections 4 to 6).
//!
//! The pages read the check registry, the same list `rdy run` plans against (`rdy::registry`), so a
//! page cannot list a check the binary does not run, and a check the binary runs cannot go missing.
//! Each page has the hand-written intro in `docs/intro/checks-<slug>.md`, then one H2 per check in the
//! order of `Family::checks`. The check's fields come first and then a `Remediation` block that holds
//! `CheckMeta::remediation` word for word. `reads` is one list for every OS (09 section 6).
//!
//! Ids in the family's stub list get no section. A registry family with no row in [`FAMILIES`] is an
//! error, so a new family cannot ship without its page.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use rdy_checks_k8s::client::guard::{ALLOWED, Access, Allowed};
use rdy_engine::check::{CheckInfo, Support};
use rdy_engine::family::Registry;

use crate::generate::{self, Generated};

/// One family page: the registry family it shows, where it is written and what the intro says.
pub struct FamilyPage {
    /// The family name in the registry, such as `net`.
    pub family: &'static str,
    /// The published page, under `docs/src/content/docs/`.
    pub path: &'static str,
    /// The hand-written intro, under `docs/intro/`. It is not published.
    pub intro: &'static str,
    /// The page title in the frontmatter.
    pub title: &'static str,
    /// The page description in the frontmatter.
    pub description: &'static str,
}

/// The family pages of M1. Each registry family needs a row here.
pub const FAMILIES: &[FamilyPage] = &[
    FamilyPage {
        family: "host",
        path: "docs/src/content/docs/checks/host.md",
        intro: "docs/intro/checks-host.md",
        title: "Host checks",
        description: "Fix each host finding with the remediation text named on its section.",
    },
    FamilyPage {
        family: "net",
        path: "docs/src/content/docs/checks/network.md",
        intro: "docs/intro/checks-network.md",
        title: "Network checks",
        description: "Fix each network finding with the command or proxy setting it names.",
    },
    FamilyPage {
        family: "k8s",
        path: "docs/src/content/docs/checks/kubernetes.md",
        intro: "docs/intro/checks-kubernetes.md",
        title: "Kubernetes checks",
        description: "Fix each cluster finding with the setting it names.",
    },
];

/// The API reads of a check, one line each, from the `ALLOWED` table of the Kubernetes guard. Only the
/// Kubernetes page has them; every other family has none.
fn api_reads(family: &str, id: &str) -> Vec<String> {
    if family != "k8s" {
        return Vec::new();
    }
    ALLOWED
        .iter()
        .filter(|entry| entry.checks.contains(&id))
        .map(api_read_line)
        .collect()
}

/// One API read as the page prints it: the group and version, the resource, its verbs and what it
/// reads from the response.
#[must_use]
pub fn api_read_line(entry: &Allowed) -> String {
    let api = if entry.group.is_empty() {
        entry.version.to_owned()
    } else {
        format!("{}/{}", entry.group, entry.version)
    };
    let mut verbs: Vec<&str> = Vec::new();
    for access in entry.access {
        let verb = match access {
            Access::List => "list",
            Access::ListInNamespace(_) => "list in a namespace",
            Access::Get(_) | Access::GetIn { .. } => "get",
        };
        if !verbs.contains(&verb) {
            verbs.push(verb);
        }
    }
    format!(
        "`{api} {}` ({}): {}",
        entry.resource,
        verbs.join(", "),
        entry.reads
    )
}

/// Renders every family page from the registry and the intros under `root`.
///
/// # Errors
///
/// A registry family with no row in [`FAMILIES`], or a missing intro. Each message names the fix.
pub fn pages(root: &Path, registry: &Registry) -> Result<Vec<Generated>> {
    for family in registry.families() {
        if !FAMILIES.iter().any(|page| page.family == family.name()) {
            bail!(
                "the check family {} has no page. Add a row for it to FAMILIES in crates/xtask/src/check_pages.rs.",
                family.name()
            );
        }
    }
    let mut files = Vec::new();
    for page in FAMILIES {
        let family = registry.family(page.family).ok_or_else(|| {
            anyhow::anyhow!(
                "the check family {} is not in the registry. Register it in crates/rdy-cli/src/registry.rs, or remove its row from FAMILIES.",
                page.family
            )
        })?;
        let intro = generate::safe_join(root, page.intro)
            .and_then(|path| Ok(std::fs::read_to_string(&path)?))
            .map_err(|err| {
                anyhow::anyhow!(
                    "cannot read the intro {}: {err}. The hand-written intro of this page lives there.",
                    page.intro
                )
            })?;
        let infos = family.checks();
        let reads = |id: &str| api_reads(page.family, id);
        files.push(Generated {
            path: page.path,
            contents: render(page, infos, family.not_built(), &reads, &intro),
        });
    }
    Ok(files)
}

/// Renders one family page. `infos` are in sort order. `not_built` are ids to leave out, and `reads`
/// gives the API reads of a check.
#[must_use]
pub fn render(
    page: &FamilyPage,
    infos: &[&CheckInfo],
    not_built: &[&str],
    reads: &dyn Fn(&str) -> Vec<String>,
    intro: &str,
) -> String {
    let mut out = format!(
        "---\ntitle: \"{}\"\ndescription: \"{}\"\n---\n\n<!-- Generated by cargo xtask docs. Do not edit. -->\n\n",
        page.title, page.description
    );
    out.push_str(intro.trim_end());
    out.push_str("\n\n");
    for info in infos.iter().filter(|info| !not_built.contains(&info.id)) {
        section(&mut out, info, &reads(info.id));
    }
    out
}

/// Writes one H2 section: the id and title, the fields as a list, the API reads, then the Remediation block.
fn section(out: &mut String, info: &CheckInfo, api: &[String]) {
    let _ = write!(out, "## `{}` {}\n\n", info.id, info.meta.title);
    let _ = writeln!(out, "- **Measures:** {}", info.summary);
    let _ = writeln!(
        out,
        "- **Needs:** {}",
        list(info.needs.iter().map(ToString::to_string))
    );
    let _ = writeln!(
        out,
        "- **Wants:** {}",
        list(info.wants.iter().map(|want| {
            if want.evidence_only {
                format!("{}, adds detail only", want.need)
            } else {
                want.need.to_string()
            }
        }))
    );
    let _ = writeln!(out, "- **Timeout:** {}", timeout(info.default_timeout));
    let _ = writeln!(
        out,
        "- **Systems:** Linux: {}. macOS: {}. Windows: {}.",
        support(&info.os.linux),
        support(&info.os.macos),
        support(&info.os.windows)
    );
    let _ = writeln!(
        out,
        "- **Reads:** {}",
        list(info.reads.iter().map(|path| format!("`{path}`")))
    );
    if !api.is_empty() {
        out.push_str("- **API reads:**\n");
        for line in api {
            let _ = writeln!(out, "  - {line}");
        }
    }
    out.push_str("\n**Remediation**\n\n");
    out.push_str(info.meta.remediation);
    out.push_str("\n\n");
}

/// The items joined with commas, or `none` when there are none.
fn list(items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

/// The support on one OS, in words.
fn support(support: &Support) -> String {
    match support {
        Support::Full => "full".to_owned(),
        Support::Partial(note) => format!("partial, {note}"),
        Support::NotYet => "not yet".to_owned(),
    }
}

/// The timeout in seconds or milliseconds. A check without one gets the engine default.
fn timeout(limit: Option<Duration>) -> String {
    match limit {
        None => "10 s, the engine default".to_owned(),
        Some(limit) if limit.subsec_millis() == 0 => format!("{} s", limit.as_secs()),
        Some(limit) => format!("{} ms", limit.as_millis()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdy_engine::check::{CheckMeta, OsSupport, Support};

    use super::*;

    const fn fake(id: &'static str, remediation: &'static str) -> CheckInfo {
        CheckInfo {
            id,
            family: "host",
            summary: "A fake check.",
            meta: CheckMeta {
                title: "Fake",
                remediation,
            },
            needs: &[],
            wants: &[],
            default_timeout: Some(Duration::from_secs(2)),
            os: OsSupport {
                linux: Support::Full,
                macos: Support::NotYet,
                windows: Support::Partial("the Windows reader is not built"),
            },
            reads: &["/proc/meminfo"],
            statfs: &[],
            env: &[],
            commands: &[],
            peers: &[],
        }
    }

    static FIRST: CheckInfo = fake("host.first", "Free up space. Run `df -h`.");
    static SECOND: CheckInfo = fake("host.second", "Add RAM. Use `free -h` to see it.");
    static STUB: CheckInfo = fake("host.stub", "Not built yet.");

    const PAGE: FamilyPage = FamilyPage {
        family: "host",
        path: "docs/src/content/docs/checks/host.md",
        intro: "docs/intro/checks-host.md",
        title: "Host checks",
        description: "Fix each host finding.",
    };

    /// A page with no API reads, for the tests of the shared layout.
    fn page_of(infos: &[&CheckInfo], not_built: &[&str], intro: &str) -> String {
        render(&PAGE, infos, not_built, &|_| Vec::new(), intro)
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// The Remediation block of the section for `id`: the text after its label, up to the next H2.
    fn remediation_of<'a>(page: &'a str, id: &str) -> &'a str {
        let heading = format!("## `{id}` ");
        let start = page.find(&heading).expect("the section exists");
        let section = &page[start..];
        let end = section[3..]
            .find("\n## ")
            .map_or(section.len(), |at| at + 3);
        let section = &section[..end];
        let label = section
            .find("**Remediation**\n\n")
            .expect("the section has a Remediation block");
        section[label + "**Remediation**\n\n".len()..].trim_end()
    }

    #[test]
    fn each_remediation_block_is_the_registry_string_word_for_word() {
        let page = page_of(&[&FIRST, &SECOND], &[], "Intro.");
        assert_eq!(remediation_of(&page, "host.first"), FIRST.meta.remediation);
        assert_eq!(
            remediation_of(&page, "host.second"),
            SECOND.meta.remediation
        );
    }

    #[test]
    fn every_check_gets_one_h2_in_sort_order() {
        let page = page_of(&[&SECOND, &FIRST], &[], "Intro.");
        let headings: Vec<&str> = page
            .lines()
            .filter(|line| line.starts_with("## "))
            .collect();
        assert_eq!(headings, ["## `host.second` Fake", "## `host.first` Fake"]);
    }

    #[test]
    fn a_stub_id_gets_no_section() {
        let page = page_of(&[&FIRST, &STUB], &["host.stub"], "Intro.");
        assert!(page.contains("## `host.first` "));
        assert!(!page.contains("host.stub"), "{page}");
    }

    #[test]
    fn reads_are_one_list_with_no_os_split_and_the_fields_are_listed() {
        let page = page_of(&[&FIRST], &[], "Intro.");
        assert!(page.contains("- **Reads:** `/proc/meminfo`\n"), "{page}");
        assert!(page.contains("- **Timeout:** 2 s\n"), "{page}");
        assert!(
            page.contains(
                "- **Systems:** Linux: full. macOS: not yet. Windows: partial, the Windows reader is not built.\n"
            ),
            "{page}"
        );
        assert!(page.contains("- **Needs:** none\n"), "{page}");
    }

    #[test]
    fn the_page_starts_with_frontmatter_the_banner_and_the_intro() {
        let page = page_of(&[&FIRST], &[], "You can use this page.\n");
        assert!(page.starts_with("---\ntitle: \"Host checks\"\n"), "{page}");
        assert!(page.contains("<!-- Generated by cargo xtask docs. Do not edit. -->"));
        assert!(page.contains("\n\nYou can use this page.\n\n## `host.first`"));
    }

    #[test]
    fn the_committed_family_pages_render_from_the_registry() -> Result<()> {
        // The drift check: `cargo xtask docs --check` compares the same render with the disk copy.
        let root = repo_root();
        let registry = crate::checks::registry()?;
        for file in pages(&root, &registry)? {
            assert!(
                generate::check_all(&root, std::slice::from_ref(&file), "docs")?,
                "{} is stale. Run `cargo xtask docs` and commit the result.",
                file.path
            );
        }
        Ok(())
    }

    #[test]
    fn every_registry_check_has_a_section_on_its_family_page() -> Result<()> {
        let root = repo_root();
        let registry = crate::checks::registry()?;
        let files = pages(&root, &registry)?;
        for family in registry.families() {
            let page_path = FAMILIES
                .iter()
                .find(|page| page.family == family.name())
                .expect("pages() refuses a family with no row")
                .path;
            let file = files
                .iter()
                .find(|file| file.path == page_path)
                .expect("written");
            let not_built = family.not_built();
            for info in family
                .checks()
                .iter()
                .filter(|info| !not_built.contains(&info.id))
            {
                let heading = format!("## `{}` ", info.id);
                assert!(
                    file.contents.contains(&heading),
                    "{} has no section",
                    info.id
                );
                assert_eq!(
                    remediation_of(&file.contents, info.id),
                    info.meta.remediation
                );
            }
        }
        Ok(())
    }

    /// A family the page table does not know. It lists no checks and builds nothing.
    struct Stray;

    impl rdy_engine::family::Family for Stray {
        fn name(&self) -> &'static str {
            "stray"
        }

        fn checks(&self) -> &'static [&'static CheckInfo] {
            &[]
        }

        fn build(
            &self,
            _: &rdy_spec::spec::CheckSpec,
            _: rdy_spec::check::CheckParams,
            _: &rdy_spec::spec::Spec,
        ) -> Result<rdy_engine::family::Built, rdy_engine::family::BuildError> {
            Err(rdy_engine::family::BuildError::Unsupported(
                "not built".to_owned(),
            ))
        }
    }

    #[test]
    fn a_family_without_a_row_is_refused() -> Result<()> {
        let mut registry = Registry::new();
        registry.register(Stray)?;
        let err = pages(&repo_root(), &registry).expect_err("a family with no row");
        assert!(err.to_string().contains("stray has no page"), "{err}");
        Ok(())
    }

    #[test]
    fn every_api_read_of_a_kubernetes_check_is_on_its_section() -> Result<()> {
        // The API reads come from the guard's ALLOWED table, so each line must be the one the table gives.
        let root = repo_root();
        let registry = crate::checks::registry()?;
        let files = pages(&root, &registry)?;
        let k8s = files
            .iter()
            .find(|file| file.path.ends_with("kubernetes.md"))
            .expect("the Kubernetes page is written");
        for family in registry.families().filter(|family| family.name() == "k8s") {
            for info in family.checks() {
                for entry in ALLOWED
                    .iter()
                    .filter(|entry| entry.checks.contains(&info.id))
                {
                    let line = format!("  - {}\n", api_read_line(entry));
                    assert!(k8s.contents.contains(&line), "{} lacks {line}", info.id);
                }
                let shown = k8s.contents.matches(&format!("## `{}` ", info.id)).count();
                assert_eq!(shown, 1, "{} has one section", info.id);
            }
        }
        Ok(())
    }
}
