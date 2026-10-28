//! The words of a check that did not run (01 section 5.2).
//!
//! A [`SkipWhy`] says why one check was skipped. [`SkipWhy::text`] gives the `message` and the `fix` of the
//! check result, written for the customer who reads the run. The kind names appear only in JSON.
//!
//! Every value a spec supplied (a check id, a field, a value, the spec file name) is escaped and cut
//! before it enters a message, so a spec cannot put a control character on the terminal.

use rdy_spec::result::SkipKind;

use super::text::{echo, escape_untrusted, shell_word};

/// The `message` and `fix` of a check result that did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipText {
    /// One line, starting with `Not run.` (or `Does not apply here.`).
    pub message: String,
    /// What to do. `None` only for `not_applicable`, which needs no action. Never an empty string.
    pub fix: Option<String>,
}

/// Why one check did not run. Each variant is one row of the table in 01 section 5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipWhy {
    /// This build has no checks of a whole family, such as `gpu`.
    NotInBuildFamily {
        /// The family, such as `gpu`.
        family: String,
    },
    /// This build has the family but not this check, such as `host.kernel`.
    NotInBuildCheck {
        /// The check id.
        id: String,
    },
    /// The id is in no version of rdy, or in no version yet.
    UnknownCheck {
        /// The check id as written in the spec.
        id: String,
        /// The version of this rdy, such as `0.1.0`.
        rdy_version: String,
        /// True when the family is reserved, so a newer rdy may know the check. False for a family
        /// that no version has, such as `upload`.
        family_reserved: bool,
        /// A close known id, from [`super::text::did_you_mean`].
        did_you_mean: Option<String>,
    },
    /// The entry has a field this rdy cannot read.
    UnsupportedField {
        /// The check id.
        check: String,
        /// The field as written in the spec.
        field: String,
        /// The version of this rdy, such as `0.1.0`.
        rdy_version: String,
        /// A close known field.
        did_you_mean: Option<String>,
    },
    /// A field holds a value that does not fit.
    UnsupportedValue {
        /// The check id.
        check: String,
        /// The field.
        field: String,
        /// The value as written.
        value: String,
        /// What the value should have been, with its article, such as `a size`.
        expected: String,
        /// What the vendor should write instead. A general sentence is used when this is `None`.
        fix: Option<String>,
    },
    /// The check needs root and the run is not root.
    MissingRoot {
        /// The spec file as typed, for the `sudo` command in the fix.
        spec_file: String,
    },
    /// The check needs a Kubernetes cluster and none was reachable.
    MissingCluster,
    /// The check has no data source on this OS yet.
    NotYetOnOs {
        /// The OS as people write it, such as `macOS`.
        os: String,
    },
    /// The spec's `os` list leaves this OS out.
    NotApplicable {
        /// The OS list as people write it, such as `linux`.
        os_list: String,
    },
    /// The run reached its deadline before the check started.
    RunDeadline {
        /// The limit of the run, in whole minutes.
        minutes: u64,
    },
    /// The run was interrupted before the check started.
    Cancelled,
}

const NEWER_RDY: &str = "Install a newer rdy. If there is none yet, ask the vendor how to go on.";

impl SkipWhy {
    /// The `skip_kind` this reason belongs to.
    #[must_use]
    pub fn kind(&self) -> SkipKind {
        match self {
            Self::NotInBuildFamily { .. } | Self::NotInBuildCheck { .. } => SkipKind::NotInBuild,
            Self::UnknownCheck { .. } => SkipKind::UnknownCheck,
            Self::UnsupportedField { .. } | Self::UnsupportedValue { .. } => {
                SkipKind::UnsupportedSpec
            }
            Self::MissingRoot { .. } | Self::MissingCluster => SkipKind::MissingNeed,
            Self::NotYetOnOs { .. } => SkipKind::NotYetOnOs,
            Self::NotApplicable { .. } => SkipKind::NotApplicable,
            Self::RunDeadline { .. } => SkipKind::RunDeadline,
            Self::Cancelled => SkipKind::Cancelled,
        }
    }

    /// The message and fix of the check result.
    #[must_use]
    pub fn text(&self) -> SkipText {
        let some = |message: String, fix: String| SkipText {
            message,
            fix: Some(fix),
        };
        match self {
            Self::NotInBuildFamily { family } => some(
                format!(
                    "Not run. This version of rdy has no {} checks yet.",
                    echo(family)
                ),
                NEWER_RDY.to_owned(),
            ),
            Self::NotInBuildCheck { id } => some(
                format!(
                    "Not run. This version of rdy does not have the check {} yet.",
                    echo(id)
                ),
                NEWER_RDY.to_owned(),
            ),
            Self::UnknownCheck {
                id,
                rdy_version,
                family_reserved: true,
                did_you_mean,
            } => {
                let version = echo(rdy_version);
                some(
                    format!(
                        "Not run. rdy {version} does not know the check '{}'.",
                        echo(id)
                    ),
                    format!(
                        "Tell the vendor. The spec may have a typo{}, or it may need a newer rdy than {version}.",
                        suggestion(did_you_mean.as_deref())
                    ),
                )
            }
            Self::UnknownCheck {
                id,
                family_reserved: false,
                did_you_mean,
                ..
            } => {
                let family = id.split_once('.').map_or(id.as_str(), |(family, _)| family);
                some(
                    format!(
                        "Not run. No version of rdy has checks named {}.",
                        echo(family)
                    ),
                    format!(
                        "Tell the vendor. The spec may have a typo{}.",
                        suggestion(did_you_mean.as_deref())
                    ),
                )
            }
            Self::UnsupportedField {
                check,
                field,
                rdy_version,
                did_you_mean,
            } => {
                let version = echo(rdy_version);
                some(
                    format!(
                        "Not run. rdy {version} cannot read '{}' in {}.",
                        echo(field),
                        echo(check)
                    ),
                    format!(
                        "Tell the vendor. The spec may have a typo{}, or it may need a newer rdy than {version}.",
                        suggestion(did_you_mean.as_deref())
                    ),
                )
            }
            Self::UnsupportedValue {
                check,
                field,
                value,
                expected,
                fix,
            } => some(
                format!(
                    "Not run. '{}: {}' in {} is not {}.",
                    echo(field),
                    echo(value),
                    echo(check),
                    echo(expected)
                ),
                fix.as_deref().map_or_else(
                    || {
                        "Tell the vendor to correct the value. rdy spec lint shows which one."
                            .to_owned()
                    },
                    escape_untrusted,
                ),
            ),
            Self::MissingRoot { spec_file } => some(
                "Not run. This check needs root.".to_owned(),
                format!("Rerun as root: sudo rdy run {}", shell_word(spec_file)),
            ),
            Self::MissingCluster => some(
                "Not run. No Kubernetes cluster was reachable.".to_owned(),
                "Set a kubeconfig, or pass --kube-context <name>, then run again.".to_owned(),
            ),
            Self::NotYetOnOs { os } => some(
                format!("Not run. This check does not work on {} yet.", echo(os)),
                "Run rdy on the machine you will install on.".to_owned(),
            ),
            Self::NotApplicable { os_list } => SkipText {
                message: format!(
                    "Does not apply here. This check is for {} only.",
                    echo(os_list)
                ),
                fix: None,
            },
            Self::RunDeadline { minutes } => some(
                format!("Not run. The run reached its {minutes} minute limit first."),
                "Run again. If it happens again, tell the vendor.".to_owned(),
            ),
            Self::Cancelled => some(
                "Not run. The run was interrupted.".to_owned(),
                "Run it again.".to_owned(),
            ),
        }
    }
}

/// ` (did you mean 'x'?)`, or nothing.
fn suggestion(did_you_mean: Option<&str>) -> String {
    did_you_mean.map_or_else(String::new, |s| format!(" (did you mean '{}'?)", echo(s)))
}

/// The message and fix of a check that ran out of time (status `timeout`, 01 section 5.2).
#[must_use]
pub fn timeout_text(after_ms: u64) -> SkipText {
    let after = if after_ms < 1000 {
        format!("{after_ms} ms")
    } else if after_ms.is_multiple_of(1000) {
        format!("{} s", after_ms / 1000)
    } else {
        format!("{}.{} s", after_ms / 1000, (after_ms % 1000) / 100)
    };
    SkipText {
        message: format!("Timed out after {after}."),
        fix: Some("Run again. If it times out again, tell the vendor which check it was.".into()),
    }
}

#[cfg(test)]
mod tests {
    use rdy_spec::result::SkipKind;

    use super::{SkipWhy, timeout_text};

    fn s(text: &str) -> String {
        text.to_owned()
    }

    /// One sample per row of 01 section 5.2.
    fn samples() -> Vec<SkipWhy> {
        vec![
            SkipWhy::NotInBuildFamily { family: s("gpu") },
            SkipWhy::NotInBuildCheck {
                id: s("host.kernel"),
            },
            SkipWhy::UnknownCheck {
                id: s("host.memroy"),
                rdy_version: s("0.1.0"),
                family_reserved: true,
                did_you_mean: Some(s("host.memory")),
            },
            SkipWhy::UnknownCheck {
                id: s("upload.now"),
                rdy_version: s("0.1.0"),
                family_reserved: false,
                did_you_mean: None,
            },
            SkipWhy::UnsupportedField {
                check: s("host.memory"),
                field: s("mn"),
                rdy_version: s("0.1.0"),
                did_you_mean: Some(s("min")),
            },
            SkipWhy::UnsupportedValue {
                check: s("host.memory"),
                field: s("min"),
                value: s("32G"),
                expected: s("a size"),
                fix: Some(s(
                    "Tell the vendor to write 32Gi, not 32G. Sizes use Ki, Mi, Gi or Ti.",
                )),
            },
            SkipWhy::MissingRoot {
                spec_file: s("acme-platform.yaml"),
            },
            SkipWhy::MissingCluster,
            SkipWhy::NotYetOnOs { os: s("macOS") },
            SkipWhy::NotApplicable {
                os_list: s("linux"),
            },
            SkipWhy::RunDeadline { minutes: 5 },
            SkipWhy::Cancelled,
        ]
    }

    #[test]
    fn the_samples_cover_every_skip_kind() {
        let known = [
            SkipKind::MissingNeed,
            SkipKind::NotInBuild,
            SkipKind::UnknownCheck,
            SkipKind::UnsupportedSpec,
            SkipKind::NotYetOnOs,
            SkipKind::NotApplicable,
            SkipKind::RunDeadline,
            SkipKind::Cancelled,
        ];
        let covered: Vec<SkipKind> = samples().iter().map(SkipWhy::kind).collect();
        for kind in known {
            assert!(covered.contains(&kind), "no sample for {kind}");
        }
    }

    #[test]
    fn every_reason_has_a_message_and_a_fix_except_not_applicable() {
        for why in samples() {
            let text = why.text();
            assert!(!text.message.is_empty(), "{why:?}");
            assert!(!text.message.contains('\n'), "{why:?}");
            match (&why.kind(), &text.fix) {
                (SkipKind::NotApplicable, None) => {}
                (SkipKind::NotApplicable, Some(f)) => panic!("not_applicable has a fix: {f}"),
                (_, Some(fix)) => assert!(!fix.is_empty(), "{why:?}"),
                (_, None) => panic!("{why:?} has no fix"),
            }
            let starts = text.message.starts_with("Not run. ")
                || text.message.starts_with("Does not apply here. ");
            assert!(starts, "{}", text.message);
        }
    }

    fn pair(why: &SkipWhy) -> (String, String) {
        let t = why.text();
        (t.message, t.fix.unwrap_or_default())
    }

    #[test]
    fn the_words_match_the_table_in_01_section_5_2() {
        let all = samples();
        assert_eq!(
            pair(&all[0]),
            (
                s("Not run. This version of rdy has no gpu checks yet."),
                s("Install a newer rdy. If there is none yet, ask the vendor how to go on.")
            )
        );
        assert_eq!(
            all[1].text().message,
            "Not run. This version of rdy does not have the check host.kernel yet."
        );
        assert_eq!(
            pair(&all[2]),
            (
                s("Not run. rdy 0.1.0 does not know the check 'host.memroy'."),
                s(
                    "Tell the vendor. The spec may have a typo (did you mean 'host.memory'?), or it may need a newer rdy than 0.1.0."
                )
            )
        );
        assert_eq!(
            all[3].text().message,
            "Not run. No version of rdy has checks named upload."
        );
        assert_eq!(
            pair(&all[4]),
            (
                s("Not run. rdy 0.1.0 cannot read 'mn' in host.memory."),
                s(
                    "Tell the vendor. The spec may have a typo (did you mean 'min'?), or it may need a newer rdy than 0.1.0."
                )
            )
        );
        assert_eq!(
            pair(&all[5]),
            (
                s("Not run. 'min: 32G' in host.memory is not a size."),
                s("Tell the vendor to write 32Gi, not 32G. Sizes use Ki, Mi, Gi or Ti.")
            )
        );
        assert_eq!(
            pair(&all[6]),
            (
                s("Not run. This check needs root."),
                s("Rerun as root: sudo rdy run acme-platform.yaml")
            )
        );
        assert_eq!(
            pair(&all[7]),
            (
                s("Not run. No Kubernetes cluster was reachable."),
                s("Set a kubeconfig, or pass --kube-context <name>, then run again.")
            )
        );
        assert_eq!(
            pair(&all[8]),
            (
                s("Not run. This check does not work on macOS yet."),
                s("Run rdy on the machine you will install on.")
            )
        );
        assert_eq!(
            all[9].text().message,
            "Does not apply here. This check is for linux only."
        );
        assert_eq!(
            pair(&all[10]),
            (
                s("Not run. The run reached its 5 minute limit first."),
                s("Run again. If it happens again, tell the vendor.")
            )
        );
        assert_eq!(
            pair(&all[11]),
            (s("Not run. The run was interrupted."), s("Run it again."))
        );
    }

    #[test]
    fn without_a_suggestion_the_typo_sentence_has_no_parenthesis() {
        let why = SkipWhy::UnsupportedField {
            check: s("host.memory"),
            field: s("zzzz"),
            rdy_version: s("0.1.0"),
            did_you_mean: None,
        };
        assert_eq!(
            why.text().fix.as_deref(),
            Some(
                "Tell the vendor. The spec may have a typo, or it may need a newer rdy than 0.1.0."
            )
        );
    }

    #[test]
    fn text_from_a_spec_is_escaped_quoted_and_cut() {
        let evil = "\u{1b}[2J\u{202e}";
        let why = SkipWhy::UnsupportedField {
            check: s(evil),
            field: s(evil),
            rdy_version: s("0.1.0"),
            did_you_mean: Some(s(evil)),
        };
        let t = why.text();
        let all = format!("{} {}", t.message, t.fix.unwrap_or_default());
        assert!(!all.chars().any(char::is_control), "{all:?}");
        assert!(!all.contains('\u{202e}'), "{all:?}");
        let root = SkipWhy::MissingRoot {
            spec_file: s("a b.yaml; rm -rf ~"),
        };
        assert_eq!(
            root.text().fix.as_deref(),
            Some("Rerun as root: sudo rdy run 'a b.yaml; rm -rf ~'")
        );
        let long = SkipWhy::NotInBuildCheck {
            id: "x".repeat(500),
        };
        assert!(long.text().message.len() < 200);
    }

    #[test]
    fn a_timeout_reads_in_seconds_or_milliseconds() {
        assert_eq!(timeout_text(10_000).message, "Timed out after 10 s.");
        assert_eq!(timeout_text(1_500).message, "Timed out after 1.5 s.");
        assert_eq!(timeout_text(250).message, "Timed out after 250 ms.");
        assert_eq!(
            timeout_text(10_000).fix.as_deref(),
            Some("Run again. If it times out again, tell the vendor which check it was.")
        );
    }
}
