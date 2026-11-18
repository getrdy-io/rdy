//! The README transcript goldens, made in process from the Replay envs (M1-135, ADR 0048).
//!
//! Each golden is what a reader sees after a prompt: the command, what `rdy` printed on stderr, then
//! `$ echo $?` and the exit code. The text is not typed by hand. It comes from `rdy_cli::run` on the machine
//! of an env, with the clock and run id pinned, so a change to the renderer, a check or a fix line fails
//! here and `UPDATE_GOLDENS=1` shows the new text in `git diff`.
//!
//! Two things differ from the env goldens, and both are display only. The spec is shown under the name a
//! reader types (`acme-platform.yaml`, `acme-quickstart.yaml`), and the version line stays `rdy <version>`
//! so a release does not change a golden. The report folder is not written (`--no-report`), so no
//! timestamped path is in the text.

use std::error::Error;

use rdy_engine::testing::golden::assert_golden;
use rdy_engine::testing::{Fixture, fixtures_dir};

use super::driver::{Cli, run_cli};
use super::readme_goldens::GENERATED;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// One transcript.
struct Case {
    /// The golden's file name under `tests/fixtures/readme/`.
    golden: &'static str,
    /// The env whose machine runs it.
    env: &'static str,
    /// The spec to run: `Env` is the env's own spec file, `Example` a file of `examples/specs/`.
    spec: Spec,
    /// The name the spec has in the folder the reader is in.
    shown: &'static str,
    /// The flags after the spec path, as shown.
    flags: &'static [&'static str],
    /// The exit code the transcript must show.
    exit: i32,
}

enum Spec {
    Env,
    Example(&'static str),
}

const RUN_FLAGS: &[&str] = &["--allow-unsigned", "--no-report"];

const CASES: &[Case] = &[
    // 07 C.5, the first refusal: a spec with no `.minisig` next to it, run without `--allow-unsigned`.
    Case {
        golden: "refusal-unsigned.txt",
        env: "all-pass",
        spec: Spec::Example("acme-quickstart.yaml"),
        shown: "acme-quickstart.yaml",
        flags: &[],
        exit: 64,
    },
    Case {
        golden: "run-quickstart.txt",
        env: "all-block",
        spec: Spec::Env,
        shown: "acme-platform.yaml",
        flags: RUN_FLAGS,
        exit: 2,
    },
    Case {
        golden: "run-ready.txt",
        env: "all-pass",
        spec: Spec::Env,
        shown: "acme-platform.yaml",
        flags: RUN_FLAGS,
        exit: 0,
    },
    // The real example spec on the all-pass machine with no cluster: what is not built or has no cluster is
    // skipped. See the env's `fixture.toml` for why the ending is not the one the ticket row guessed.
    Case {
        golden: "run-platform.txt",
        env: "acme-platform",
        spec: Spec::Env,
        shown: "acme-platform.yaml",
        flags: RUN_FLAGS,
        exit: 2,
    },
];

/// Makes the transcript text of `case`.
fn make(case: &Case) -> TestResult<String> {
    let root = fixtures_dir();
    let spec_file = match case.spec {
        Spec::Env => {
            let fixture = Fixture::load(&root, &format!("envs/{}", case.env))?;
            let name = fixture
                .manifest()
                .spec
                .clone()
                .ok_or("the env has no spec")?;
            root.join("envs").join(case.env).join(name)
        }
        Spec::Example(name) => root.join("../../examples/specs").join(name),
    };
    let folder = tempfile::tempdir()?;
    let spec_path = folder.path().join(case.shown);
    std::fs::copy(&spec_file, &spec_path)?;
    let spec_arg = spec_path.to_string_lossy().into_owned();
    let mut args = vec!["run", spec_arg.as_str()];
    args.extend(case.flags);
    let cli = run_cli(case.env, &args)?;
    assert_eq!(cli.code, case.exit, "{}: exit code", case.golden);
    assert!(
        cli.stdout.is_empty(),
        "{}: stdout is not empty",
        case.golden
    );
    let prefix = format!(
        "{}{}",
        folder.path().to_string_lossy(),
        std::path::MAIN_SEPARATOR
    );
    Ok(transcript(case, &cli, &prefix))
}

/// The text of the golden: the shown command, the stderr with the folder and the version made stable, and
/// the exit code.
fn transcript(case: &Case, cli: &Cli, folder_prefix: &str) -> String {
    let version_line = format!("rdy {}", env!("CARGO_PKG_VERSION"));
    let mut text = format!("$ rdy run {}", case.shown);
    for flag in case.flags {
        text.push(' ');
        text.push_str(flag);
    }
    text.push('\n');
    for line in cli.stderr.replace(folder_prefix, "").lines() {
        text.push_str(if line == version_line {
            "rdy <version>"
        } else {
            line
        });
        text.push('\n');
    }
    text.push_str(&format!("$ echo $?\n{}\n", case.exit));
    text
}

#[test]
fn every_readme_transcript_golden_is_made_from_its_env() -> TestResult {
    if rdy_engine::check::current_os() != rdy_engine::check::Os::Linux {
        eprintln!("readme goldens: the envs are Linux machines, skipping on this OS");
        return Ok(());
    }
    for case in CASES {
        let text = make(case)?;
        assert_golden(fixtures_dir().join("readme").join(case.golden), text);
    }
    Ok(())
}

#[test]
fn the_generator_lists_exactly_the_goldens_on_disk() -> TestResult {
    let mut listed: Vec<&str> = CASES.iter().map(|case| case.golden).collect();
    listed.sort_unstable();
    let mut shared: Vec<&str> = GENERATED.to_vec();
    shared.sort_unstable();
    assert_eq!(listed, shared, "the cases and `GENERATED` differ");
    let mut on_disk: Vec<String> = std::fs::read_dir(fixtures_dir().join("readme"))?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()?;
    on_disk.sort_unstable();
    assert_eq!(
        on_disk, shared,
        "tests/fixtures/readme/ holds a file the generator does not make, or lacks one it does"
    );
    Ok(())
}
