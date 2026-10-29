//! The clap command tree. The words come from `docs/plan/07-cli-ux.md`, Appendix A.
//!
//! Every command of M1 is here. Only `version` does anything yet. The rest are filled in by later
//! tickets. A flag that is listed here but not yet read is parsed and ignored.
//!
//! Help text is written out by hand and wrapped at 80 columns, because clap does not wrap it in
//! this build (the `wrap_help` feature is off, so output does not depend on the terminal).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// `<version> (<commit> <date>)`, built by `build.rs`.
pub(crate) const VERSION: &str = env!("RDY_VERSION");

/// The 7-character commit of the build, or empty when `build.rs` did not know it.
pub(crate) const COMMIT: &str = env!("RDY_COMMIT");

/// The UTC commit date as `YYYY-MM-DD`, or empty when `build.rs` did not know it.
pub(crate) const COMMIT_DATE: &str = env!("RDY_DATE");

/// The Rust target triple of the build.
pub(crate) const TARGET: &str = env!("RDY_TARGET");

const ABOUT: &str = "Check an environment against a vendor's requirements before install day";

const ROOT_LONG_ABOUT: &str = "\
Check an environment against a vendor's requirements before install day.

rdy runs a signed spec of checks on this machine. It prints what is ready,
what is not, and how to fix it. It writes an HTML report and a JSON report.
It works offline. It never asks for sudo. Nothing leaves this machine unless
you send it.";

const ROOT_AFTER_LONG_HELP: &str = "\
Examples:
  Run a spec your vendor signed:
    rdy run acme-platform.yaml

  Use rdy as a gate in CI and keep the result:
    rdy run acme-platform.yaml --json > result.json

  Check a signature without running anything:
    rdy verify acme-platform.yaml

  Trust a vendor's key, once, after you check its fingerprint:
    rdy trust add acme-platform --key acme-platform.pub

Exit codes:
  0   READY
  1   READY with warnings
  2   NOT READY
  64  Usage error, or a spec that must change
  70  Internal error, the report could not be written, or the run was stopped

Environment:
  NO_COLOR     Turn colors off (any non-empty value)
  HTTPS_PROXY  Proxy for network checks (also HTTP_PROXY, NO_PROXY)
  KUBECONFIG   Kubeconfig for Kubernetes checks
  RUST_LOG     Log level for diagnostics, for example RUST_LOG=rdy=debug

Learn more: https://docs.getrdy.io
Report a bug: https://github.com/getrdy-io/rdy/issues";

const RUN_LONG_ABOUT: &str = "\
Run the checks in a spec and write the reports

rdy checks this machine against the spec, prints the result, and writes an
HTML report and a JSON report into a new folder. It runs what it can and says
what it could not run. It never asks for sudo and never changes anything.

The spec must be signed by a key you trust (see 'rdy trust add'). rdy refuses
a spec with a signature that does not match, and a spec signed by a key you
have not trusted. To run a spec that has no signature at all, such as an
example file, see --allow-unsigned.";

const RUN_AFTER_LONG_HELP: &str = "\
Verdict:
  NOT READY if anything blocks or a required check could not run.
  READY with warnings if only optional things are wrong.
  READY if every check ran and passed.

Examples:
  Run a spec your vendor signed:
    rdy run acme-platform.yaml

  Run an example spec that has no signature (you wrote it, or you trust it):
    rdy run acme-quickstart.yaml --allow-unsigned

  Use the exit code in a script and keep the JSON result:
    rdy run acme-platform.yaml --json > result.json
    echo $?

  Check a cluster with a kubeconfig and context you choose:
    rdy run acme-platform.yaml --kubeconfig ~/.kube/acme --kube-context staging

  Run with no network, for a host-only spec on an air-gapped machine:
    rdy run acme-edge.yaml --no-network

Files:
  rdy creates a new folder, rdy-report-<product>-<time>/, with mode 0700. It
  holds the HTML report, the JSON report, and a copy of the spec and its
  signature. rdy never overwrites a folder.

Exit codes:
  0   READY
  1   READY with warnings
  2   NOT READY
  64  Usage error, or a spec that must change
  70  Internal error, the report could not be written, or the run was stopped";

const VERIFY_LONG_ABOUT: &str = "\
Check a spec's signature without running any checks

Reads the spec and its signature and checks the signature against the keys
you trust. Prints who signed it and when. Exit 0 means 'rdy run' would accept
this file with the same --sig and --key. It never asks a question.";

const VERIFY_AFTER_LONG_HELP: &str = "\
Examples:
  Check a spec your vendor sent:
    rdy verify acme-platform.yaml

  Check it in a script:
    rdy verify acme-platform.yaml --json

Exit codes:
  0   Verified
  64  Not verified: no signature, a signature that does not match, or a key
      you have not trusted
  70  Internal error";

const SPEC_AFTER_HELP: &str = "See also: 'rdy verify <SPEC>' checks a signature.";

const LINT_LONG_ABOUT: &str = "\
Check a spec file for mistakes

Reads the spec and reports every problem with its line and column. Run it
before you sign. It never runs a check and never needs a signature.";

const LINT_AFTER_LONG_HELP: &str = "\
Examples:
  Check a spec:
    rdy spec lint acme-platform.yaml

  Use it in CI:
    rdy spec lint acme-platform.yaml --json

Exit codes:
  0   No problems
  1   Warnings only
  2   The spec has errors
  64  Usage error, or the file cannot be read
  70  Internal error";

const SIGN_LONG_ABOUT: &str = "\
Sign a spec with your secret key

Runs 'rdy spec lint' first and refuses to sign a spec with errors. Then it
signs the exact bytes of the file and writes <SPEC>.minisig next to it. It
checks its own signature and prints the key fingerprint and the line to send
your customers. Stock minisign can verify the signature.";

const SIGN_AFTER_LONG_HELP: &str = "\
Environment:
  RDY_KEY_PASSWORD  The key password, for CI. Never put it on the command line.
                    Other processes of your user and root can read it, and
                    child processes inherit it. Use a masked secret in CI.

Examples:
  Sign a spec:
    rdy spec sign acme-platform.yaml --secret-key acme-signing.key

Exit codes:
  0   Signed and verified
  64  Refused: the spec has errors, the key is readable by others, the
      signature file exists, or the password is wrong
  70  Internal error";

const KEYGEN_LONG_ABOUT: &str = "\
Make a signing key pair

Writes <NAME>.key (secret) and <NAME>.pub (public). The secret key is
password protected and readable only by you. rdy never overwrites a key. Use
a key only for specs. Back it up: anyone who has it can sign specs as you.";

const KEYGEN_AFTER_LONG_HELP: &str = "\
Environment:
  RDY_KEY_PASSWORD  The new key password, for CI. Never put it on the command
                    line. Other processes of your user and root can read it,
                    and child processes inherit it. Use a masked secret in CI.

Examples:
  Make a key pair:
    rdy spec keygen acme-signing

Exit codes:
  0   Key pair written
  64  A key file already exists, or the passwords did not match
  70  Internal error";

const TRUST_LONG_ABOUT: &str = "\
Choose which vendor keys rdy trusts

rdy runs a spec only if a key you trust for that product signed it. Trust is
per product: a key trusted for acme-platform means nothing for another
product. Ask the vendor for the key by another route than the spec, and check
its fingerprint before you say yes.";

const TRUST_AFTER_LONG_HELP: &str = "\
Where keys are kept:
  As a normal user: ~/.config/rdy/trust.yaml, then /etc/rdy/trust.yaml.
  As root: only /etc/rdy/trust.yaml. Run 'sudo rdy trust add' to trust a
  key for root runs.";

const TRUST_ADD_LONG_ABOUT: &str = "\
Trust a vendor key for one product

Shows the key id and the fingerprint (SHA-256 of the public key) and asks
you to compare the fingerprint with the one the vendor published. Answer y
only if they match. rdy saves the key only after you say yes.";

const TRUST_ADD_AFTER_LONG_HELP: &str = "\
Examples:
  Trust a key for yourself:
    rdy trust add acme-platform --key acme-platform.pub

  Trust a key for runs as root:
    sudo rdy trust add acme-platform --key acme-platform.pub

Exit codes:
  0   Key saved
  64  Not saved: you answered no, there is no terminal and no --yes, the file
      is a secret key, or the product already has a key with this key id
  70  Internal error";

const TRUST_LIST_LONG_ABOUT: &str = "\
Show the keys you trust

Prints every trusted key with its product, key id, fingerprint, the date you
added it, and your note. As a normal user it lists your file and the system
file. As root it lists only the system file.";

const TRUST_LIST_AFTER_LONG_HELP: &str = "\
Exit codes:
  0   Done, even when no key is trusted yet
  64  The trust file is unsafe: other users can write to it
  70  Internal error";

const TRUST_REMOVE_LONG_ABOUT: &str = "\
Stop trusting a key

Removes the key for a product from the trust file you can write: yours as a
normal user, the system file as root. Specs signed by it are refused after
this. If the product has two keys, say which one with --key-id.";

const TRUST_REMOVE_AFTER_LONG_HELP: &str = "\
Examples:
  Stop trusting a vendor:
    rdy trust remove acme-platform

Exit codes:
  0   Key removed
  64  Not removed: no such key, or the product has two keys and no --key-id
  70  Internal error";

const VERSION_LONG_ABOUT: &str = "\
Print the version

Prints the version, the commit and the build date. Put this in a bug report.";

const VERSION_AFTER_LONG_HELP: &str = "\
Example output:
  rdy 0.1.0 (4c1e9a2 2027-03-07)";

/// The `rdy` command line.
#[derive(Debug, Parser)]
#[command(
    name = "rdy",
    bin_name = "rdy",
    version = VERSION,
    disable_version_flag = true,
    disable_help_subcommand = true,
    about = ABOUT,
    long_about = ROOT_LONG_ABOUT,
    after_long_help = ROOT_AFTER_LONG_HELP,
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Cli {
    /// Options every command takes, before or after the subcommand.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The command to run.
    #[command(subcommand)]
    pub command: Commands,
}

/// Options every command takes (07 section 1, Global flags).
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// When to use colors.
    #[arg(
        long,
        global = true,
        display_order = 900,
        value_name = "WHEN",
        value_enum,
        default_value = "auto",
        hide_possible_values = true,
        hide_default_value = true,
        help = "Colors: auto, always, never [default: auto]"
    )]
    pub color: ColorChoice,

    /// When to show live progress.
    #[arg(
        long,
        global = true,
        display_order = 901,
        value_name = "WHEN",
        value_enum,
        default_value = "auto",
        hide_possible_values = true,
        hide_default_value = true,
        hide_env = true,
        env = "RDY_PROGRESS",
        help = "Live progress: auto, never [default: auto]"
    )]
    pub progress: ProgressChoice,

    /// Print less.
    #[arg(
        short,
        long,
        global = true,
        display_order = 902,
        conflicts_with = "verbose",
        help = "Print less"
    )]
    pub quiet: bool,

    /// Print more.
    #[arg(short, long, global = true, display_order = 903, help = "Print more")]
    pub verbose: bool,
}

/// Values of `--color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    /// Colors when stderr is a terminal.
    Auto,
    /// Always use colors.
    Always,
    /// Never use colors.
    Never,
}

/// Values of `--progress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProgressChoice {
    /// Live progress when stderr is a terminal.
    Auto,
    /// No live progress.
    Never,
}

/// The M1 commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run the checks in a spec and write the reports.
    #[command(
        about = "Run the checks in a spec and write the reports",
        long_about = RUN_LONG_ABOUT,
        after_long_help = RUN_AFTER_LONG_HELP,
    )]
    Run(RunArgs),

    /// Check a spec's signature without running any checks.
    #[command(
        about = "Check a spec's signature without running any checks",
        long_about = VERIFY_LONG_ABOUT,
        after_long_help = VERIFY_AFTER_LONG_HELP,
    )]
    Verify(VerifyArgs),

    /// Lint, sign and make keys for spec files.
    #[command(
        about = "Lint, sign and make keys for spec files",
        after_help = SPEC_AFTER_HELP,
        subcommand_required = true,
        arg_required_else_help = true,
        disable_help_subcommand = true,
    )]
    Spec {
        /// The spec command to run.
        #[command(subcommand)]
        command: SpecCommand,
    },

    /// Choose which vendor keys rdy trusts.
    #[command(
        about = "Choose which vendor keys rdy trusts",
        long_about = TRUST_LONG_ABOUT,
        after_long_help = TRUST_AFTER_LONG_HELP,
        subcommand_required = true,
        arg_required_else_help = true,
        disable_help_subcommand = true,
    )]
    Trust {
        /// The trust command to run.
        #[command(subcommand)]
        command: TrustCommand,
    },

    /// Print the version.
    #[command(
        about = "Print the version",
        long_about = VERSION_LONG_ABOUT,
        after_long_help = VERSION_AFTER_LONG_HELP,
    )]
    Version(VersionArgs),

    /// Print help for a command.
    #[command(name = "help", about = "Print help for a command")]
    Help {
        /// The command to show help for, such as `spec lint`.
        #[arg(value_name = "COMMAND", num_args = 0..)]
        command: Vec<String>,
    },
}

/// Commands under `rdy spec`. `init` is M3 and is not here.
#[derive(Debug, Subcommand)]
pub enum SpecCommand {
    /// Check a spec file for mistakes.
    #[command(
        about = "Check a spec file for mistakes",
        long_about = LINT_LONG_ABOUT,
        after_long_help = LINT_AFTER_LONG_HELP,
    )]
    Lint(LintArgs),

    /// Sign a spec with your secret key.
    #[command(
        about = "Sign a spec with your secret key",
        long_about = SIGN_LONG_ABOUT,
        after_long_help = SIGN_AFTER_LONG_HELP,
    )]
    Sign(SignArgs),

    /// Make a signing key pair.
    #[command(
        about = "Make a signing key pair",
        long_about = KEYGEN_LONG_ABOUT,
        after_long_help = KEYGEN_AFTER_LONG_HELP,
    )]
    Keygen(KeygenArgs),
}

/// Commands under `rdy trust`.
#[derive(Debug, Subcommand)]
pub enum TrustCommand {
    /// Trust a vendor key for one product.
    #[command(
        about = "Trust a vendor key for one product",
        long_about = TRUST_ADD_LONG_ABOUT,
        after_long_help = TRUST_ADD_AFTER_LONG_HELP,
    )]
    Add(TrustAddArgs),

    /// Show the keys you trust.
    #[command(
        about = "Show the keys you trust",
        long_about = TRUST_LIST_LONG_ABOUT,
        after_long_help = TRUST_LIST_AFTER_LONG_HELP,
    )]
    List,

    /// Stop trusting a key.
    #[command(
        about = "Stop trusting a key",
        long_about = TRUST_REMOVE_LONG_ABOUT,
        after_long_help = TRUST_REMOVE_AFTER_LONG_HELP,
    )]
    Remove(TrustRemoveArgs),
}

/// Arguments of `rdy run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The spec file.
    #[arg(
        value_name = "SPEC",
        help = "The spec file, for example acme-platform.yaml",
        long_help = "The spec file, for example acme-platform.yaml. Its signature is\nread from <SPEC>.minisig unless you pass --sig."
    )]
    pub spec: PathBuf,

    /// Signature file.
    #[arg(
        long,
        value_name = "FILE",
        help_heading = "Signature",
        help = "Read the signature from this file"
    )]
    pub sig: Option<PathBuf>,

    /// A public key to trust for this run only. Argv only.
    #[arg(
        long,
        value_name = "KEY",
        help_heading = "Signature",
        help = "Trust this public key for this run only",
        long_help = "Trust this public key for this run only. A key file or\nthe key text. Nothing is saved, and the run prints a\nKEY NOT PINNED warning. Use 'rdy trust add' to keep a\nkey."
    )]
    pub key: Option<String>,

    /// Run a spec that has no signature. Argv only.
    #[arg(
        long,
        help_heading = "Signature",
        help = "Run a spec that has no signature",
        long_help = "Run a spec that has no signature. rdy prints an\nUNSIGNED SPEC warning and marks every report. A\nsignature that does not match is still refused."
    )]
    pub allow_unsigned: bool,

    /// Print the JSON report on stdout.
    #[arg(
        long,
        help_heading = "Output",
        help = "Print the JSON report on stdout",
        long_help = "Print the JSON report on stdout. The text report still\ngoes to stderr."
    )]
    pub json: bool,

    /// Folder to create the report folder in.
    #[arg(
        long,
        value_name = "DIR",
        help_heading = "Output",
        help = "Folder to create the report folder in",
        long_help = "Folder to create the report folder in\n[default: . ; on Windows %USERPROFILE%\\rdy-reports]"
    )]
    pub out_dir: Option<PathBuf>,

    /// Write no report files.
    #[arg(long, help_heading = "Output", help = "Write no report files")]
    pub no_report: bool,

    /// Kubeconfig to use.
    #[arg(
        long,
        value_name = "FILE",
        help_heading = "Scope",
        help = "Kubeconfig to use",
        long_help = "Kubeconfig to use. Use only one you trust: a\nkubeconfig can run programs."
    )]
    pub kubeconfig: Option<PathBuf>,

    /// Kubernetes context to use.
    #[arg(
        long,
        value_name = "NAME",
        help_heading = "Scope",
        help = "Kubernetes context to use"
    )]
    pub kube_context: Option<String>,

    /// Open no network connections.
    #[arg(
        long,
        help_heading = "Scope",
        help = "Open no network connections",
        long_help = "Open no network connections. Network and\nKubernetes checks are skipped. A Kubernetes flag\nis ignored, and the header says so."
    )]
    pub no_network: bool,

    /// Checks to run at once.
    #[arg(
        long,
        value_name = "N",
        help_heading = "Scope",
        help = "Checks to run at once [default: 8, max: 32]"
    )]
    pub jobs: Option<u32>,
}

/// Arguments of `rdy verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The spec file.
    #[arg(
        value_name = "SPEC",
        help = "The spec file, for example acme-platform.yaml"
    )]
    pub spec: PathBuf,

    /// Signature file.
    #[arg(
        long,
        value_name = "FILE",
        help = "Read the signature from this file",
        long_help = "Read the signature from this file\n[default: <SPEC>.minisig]"
    )]
    pub sig: Option<PathBuf>,

    /// A public key to check against. Argv only.
    #[arg(
        long,
        value_name = "KEY",
        help = "Check against this public key only, for this command",
        long_help = "Check against this public key only, for this command.\nPrints a KEY NOT PINNED warning."
    )]
    pub key: Option<String>,

    /// Print a JSON result on stdout.
    #[arg(long, help = "Print a JSON result on stdout")]
    pub json: bool,
}

/// Arguments of `rdy spec lint`.
#[derive(Debug, Args)]
pub struct LintArgs {
    /// The spec file.
    #[arg(
        value_name = "SPEC",
        help = "The spec file, for example acme-platform.yaml"
    )]
    pub spec: PathBuf,

    /// Print a JSON result on stdout.
    #[arg(long, help = "Print a JSON result on stdout")]
    pub json: bool,
}

/// Arguments of `rdy spec sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// The spec file.
    #[arg(
        value_name = "SPEC",
        help = "The spec file, for example acme-platform.yaml"
    )]
    pub spec: PathBuf,

    /// The secret key to sign with.
    #[arg(
        long,
        required = true,
        value_name = "FILE",
        help = "Your secret key, made with 'rdy spec keygen'"
    )]
    pub secret_key: PathBuf,

    /// Where to write the signature.
    #[arg(
        long,
        value_name = "FILE",
        help = "Where to write the signature",
        long_help = "Where to write the signature\n[default: <SPEC>.minisig]"
    )]
    pub sig: Option<PathBuf>,

    /// Replace the signature file if it exists.
    #[arg(long, help = "Replace the signature file if it exists")]
    pub force: bool,

    /// Read the key password from a file.
    #[arg(
        long,
        value_name = "FILE",
        help = "Read the key password from a file",
        long_help = "Read the key password from a file, or '-' for\nstandard input. The prompt is the default."
    )]
    pub password_file: Option<PathBuf>,
}

/// Arguments of `rdy spec keygen`.
#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Name for the key files.
    #[arg(
        value_name = "NAME",
        help = "Name for the key files, for example acme-signing"
    )]
    pub name: String,

    /// Do not protect the secret key with a password.
    #[arg(
        long,
        help = "Do not protect the secret key with a password",
        long_help = "Do not protect the secret key with a password.\nFor CI only."
    )]
    pub unencrypted: bool,

    /// Read the new password from a file.
    #[arg(
        long,
        value_name = "FILE",
        help = "Read the new password from a file",
        long_help = "Read the new password from a file, or '-' for\nstandard input. The prompt is the default."
    )]
    pub password_file: Option<PathBuf>,
}

/// Arguments of `rdy trust add`.
#[derive(Debug, Args)]
pub struct TrustAddArgs {
    /// The product the key may sign for.
    #[arg(
        value_name = "PRODUCT",
        help = "The product the key may sign for, for example acme-platform"
    )]
    pub product: String,

    /// The vendor's public key.
    #[arg(
        long,
        required = true,
        value_name = "KEY",
        help = "The vendor's public key: a .pub file, or the key text"
    )]
    pub key: String,

    /// Do not ask. Argv only.
    #[arg(
        long,
        help = "Do not ask. For scripts",
        long_help = "Do not ask. For scripts. Only use it after you have\nchecked the fingerprint."
    )]
    pub yes: bool,

    /// A note for yourself.
    #[arg(
        long,
        value_name = "TEXT",
        help = "A note for yourself",
        long_help = "A note for yourself. It appears in every report you send."
    )]
    pub note: Option<String>,
}

/// Arguments of `rdy trust remove`.
#[derive(Debug, Args)]
pub struct TrustRemoveArgs {
    /// The product to stop trusting.
    #[arg(
        value_name = "PRODUCT",
        help = "The product to stop trusting, for example acme-platform"
    )]
    pub product: String,

    /// Remove only the key with this id.
    #[arg(
        long,
        value_name = "ID",
        help = "Remove only the key with this id",
        long_help = "Remove only the key with this id, as 'rdy trust list'\nshows it"
    )]
    pub key_id: Option<String>,
}

/// Arguments of `rdy version`.
#[derive(Debug, Args)]
pub struct VersionArgs {
    /// Print the fields as JSON.
    #[arg(long, help = "Print the fields as JSON on stdout")]
    pub json: bool,
}
