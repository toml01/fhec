use clap::{Parser, Subcommand};
use fhec_cli::commands::{self, GlobalArgs};
use fhec_cli::config::AclMode;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fhec",
    version,
    about = "fhec — .fsol → CoFHE Solidity transpiler"
)]
struct Cli {
    /// Path to fhec.toml (default: search upward from the working directory).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Emit diagnostics as a JSON array (spec §10.2) on stdout.
    #[arg(long, global = true)]
    json: bool,

    /// Verbose progress output on stderr.
    #[arg(long, global = true)]
    verbose: bool,

    /// CI mode: write nothing; fail when regeneration would change the out dir.
    #[arg(long, global = true)]
    frozen: bool,

    /// Apply safe fix-its to the original sources, then re-check.
    #[arg(long, global = true)]
    fix: bool,

    /// Override the ACL mode: insert | suggest.
    #[arg(long, global = true, value_name = "MODE")]
    acl: Option<String>,

    /// Skip the solc verification gate (stage 8).
    #[arg(long, global = true)]
    no_verify: bool,

    /// Also forward non-error solc diagnostics from files outside project.src.
    #[arg(long, global = true)]
    all_solc_warnings: bool,

    /// Re-transpile the generated output and assert byte identity (spec §1.4).
    #[arg(long, global = true, hide = true)]
    self_check: bool,

    /// Rebuild or recheck when dialect sources or fhec.toml change.
    #[arg(long, global = true)]
    watch: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Transpile the project into the out dir (stages 2-8).
    Build,
    /// Parse and check the project without writing output.
    Check,
    /// Scaffold fhec.toml and a sample contract in the current directory.
    Init,
    /// Explain a diagnostic code (e.g. `fhec explain FHE2007`).
    Explain {
        /// The diagnostic code, e.g. FHE2007.
        code: String,
    },
    /// Remove the generated out dir.
    Clean,
    /// Print the effective fhec.toml as JSON.
    Config,
}

fn main() {
    let cli = Cli::parse();
    let acl = match cli.acl.as_deref() {
        None => None,
        Some("insert") => Some(AclMode::Insert),
        Some("suggest") => Some(AclMode::Suggest),
        Some(other) => {
            eprintln!("fhec: invalid --acl mode {other:?} (expected insert or suggest)");
            std::process::exit(2);
        }
    };
    let g = GlobalArgs {
        config: cli.config,
        json: cli.json,
        verbose: cli.verbose,
        frozen: cli.frozen,
        fix: cli.fix,
        acl,
        no_verify: cli.no_verify,
        self_check: cli.self_check,
        watch: cli.watch,
        all_solc_warnings: cli.all_solc_warnings,
    };
    let code = match cli.command {
        Command::Build if g.watch => fhec_cli::watch::cmd_watch(&g, commands::cmd_build),
        Command::Check if g.watch => fhec_cli::watch::cmd_watch(&g, commands::cmd_check),
        Command::Build => commands::cmd_build(&g),
        Command::Check => commands::cmd_check(&g),
        Command::Init | Command::Explain { .. } | Command::Clean | Command::Config if g.watch => {
            eprintln!("fhec: --watch is only valid with build or check");
            2
        }
        Command::Init => commands::cmd_init(),
        Command::Explain { code } => commands::cmd_explain(&code),
        Command::Clean => commands::cmd_clean(&g),
        Command::Config => commands::cmd_config(&g),
    };
    std::process::exit(code);
}
