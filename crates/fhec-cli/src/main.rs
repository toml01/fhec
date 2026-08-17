use clap::{Parser, Subcommand};
use fhec_cli::commands::{self, GlobalArgs};
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

    /// Fail when regeneration would change the out dir (reserved, CI mode).
    #[arg(long, global = true)]
    frozen: bool,

    /// Auto-apply safe fix-its (reserved).
    #[arg(long, global = true)]
    fix: bool,

    /// Override the ACL mode: insert | suggest (reserved).
    #[arg(long, global = true, value_name = "MODE")]
    acl: Option<String>,

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
}

fn main() {
    let cli = Cli::parse();
    // Reserved flags: parsed so they are claimed, rejected until implemented.
    for (set, name) in [
        (cli.frozen, "--frozen"),
        (cli.fix, "--fix"),
        (cli.acl.is_some(), "--acl"),
    ] {
        if set {
            eprintln!("fhec: {name} is not implemented yet");
            std::process::exit(2);
        }
    }
    let g = GlobalArgs {
        config: cli.config,
        json: cli.json,
        verbose: cli.verbose,
    };
    let code = match cli.command {
        Command::Build => commands::cmd_build(&g),
        Command::Check => commands::cmd_check(&g),
        Command::Init => commands::cmd_init(),
        Command::Explain { code } => commands::cmd_explain(&code),
        Command::Clean => commands::cmd_clean(&g),
    };
    std::process::exit(code);
}
