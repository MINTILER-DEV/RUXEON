use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ruxeon", about = "Linux user-mode runtime for Windows")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        rootfs: Option<PathBuf>,
        program: PathBuf,
        args: Vec<String>,
    },
    Shell {
        #[arg(long)]
        rootfs: PathBuf,
    },
    Trace {
        program: PathBuf,
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { program, .. } => {
            println!("ruxeon run scaffold: {}", program.display());
        }
        Command::Shell { rootfs } => {
            println!("ruxeon shell scaffold: {}", rootfs.display());
        }
        Command::Trace { program, .. } => {
            println!("ruxeon trace scaffold: {}", program.display());
        }
    }
    Ok(())
}
