mod capture;
mod ui;

use clap::Parser;

/// Watch what processes do — files, network, syscalls — live, via eBPF.
#[derive(Parser, Debug)]
#[command(name = "procscope", version, about)]
struct Cli {
    /// Only watch this PID.
    #[arg(short, long)]
    pid: Option<u32>,

    /// Launch this command and watch it (everything after `--`).
    #[arg(last = true)]
    command: Vec<String>,

    /// Print captured events as plain text instead of the TUI (pipeable).
    #[arg(long)]
    print: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    capture::run(cli.pid, cli.command, cli.print).await
}
