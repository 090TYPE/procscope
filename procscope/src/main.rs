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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    capture::run(cli.pid, cli.command).await
}
