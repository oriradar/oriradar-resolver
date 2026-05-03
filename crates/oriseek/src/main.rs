use std::time::Duration;

use clap::{Parser, Subcommand};
use oriseek::{normalize_domains, read_domains_from_stdin, resolve_batch};

#[derive(Parser)]
#[command(name = "oriseek", about = "DNS enrichment engine for Oriradar", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Resolve DNS records for many domains and print one JSON line per domain.
    Resolve {
        /// Domains passed directly on the CLI.
        domains: Vec<String>,
        /// Read newline-separated domains from stdin.
        #[arg(long)]
        stdin: bool,
        /// Max concurrent resolutions.
        #[arg(long, default_value_t = 256)]
        concurrency: usize,
        /// Per-lookup timeout in milliseconds.
        #[arg(long, default_value_t = 2_000)]
        timeout_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Resolve {
            mut domains,
            stdin,
            concurrency,
            timeout_ms,
        } => {
            if stdin {
                domains.extend(read_domains_from_stdin()?);
            }
            let domains = normalize_domains(domains);
            let lines = resolve_batch(domains, concurrency, Duration::from_millis(timeout_ms)).await?;
            for line in lines {
                println!("{}", serde_json::to_string(&line)?);
            }
        }
    }
    Ok(())
}
