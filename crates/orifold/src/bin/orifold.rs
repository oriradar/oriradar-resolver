//! CLI for **orifold** — JSON lines for Python / shell integration.

use std::io::{self, Read, Write};

use clap::{Parser, Subcommand};
use orifold::{enumerate, PermutationLine};

#[derive(Parser)]
#[command(name = "orifold", about = "Domain typosquat permutations (standalone Rust engine)", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print permutations as JSON lines (one object per line).
    Enumerate {
        /// Registrable domain, e.g. example.com
        domain: String,
        #[arg(long, default_value_t = 500)]
        max: usize,
    },
    /// Print the number of generated permutations.
    Count {
        /// Registrable domain, e.g. example.com
        domain: String,
        #[arg(long, default_value_t = 500)]
        max: usize,
    },
    /// Read many domains from stdin and print JSON lines with the input domain attached.
    EnumerateBatch {
        #[arg(long, default_value_t = 500)]
        max: usize,
    },
    /// Read many domains from stdin and print a JSON object with per-domain counts.
    CountBatch {
        #[arg(long, default_value_t = 500)]
        max: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Enumerate { domain, max } => {
            let lines: Vec<PermutationLine> = enumerate(&domain, max)?;
            let stdout = io::stdout();
            let mut writer = io::BufWriter::new(stdout.lock());
            for line in lines {
                writer.write_all(serde_json::to_string(&line)?.as_bytes())?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
        Command::Count { domain, max } => {
            let lines: Vec<PermutationLine> = enumerate(&domain, max)?;
            println!("{}", lines.len());
        }
        Command::EnumerateBatch { max } => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            let stdout = io::stdout();
            let mut writer = io::BufWriter::new(stdout.lock());
            for domain in buffer.lines().map(str::trim).filter(|line| !line.is_empty()) {
                let lines = enumerate(domain, max)?;
                for line in lines {
                    let output = serde_json::json!({
                        "domain": domain,
                        "fqdn": line.fqdn,
                        "kind": line.kind,
                    });
                    writer.write_all(output.to_string().as_bytes())?;
                    writer.write_all(b"\n")?;
                }
            }
            writer.flush()?;
        }
        Command::CountBatch { max } => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            let mut counts = serde_json::Map::new();
            for domain in buffer.lines().map(str::trim).filter(|line| !line.is_empty()) {
                let lines = enumerate(domain, max)?;
                counts.insert(domain.to_string(), serde_json::Value::from(lines.len()));
            }
            println!("{}", serde_json::Value::Object(counts));
        }
    }
    Ok(())
}
