mod check;
mod cli;
mod compute;
mod hash;

use clap::Parser;
use cli::Cli;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let stdout = io::stdout();
    // Batch output: the default stdout lock flushes on every newline.
    let mut out = BufWriter::with_capacity(1 << 16, stdout.lock());

    let code = if cli.check {
        check::run_check(&cli.files, &mut out)
    } else {
        compute::run_compute(&cli.files, cli.binary, &mut out)
    };

    let _ = out.flush();
    code
}
