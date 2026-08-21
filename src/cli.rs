use clap::Parser;

/// Compute or check SHA-256 checksums, compatible with GNU sha256sum.
///
/// With no FILE, or when FILE is '-', read standard input.
#[derive(Parser)]
#[command(name = "sha256sum", version, about)]
pub(crate) struct Cli {
    /// Read checksums from the FILEs and check them
    #[arg(short = 'c', long)]
    pub(crate) check: bool,

    /// Read in binary mode (default; affects only the output marker)
    #[arg(short = 'b', long)]
    pub(crate) binary: bool,

    /// Read in text mode (ignored, included for compatibility)
    #[arg(short = 't', long)]
    pub(crate) text: bool,

    /// Files to process ('-' means standard input)
    #[arg(name = "FILE")]
    pub(crate) files: Vec<String>,
}
