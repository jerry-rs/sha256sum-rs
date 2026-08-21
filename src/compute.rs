use crate::hash;
use std::io::Write;
use std::process::ExitCode;

pub(crate) fn run_compute<W: Write>(files: &[String], binary: bool, out: &mut W) -> ExitCode {
    let sources: Vec<&str> = if files.is_empty() {
        vec!["-"]
    } else {
        files.iter().map(String::as_str).collect()
    };

    // Hash everything in parallel, then print in argument order.
    let results = hash::hash_all(&sources, true);

    let mut had_error = false;
    let mut hex = [0u8; 64];
    for (source, result) in sources.iter().zip(results) {
        match result {
            Ok(h) => {
                let hex = hash::hex_lower(&h, &mut hex);
                // GNU format: "hash  name" (text) or "hash *name" (binary)
                let sep = if binary { " *" } else { "  " };
                let _ = writeln!(out, "{hex}{sep}{source}");
            }
            Err(e) => {
                eprintln!("sha256sum: {source}: {e}");
                had_error = true;
            }
        }
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
