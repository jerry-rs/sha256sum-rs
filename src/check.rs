use crate::hash;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;

/// Parse one line of a checksum file: "<64 hex chars><separator><name>".
/// The separator is "  " (text), " *" (binary), or any whitespace mix plus
/// an optional '*' (BSD tools use a tab). Returns (hash, name).
fn parse_line(line: &str) -> Option<([u8; 32], &str)> {
    let trimmed = line.trim_end_matches(['\n', '\r']).trim_start();
    let bytes = trimmed.as_bytes();
    if bytes.len() < 64 {
        return None;
    }

    let (hex_part, rest) = bytes.split_at(64);
    let mut hash = [0u8; 32];
    faster_hex::hex_decode(hex_part, &mut hash).ok()?;

    let rest = std::str::from_utf8(rest).ok()?.trim_start();
    let name = rest.strip_prefix('*').unwrap_or(rest).trim_start();
    if name.is_empty() {
        return None;
    }
    Some((hash, name))
}

/// Verify checksums read from `reader`: parse all lines, hash the listed
/// files in parallel, then report in file order. Returns the number of failures.
fn check_reader<R: Read, W: Write>(mut reader: R, out: &mut W) -> usize {
    let mut content = String::new();
    if let Err(e) = reader.read_to_string(&mut content) {
        eprintln!("sha256sum: error reading checksums: {e}");
        return 1;
    }

    let mut entries: Vec<([u8; 32], &str)> = Vec::new();
    let mut failed = 0usize;
    for line in content.lines() {
        match parse_line(line) {
            Some(e) => entries.push(e),
            None => {
                if line.trim().is_empty() {
                    continue;
                }
                eprintln!("sha256sum: improperly formatted SHA256 line: {}", line.trim());
                failed += 1;
            }
        }
    }

    let names: Vec<&str> = entries.iter().map(|(_, n)| *n).collect();
    let results = hash::hash_all(&names, false);

    for ((expected, name), result) in entries.iter().zip(results) {
        match result {
            Ok(actual) if &actual == expected => {
                let _ = writeln!(out, "{name}: OK");
            }
            Ok(_) => {
                eprintln!("{name}: FAILED");
                failed += 1;
            }
            Err(e) => {
                eprintln!("sha256sum: {name}: {e}");
                failed += 1;
            }
        }
    }

    failed
}

/// Verify all checksum files (or stdin when empty / "-").
pub(crate) fn run_check<W: Write>(files: &[String], out: &mut W) -> ExitCode {
    let mut failed = 0usize;

    if files.is_empty() {
        failed += check_reader(io::stdin().lock(), out);
    } else {
        for source in files {
            if source == "-" {
                failed += check_reader(io::stdin().lock(), out);
            } else {
                match File::open(source) {
                    Ok(f) => failed += check_reader(f, out),
                    Err(e) => {
                        eprintln!("sha256sum: {source}: {e}");
                        failed += 1;
                    }
                }
            }
        }
    }

    if failed > 0 {
        let pl = if failed == 1 { "" } else { "s" };
        eprintln!("sha256sum: WARNING: {failed} listed file{pl} could not be checked");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_reader, hex_lower};

    const HASH: &str = "e8c39f0527426d4a81ce68a56f727793aa2bf928059dc57a229f885d8cffc304";

    #[test]
    fn parse_text_mode() {
        let line = format!("{HASH}  /tmp/a.bin\n");
        let (h, name) = parse_line(&line).unwrap();
        assert_eq!(name, "/tmp/a.bin");
        assert_eq!(h[0], 0xe8);
        assert_eq!(h[31], 0x04);
    }

    #[test]
    fn parse_binary_mode() {
        let line = format!("{HASH} */tmp/a.bin\n");
        let (_, name) = parse_line(&line).unwrap();
        assert_eq!(name, "/tmp/a.bin");
    }

    #[test]
    fn parse_tab_separator() {
        let line = format!("{HASH}\t/tmp/a.bin\n");
        let (_, name) = parse_line(&line).unwrap();
        assert_eq!(name, "/tmp/a.bin");
    }

    #[test]
    fn parse_invalid() {
        assert!(parse_line("").is_none());
        assert!(parse_line("zzz").is_none());
        assert!(parse_line(HASH).is_none());
        assert!(parse_line(&format!("{HASH}  ")).is_none());
    }

    #[test]
    fn roundtrip_hex() {
        let hash = hash_reader(b"hello world".as_slice()).unwrap();
        let mut buf = [0u8; 64];
        let hex = hex_lower(&hash, &mut buf).to_string();
        let line = format!("{hex}  x\n");
        let (decoded, _) = parse_line(&line).unwrap();
        assert_eq!(decoded, hash);
    }
}
