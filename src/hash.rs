use memmap2::{Mmap, MmapOptions};
use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

#[cfg(unix)]
use memmap2::{Advice, UncheckedAdvice};

/// Streaming buffer for stdin, pipes, devices, and mmap fallback.
const STREAM_BUF_SIZE: usize = 8 << 20; // 8 MiB
/// Mapped window size. Must be a multiple of the system page size
/// (4 KiB / 16 KiB). Caps resident memory per worker on huge files.
const MAP_WINDOW: usize = 64 << 20; // 64 MiB

fn digest_to_array(d: Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn hash_reader_from<R: Read>(mut reader: R, mut ctx: Context) -> io::Result<[u8; 32]> {
    let mut buf = vec![0u8; STREAM_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(digest_to_array(ctx.finish()))
}

/// Hash a stream in chunks (used for stdin, pipes, devices).
pub(crate) fn hash_reader<R: Read>(reader: R) -> io::Result<[u8; 32]> {
    hash_reader_from(reader, Context::new(&SHA256))
}

/// Map `[offset, offset+len)` of a regular file. `offset` is a multiple of
/// `MAP_WINDOW`, so it is page-aligned. Returns `None` if mmap is unavailable.
fn map_window(file: &File, offset: u64, file_len: u64) -> Option<Mmap> {
    let win = (file_len - offset).min(MAP_WINDOW as u64) as usize;
    // SAFETY: read-only mapping of a regular file. A concurrent truncation by
    // another process could raise SIGBUS; accepted trade-off for a checksum tool.
    let map = unsafe { MmapOptions::new().offset(offset).len(win).map(file).ok()? };
    #[cfg(unix)]
    let _ = map.advise(Advice::Sequential);
    Some(map)
}

/// Release pages behind the scan so a file larger than RAM does not pin cache.
/// Only used after we are done reading `map`.
fn drop_pages(_map: &Mmap, evict: bool) {
    if !evict {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: this mapping is never read again after the caller hashes it.
        let _ = unsafe { _map.unchecked_advise(UncheckedAdvice::DontNeed) };
    }
}

/// Hash a regular file with windowed mmap: at most two windows live at once
/// (current + prefetch). Falls back to streaming if mmap fails.
fn hash_file(mut file: File, len: u64) -> io::Result<[u8; 32]> {
    let mut ctx = Context::new(&SHA256);
    let evict = len > MAP_WINDOW as u64;

    let Some(mut current) = map_window(&file, 0, len) else {
        return hash_reader_from(file, ctx);
    };
    let mut offset = current.len() as u64;

    while offset < len {
        match map_window(&file, offset, len) {
            Some(next) => {
                #[cfg(unix)]
                let _ = next.advise(Advice::WillNeed);
                ctx.update(&current);
                drop_pages(&current, evict);
                offset += next.len() as u64;
                current = next;
            }
            None => {
                ctx.update(&current);
                drop_pages(&current, evict);
                file.seek(SeekFrom::Start(offset))?;
                return hash_reader_from(file, ctx);
            }
        }
    }

    ctx.update(&current);
    drop_pages(&current, evict);
    Ok(digest_to_array(ctx.finish()))
}

/// Hash a file by memory-mapping it in windows, avoiding a full-file mapping
/// that would pin RAM on huge inputs. Falls back to streaming for empty or
/// non-regular files (devices, procfs, ...) and if mmap fails.
pub(crate) fn hash_path(path: &str) -> io::Result<[u8; 32]> {
    let file = File::open(path)?;
    let meta = file.metadata()?;

    if meta.is_file() && meta.len() > 0 {
        hash_file(file, meta.len())
    } else {
        hash_reader(file)
    }
}

/// Hash many sources in parallel (one thread per core, atomic work-stealing).
/// Results are returned in the same order as `sources`.
/// When `stdin_is_dash` is true, "-" reads standard input (compute mode);
/// otherwise "-" is treated as a literal file name (check mode).
pub(crate) fn hash_all(sources: &[&str], stdin_is_dash: bool) -> Vec<io::Result<[u8; 32]>> {
    let n = sources.len();
    let work = |src: &str| {
        if stdin_is_dash && src == "-" {
            hash_reader(io::stdin().lock())
        } else {
            hash_path(src)
        }
    };

    let workers = thread::available_parallelism().map_or(1, |n| n.get()).min(n);
    if workers <= 1 {
        return sources.iter().map(|s| work(s)).collect();
    }

    let next = AtomicUsize::new(0);
    let mut slots: Vec<Option<io::Result<[u8; 32]>>> = Vec::new();
    slots.resize_with(n, || None);

    thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                s.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= n {
                            break;
                        }
                        local.push((i, work(sources[i])));
                    }
                    local
                })
            })
            .collect();

        for h in handles {
            for (i, r) in h.join().expect("hash worker panicked") {
                slots[i] = Some(r);
            }
        }
    });

    slots
        .into_iter()
        .map(|s| s.expect("every index is processed exactly once"))
        .collect()
}

/// Encode a digest as lowercase hex into a stack buffer (SIMD-accelerated).
pub(crate) fn hex_lower<'a>(hash: &[u8; 32], buf: &'a mut [u8; 64]) -> &'a str {
    faster_hex::hex_encode(hash, buf).expect("64 bytes of output for 32 bytes of input")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        let hash = hash_reader(b"abc".as_slice()).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(
            hex_lower(&hash, &mut buf),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn empty_input() {
        let hash = hash_reader(io::empty()).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(
            hex_lower(&hash, &mut buf),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_path_matches_reader() {
        let path = std::env::temp_dir().join("untitled_hash_path.bin");
        let data: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let mapped = hash_path(path.to_str().unwrap()).unwrap();
        let streamed = hash_reader(data.as_slice()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(mapped, streamed);
    }

    #[test]
    fn hash_all_preserves_order() {
        let dir = std::env::temp_dir();
        let p1 = dir.join("untitled_test_a.bin");
        let p2 = dir.join("untitled_test_b.bin");
        std::fs::write(&p1, b"aaa").unwrap();
        std::fs::write(&p2, b"bbb").unwrap();

        let names = [p1, p2];
        let refs: Vec<&str> = names.iter().map(|p| p.to_str().unwrap()).collect();
        let results = hash_all(&refs, false);

        assert_eq!(
            results[0].as_ref().unwrap(),
            &hash_reader(b"aaa".as_slice()).unwrap()
        );
        assert_eq!(
            results[1].as_ref().unwrap(),
            &hash_reader(b"bbb".as_slice()).unwrap()
        );
        for p in &names {
            let _ = std::fs::remove_file(p);
        }
    }
}
