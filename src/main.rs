use clap::Parser;
use log::{debug, info, warn};
use sha2::{Sha256, Digest};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use infer::Infer;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The path to the file to hash
    file_path: String,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// This program calculates the SHA-256 hash of a file and searches for a text file
/// in the files' directory that contains the hash. If found, it prints the name of the
/// text file containing the matched hash.
/// Usage: cargo run <file_path>
/// Example: cargo run example.exe
fn read_text_file(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(&[0xff, 0xfe]) {
        // UTF-16 LE BOM detected
        let u16_slice: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&u16_slice))
    } else {
        // Fallback to UTF-8
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

fn calculate_sha256<P: AsRef<Path>>(path: P) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn find_file_with_hash(file_path: &str, hash: &str) -> Option<String> {
    let infer = Infer::new();
    let directory_of_hashed_file = Path::new(file_path).parent()?;
    let hash_extensions = [
        "md5", "sha1", "sha256", "sha512", "sum", "hash", "checksum", "txt"
    ];
    let hash_patterns = [
        "CHECKSUMS", "SHA256SUMS", "MD5SUMS", "sha256sum", "checksums", "hashes"
    ];
    let mut unknown_files = Vec::new();

    for entry in fs::read_dir(directory_of_hashed_file).ok()? {
        let path = entry.ok()?.path();
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        let mut treat_as_text = false;
        let mut skip_reason = String::new();

        // Always check files with hash-related extensions or patterns
        if hash_extensions.iter().any(|e| ext == *e)
            || hash_patterns.iter().any(|pat| file_name.contains(pat.to_ascii_lowercase().as_str()))
        {
            treat_as_text = true;
        } else {
            match infer.get_from_path(&path) {
                Ok(Some(kind)) => {
                    let mime = kind.mime_type();
                    if mime.starts_with("text") || mime == "application/octet-stream" {
                        treat_as_text = true;
                    } else {
                        skip_reason = format!("MIME type detected as non-text: {}", mime);
                    }
                },
                _ => {
                    // Unknown or unsupported MIME type, save for later
                    unknown_files.push(path.clone());
                    skip_reason = "Unknown or unsupported MIME type (will check last)".to_string();
                }
            }
        }
        if !treat_as_text {
            debug!("Skipping {:?} ({})", path, skip_reason);
            continue;
        }
        info!("➡️ Searching file: {:?}", path);
        if let Ok(contents) = read_text_file(&path) {
            for line in contents.lines() {
                if line
                    .split_whitespace()
                    .any(|word| word.eq_ignore_ascii_case(hash))
                {
                    return path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(String::from);
                }
            }
        }
    }
    // Now check unknown files last
    for path in unknown_files {
        info!("➡️ Searching unknown file type: {:?}", path);
        if let Ok(contents) = read_text_file(&path) {
            for line in contents.lines() {
                if line
                    .split_whitespace()
                    .any(|word| word.eq_ignore_ascii_case(hash))
                {
                    return path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(String::from);
                }
            }
        }
    }
    None
}


fn main() {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(match cli.verbose {
            0 => log::LevelFilter::Warn,
            1 => log::LevelFilter::Info,
            2 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .init();

    match calculate_sha256(&cli.file_path) {
        Ok(hash) => {
            info!("{}", hash);
            match find_file_with_hash(&cli.file_path, &hash) {
                Some(file_name) => info!("{}", file_name),
                None => warn!("No matching text file found."),
            }
        }
        Err(e) => warn!("Error calculating hash: {}", e),
    }
}
