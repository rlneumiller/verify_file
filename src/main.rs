use clap::Parser;
use digest::Digest;
use infer::Infer;
use log::{debug, info, warn};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The path to the file to hash
    file_path: String,

    /// The hash algorithm to use
    #[arg(short, long, default_value = "sha256")]
    algorithm: String,

    /// Enable verbose logging. Pass once for debug, twice for trace.
    /// For example, `-v` or `--verbose` for debug, `-vv` for trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// This program calculates the SHA-256 hash of a file and searches for a text file
/// in the files' directory that contains the hash. If found, it prints the name of the
/// text file containing the matched hash.
/// Usage: cargo run <file_path>
/// Example: cargo run example.exe
fn read_text_file(path: &Path) -> std::io::Result<String> {
    fs::read_to_string(path)
}

fn calculate_hash<D: Digest>(
    path: &str,
    mut hasher: D,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let result = hasher.finalize();
    Ok(result
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect())
}

fn find_file_with_hash(file_path: &str, hash: &str) -> Option<String> {
    let infer = Infer::new();
    let parent_path = Path::new(file_path).parent()?;
    let directory_of_hashed_file = if parent_path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent_path
    };
    let hash_extensions = [
        "md5", "sha1", "sha256", "sha512", "sum", "hash", "checksum", "txt"
    ];
    let hash_patterns = [
        "CHECKSUMS", "SHA256SUMS", "MD5SUMS", "sha256sum", "checksums", "hashes"
    ];
    let mut unknown_files = Vec::new();

    let dir_reader = match fs::read_dir(directory_of_hashed_file) {
        Ok(reader) => reader,
        Err(e) => {
            warn!(
                "Failed to read directory '{:?}': {}",
                directory_of_hashed_file, e
            );
            return None;
        }
    };

    for entry_result in dir_reader {
        let path = match entry_result {
            Ok(entry) => entry.path(),
            Err(e) => {
                warn!("Failed to read directory entry: {}", e);
                continue;
            }
        };
        println!("➡️ Checking file: {:?}", path);
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        let mut treat_as_text = false;
        let mut skip_reason = String::new();

        // Always check files with hash-related extensions or patterns
        // If there are mime types or an RFC that defines standard extensions for hash files
        // I didn't find any, so use sketchy heuristics instead

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
                    // Unknown or unsupported MIME type, save for later and check last
                    // if no other matches were found before we get there
                    unknown_files.push(path.clone());
                    skip_reason = "Unknown or unsupported MIME type (will check last)".to_string();
                }
            }
        }
        if !treat_as_text {
            debug!("➡️ Skipping {:?} ({})", path, skip_reason);
            continue;
        }
        debug!("➡️ Searching file: {:?}", path);
        if let Ok(contents) = read_text_file(&path) {
            for line in contents.lines() {
                if line
                    .split_whitespace()
                    .any(|word| word.trim().eq_ignore_ascii_case(hash))
                {
                    return path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(String::from);
                }
            }
        }
    }
    // Since we didn't find the hash in 'known' files types, check the unidentifiec filetypes
    for path in unknown_files {
        debug!("➡️ Searching unknown file type: {:?}", path);
        if let Ok(contents) = read_text_file(&path) {
            for line in contents.lines() {
                if line
                    .split_whitespace()
                    .any(|word| word.trim().eq_ignore_ascii_case(hash))
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
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .init();

    let hash_result = match cli.algorithm.to_lowercase().as_str() {
        "md5" => calculate_hash(&cli.file_path, Md5::new()),
        "sha1" => calculate_hash(&cli.file_path, Sha1::new()),
        "sha256" => calculate_hash(&cli.file_path, Sha256::new()),
        "sha512" => calculate_hash(&cli.file_path, Sha512::new()),
        _ => {
            warn!(
                "Unsupported hash algorithm: {}. Defaulting to SHA256.",
                cli.algorithm
            );
            calculate_hash(&cli.file_path, Sha256::new())
        }
    };

    match hash_result {
        Ok(hash) => {
            info!("⭐ File hash: {}", hash);
            match find_file_with_hash(&cli.file_path, &hash) {
                Some(file_name) => {
                    let hashed_file_name = Path::new(&cli.file_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&cli.file_path);
                    info!(
                        "✅ Matches {} hash found in {}",
                        hashed_file_name, file_name
                    );
                }
                None => warn!("❌ Failed to find a matching hash. Unable to verify the file."),
            }
        }
        Err(e) => warn!("Error calculating hash: {}", e),
    }
}
