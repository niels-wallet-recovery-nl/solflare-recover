// ============================================================================
//  solflare-recover  v0.7.0
//  High-performance password recovery tool for legacy Solflare keystores
//  This tool is provided to you Free of change by Niels from Wallet Recovery NL
//
//  DESCRIPTION:
//    Brute-force password recovery for Solana solflare legacy keystore JSON files using
//    PBKDF2-SHA512 (or SHA-256) key derivation and AES-CTR decryption.
//    Verified against the decrypted public key in the keystore itself.
//
//  SOLFLARE DEVIATIONS FROM WEB3 SECRET STORAGE:
//    1. cipher field is often wrong (claims aes-128-ctr, actually uses AES-256)
//    2. salt is raw ASCII bytes of hex string, not decoded hex (64 bytes, not 32)
//    3. IV comes from counter integer, not an iv field (big-endian, right-aligned)
//
//  BUILD:
//    cargo clean
//    RUSTFLAGS="-C target-cpu=native" cargo build --release
//
//  EXAMPLE USE:
//    echo 'Solana123' | solflare-recover -f keystore.json
//    solflare-recover -f keystore.json -p passwords.txt -w 8
//    cat rockyou.txt | solflare-recover -f keystore.json -w 8
//    solflare-recover -f keystore.json -p words.txt -w 8 -e false
//
//  PERFORMANCE:
//    Single thread:  ~350 passwords/second (c=8192, SHA-512)
//    8 threads:      ~2,500 passwords/second (near-linear scaling)
//
//  OUTPUT:
//    On success: password printed to console + entry written to pot.txt
//    pot.txt format: file_name:password:private_key_base58
//
//  LICENSE: Apache 2.0
// ============================================================================

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, sync_channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use aes::{Aes128, Aes256};
use ctr::cipher::generic_array::GenericArray;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use openssl::hash::{hash, MessageDigest};
use openssl::pkcs5;
use serde_json::Value;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

const DEFAULT_KEYSTORE: &str = "solflare-keystore.json";
const POT_FILE: &str = "pot.txt";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BATCH: usize = 32;        // passwords per batch sent to workers
const QUEUE_DEPTH: usize = 2;   // worker queue depth

// ============================================================================
//  Types
// ============================================================================

/// Salt encoding mode: raw (ASCII bytes) vs hex (decoded bytes)
#[derive(Clone, Copy, Debug, PartialEq)]
enum SaltMode {
    Raw,   // ASCII bytes of hex string (Solflare legacy)
    Hex,   // Decoded hex bytes (Web3 convention)
}

/// PBKDF2 HMAC pseudo-random function hash algorithm
#[derive(Clone, Copy, Debug, PartialEq)]
enum PrfHash {
    Sha256,
    Sha512,
}

impl PrfHash {
    /// Parse prf field from keystore (handles variations like hmac-sha512, hmac_with_sha512)
    fn parse(s: &str) -> Result<Self, String> {
        let norm = s.to_ascii_lowercase().replace('_', "-");
        match norm.as_str() {
            "sha256" | "hmac-sha256" | "hmac-with-sha256" => Ok(PrfHash::Sha256),
            "sha512" | "hmac-sha512" | "hmac-with-sha512" => Ok(PrfHash::Sha512),
            other => Err(format!("unsupported kdfparams.prf {:?}", other)),
        }
    }

    /// Convert to OpenSSL message digest for PKCS5 PBKDF2
    fn digest(self) -> MessageDigest {
        match self {
            PrfHash::Sha256 => MessageDigest::sha256(),
            PrfHash::Sha512 => MessageDigest::sha512(),
        }
    }

    /// Display name for banner output
    fn name(self) -> &'static str {
        match self {
            PrfHash::Sha256 => "sha256",
            PrfHash::Sha512 => "sha512",
        }
    }
}

/// IV candidate with decoded bytes and human-readable label
struct IvCandidate {
    bytes: [u8; 16],
    label: &'static str,
}

/// Parsed keystore JSON with all crypto parameters extracted
struct Keystore {
    ciphertext: Vec<u8>,
    ivs: Vec<IvCandidate>,
    salt: Vec<u8>,
    c: u32,                    // PBKDF2 iterations
    dklen: usize,              // derived key length (determines AES variant)
    prf: PrfHash,
    mac: Option<Vec<u8>>,      // optional MAC for fast-reject
    target: Option<String>,    // auto-discovered address
    target_path: Option<String>, // JSON path to address field
    cipher_declared: String,   // from keystore (often wrong)
    actual_key_len: usize,     // dklen (actual AES key used)
    top_keys: Vec<String>,     // top-level JSON keys (debug info)
}

/// Runtime configuration from CLI arguments
struct Config {
    keystore_path: String,
    password_file: Option<String>,
    salt_mode: SaltMode,
    target: Option<String>,       // override auto-discovered address
    mac_check: bool,
    iv_override: Option<[u8; 16]>,
    export_private_key: bool,     // write privkey to pot.txt
    debug: bool,                  // print address per password (-w 1 forced)
    dump: bool,                   // print full crypto details (-w 1 forced)
    list_targets: bool,           // list all addresses then exit
    workers: usize,
}

// ============================================================================
//  CLI
// ============================================================================

/// Generate help/usage text
fn usage() -> String {
    format!(
        r#"solflare-recover {VERSION} - Solflare / Solana keystore password recovery

USAGE:
    cat words.txt | solflare-recover [OPTIONS]

OPTIONS:
    -f, --file <PATH>       keystore JSON (default: {DEFAULT_KEYSTORE})
    -p, --password-file <PATH>
                            read passwords from a file instead of stdin
    -e, --export-private-key <BOOL>
                            write recovered private key to pot.txt (default: true)
    -w, --workers <N>       worker threads (default: 1)
        --target <ADDR>     base58 address to match
        --list-targets      print every address-shaped string in keystore, then exit
        --salt-mode <MODE>  raw | hex   (default: raw)
        --iv-hex <HEX>      override the IV, 32 hex chars
        --mac-check         enable MAC fast-reject (OFF by default)
        --dump              print derived key + addresses per password. Forces -w 1.
    -d, --debug             print derived address per password. Forces -w 1.
    -h, --help              show this help
    -V, --version           show version

VERIFICATION:
    Address derived from decrypted plaintext must equal target address.
    Decrypted payload interpreted two ways:
      - bytes  0..32 as ed25519 seed, address derived
      - bytes 32..64 as literal public key

INPUT:
    Passwords from stdin or file, one per line.
"#
    )
}

/// Parse command-line arguments into Config struct
fn parse_args() -> Config {
    let mut cfg = Config {
        password_file: None,
        salt_mode: SaltMode::Raw,
        keystore_path: DEFAULT_KEYSTORE.to_string(),
        target: None,
        mac_check: false,
        iv_override: None,
        export_private_key: true,
        debug: false,
        dump: false,
        list_targets: false,
        workers: 1,
    };

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;

    macro_rules! take_value {
        () => {{
            i += 1;
            match args.get(i) {
                Some(v) => v.clone(),
                None => {
                    eprintln!("error: option {} requires a value", args[i - 1]);
                    process::exit(2);
                }
            }
        }};
    }

    while i < args.len() {
        let arg = args[i].clone();
        match arg.as_str() {
            "-f" | "--file" => cfg.keystore_path = take_value!(),
            "-p" | "--password-file" => cfg.password_file = Some(take_value!()),
            "-w" | "--workers" => {
                let v = take_value!();
                match v.parse::<usize>() {
                    Ok(n) if n >= 1 => cfg.workers = n,
                    _ => {
                        eprintln!("error: --workers needs positive integer");
                        process::exit(2);
                    }
                }
            }
            "--target" => cfg.target = Some(take_value!()),
            "--list-targets" => cfg.list_targets = true,
            "--salt-mode" => {
                let m = take_value!();
                cfg.salt_mode = match m.as_str() {
                    "raw" => SaltMode::Raw,
                    "hex" => SaltMode::Hex,
                    other => {
                        eprintln!("error: unknown salt mode {:?}", other);
                        process::exit(2);
                    }
                };
            }
            "--iv-hex" => {
                let h = take_value!();
                let b = match hex::decode(&h) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("error: bad --iv-hex: {}", e);
                        process::exit(2);
                    }
                };
                if b.len() != 16 {
                    eprintln!("error: --iv-hex must be 32 hex chars (16 bytes), got {}", b.len());
                    process::exit(2);
                }
                let mut a = [0u8; 16];
                a.copy_from_slice(&b);
                cfg.iv_override = Some(a);
            }
            "--mac-check" => cfg.mac_check = true,
            "--dump" => cfg.dump = true,
            "-d" | "--debug" => cfg.debug = true,
            "-h" | "--help" => {
                print!("{}", usage());
                process::exit(0);
            }
            "-e" | "--export-private-key" => {
                let v = take_value!();
                cfg.export_private_key = match v.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => {
                        eprintln!("error: --export-private-key needs true or false, got {:?}", v);
                        process::exit(2);
                    }
                };
            }
            "-V" | "--version" => {
                println!("solflare-recover {}", VERSION);
                process::exit(0);
            }
            _ => {
                eprintln!("error: unknown argument {:?}", arg);
                process::exit(2);
            }
        }
        i += 1;
    }

    if (cfg.dump || cfg.debug) && cfg.workers != 1 {
        eprintln!("note: --dump/--debug force -w 1");
        cfg.workers = 1;
    }

    cfg
}

// ============================================================================
//  Target Discovery
// ============================================================================

/// Normalize JSON key names for case-insensitive comparison
fn normalize_key(k: &str) -> String {
    k.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Check if string is plausible Base58 address (32 decoded bytes)
fn looks_like_address(s: &str) -> bool {
    if s.len() < 32 || s.len() > 44 {
        return false;
    }
    matches!(bs58::decode(s).into_vec(), Ok(v) if v.len() == 32)
}

/// Rank JSON keys by likelihood of being the address field (lower = better)
fn key_rank(norm: &str) -> Option<u8> {
    match norm {
        "publickey" => Some(0),
        "pubkey" => Some(1),
        "address" => Some(2),
        "walletaddress" => Some(3),
        "account" => Some(4),
        "owner" => Some(5),
        _ => None,
    }
}

/// Recursively walk JSON tree collecting address-shaped strings
/// Found targets sorted by key_rank then path length
fn collect_targets(
    v: &Value,
    path: &str,
    out: &mut Vec<(u8, String, String)>,
    all_strings: &mut std::collections::HashMap<String, String>,
) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let child = if path.is_empty() { k.clone() } else { format!("{}.{}", path, k) };
                if let Some(s) = val.as_str() {
                    if looks_like_address(s) {
                        all_strings.insert(child.clone(), s.to_string());
                    }
                    if let Some(rank) = key_rank(&normalize_key(k)) {
                        if looks_like_address(s) {
                            out.push((rank, child.clone(), s.to_string()));
                        }
                    }
                }
                collect_targets(val, &child, out, all_strings);
            }
        }
        Value::Array(arr) => {
            for (idx, val) in arr.iter().enumerate() {
                collect_targets(val, &format!("{}[{}]", path, idx), out, all_strings);
            }
        }
        _ => {}
    }
}

// ============================================================================
//  IV Candidates
// ============================================================================

/// Add unique IV candidate to list
fn push_unique(out: &mut Vec<IvCandidate>, bytes: [u8; 16], label: &'static str) {
    if !out.iter().any(|c| c.bytes == bytes) {
        out.push(IvCandidate { bytes, label });
    }
}

/// Build IV candidates from cipherparams object
/// Supports: explicit iv field OR counter integer (PyCryptodome convention)
fn build_iv_candidates(cp: &Value) -> Result<Vec<IvCandidate>, String> {
    let mut out: Vec<IvCandidate> = Vec::new();

    // Standard Web3: explicit iv field (hex string)
    if let Some(iv_hex) = cp.get("iv").and_then(|x| x.as_str()) {
        let b = hex::decode(iv_hex).map_err(|e| format!("bad iv hex: {}", e))?;
        if b.len() != 16 {
            return Err(format!("iv must be 16 bytes, got {}", b.len()));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        push_unique(&mut out, a, "iv-field");
    }

    // Solflare legacy: counter integer (128-bit BE, right-aligned)
    if let Some(cnt) = cp.get("counter").and_then(|x| x.as_u64()) {
        let mut b = [0u8; 16];
        b[8..].copy_from_slice(&cnt.to_be_bytes());
        push_unique(&mut out, b, "counter-be128-PyCryptodome");
    }

    if out.is_empty() {
        return Err("cipherparams has neither \"iv\" nor \"counter\"".to_string());
    }
    Ok(out)
}

// ============================================================================
//  Helpers
// ============================================================================

/// Strip every CR and LF *anywhere* in the line, not merely at the ends.
/// Survives concatenated CRLF wordlists where stray '\r' sits mid-line.
fn scrub(s: &mut String) {
    // Strip ASCII and Unicode line separators that can corrupt passwords from mixed-format wordlists.
    // Includes CR/LF, VT/FF, C0 control separators (file/group/record/unit), NEL, and Unicode line/para breaks.
    s.retain(|c| !matches!(c, '\r' | '\n' | '\u{0b}' | '\u{0c}' | '\u{1c}'..='\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'));
}

/// Format elapsed seconds as HH:MM:SS
fn fmt_time(secs: f64) -> String {
    let hrs = secs as u64 / 3600;
    let mins = (secs as u64 % 3600) / 60;
    let sec = secs as u64 % 60;
    format!("{:02}:{:02}:{:02}", hrs, mins, sec)
}

/// Encode first 32 bytes of plaintext as Base58 private key
/// These 32 bytes ARE the ed25519 seed (raw, not compressed)
fn derive_private_key_base58(plaintext: &[u8]) -> Option<String> {
    if plaintext.len() < 32 {
        return None;
    }
    Some(bs58::encode(&plaintext[..32]).into_string())
}

// ============================================================================
//  Keystore Parsing
// ============================================================================

/// Parse keystore JSON, extract crypto params, discover target address
/// Falls back to highest-ranked address-shaped string if no explicit target
fn parse_keystore(cfg: &Config) -> Result<Keystore, String> {
    let raw = fs::read_to_string(&cfg.keystore_path)
        .map_err(|e| format!("cannot read {}: {}", cfg.keystore_path, e))?;
    let v: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON: {}", e))?;

    let top_keys: Vec<String> = v
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    // ---- Target discovery ----
    let mut found: Vec<(u8, String, String)> = Vec::new();
    let mut all_strings: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    collect_targets(&v, "", &mut found, &mut all_strings);
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.len().cmp(&b.1.len())));

    if cfg.list_targets {
        eprintln!("address-shaped strings in {}:", cfg.keystore_path);
        if all_strings.is_empty() {
            eprintln!("  (none)");
        } else {
            let mut rows: Vec<_> = all_strings.iter().collect();
            rows.sort_by_key(|(k, _)| k.as_str());
            for (path, val) in rows {
                let marked = if found.iter().any(|(_, p, _)| p == path) { " <-- recognised" } else { "" };
                eprintln!("  {} = {}{}", path, val, marked);
            }
        }
        process::exit(0);
    }

    let (target, target_path) = match found.first() {
        Some((_, path, val)) => (Some(val.clone()), Some(path.clone())),
        None => (None, None),
    };

    // ---- Crypto section ----
    let crypto = v.get("crypto").or_else(|| v.get("Crypto")).ok_or_else(|| {
        format!("no \"crypto\" object (keys: {:?})", top_keys)
    })?;

    let cipher_declared = crypto.get("cipher").and_then(|x| x.as_str()).unwrap_or("aes-256-ctr").to_string();
    let kdfp = crypto.get("kdfparams").ok_or("missing kdfparams")?;

    let c = kdfp.get("c").and_then(|x| x.as_u64()).ok_or("missing c")? as u32;
    let dklen = kdfp.get("dklen").and_then(|x| x.as_u64()).ok_or("missing dklen")? as usize;

    let prf = PrfHash::parse(kdfp.get("prf").and_then(|x| x.as_str()).unwrap_or("hmac-sha512"))?;

    let salt_hex = kdfp.get("salt").and_then(|x| x.as_str()).ok_or("missing salt")?;
    let salt = match cfg.salt_mode {
        SaltMode::Raw => salt_hex.as_bytes().to_vec(),
        SaltMode::Hex => hex::decode(salt_hex).map_err(|e| format!("salt error: {}", e))?,
    };

    let ct_hex = crypto.get("ciphertext").and_then(|x| x.as_str()).ok_or("missing ciphertext")?;
    let ciphertext = hex::decode(ct_hex).map_err(|e| format!("ciphertext error: {}", e))?;

    let ivs = if let Some(o) = cfg.iv_override {
        vec![IvCandidate { bytes: o, label: "cli-override" }]
    } else {
        let cp = crypto.get("cipherparams").ok_or("missing cipherparams")?;
        build_iv_candidates(cp)?
    };

    let mac = crypto
        .get("mac")
        .and_then(|x| x.as_str())
        .map(|m| hex::decode(m))
        .transpose()
        .map_err(|e| format!("mac error: {}", e))?;

    // NOTE: dklen determines AES variant, NOT cipher_declared field
    let actual_key_len = dklen;

    Ok(Keystore {
        ciphertext, ivs, salt, c, dklen, prf, mac, target, target_path, cipher_declared, actual_key_len, top_keys,
    })
}

// ============================================================================
//  Crypto Operations
// ============================================================================

/// Derive encryption key using PBKDF2-HMAC via OpenSSL (same as Python reference)
/// This uses the exact same underlying function that PyCryptodome calls
fn derive_key(pw: &[u8], ks: &Keystore) -> Option<Vec<u8>> {
    let mut key = vec![0u8; ks.dklen];
    pkcs5::pbkdf2_hmac(pw, &ks.salt, ks.c as usize, ks.prf.digest(), &mut key).ok()?;
    Some(key)
}

/// Compute Solana CLI MAC: sha256(key[16..32] || ciphertext)
/// Used for fast-reject when --mac-check is enabled
fn compute_mac(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if key.len() < 32 {
        return None;
    }
    let mut buf = Vec::with_capacity(16 + ciphertext.len());
    buf.extend_from_slice(&key[16..32]);
    buf.extend_from_slice(ciphertext);
    hash(MessageDigest::sha256(), &buf).ok().map(|d| d.to_vec())
}

/// Derive candidate addresses from decrypted plaintext
/// Method 1: bytes 0..32 as ed25519 seed -> derive address
/// Method 2: bytes 32..64 as literal public key (alternative interpretation)
fn candidate_addresses(plaintext: &[u8]) -> Vec<String> {
    let mut out = Vec::with_capacity(2);

    if plaintext.len() >= 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&plaintext[..32]);
        let sk = SigningKey::from_bytes(&seed);
        out.push(bs58::encode(sk.verifying_key().to_bytes()).into_string());
    }

    if plaintext.len() >= 64 {
        out.push(bs58::encode(&plaintext[32..64]).into_string());
    }
    out
}

/// Attempt to decrypt with given password, verify against target address
/// Returns (IV_label, private_key_base58) on match, None otherwise
fn try_password(
    pw: &str,
    ks: &Keystore,
    cfg: &Config,
    target: &str,
) -> Option<(&'static str, String)> {
    let key = derive_key(pw.as_bytes(), ks)?;

    // Optional MAC fast-reject before expensive decryption
    if cfg.mac_check {
        if let Some(expected) = &ks.mac {
            if expected.len() == 32 {
                if let Some(got) = compute_mac(&key, &ks.ciphertext) {
                    if got != *expected {
                        return None;
                    }
                }
            }
        }
    }

    // Try each IV candidate until decryption succeeds
    for iv in &ks.ivs {
        let mut buf = ks.ciphertext.clone();

        // Select AES variant based on KEY LENGTH (not cipher declaration)
        if key.len() >= 32 {
            let mut c = Aes256Ctr::new(
                GenericArray::from_slice(&key[..32]),
                GenericArray::from_slice(&iv.bytes),
            );
            c.apply_keystream(&mut buf);
        } else {
            let mut c = Aes128Ctr::new(
                GenericArray::from_slice(&key[..16]),
                GenericArray::from_slice(&iv.bytes),
            );
            c.apply_keystream(&mut buf);
        }

        let cands = candidate_addresses(&buf);

        if cfg.debug {
            eprintln!("pw={:<26} iv={:<35} -> {}", format!("{:?}", pw), iv.label, cands.join(" | "));
        }

        if cfg.dump {
            eprintln!("pw        : {:?}", pw);
            eprintln!("key       : {}", hex::encode(&key));
            eprintln!("iv [{}] : {}", iv.label, hex::encode(iv.bytes));
            eprintln!("plaintext : {}", hex::encode(&buf));
            for a in &cands {
                eprintln!("  derived : {}", a);
            }
            eprintln!("  target  : {}\n", target);
        }

        if cands.iter().any(|a| a == target) {
            let priv_key = derive_private_key_base58(&buf)?;
            return Some((iv.label, priv_key));
        }
    }
    None
}

// ============================================================================
//  Worker Threads
// ============================================================================

/// Worker thread: receive password batches, attempt decryption, send matches
fn worker(
    rx: Receiver<Vec<String>>,
    ks: Arc<Keystore>,
    target: Arc<String>,
    cfg: Arc<Config>,
    stop: Arc<AtomicBool>,
    processed: Arc<AtomicU64>,
    found_tx: Sender<(String, &'static str, String)>,
) {
    while let Ok(batch) = rx.recv() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        for pw in batch {
            processed.fetch_add(1, Ordering::Relaxed);

            if let Some((label, priv_key)) = try_password(&pw, &ks, &cfg, &target) {
                let _ = found_tx.send((pw, label, priv_key));
                stop.store(true, Ordering::Relaxed);
                return;
            }

            if stop.load(Ordering::Relaxed) {
                return;
            }
        }
    }
}

/// Append successful crack to pot.txt (password file format)
/// Format: file_name:password:private_key (one entry per line)
/// Duplicate entries are skipped
fn write_pot(file_name: &str, pw: &str, priv_key: &str, export: bool) -> io::Result<String> {
    let path = POT_FILE.to_string();
    let export = export && !priv_key.is_empty();
    let entry = format!("{}:{}:{}", file_name, pw, if export { priv_key } else { "PRIVATE_KEY_HIDDEN" });

    // Check for duplicate entry
    if fs::metadata(&path).is_ok() {
        if let Ok(content) = fs::read_to_string(&path) {
            if content.lines().any(|l| l == entry) {
                return Ok(path);
            }
        }
    }

    // Append with header on first write
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&path)?;
    if fs::metadata(&path)?.len() == 0 {
        writeln!(f, "file_name:password:private_key")?;
    }
    writeln!(f, "{}", entry)?;
    f.flush()?;
    Ok(path)
}

/// Format password rate as "{X.X} pw/s"
fn fmt_rate(n: u64, secs: f64) -> String {
    format!("{:.1} pw/s", n as f64 / secs.max(1e-9))
}

// ============================================================================
//  Main Entry Point
// ============================================================================

fn main() {
    let cfg = Arc::new(parse_args());

    let ks = Arc::new(match parse_keystore(&cfg) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    });

    let target = Arc::new(match cfg.target.clone().or_else(|| ks.target.clone()) {
        Some(t) => t,
        None => {
            eprintln!("error: no address to verify against in {}", cfg.keystore_path);
            eprintln!("       run --list-targets or pass --target <base58>");
            process::exit(1);
        }
    });

    // Determine password source (fail fast before banner)
    let reader: Box<dyn BufRead> = match cfg.password_file.as_deref() {
        Some(path) => match File::open(path) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => {
                eprintln!("error: cannot open password file {}: {}", path, e);
                process::exit(1);
            }
        },
        None => Box::new(BufReader::new(io::stdin().lock())),
    };

    // Print runtime banner
    let iv_labels: Vec<&str> = ks.ivs.iter().map(|i| i.label).collect();
    eprintln!("keystore       : {}", cfg.keystore_path);
    eprintln!("keys           : {:?}", ks.top_keys);
    eprintln!("kdf            : pbkdf2-{}  c={}  dklen={}  salt={} bytes ({:?})",
              ks.prf.name(), ks.c, ks.dklen, ks.salt.len(), cfg.salt_mode);
    eprintln!("cipher (claim) : {} (declared in keystore, may be WRONG)", ks.cipher_declared);
    eprintln!("key len (use)  : {} bytes (from dklen, used for AES variant)", ks.actual_key_len);
    eprintln!("iv             : {} candidate(s) [{}]", ks.ivs.len(), iv_labels.join(", "));
    eprintln!("mac            : {}", if ks.mac.is_some() && cfg.mac_check {
        "present, checked"
    } else if ks.mac.is_some() {
        "present but NOT checked (use --mac-check)"
    } else {
        "absent"
    });
    eprintln!("target         : {}  (from {})", target, ks.target_path.as_deref().unwrap_or("--target"));
    eprintln!("workers        : {}", cfg.workers);
    eprintln!("export privkey : {}", cfg.export_private_key);
    eprintln!("input          : {}", match cfg.password_file.as_deref() {
        Some(p) => format!("file {}", p),
        None => "stdin".to_string(),
    });
    eprintln!();

    // Spawn worker threads
    let n = cfg.workers;
    let mut senders: Vec<mpsc::SyncSender<Vec<String>>> = Vec::with_capacity(n);
    let mut handles = Vec::with_capacity(n);

    let (found_tx, found_rx) = mpsc::channel::<(String, &'static str, String)>();
    let stop = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicU64::new(0));

    for _ in 0..n {
        let (tx, rx) = sync_channel::<Vec<String>>(QUEUE_DEPTH);
        senders.push(tx);

        let ks = Arc::clone(&ks);
        let target = Arc::clone(&target);
        let cfg = Arc::clone(&cfg);
        let stop = Arc::clone(&stop);
        let processed = Arc::clone(&processed);
        let ftx = found_tx.clone();

        handles.push(thread::spawn(move || {
            worker(rx, ks, target, cfg, stop, processed, ftx);
        }));
    }
    drop(found_tx);

    // Feed passwords from input source
    let started = Instant::now();
    let mut batch: Vec<String> = Vec::with_capacity(BATCH);
    let mut rr = 0usize;
    let mut last_report = Instant::now();
    let mut report_every = Duration::from_secs(10);
    let mut matched: Option<(String, &'static str, String)> = None;
    let mut read_failed = false;
    let sample = String::new();

    for line in reader.lines() {
        let mut pw = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("input error: {}", e);
                read_failed = true;
                break;
            }
        };

        scrub(&mut pw);              // <-- kills \r and \n wherever they hide

        if pw.is_empty() {
            continue;                // blank / CR-only lines are skipped, as before
        }

        if batch.len() == BATCH {
            let b = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
            if senders[rr].send(b).is_err() {
                break;
            }
            rr = (rr + 1) % n;

            if let Ok(hit) = found_rx.try_recv() {
                matched = Some(hit);
                break;
            }
        }

        // Progress reporting: 10s first interval, then 60s
        if last_report.elapsed() >= report_every {
            let done = processed.load(Ordering::Relaxed);
            let elapsed = started.elapsed().as_secs_f64();
            eprintln!("[progress] {:>10} tried  {}  ({})  sample: {:?}",
                     done, fmt_rate(done, elapsed), fmt_time(elapsed), sample);
            last_report = Instant::now();
            report_every = Duration::from_secs(60);
        }
    }

    // Flush remaining batch
    if !batch.is_empty() && !stop.load(Ordering::Relaxed) {
        let _ = senders[rr].send(batch);
    }
    drop(senders);
    for h in handles {
        let _ = h.join();
    }

    // Drain any late-arriving matches
    if matched.is_none() {
        while let Ok(hit) = found_rx.try_recv() {
            matched = Some(hit);
        }
    }

    // Final verdict, update statistics on cracking progress and speed
    let elapsed = started.elapsed().as_secs_f64();
    let tried = processed.load(Ordering::Relaxed);

    match matched {
        Some((pw, label, priv_key)) => {
            eprintln!("\n*** MATCH ***");
            eprintln!("password   : {}", pw);
            eprintln!("address    : {}", target);
            eprintln!("iv variant : {}", label);
            // PRIVATE KEY DELIBERATELY NOT PRINTED TO CONSOLE SINCE THIS WOULD BE A SECURITY RISK
            eprintln!("searched   : {} candidates in {:.2}s ({})", tried, elapsed, fmt_rate(tried, elapsed));
            match write_pot(&cfg.keystore_path, &pw, &priv_key, cfg.export_private_key) {
                Ok(p) => eprintln!("written    : {}", p),
                Err(e) => eprintln!("warning    : could not write pot file: {}", e),
            }
            process::exit(0);
        }
        None => {
            if read_failed {
                eprintln!("\naborted after {} candidates - input error", tried);
                process::exit(2);
            }
            eprintln!("\nexhausted: {} candidates in {:.2}s ({}) - no match", tried, elapsed, fmt_rate(tried, elapsed));
            process::exit(1);
        }
    }
}
