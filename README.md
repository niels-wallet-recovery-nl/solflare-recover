

```markdown
# solflare-recover

***Solflare-recover*** is a high-performance password recovery tool for legacy Solflare Solana keystore files. Built in Rust with multi-threading for optimal cracking speed (~2,500 passwords per second on 8 threads).

The tool **a)** reads candidate passwords from a file or STDIN, **b)** derives the key, **c)** decrypts the keystore, and **d)** verifies the resulting address against the one recorded in the file. When found, the password is printed to the console and both password and private key are written to `pot.txt` for import into other Solana wallets.

This tool is offered free of charge by Niels from [Wallet Recovery NL](https://walletrecovery.nl/). For professional assistance, I normally charge 10–15% of the wallet's value, only upon successful recovery.
<img width="1905" height="394" alt="solflare-recover-solana" src="https://github.com/user-attachments/assets/7ea620bb-d859-4528-ab64-784d3a11124d" />

## Requirements

- **Binary users:** No additional dependencies — download the Linux binary or Windows executable.
- **Source builders:** Rust (stable, 2021 edition) and OpenSSL development headers.

## Build

```bash
cargo clean
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

`target-cpu=native` matters. Without it, expect slower cracking speed.

## Examples

Use `./solflare-recover` on Linux/macOS or `solflare-recover.exe` on Windows.

```bash
# Single password test
echo 'Solana123' | solflare-recover.exe -f solflare-keystore-5f8p1fPaY8pEt6XhW7CxYdensmDCZUPZ2HygUzb8gtDC_Solana123.json

# Multiple passwords with 8 threads
solflare-recover.exe -f keystore.json -p passwords.txt -w 8 

# Load from STDIN (e.g., hashcat output)
cat rockyou.txt | ./solflare-recover -f keystore.json -w 8

# Disable private key export
solflare-recover.exe -f keystore.json -p passwords.txt -w 8 -e false
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file <PATH>` | Keystore JSON | `solflare-keystore.json` |
| `-p, --password-file <PATH>` | Password list file | Optional (STDIN) |
| `-w, --workers <N>` | Worker threads | `1` |
| `-e, --export-private-key <BOOL>` | Write private key to pot.txt | `true` |
| `--target <ADDR>` | Override detected address | Auto-discovered |
| `--list-targets` | List all address-shaped strings | — |
| `--salt-mode <MODE>` | `raw` (Solflare) or `hex` (Web3) | `raw` |
| `--iv-hex <HEX>` | Manual IV override (32 hex chars) | Derived |
| `--mac-check` | Enable MAC validation | Off |
| `--dump` | Print key/plaintext per password | Off |
| `-d, --debug` | Print derived address per password | Off |
| `-V, --version` | Show version | — |
| `-h, --help` | Show help | — |

`--dump` and `--debug` force `-w 1` for readable output.

## Why This Tool Exists

Solflare keystores deviate from the Web3 Secret Storage convention:

1. **Wrong `cipher` field.** Keystores declare `"aes-128-ctr"` but PBKDF2 outputs 32 bytes. PyCryptodome selects AES variant from *key length*, making this effectively AES-256-CTR. Honoring the declaration produces garbage.

2. **Raw salt encoding.** The `salt` is a hex string but fed to PBKDF2 as raw ASCII bytes, not decoded. Result: 64 bytes, not 32.

3. **No explicit IV.** `cipherparams` contains a `counter` integer mapped to the 128-bit AES-CTR initial block as big-endian, right-aligned.

This tool handles all three Solflare-specific deviations. It was verified against a reference Python implementation and tested with wallets created on legacy.solflare.com.

## Performance

Tested with `c=8192`, SHA-512, release build with `target-cpu=native`:

| Threads | Throughput |
|---------|------------|
| 1 | ~350 pw/s |
| 8 | ~2,500 pw/s |

Scaling is close to linear.

## Legal

Use only on keystores you own or are authorized to recover.

## License

Apache License 2.0.

## Buy Me a Beer

If this helped you recover a wallet, donations are appreciated.

| Chain | Address |
|-------|---------|
| Solana | `9DaPuWKExgtAamgo9gmXbyQXX2fvktPShHRWrYYvZVhQ` |
| Bitcoin | `bc1qma6ag4vye3qp3h97jddnautqfj6y8xf7ggh9pd` |
| Ethereum | `0x7C1e20d4c3bd294715Bad72cA82a6d1D28043CE0` |
```
