# solflare-recover

***Solflare-recover*** is a high performance (2500 password per second) password recovery tool for Solana legacy Solflare keystore wallet files. The tool is build using the Rust programming language for optimal multi-threaded fast password recovery.  
The tool **a)** reads candidate passwords from either a file or STDIN, **b)** derives the key, **c)** decrypts the keystore, and checks the resulting address against the one recorded in the file. When the correct password is found it is printed to the console. In addition the password and exported private-key are written to the `pot.txt` file for easy importing in other Solana wallets. This tool is offered to you free of charge by Niels from [Wallet Recovery NL](https://walletrecovery.nl/).  
In case you need help, feel free to reach out. I normally charge 10-15% of the wallets value, only upon successfull recovery of your funds.


## Requirements
- If you just want to run the tool, download the Linux binary or Windows executable.
If you want to compile the tool for optimal performance on your specific CPU you would need:
- Rust (stable, 2021 edition) and openSSL development headers.
In case you just want to run this tool, there are no additional requirement, just downlaod the executable or binary.

## Build

```bash
cargo clean
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

`target-cpu=native` matters. Without it you can expect somewhat slower password cracking speed


## Example use  
Note that in the example commands below you should use `./solflare-recover` when on Linux/Mac, while using `solflare-recover.exe` when on Windows.

```bash
# Single password `Solana123` to test against the test wallet 
echo 'Solana123' | solflare-recover.exe -f solflare-keystore-5f8p1fPaY8pEt6XhW7CxYdensmDCZUPZ2HygUzb8gtDC_Solana123.json

# Try passwords from a file, use 8 threads
solflare-recover.exe -f keystore.json -p passwords.txt -w 8 

# Load passwords from STDIN from a file or a tool like hashcat
cat rockyou.txt | ./solflare-recover -f keystore.json -w 8

# Recover password but do not export (-e) the privatekey
solflare-recover.exe -f keystore.json -p passwords.txt -w 8 
 -e False
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file <PATH>` | Keystore JSON | `solflare-keystore.json` |
| `-p, --file <PATH>` | Password text file | Optional, you can use STDIN |
| `-w, --workers <N>` | Worker threads | `1` |
| `-e, --export <N>` | Export priv-key, default True | True/False |
| `--target <ADDR>` | Base58 address to match, overriding the keystore | discovered |
| `--list-targets` | Print every address-shaped string in the keystore, then exit | |
| `--salt-mode <MODE>` | `raw` (Solflare) or `hex` (Web3 convention) | `raw` |
| `--iv-hex <HEX>` | Override the IV, 32 hex chars | derived |
| `--mac-check` | Enable the MAC fast-reject | off |
| `--dump` | Print derived key, plaintext and addresses per password | off |
| `-d, --debug` | Print the derived address per password | off |
| `-V, --version` | Show version | |
| `-h, --help` | Show help | |

`--dump` and `--debug` force `-w 1` so the output stays readable.

## Why this tool exists?

Solflare keystores deviate from the Web3 Secret Storage convention and therefore needs a dedicated password recovery tool:

1. **The `cipher` field is wrong.** Keystores declare `"aes-128-ctr"` while the PBKDF2 output is 32 bytes. PyCryptodome (and Solflare itself) select the AES variant from the *key length*, so the effective cipher is AES-256-CTR. Honour the declared field and you decrypt to garbage.
2. **The salt is not hex-decoded.** `salt` is a hex string, but it is fed to PBKDF2 as the raw ASCII bytes of that string, not as decoded bytes. A 64-byte salt, not 32.
3. **There is no IV.** `cipherparams` carries a `counter` integer instead. It maps to the 128-bit AES-CTR initial block as a big-endian integer, right-aligned.

This tool handles all three of these solflare specific deviation and was verifies against a inhouse reference Python implementation and using a teste wallet created on https://legacy.solflare.com.

## Performance

Measured on the author's machine, `c=8192`, SHA-512, release build with
`target-cpu=native`:

| Threads | Throughput |
|---------|-----------|
| 1 | ~350 pw/s |
| 8 | ~2,500 pw/s |

Scaling is close to linear. 


## Legal
Use only on keystores you own or are authorised to recover. 

## License
Apache License 2.0.

## Buy me a beer

If this saved you a wallet, donations are appreciated.

| Chain | Address |
|-------|---------|
| Solana | `9DaPuWKExgtAamgo9gmXbyQXX2fvktPShHRWrYYvZVhQ` |
| Bitcoin | `bc1qma6ag4vye3qp3h97jddnautqfj6y8xf7ggh9pd` |
| Ethereum | `0x7C1e20d4c3bd294715Bad72cA82a6d1D28043CE0` |


