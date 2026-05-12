# seald

`seald` is a small CLI for encrypting and decrypting files with a passphrase.

It is useful for developers, SRE/DevOps engineers, and operations teams that need a scriptable way to protect files at rest or in transit.

## Who this is useful for

- Developers handling local sensitive artifacts (`.env` backups, exports, dumps).
- DevOps/SRE teams encrypting files in automation and CI/CD.
- Security-minded teams standardizing file protection workflows.
- Support/ops teams sharing sensitive logs or diagnostic bundles.

## What it does

- `encrypt`: reads input bytes and writes a locked `.sld` payload.
- `decrypt`: reads a `.sld` payload and writes plaintext output.
- Supports file paths and stdio streams (`-` for stdin/stdout).
- Uses Argon2-based key derivation with selectable presets and explicit KDF knobs.

See [`FORMAT.md`](./FORMAT.md) for the `.sld` file format details.

## Install

### Cargo

```bash
cargo install seald
```

### Homebrew

```bash
brew tap daniel-zahariev/tap
brew install daniel-zahariev/tap/seald
```

Or in a single command:

```bash
brew install daniel-zahariev/tap/seald
```

Upgrade later with:

```bash
brew upgrade daniel-zahariev/tap/seald
```

### APT (Debian/Ubuntu)

```bash
curl -fsSL https://daniel-zahariev.github.io/seald/apt/seald-archive-keyring.gpg \
  -o /tmp/seald-archive-keyring.gpg
sudo install -o root -g root -m 0644 /tmp/seald-archive-keyring.gpg /usr/share/keyrings/seald-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/seald-archive-keyring.gpg] https://daniel-zahariev.github.io/seald/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/seald.list >/dev/null
sudo apt update
sudo apt install seald
```

## Build

```bash
cargo build --release
```

Binary path:

```bash
./target/release/seald
```

Or run directly with Cargo:

```bash
cargo run -- <command> [args...]
```

## Common usage

Encrypt a file:

```bash
seald encrypt notes.txt -o notes.sld
```

Decrypt a file:

```bash
seald decrypt notes.sld -o notes.txt
```

Use environment variable for non-interactive usage:

```bash
SEALD_PASSWORD='your-passphrase' seald encrypt data.bin -o data.bin.sld --level strong
SEALD_PASSWORD='your-passphrase' seald decrypt data.bin.sld -o data.bin
```

Stream mode:

```bash
seald encrypt -o - - < input.bin > output.sld
seald decrypt -o - input.sld > output.bin
```

Show full help:

```bash
seald --help
seald encrypt --help
seald decrypt --help
```

## Passphrase behavior

Passphrase lookup order:

1. `--password/-p`
2. `SEALD_PASSWORD`
3. Hidden interactive prompt

Short passphrases are rejected by default unless `--allow-weak-passphrase` is set.

For scripts, prefer `SEALD_PASSWORD` over `-p` to avoid exposing secrets in process listings.

## KDF tuning

Use a preset:

- `fast`
- `standard` (default)
- `strong`
- `paranoid`

Or provide explicit knobs:

- `--kdf-memory-kib`
- `--kdf-time-cost`
- `--kdf-parallelism`

When explicit KDF values are provided, they override preset defaults.
