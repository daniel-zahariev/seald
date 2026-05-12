# Seald File Format (`SLD\x01`)

This document specifies the current binary format used by `seald`.

This format is intentionally not backward compatible with older `SLD` variants.

## Overview

- Magic: `SLD\x01`
- KDF: Argon2id
- Cipher: ChaCha20-Poly1305
- Encryption mode: chunked AEAD
- Header metadata is authenticated by including it in AEAD AAD for every chunk.
- A mandatory final authentication marker is always written, even for empty plaintext.

## Binary Layout

All integer fields are little-endian.

### Header

| Field | Size | Notes |
|---|---:|---|
| `magic` | 4 | ASCII `SLD\x01` |
| `header_version` | 1 | Currently `1` |
| `kdf_id` | 1 | `1` = Argon2id |
| `cipher_id` | 1 | `1` = ChaCha20-Poly1305 |
| `kdf_mem_cost_kib` | 4 | Argon2 memory cost in KiB |
| `kdf_time_cost` | 4 | Argon2 iterations |
| `kdf_parallelism` | 4 | Argon2 parallelism (lanes) |
| `chunk_plain_len` | 4 | Must match implementation constant (`262144`) |
| `salt` | 16 | Random per file |

Header size: `39` bytes.

### Chunks

After the header, the stream contains one or more records:

| Field | Size | Notes |
|---|---:|---|
| `chunk_index` | 8 | Starts at `0`, increments by `1` |
| `nonce` | 12 | Random per chunk |
| `plain_len` | 4 | Plaintext size for this chunk |
| `ciphertext_and_tag` | `plain_len + 16` | ChaCha20-Poly1305 output |

AAD for each chunk is:

`header_aad_prefix || chunk_index_le_u64`

Where `header_aad_prefix` is:

`header_version || kdf_id || cipher_id || kdf_mem_cost_kib || kdf_time_cost || kdf_parallelism || chunk_plain_len || salt`

## Mandatory Final Authentication Marker

Encryption always writes a final marker chunk:

- `plain_len = 0`
- plaintext payload is empty
- AEAD still produces a 16-byte tag
- `chunk_index` is the next sequential index after the last data chunk

Decryption requirements:

- Missing final marker is an error.
- Any extra data after the final marker is an error.

This ensures authenticated metadata even when plaintext is empty.

## Validation Rules

Current policy checks:

- `kdf_mem_cost_kib` in `[8192, 262144]`
- `kdf_time_cost` in `[1, 10]`
- `kdf_parallelism` in `[1, 8]`
- `chunk_plain_len` must be exactly `262144`
- KDF parameter tuple must be valid for Argon2 implementation
- `chunk_index` must be strictly sequential

## Interop Notes

- Decrypt derives KDF settings from header fields, not from CLI presets.
- `--level` is only a shorthand for selecting default KDF knobs at encryption time.
- Explicit KDF knobs override preset defaults and are persisted in the header.
