//! `seald` — CLI for locking and unlocking `.sld` files.
//!
//! Passphrase: `--password`, else `SEALD_PASSWORD`, else a hidden prompt.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use seald::{
    decrypt_file_with_policy, encrypt_file_with_kdf_params, kdf_costs_for_level, Argon2Level,
};
use zeroize::Zeroizing;

const EXAMPLES_ENCRYPT: &str = r#"Examples:
  seald encrypt notes.txt -o ./notes.sld
      Write to an explicit path.

  seald encrypt - < notes.txt > notes.sld
      Read stdin; write locked data to stdout (`-` means stdio).

  SEALD_PASSWORD='...' seald encrypt data.bin --level strong
      Non-interactive: passphrase from the environment (avoid `-p` in scripts where it may show in process listings).

  # PowerShell
  $env:SEALD_PASSWORD='...'; seald encrypt data.bin --level strong

  # cmd.exe
  set "SEALD_PASSWORD=..." && seald encrypt data.bin --level strong

  seald encrypt data.bin --level standard --kdf-memory-kib 65536 --kdf-time-cost 4 --kdf-parallelism 2
      Use explicit KDF knobs (level acts as shorthand/default for omitted knobs).
"#;

const EXAMPLES_DECRYPT: &str = r#"Examples:
  seald decrypt notes.txt.sld -o notes.txt
      Write to an explicit output file.

  seald decrypt notes.txt.sld -o -
      Write unlocked bytes to stdout (warning: output may be partial if verification fails late).

  # PowerShell
  seald decrypt notes.txt.sld -o notes.txt

  # KDF preset is stored in the file header; no --level needed.
"#;

/// Maps to internal key-stretching cost (not shown in `--help`).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, ValueEnum)]
enum CliArgon2Level {
    /// Light
    Fast,
    /// Default
    #[default]
    Standard,
    /// Heavy
    Strong,
    /// Heaviest
    Paranoid,
}

#[derive(Parser)]
#[command(name = "seald", version, about = "Encrypt or decrypt files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a locked `.sld` file (or locked stream to stdout).
    ///
    /// `--output/-o` is required. Use `-o -` for stdout.
    ///
    /// Passphrase: prefer `SEALD_PASSWORD` in scripts over `-p`; otherwise you are prompted on a TTY (hidden).
    /// Passphrases shorter than 12 bytes are rejected unless `--allow-weak-passphrase` is set.
    ///
    /// `--level` is not stored in the output; use the same `--level` when unlocking.
    #[command(after_long_help = EXAMPLES_ENCRYPT)]
    Encrypt {
        /// File to read, or `-` for stdin
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Locked output path, or `-` for stdout
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
        /// Passphrase (`SEALD_PASSWORD` or TTY prompt if unset)
        #[arg(short, long, value_name = "STRING")]
        password: Option<String>,
        /// Allow passphrases shorter than 12 bytes (not recommended)
        #[arg(long)]
        allow_weak_passphrase: bool,
        /// Cost preset (not stored in the file; must match when decrypting)
        #[arg(
            long = "level",
            value_enum,
            default_value_t = CliArgon2Level::Standard,
            value_name = "PRESET",
            hide_possible_values = true
        )]
        level: CliArgon2Level,
        /// Argon2 memory cost in KiB (overrides the preset value)
        #[arg(long = "kdf-memory-kib", value_name = "KIB")]
        kdf_memory_kib: Option<u32>,
        /// Argon2 time cost / iterations (overrides the preset value)
        #[arg(long = "kdf-time-cost", value_name = "N")]
        kdf_time_cost: Option<u32>,
        /// Argon2 parallelism / lanes (overrides the preset value)
        #[arg(long = "kdf-parallelism", value_name = "N")]
        kdf_parallelism: Option<u32>,
    },
    /// Read a `.sld` file and write unlocked output.
    ///
    /// Passphrase: prefer `SEALD_PASSWORD` in scripts over `-p`; otherwise you are prompted on a TTY (hidden).
    /// Passphrases shorter than 12 bytes are rejected unless `--allow-weak-passphrase` is set.
    ///
    /// KDF settings are read from the file header.
    #[command(after_long_help = EXAMPLES_DECRYPT)]
    Decrypt {
        /// Locked file, or `-` for stdin
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output path, or `-` for stdout
        #[arg(short, long, value_name = "OUTPUT")]
        output: PathBuf,
        /// Passphrase (`SEALD_PASSWORD` or TTY prompt if unset)
        #[arg(short, long, value_name = "STRING")]
        password: Option<String>,
        /// Allow passphrases shorter than 12 bytes (not recommended)
        #[arg(long)]
        allow_weak_passphrase: bool,
    },
}

fn passphrase(cli_password: Option<String>) -> Result<Zeroizing<Vec<u8>>, String> {
    if let Some(p) = cli_password {
        return Ok(Zeroizing::new(p.into_bytes()));
    }
    if let Ok(p) = std::env::var("SEALD_PASSWORD") {
        return Ok(Zeroizing::new(p.into_bytes()));
    }
    // No `-p` / `--password` and no env: read from the controlling terminal so the
    // passphrase is not echoed and does not appear in `ps` (unlike argv). Uses
    // `/dev/tty` when stdin is piped but a TTY exists (e.g. `cat f | seald encrypt -`).
    let p = rpassword::prompt_password("Passphrase: ").map_err(|e| {
        format!(
            "passphrase required: could not read from terminal ({e}); use --password / -p or set SEALD_PASSWORD"
        )
    })?;
    if p.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    Ok(Zeroizing::new(p.into_bytes()))
}
fn map_level(level: CliArgon2Level) -> Argon2Level {
    match level {
        CliArgon2Level::Fast => Argon2Level::Fast,
        CliArgon2Level::Standard => Argon2Level::Standard,
        CliArgon2Level::Strong => Argon2Level::Strong,
        CliArgon2Level::Paranoid => Argon2Level::Paranoid,
    }
}

fn resolve_kdf_params(
    level: CliArgon2Level,
    kdf_memory_kib: Option<u32>,
    kdf_time_cost: Option<u32>,
    kdf_parallelism: Option<u32>,
) -> (u32, u32, u32) {
    let (preset_mem, preset_time, preset_parallelism) = kdf_costs_for_level(map_level(level));
    (
        kdf_memory_kib.unwrap_or(preset_mem),
        kdf_time_cost.unwrap_or(preset_time),
        kdf_parallelism.unwrap_or(preset_parallelism),
    )
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Encrypt {
            input,
            output,
            password,
            allow_weak_passphrase,
            level,
            kdf_memory_kib,
            kdf_time_cost,
            kdf_parallelism,
        } => {
            let pass = passphrase(password);
            match pass {
                Ok(pass) => {
                    let (mem, time, parallelism) =
                        resolve_kdf_params(level, kdf_memory_kib, kdf_time_cost, kdf_parallelism);
                    encrypt_file_with_kdf_params(
                    input,
                    Some(output),
                    pass.as_ref(),
                    mem,
                    time,
                    parallelism,
                    allow_weak_passphrase,
                )
                }
                Err(e) => Err(e),
            }
        }
        Command::Decrypt {
            input,
            output,
            password,
            allow_weak_passphrase,
        } => {
            if output.as_os_str() == "-" {
                eprintln!(
                    "warning: stdout mode may emit partial plaintext if verification fails late."
                );
            }
            let pass = passphrase(password);
            match pass {
                Ok(pass) => decrypt_file_with_policy(
                    input,
                    Some(output),
                    pass.as_ref(),
                    allow_weak_passphrase,
                ),
                Err(e) => Err(e),
            }
        }
    };
    if let Err(e) = res {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
