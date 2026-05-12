use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

use argon2::{Argon2, Params};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"SLD\x01";
const HEADER_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_CHACHA20POLY1305: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MIN_PASSPHRASE_LEN: usize = 12;
const MIN_KDF_MEMORY_KIB: u32 = 8_192;
const MAX_KDF_MEMORY_KIB: u32 = 262_144;
const MIN_KDF_TIME_COST: u32 = 1;
const MAX_KDF_TIME_COST: u32 = 10;
const MIN_KDF_PARALLELISM: u32 = 1;
const MAX_KDF_PARALLELISM: u32 = 8;
/// Plaintext bytes per AEAD chunk (ciphertext chunk adds `TAG_LEN` on disk).
const CHUNK_PLAIN: usize = 256 * 1024;

#[derive(Clone)]
struct FileHeader {
    kdf_mem_cost: u32,
    kdf_time_cost: u32,
    kdf_parallelism: u32,
    chunk_plain: u32,
    salt: [u8; SALT_LEN],
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Argon2Level {
    Fast,
    #[default]
    Standard,
    Strong,
    Paranoid,
}

fn is_dash(p: &Path) -> bool {
    p.as_os_str() == "-"
}

pub fn kdf_costs_for_level(level: Argon2Level) -> (u32, u32, u32) {
    match level {
        Argon2Level::Fast => (32_768, 2, 1),
        Argon2Level::Standard => (65_536, 3, 1),
        Argon2Level::Strong => (131_072, 4, 1),
        Argon2Level::Paranoid => (262_144, 5, 1),
    }
}

fn argon2_params(mem_cost: u32, time_cost: u32, parallelism: u32) -> Result<Params, argon2::Error> {
    Params::new(mem_cost, time_cost, parallelism, Some(KEY_LEN))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    mem_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, argon2::Error> {
    let params = argon2_params(mem_cost, time_cost, parallelism)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut raw = Zeroizing::new([0u8; KEY_LEN]);
    argon2.hash_password_into(passphrase, salt, raw.as_mut())?;
    Ok(raw)
}

fn validate_passphrase(passphrase: &[u8], allow_weak_passphrase: bool) -> Result<(), String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".to_string());
    }
    if !allow_weak_passphrase && passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(format!(
            "passphrase too weak: need at least {MIN_PASSPHRASE_LEN} bytes"
        ));
    }
    Ok(())
}

fn validate_kdf_params(mem_cost: u32, time_cost: u32, parallelism: u32) -> Result<(), String> {
    if !(MIN_KDF_MEMORY_KIB..=MAX_KDF_MEMORY_KIB).contains(&mem_cost) {
        return Err(format!(
            "invalid Argon2 memory cost: must be between {MIN_KDF_MEMORY_KIB} and {MAX_KDF_MEMORY_KIB} KiB"
        ));
    }
    if !(MIN_KDF_TIME_COST..=MAX_KDF_TIME_COST).contains(&time_cost) {
        return Err(format!(
            "invalid Argon2 time cost: must be between {MIN_KDF_TIME_COST} and {MAX_KDF_TIME_COST}"
        ));
    }
    if !(MIN_KDF_PARALLELISM..=MAX_KDF_PARALLELISM).contains(&parallelism) {
        return Err(format!(
            "invalid Argon2 parallelism: must be between {MIN_KDF_PARALLELISM} and {MAX_KDF_PARALLELISM}"
        ));
    }
    argon2_params(mem_cost, time_cost, parallelism)
        .map_err(|_| "invalid Argon2 parameters".to_string())?;
    Ok(())
}

impl FileHeader {
    fn from_kdf_params(
        kdf_mem_cost: u32,
        kdf_time_cost: u32,
        kdf_parallelism: u32,
        salt: [u8; SALT_LEN],
    ) -> Result<Self, String> {
        validate_kdf_params(kdf_mem_cost, kdf_time_cost, kdf_parallelism)?;
        Ok(Self {
            kdf_mem_cost,
            kdf_time_cost,
            kdf_parallelism,
            chunk_plain: CHUNK_PLAIN as u32,
            salt,
        })
    }

    fn aad_prefix_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 1 + 4 + 4 + 4 + 4 + SALT_LEN);
        out.push(HEADER_VERSION);
        out.push(KDF_ARGON2ID);
        out.push(CIPHER_CHACHA20POLY1305);
        out.extend_from_slice(&self.kdf_mem_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf_time_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf_parallelism.to_le_bytes());
        out.extend_from_slice(&self.chunk_plain.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out
    }
}

fn write_header<W: Write + ?Sized>(writer: &mut W, header: &FileHeader) -> Result<(), String> {
    writer
        .write_all(MAGIC)
        .map_err(|e| format!("write header magic: {e}"))?;
    writer
        .write_all(&[HEADER_VERSION, KDF_ARGON2ID, CIPHER_CHACHA20POLY1305])
        .map_err(|e| format!("write header ids: {e}"))?;
    writer
        .write_all(&header.kdf_mem_cost.to_le_bytes())
        .map_err(|e| format!("write kdf mem cost: {e}"))?;
    writer
        .write_all(&header.kdf_time_cost.to_le_bytes())
        .map_err(|e| format!("write kdf time cost: {e}"))?;
    writer
        .write_all(&header.kdf_parallelism.to_le_bytes())
        .map_err(|e| format!("write kdf parallelism: {e}"))?;
    writer
        .write_all(&header.chunk_plain.to_le_bytes())
        .map_err(|e| format!("write chunk size: {e}"))?;
    writer
        .write_all(&header.salt)
        .map_err(|e| format!("write salt: {e}"))?;
    Ok(())
}

fn read_header<R: Read>(reader: &mut R) -> Result<FileHeader, String> {
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|e| format!("read header magic: {e}"))?;
    if magic != *MAGIC {
        return Err("not an sld file (unsupported format version)".into());
    }

    let mut ids = [0u8; 3];
    reader
        .read_exact(&mut ids)
        .map_err(|e| format!("read header ids: {e}"))?;
    if ids[0] != HEADER_VERSION {
        return Err("unsupported sld header version".into());
    }
    if ids[1] != KDF_ARGON2ID {
        return Err("unsupported KDF in sld header".into());
    }
    if ids[2] != CIPHER_CHACHA20POLY1305 {
        return Err("unsupported cipher in sld header".into());
    }

    let mut u32_buf = [0u8; 4];
    reader
        .read_exact(&mut u32_buf)
        .map_err(|e| format!("read kdf mem cost: {e}"))?;
    let kdf_mem_cost = u32::from_le_bytes(u32_buf);
    reader
        .read_exact(&mut u32_buf)
        .map_err(|e| format!("read kdf time cost: {e}"))?;
    let kdf_time_cost = u32::from_le_bytes(u32_buf);
    reader
        .read_exact(&mut u32_buf)
        .map_err(|e| format!("read kdf parallelism: {e}"))?;
    let kdf_parallelism = u32::from_le_bytes(u32_buf);
    reader
        .read_exact(&mut u32_buf)
        .map_err(|e| format!("read chunk size: {e}"))?;
    let chunk_plain = u32::from_le_bytes(u32_buf);

    validate_kdf_params(kdf_mem_cost, kdf_time_cost, kdf_parallelism)
        .map_err(|e| format!("{e} in sld header"))?;
    if chunk_plain == 0 || chunk_plain as usize != CHUNK_PLAIN {
        return Err("unsupported chunk size in sld header".into());
    }

    let mut salt = [0u8; SALT_LEN];
    reader
        .read_exact(&mut salt)
        .map_err(|e| format!("read salt: {e}"))?;

    Ok(FileHeader {
        kdf_mem_cost,
        kdf_time_cost,
        kdf_parallelism,
        chunk_plain,
        salt,
    })
}

fn open_input_reader(input: &Path) -> Result<BufReader<Box<dyn Read>>, String> {
    let r: Box<dyn Read> = if is_dash(input) {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(input).map_err(|e| format!("open {} for read: {e}", input.display()))?)
    };
    Ok(BufReader::new(r))
}

enum OutputSink {
    Stdout(BufWriter<Box<dyn Write>>),
    AtomicFile {
        writer: BufWriter<File>,
        temp_path: PathBuf,
        final_path: PathBuf,
    },
}

impl OutputSink {
    fn writer(&mut self) -> &mut dyn Write {
        match self {
            OutputSink::Stdout(w) => w,
            OutputSink::AtomicFile { writer, .. } => writer,
        }
    }

    fn commit(mut self) -> Result<(), String> {
        match &mut self {
            OutputSink::Stdout(w) => w.flush().map_err(|e| format!("flush output: {e}")),
            OutputSink::AtomicFile {
                writer,
                temp_path,
                final_path,
            } => {
                writer.flush().map_err(|e| format!("flush output: {e}"))?;
                writer
                    .get_ref()
                    .sync_all()
                    .map_err(|e| format!("sync output {}: {e}", temp_path.display()))?;
                let temp_disp = temp_path.display().to_string();
                let final_disp = final_path.display().to_string();
                std::fs::rename(&*temp_path, &*final_path).map_err(|e| {
                    format!(
                        "atomically replace {} from {}: {e}",
                        final_disp, temp_disp
                    )
                })
            }
        }
    }
}

impl Drop for OutputSink {
    fn drop(&mut self) {
        if let OutputSink::AtomicFile { temp_path, .. } = self {
            let _ = std::fs::remove_file(temp_path);
        }
    }
}

fn random_temp_suffix() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn open_atomic_temp_file(final_path: &Path) -> Result<(PathBuf, File), String> {
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let name = final_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("seald-output"))
        .to_string_lossy();

    for _ in 0..32 {
        let temp_path = parent.join(format!(".{name}.{}.tmp", random_temp_suffix()));
        #[cfg(unix)]
        let open_res = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path);
        #[cfg(not(unix))]
        let open_res = OpenOptions::new().write(true).create_new(true).open(&temp_path);

        match open_res {
            Ok(f) => {
                #[cfg(unix)]
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("set permissions on {}: {e}", temp_path.display()))?;
                return Ok((temp_path, f));
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("create temp output in {}: {e}", parent.display())),
        }
    }

    Err(format!(
        "could not allocate a unique temp output path in {}",
        parent.display()
    ))
}

fn open_output_sink(path: &Path) -> Result<OutputSink, String> {
    if is_dash(path) {
        let w: Box<dyn Write> = Box::new(io::stdout());
        return Ok(OutputSink::Stdout(BufWriter::new(w)));
    }

    let (temp_path, f) = open_atomic_temp_file(path)?;
    Ok(OutputSink::AtomicFile {
        writer: BufWriter::new(f),
        temp_path,
        final_path: path.to_path_buf(),
    })
}

pub fn encrypt_file(
    input: PathBuf,
    output: Option<PathBuf>,
    passphrase: &[u8],
    level: Argon2Level,
) -> Result<(), String> {
    encrypt_file_with_policy(input, output, passphrase, level, false)
}

pub fn encrypt_file_with_policy(
    input: PathBuf,
    output: Option<PathBuf>,
    passphrase: &[u8],
    level: Argon2Level,
    allow_weak_passphrase: bool,
) -> Result<(), String> {
    let (kdf_mem_cost, kdf_time_cost, kdf_parallelism) = kdf_costs_for_level(level);
    encrypt_file_with_kdf_params(
        input,
        output,
        passphrase,
        kdf_mem_cost,
        kdf_time_cost,
        kdf_parallelism,
        allow_weak_passphrase,
    )
}

pub fn encrypt_file_with_kdf_params(
    input: PathBuf,
    output: Option<PathBuf>,
    passphrase: &[u8],
    kdf_mem_cost: u32,
    kdf_time_cost: u32,
    kdf_parallelism: u32,
    allow_weak_passphrase: bool,
) -> Result<(), String> {
    validate_passphrase(passphrase, allow_weak_passphrase)?;
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let header = FileHeader::from_kdf_params(kdf_mem_cost, kdf_time_cost, kdf_parallelism, salt)?;

    let cipher = {
        let key_material = derive_key(
            passphrase,
            &header.salt,
            header.kdf_mem_cost,
            header.kdf_time_cost,
            header.kdf_parallelism,
        )
        .map_err(|e| e.to_string())?;
        ChaCha20Poly1305::new(Key::from_slice(key_material.as_ref()))
    };

    let mut reader = open_input_reader(&input)?;

    let mut sink: OutputSink = match output.as_ref() {
        Some(p) => open_output_sink(p)?,
        None if is_dash(&input) => open_output_sink(Path::new("-"))?,
        None => {
            let mut p = input.clone();
            let mut name = p.file_name().unwrap_or_default().to_os_string();
            name.push(".sld");
            p.set_file_name(name);
            open_output_sink(&p)?
        }
    };

    write_header(sink.writer(), &header)?;
    let header_aad = header.aad_prefix_bytes();
    salt.zeroize();

    let mut chunk_buf = vec![0u8; CHUNK_PLAIN];
    let mut chunk_index: u64 = 0;

    loop {
        let n = reader
            .read(&mut chunk_buf)
            .map_err(|e| format!("read plaintext: {e}"))?;
        if n == 0 {
            break;
        }

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut aad = Vec::with_capacity(header_aad.len() + 8);
        aad.extend_from_slice(&header_aad);
        aad.extend_from_slice(&chunk_index.to_le_bytes());
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &chunk_buf[..n],
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| "encrypt failed".to_string())?;

        sink.writer()
            .write_all(&chunk_index.to_le_bytes())
            .map_err(|e| format!("write chunk index: {e}"))?;
        sink.writer()
            .write_all(&nonce)
            .map_err(|e| format!("write nonce: {e}"))?;
        sink.writer()
            .write_all(&(n as u32).to_le_bytes())
            .map_err(|e| format!("write length: {e}"))?;
        sink.writer()
            .write_all(&ct)
            .map_err(|e| format!("write ciphertext: {e}"))?;

        chunk_buf[..n].zeroize();

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or_else(|| "too many chunks".to_string())?;
    }

    // Mandatory final marker (empty plaintext chunk) authenticates metadata
    // even when the payload is empty.
    let mut final_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut final_nonce);
    let mut final_aad = Vec::with_capacity(header_aad.len() + 8);
    final_aad.extend_from_slice(&header_aad);
    final_aad.extend_from_slice(&chunk_index.to_le_bytes());
    let final_ct = cipher
        .encrypt(
            Nonce::from_slice(&final_nonce),
            Payload {
                msg: &[],
                aad: final_aad.as_slice(),
            },
        )
        .map_err(|_| "encrypt final marker failed".to_string())?;
    sink.writer()
        .write_all(&chunk_index.to_le_bytes())
        .map_err(|e| format!("write final marker index: {e}"))?;
    sink.writer()
        .write_all(&final_nonce)
        .map_err(|e| format!("write final marker nonce: {e}"))?;
    sink.writer()
        .write_all(&0u32.to_le_bytes())
        .map_err(|e| format!("write final marker length: {e}"))?;
    sink.writer()
        .write_all(&final_ct)
        .map_err(|e| format!("write final marker ciphertext: {e}"))?;

    sink.commit()?;
    chunk_buf.zeroize();
    Ok(())
}

/// Next chunk index (`u64` LE), or `None` if the stream ends at a chunk boundary.
fn read_chunk_index_le<R: Read>(r: &mut R) -> Result<Option<u64>, String> {
    let mut first = [0u8; 1];
    match r.read_exact(&mut first) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("read chunk index: {e}")),
    }
    let mut rest = [0u8; 7];
    r.read_exact(&mut rest)
        .map_err(|e| format!("truncated chunk header: {e}"))?;
    let mut buf = [0u8; 8];
    buf[0] = first[0];
    buf[1..].copy_from_slice(&rest);
    Ok(Some(u64::from_le_bytes(buf)))
}

fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    passphrase: &[u8],
    header: &FileHeader,
) -> Result<(), String> {
    let cipher = {
        let key_material = derive_key(
            passphrase,
            &header.salt,
            header.kdf_mem_cost,
            header.kdf_time_cost,
            header.kdf_parallelism,
        )
        .map_err(|e| e.to_string())?;
        ChaCha20Poly1305::new(Key::from_slice(key_material.as_ref()))
    };
    let header_aad = header.aad_prefix_bytes();

    let mut expected: u64 = 0;
    loop {
        let idx = match read_chunk_index_le(&mut reader)? {
            None => return Err("missing final authentication marker".into()),
            Some(v) => v,
        };
        if idx != expected {
            return Err("chunk out of order or corrupt header".into());
        }

        let mut nonce = [0u8; NONCE_LEN];
        reader
            .read_exact(&mut nonce)
            .map_err(|e| format!("read nonce: {e}"))?;

        let mut plen_buf = [0u8; 4];
        reader
            .read_exact(&mut plen_buf)
            .map_err(|e| format!("read plaintext length: {e}"))?;
        let plen = u32::from_le_bytes(plen_buf) as usize;
        if plen > CHUNK_PLAIN {
            return Err("invalid chunk plaintext length (corrupt or tampered file)".into());
        }

        let ct_len = plen
            .checked_add(TAG_LEN)
            .ok_or_else(|| "invalid chunk length".to_string())?;
        let mut ct = vec![0u8; ct_len];
        reader
            .read_exact(&mut ct)
            .map_err(|e| format!("read ciphertext: {e}"))?;

        let mut aad = Vec::with_capacity(header_aad.len() + 8);
        aad.extend_from_slice(&header_aad);
        aad.extend_from_slice(&expected.to_le_bytes());
        let mut plain = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| "decrypt failed (wrong passphrase or corrupt data)".to_string())?;

        if plen == 0 {
            // Final marker reached: authenticated empty payload; no plaintext output.
            plain.zeroize();
            ct.zeroize();
            match read_chunk_index_le(&mut reader)? {
                None => break,
                Some(_) => return Err("trailing data after final authentication marker".into()),
            }
        } else {
            let write_res = writer.write_all(&plain);
            plain.zeroize();
            ct.zeroize();
            write_res.map_err(|e| format!("write plaintext: {e}"))?;
        }

        expected = expected
            .checked_add(1)
            .ok_or_else(|| "too many chunks".to_string())?;
    }

    writer.flush().map_err(|e| format!("flush output: {e}"))?;
    Ok(())
}

pub fn decrypt_file(
    input: PathBuf,
    output: Option<PathBuf>,
    passphrase: &[u8],
) -> Result<(), String> {
    decrypt_file_with_policy(input, output, passphrase, false)
}

pub fn decrypt_file_with_policy(
    input: PathBuf,
    output: Option<PathBuf>,
    passphrase: &[u8],
    allow_weak_passphrase: bool,
) -> Result<(), String> {
    validate_passphrase(passphrase, allow_weak_passphrase)?;
    let mut reader = open_input_reader(&input)?;
    let header = read_header(&mut reader)?;

    let out_path = output.as_deref().unwrap_or_else(|| Path::new("-"));
    let mut sink = open_output_sink(out_path)?;
    decrypt_stream(reader, sink.writer(), passphrase, &header)?;
    sink.commit()?;
    Ok(())
}

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(message);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn cstr_to_path(ptr: *const c_char, field_name: &str) -> Result<PathBuf, String> {
    if ptr.is_null() {
        return Err(format!("{field_name} pointer is null"));
    }
    // SAFETY: caller promises `ptr` points to a valid, NUL-terminated C string.
    let c = unsafe { CStr::from_ptr(ptr) };
    let s = c
        .to_str()
        .map_err(|_| format!("{field_name} is not valid UTF-8"))?;
    Ok(PathBuf::from(s))
}

fn cstr_to_optional_path(ptr: *const c_char) -> Result<Option<PathBuf>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: caller promises `ptr` points to a valid, NUL-terminated C string.
    let c = unsafe { CStr::from_ptr(ptr) };
    let s = c.to_str().map_err(|_| "output is not valid UTF-8".to_string())?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PathBuf::from(s)))
    }
}

fn cstr_to_password(ptr: *const c_char) -> Result<Zeroizing<Vec<u8>>, String> {
    if ptr.is_null() {
        return Err("password pointer is null".to_string());
    }
    // SAFETY: caller promises `ptr` points to a valid, NUL-terminated C string.
    let c = unsafe { CStr::from_ptr(ptr) };
    let s = c
        .to_str()
        .map_err(|_| "password is not valid UTF-8".to_string())?;
    if s.is_empty() {
        return Err("password cannot be empty".to_string());
    }
    Ok(Zeroizing::new(s.as_bytes().to_vec()))
}

fn level_from_u32(level: u32) -> Result<Argon2Level, String> {
    match level {
        0 => Ok(Argon2Level::Fast),
        1 => Ok(Argon2Level::Standard),
        2 => Ok(Argon2Level::Strong),
        3 => Ok(Argon2Level::Paranoid),
        _ => Err("invalid level (expected 0=fast, 1=standard, 2=strong, 3=paranoid)".to_string()),
    }
}

#[no_mangle]
pub extern "C" fn seald_encrypt_file(
    input_path: *const c_char,
    output_path_or_null: *const c_char,
    password: *const c_char,
    level: u32,
) -> i32 {
    let result = (|| {
        let input = cstr_to_path(input_path, "input_path")?;
        let output = cstr_to_optional_path(output_path_or_null)?;
        let pass = cstr_to_password(password)?;
        let lvl = level_from_u32(level)?;
        encrypt_file(input, output, pass.as_ref(), lvl)
    })();

    match result {
        Ok(()) => {
            clear_last_error();
            0
        }
        Err(e) => {
            set_last_error(e);
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn seald_decrypt_file(
    input_path: *const c_char,
    output_path_or_null: *const c_char,
    password: *const c_char,
) -> i32 {
    let result = (|| {
        let input = cstr_to_path(input_path, "input_path")?;
        let output = cstr_to_optional_path(output_path_or_null)?;
        let pass = cstr_to_password(password)?;
        decrypt_file(input, output, pass.as_ref())
    })();

    match result {
        Ok(()) => {
            clear_last_error();
            0
        }
        Err(e) => {
            set_last_error(e);
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn seald_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|slot| {
        if let Some(message) = slot.borrow().as_ref() {
            match CString::new(message.as_str()) {
                Ok(c) => c.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        } else {
            std::ptr::null_mut()
        }
    })
}

#[no_mangle]
pub extern "C" fn seald_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` must have been allocated by `CString::into_raw` in this library.
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("seald-test-{}-{}-{name}", std::process::id(), nanos))
    }

    #[test]
    fn round_trip_and_header_contains_kdf_metadata() {
        let plain_path = unique_path("plain.bin");
        let enc_path = unique_path("plain.bin.sld");
        let out_path = unique_path("out.bin");
        let plaintext = b"header-aware encryption test payload";

        fs::write(&plain_path, plaintext).expect("write plaintext file");
        encrypt_file(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"test-passphrase",
            Argon2Level::Strong,
        )
        .expect("encrypt file");

        let enc = fs::read(&enc_path).expect("read encrypted file");
        assert_eq!(&enc[0..4], MAGIC);
        assert_eq!(enc[4], HEADER_VERSION);
        assert_eq!(enc[5], KDF_ARGON2ID);
        assert_eq!(enc[6], CIPHER_CHACHA20POLY1305);

        let mem = u32::from_le_bytes(enc[7..11].try_into().expect("mem cost bytes"));
        let time = u32::from_le_bytes(enc[11..15].try_into().expect("time cost bytes"));
        let parallelism = u32::from_le_bytes(enc[15..19].try_into().expect("parallelism bytes"));
        let chunk = u32::from_le_bytes(enc[19..23].try_into().expect("chunk bytes"));
        let (exp_mem, exp_time, exp_parallelism) = kdf_costs_for_level(Argon2Level::Strong);
        assert_eq!(mem, exp_mem);
        assert_eq!(time, exp_time);
        assert_eq!(parallelism, exp_parallelism);
        assert_eq!(chunk, CHUNK_PLAIN as u32);

        decrypt_file(enc_path.clone(), Some(out_path.clone()), b"test-passphrase")
            .expect("decrypt file");
        let roundtrip = fs::read(&out_path).expect("read decrypted file");
        assert_eq!(roundtrip, plaintext);

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
        let _ = fs::remove_file(out_path);
    }

    #[test]
    fn decrypt_rejects_old_format_magic() {
        let old_path = unique_path("old-format.sld");
        fs::write(&old_path, b"SLD\x02legacy").expect("write old format file");

        let err = decrypt_file(old_path.clone(), None, b"test-passphrase").expect_err("must reject old format");
        assert!(err.contains("unsupported format version"));

        let _ = fs::remove_file(old_path);
    }

    #[test]
    fn decrypt_rejects_invalid_header_kdf_params() {
        let bad_path = unique_path("invalid-kdf.sld");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(HEADER_VERSION);
        bytes.push(KDF_ARGON2ID);
        bytes.push(CIPHER_CHACHA20POLY1305);
        bytes.extend_from_slice(&19_456u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // invalid parallelism for Argon2.
        bytes.extend_from_slice(&(CHUNK_PLAIN as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; SALT_LEN]);
        fs::write(&bad_path, bytes).expect("write invalid header file");

        let err = decrypt_file(bad_path.clone(), None, b"test-passphrase")
            .expect_err("invalid kdf header should fail");
        assert!(err.contains("in sld header"));

        let _ = fs::remove_file(bad_path);
    }

    #[test]
    fn decrypt_fails_if_authenticated_header_metadata_is_tampered() {
        let plain_path = unique_path("tamper-plain.bin");
        let enc_path = unique_path("tamper-plain.bin.sld");
        fs::write(&plain_path, b"tamper test").expect("write plaintext");

        encrypt_file(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"test-passphrase",
            Argon2Level::Standard,
        )
        .expect("encrypt file");

        let mut enc = fs::read(&enc_path).expect("read encrypted file");
        // kdf_time_cost is bytes [11..15]. Flip to a different valid value.
        let mut kdf_time = u32::from_le_bytes(enc[11..15].try_into().expect("kdf time bytes"));
        kdf_time = if kdf_time > 1 { kdf_time - 1 } else { kdf_time + 1 };
        enc[11..15].copy_from_slice(&kdf_time.to_le_bytes());
        fs::write(&enc_path, enc).expect("write tampered encrypted file");

        let err = decrypt_file(enc_path.clone(), None, b"test-passphrase")
            .expect_err("tampered metadata should fail decryption");
        assert!(err.contains("decrypt failed"));

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
    }

    #[test]
    fn short_passphrase_is_rejected_by_default_policy() {
        let plain_path = unique_path("weak-pass-plain.bin");
        let enc_path = unique_path("weak-pass-plain.bin.sld");
        fs::write(&plain_path, b"weak passphrase policy test").expect("write plaintext");

        let err = encrypt_file(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"shortpass",
            Argon2Level::Standard,
        )
        .expect_err("short passphrase should be rejected");
        assert!(err.contains("passphrase too weak"));

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
    }

    #[test]
    fn allow_weak_passphrase_override_allows_short_passphrase() {
        let plain_path = unique_path("allow-weak-plain.bin");
        let enc_path = unique_path("allow-weak-plain.bin.sld");
        let out_path = unique_path("allow-weak-out.bin");
        let plaintext = b"short passphrase allowed with explicit override";
        fs::write(&plain_path, plaintext).expect("write plaintext");

        encrypt_file_with_policy(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"shortpass",
            Argon2Level::Fast,
            true,
        )
        .expect("encryption should allow short passphrase with override");

        decrypt_file_with_policy(enc_path.clone(), Some(out_path.clone()), b"shortpass", true)
            .expect("decryption should allow short passphrase with override");
        let roundtrip = fs::read(&out_path).expect("read decrypted output");
        assert_eq!(roundtrip, plaintext);

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
        let _ = fs::remove_file(out_path);
    }

    #[test]
    fn encrypt_with_explicit_kdf_knobs_stores_those_values() {
        let plain_path = unique_path("explicit-kdf-plain.bin");
        let enc_path = unique_path("explicit-kdf-plain.bin.sld");
        fs::write(&plain_path, b"explicit kdf knobs").expect("write plaintext");

        encrypt_file_with_kdf_params(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"test-passphrase",
            32_768,
            4,
            2,
            false,
        )
        .expect("encrypt with explicit kdf params");

        let enc = fs::read(&enc_path).expect("read encrypted file");
        let mem = u32::from_le_bytes(enc[7..11].try_into().expect("mem cost bytes"));
        let time = u32::from_le_bytes(enc[11..15].try_into().expect("time cost bytes"));
        let parallelism = u32::from_le_bytes(enc[15..19].try_into().expect("parallelism bytes"));
        assert_eq!(mem, 32_768);
        assert_eq!(time, 4);
        assert_eq!(parallelism, 2);

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
    }

    #[test]
    fn encrypt_with_invalid_kdf_knobs_is_rejected() {
        let plain_path = unique_path("invalid-kdf-knobs-plain.bin");
        let enc_path = unique_path("invalid-kdf-knobs-plain.bin.sld");
        fs::write(&plain_path, b"invalid kdf knobs").expect("write plaintext");

        let err = encrypt_file_with_kdf_params(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"test-passphrase",
            19_456,
            3,
            0,
            false,
        )
        .expect_err("invalid parallelism should fail");
        assert!(err.contains("invalid Argon2 parallelism"));

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
    }

    #[test]
    fn decrypt_rejects_missing_final_authentication_marker() {
        let path = unique_path("missing-final-marker.sld");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(HEADER_VERSION);
        bytes.push(KDF_ARGON2ID);
        bytes.push(CIPHER_CHACHA20POLY1305);
        bytes.extend_from_slice(&19_456u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(CHUNK_PLAIN as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; SALT_LEN]);
        fs::write(&path, bytes).expect("write header-only file");

        let err = decrypt_file(path.clone(), None, b"test-passphrase")
            .expect_err("missing final marker should fail");
        assert!(err.contains("missing final authentication marker"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn decrypt_rejects_excessive_kdf_memory_in_header() {
        let path = unique_path("excessive-kdf-memory.sld");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(HEADER_VERSION);
        bytes.push(KDF_ARGON2ID);
        bytes.push(CIPHER_CHACHA20POLY1305);
        bytes.extend_from_slice(&(MAX_KDF_MEMORY_KIB + 1).to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(CHUNK_PLAIN as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; SALT_LEN]);
        fs::write(&path, bytes).expect("write excessive-kdf file");

        let err = decrypt_file(path.clone(), None, b"test-passphrase")
            .expect_err("excessive kdf memory should fail");
        assert!(err.contains("invalid Argon2 memory cost"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn decrypt_failure_does_not_leave_partial_output_file() {
        let plain_path = unique_path("atomic-plain.bin");
        let enc_path = unique_path("atomic-plain.bin.sld");
        let out_path = unique_path("atomic-out.bin");
        let mut plaintext = vec![0u8; CHUNK_PLAIN + 1024];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        fs::write(&plain_path, &plaintext).expect("write plaintext");
        encrypt_file(
            plain_path.clone(),
            Some(enc_path.clone()),
            b"test-passphrase",
            Argon2Level::Standard,
        )
        .expect("encrypt file");

        let mut enc = fs::read(&enc_path).expect("read encrypted file");
        // Corrupt one byte near the end so decrypt fails after some data was processed.
        let last = enc.len().saturating_sub(1);
        enc[last] ^= 0x80;
        fs::write(&enc_path, &enc).expect("rewrite corrupted encrypted file");

        let err = decrypt_file(enc_path.clone(), Some(out_path.clone()), b"test-passphrase")
            .expect_err("decrypt should fail on tampered ciphertext");
        assert!(err.contains("decrypt failed"));
        assert!(!out_path.exists(), "output path should not exist after failed decrypt");

        let _ = fs::remove_file(plain_path);
        let _ = fs::remove_file(enc_path);
        let _ = fs::remove_file(out_path);
    }
}
