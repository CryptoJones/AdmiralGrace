//! PE CodeView RSDS inspection and Microsoft-compatible symbol server lookup (#400).
//!
//! A Windows PE image records the PDB it was linked against in its
//! `IMAGE_DIRECTORY_ENTRY_DEBUG` CodeView (`RSDS`) entry: a 16-byte GUID,
//! an age counter, and the PDB path. Together those form the symbol-store
//! lookup key `<GUID_UPPER><age_hex>` under `<pdb_filename>/<key>/<pdb_filename>`.
//!
//! [`codeview_of_bytes`] reads the PE entry; [`find_local_pdb`] checks sibling
//! files and the local symbol cache; [`fetch_pdb`] downloads from an `http://`,
//! `https://`, or directory symbol store and verifies the downloaded PDB's GUID.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const MAX_PDB_BYTES: usize = 512 * 1024 * 1024;
const MAX_HEAD_BYTES: usize = 32 * 1024;

/// CodeView `RSDS` identity extracted from a PE image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeViewInfo {
    /// Raw 16-byte little-endian GUID from the RSDS record.
    pub guid: [u8; 16],
    /// Canonical 32-character uppercase hex GUID (`Data1..Data4` in RFC-4122 byte order).
    pub guid_hex: String,
    /// PDB age counter recorded in the PE image.
    pub age: u32,
    /// Path to the PDB as recorded at link time (may be Windows or Unix style).
    pub path: String,
    /// Basename of `path` (split across both `/` and `\`).
    pub filename: String,
    /// Symbol server lookup identifier: `<GUID_HEX><age:x>`.
    pub id: String,
}

/// Result of resolving or fetching a PDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    /// Path on disk where the PDB now lives.
    pub path: PathBuf,
    /// Where the PDB came from (`"cache"`, `"sibling"`, or the server URL).
    pub source: String,
    /// Whether the file was served from the local cache without downloading.
    pub cached: bool,
}

/// Format a raw little-endian RSDS GUID `[u8; 16]` into Microsoft's 32-char
/// uppercase hex string (`Data1` BE, `Data2` BE, `Data3` BE, `Data4`).
pub fn format_rsds_guid(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{d1:08X}{d2:04X}{d3:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// Format a PDB GUID (`pdb::PDBInformation::guid`) into Microsoft's 32-char
/// uppercase hex string.
pub fn format_pdb_guid(guid: impl std::fmt::Display) -> String {
    guid.to_string().replace('-', "").to_ascii_uppercase()
}

/// Basename of a Windows or POSIX path (`C:\out\foo.pdb` -> `foo.pdb`).
pub fn pdb_basename(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_string()
}

/// Extract CodeView RSDS PDB identity from a PE image's bytes.
/// Returns `Ok(None)` if the image is not a PE or carries no RSDS debug directory.
pub fn codeview_of_bytes(bytes: &[u8]) -> Result<Option<CodeViewInfo>, String> {
    use object::Object as _;

    let file = object::File::parse(bytes).map_err(|e| format!("parsing image: {e}"))?;
    let Some(cv) = file
        .pdb_info()
        .map_err(|e| format!("reading PE debug directory: {e}"))?
    else {
        return Ok(None);
    };
    let path = String::from_utf8_lossy(cv.path()).into_owned();
    let filename = pdb_basename(&path);
    let guid = cv.guid();
    let guid_hex = format_rsds_guid(&guid);
    let age = cv.age();
    let id = format!("{guid_hex}{age:x}");
    Ok(Some(CodeViewInfo {
        guid,
        guid_hex,
        age,
        path,
        filename,
        id,
    }))
}

/// Extract CodeView RSDS PDB identity from an image file on disk.
pub fn codeview_of_file(path: &Path) -> Result<Option<CodeViewInfo>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    codeview_of_bytes(&bytes)
}

/// Default local symbol cache directory (`$XDG_CACHE_HOME/ag/symbols`,
/// `$HOME/.cache/ag/symbols`, or `%LOCALAPPDATA%/ag/symbols`).
pub fn default_cache_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("ag").join("symbols");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".cache").join("ag").join("symbols");
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return PathBuf::from(local).join("ag").join("symbols");
    }
    std::env::temp_dir().join("ag-symbols")
}

/// Standard symbol-store cache path: `<cache>/<filename>/<id>/<filename>`.
pub fn cache_path(cache_dir: &Path, filename: &str, id: &str) -> PathBuf {
    cache_dir.join(filename).join(id).join(filename)
}

/// Parse a Microsoft `_NT_SYMBOL_PATH`-style specification (`;` separated):
/// `SRV*cache*url`, `CACHE*dir`, plain URLs (`http://`, `https://`), or
/// local symbol store directories. Returns `(cache_dir, servers)`.
pub fn parse_symbol_path(spec: &str) -> (Option<PathBuf>, Vec<String>) {
    let mut cache: Option<PathBuf> = None;
    let mut servers: Vec<String> = Vec::new();
    for entry in spec.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let upper = entry.to_ascii_uppercase();
        if upper.starts_with("SRV*") {
            let parts: Vec<&str> = entry.split('*').skip(1).collect();
            for (idx, part) in parts.iter().enumerate() {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                let is_last = idx + 1 == parts.len();
                if p.starts_with("http://") || p.starts_with("https://") {
                    servers.push(p.to_string());
                } else if is_last && parts.len() >= 2 {
                    servers.push(p.to_string());
                } else if cache.is_none() {
                    cache = Some(PathBuf::from(p));
                }
            }
        } else if upper.starts_with("CACHE*") {
            if let Some(dir) = entry.split('*').nth(1).map(str::trim).filter(|s| !s.is_empty()) {
                if cache.is_none() {
                    cache = Some(PathBuf::from(dir));
                }
            }
        } else {
            servers.push(entry.to_string());
        }
    }
    (cache, servers)
}

/// Check whether a PDB file at `path` matches `cv.guid_hex` (and `age >= cv.age`).
pub fn pdb_matches_codeview(path: &Path, cv: &CodeViewInfo) -> Result<bool, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    pdb_bytes_match_codeview(&bytes, cv)
}

/// Check whether raw PDB bytes match `cv.guid_hex`.
pub fn pdb_bytes_match_codeview(bytes: &[u8], cv: &CodeViewInfo) -> Result<bool, String> {
    let mut pdb = pdb::PDB::open(std::io::Cursor::new(bytes))
        .map_err(|e| format!("not a valid PDB: {e}"))?;
    let info = pdb
        .pdb_information()
        .map_err(|e| format!("reading PDB info stream: {e}"))?;
    let guid_hex = format_pdb_guid(info.guid);
    if !guid_hex.eq_ignore_ascii_case(&cv.guid_hex) {
        return Ok(false);
    }
    let dbi_age = pdb.debug_information().ok().and_then(|d| d.age());
    let age = dbi_age.unwrap_or(info.age);
    Ok(info.age >= cv.age || age >= cv.age)
}

/// Look for an existing matching PDB locally: beside `binary_path` (by RSDS
/// filename or `<binary_stem>.pdb`), or inside `cache_dir` at `<cache>/<name>/<id>/<name>`.
pub fn find_local_pdb(
    binary_path: Option<&Path>,
    cv: &CodeViewInfo,
    cache_dir: Option<&Path>,
) -> Option<FetchResult> {
    if let Some(bin) = binary_path {
        if let Some(dir) = bin.parent() {
            let mut candidates = Vec::new();
            if !cv.filename.is_empty() {
                candidates.push(dir.join(&cv.filename));
            }
            let stem_pdb = bin.with_extension("pdb");
            if !candidates.contains(&stem_pdb) {
                candidates.push(stem_pdb);
            }
            for cand in candidates {
                if cand.is_file() && pdb_matches_codeview(&cand, cv).unwrap_or(false) {
                    return Some(FetchResult {
                        path: cand,
                        source: "sibling".to_string(),
                        cached: true,
                    });
                }
            }
        }
    }
    if let Some(cache) = cache_dir {
        let cached = cache_path(cache, &cv.filename, &cv.id);
        if cached.is_file() && pdb_matches_codeview(&cached, cv).unwrap_or(false) {
            return Some(FetchResult {
                path: cached,
                source: "cache".to_string(),
                cached: true,
            });
        }
    }
    None
}

/// Build the symbol-server download URL for `cv` under `server`.
pub fn symbol_url(server: &str, cv: &CodeViewInfo) -> String {
    let base = server.trim_end_matches('/');
    let file = percent_encode_segment(&cv.filename);
    format!("{base}/{file}/{}/{file}", cv.id)
}

/// Fetch a PDB matching `cv` from `cache_dir` or `servers`, writing it to
/// `dest` (or into `cache_dir/<filename>/<id>/<filename>` when `dest` is `None`).
pub fn fetch_pdb(
    cv: &CodeViewInfo,
    servers: &[String],
    cache_dir: &Path,
    dest: Option<&Path>,
) -> Result<FetchResult, String> {
    if cv.filename.is_empty() {
        return Err("the PE CodeView record names no PDB filename".to_string());
    }
    let cached_target = cache_path(cache_dir, &cv.filename, &cv.id);
    if cached_target.is_file() && pdb_matches_codeview(&cached_target, cv).unwrap_or(false) {
        if let Some(out) = dest {
            if out != cached_target {
                copy_file_atomic(&cached_target, out)?;
            }
            return Ok(FetchResult {
                path: out.to_path_buf(),
                source: "cache".to_string(),
                cached: true,
            });
        }
        return Ok(FetchResult {
            path: cached_target,
            source: "cache".to_string(),
            cached: true,
        });
    }

    if servers.is_empty() {
        return Err(format!(
            "no symbol server configured for {} ({}); pass --server URL or set _NT_SYMBOL_PATH",
            cv.filename, cv.id
        ));
    }

    let mut errors = Vec::new();
    for server in servers {
        match fetch_from_one_server(server, cv) {
            Ok(bytes) => {
                if !pdb_bytes_match_codeview(&bytes, cv)? {
                    errors.push(format!(
                        "{server}: downloaded {} does not match GUID {}",
                        cv.filename, cv.id
                    ));
                    continue;
                }
                write_file_atomic(&cached_target, &bytes)?;
                let final_path = if let Some(out) = dest {
                    if out != cached_target {
                        write_file_atomic(out, &bytes)?;
                    }
                    out.to_path_buf()
                } else {
                    cached_target
                };
                return Ok(FetchResult {
                    path: final_path,
                    source: server.clone(),
                    cached: false,
                });
            }
            Err(err) => errors.push(format!("{server}: {err}")),
        }
    }

    Err(format!(
        "could not fetch {} ({}): {}",
        cv.filename,
        cv.id,
        errors.join("; ")
    ))
}

fn fetch_from_one_server(server: &str, cv: &CodeViewInfo) -> Result<Vec<u8>, String> {
    let trimmed = server.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let url = symbol_url(trimmed, cv);
        http_get_following_redirects(&url, MAX_REDIRECTS)
    } else {
        // Local directory symbol store.
        let store = Path::new(trimmed);
        let direct = cache_path(store, &cv.filename, &cv.id);
        if direct.is_file() {
            return std::fs::read(&direct)
                .map_err(|e| format!("reading {}: {e}", direct.display()));
        }
        let flat = store.join(&cv.filename);
        if flat.is_file() {
            return std::fs::read(&flat).map_err(|e| format!("reading {}: {e}", flat.display()));
        }
        Err(format!("not found at {}", direct.display()))
    }
}

fn http_get_following_redirects(url: &str, redirects_left: usize) -> Result<Vec<u8>, String> {
    if url.starts_with("https://") {
        return fetch_https_via_curl(url);
    }
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("{url}: unsupported URL scheme (expected http:// or https://)"))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains(['@', ' ', '\r', '\n']) {
        return Err(format!("{url}: invalid HTTP authority"));
    }
    let has_port = match authority.rfind(':') {
        Some(colon) => !authority[colon..].contains(']'),
        None => false,
    };
    let dial = if has_port {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    let addrs = dial
        .to_socket_addrs()
        .map_err(|e| format!("resolving {dial}: {e}"))?;
    let mut stream = None;
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| match last_err {
        Some(e) => format!("connecting to {dial}: {e}"),
        None => format!("no address resolved for {dial}"),
    })?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: AdmiralGrace/1.0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("sending request to {url}: {e}"))?;
    let _ = stream.flush();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("reading status from {url}: {e}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("{url}: invalid HTTP status line"))?;

    let mut head_bytes = status_line.len();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut location: Option<String> = None;

    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("reading headers from {url}: {e}"))?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        head_bytes += n;
        if head_bytes > MAX_HEAD_BYTES {
            return Err(format!("{url}: HTTP response headers too large"));
        }
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let val = val.trim();
            match name.as_str() {
                "content-length" => {
                    content_length = val.parse::<usize>().ok();
                }
                "transfer-encoding" if val.to_ascii_lowercase().contains("chunked") => {
                    chunked = true;
                }
                "location" => {
                    location = Some(val.to_string());
                }
                _ => {}
            }
        }
    }

    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        let target = location.ok_or_else(|| format!("{url}: HTTP {status} without Location"))?;
        if redirects_left == 0 {
            return Err(format!("{url}: too many redirects"));
        }
        let next = if target.starts_with("http://") || target.starts_with("https://") {
            target
        } else if target.starts_with('/') {
            format!("http://{authority}{target}")
        } else {
            return Err(format!("{url}: unsupported redirect Location {target:?}"));
        };
        return http_get_following_redirects(&next, redirects_left - 1);
    }

    if status != 200 {
        return Err(format!("HTTP {status}"));
    }

    let body = if chunked {
        read_chunked(&mut reader)?
    } else if let Some(len) = content_length {
        if len > MAX_PDB_BYTES {
            return Err(format!("response body ({len} bytes) exceeds limit"));
        }
        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf)
            .map_err(|e| format!("reading response body from {url}: {e}"))?;
        buf
    } else {
        let mut buf = Vec::new();
        reader
            .take((MAX_PDB_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading response body from {url}: {e}"))?;
        if buf.len() > MAX_PDB_BYTES {
            return Err("response body exceeds limit".to_string());
        }
        buf
    };

    Ok(body)
}

fn read_chunked<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = reader
            .read_line(&mut size_line)
            .map_err(|e| format!("reading chunk size: {e}"))?;
        if n == 0 {
            break;
        }
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len =
            usize::from_str_radix(hex, 16).map_err(|_| format!("bad chunk length {hex:?}"))?;
        if chunk_len == 0 {
            break;
        }
        if out.len().saturating_add(chunk_len) > MAX_PDB_BYTES {
            return Err("chunked response exceeds limit".to_string());
        }
        let start = out.len();
        out.resize(start + chunk_len, 0);
        reader
            .read_exact(&mut out[start..])
            .map_err(|e| format!("reading chunk payload: {e}"))?;
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf);
    }
    Ok(out)
}

fn fetch_https_via_curl(url: &str) -> Result<Vec<u8>, String> {
    let temp = std::env::temp_dir().join(format!(
        "ag-pdb-fetch-{}-{:?}.tmp",
        std::process::id(),
        std::thread::current().id()
    ));
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--connect-timeout",
            "15",
            "--max-time",
            "120",
            "-o",
        ])
        .arg(&temp)
        .arg(url)
        .output();
    let result = match output {
        Ok(out) if out.status.success() => {
            std::fs::read(&temp).map_err(|e| format!("reading downloaded file: {e}"))
        }
        Ok(out) => {
            let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
            Err(if msg.is_empty() {
                format!("curl exited with status {}", out.status)
            } else {
                msg
            })
        }
        Err(e) => Err(format!(
            "cannot download over HTTPS without `curl` ({e}); download the PDB manually or use an http:// symbol server"
        )),
    };
    let _ = std::fs::remove_file(&temp);
    result
}

fn write_file_atomic(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let tmp = dest.with_extension("pdb.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("moving {} to {}: {e}", tmp.display(), dest.display())
    })
}

fn copy_file_atomic(src: &Path, dest: &Path) -> Result<(), String> {
    let bytes = std::fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?;
    write_file_atomic(dest, &bytes)
}

fn percent_encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rsds_guid_and_parses_symbol_path() {
        // Little-endian RSDS bytes for GUID {12345678-9ABC-DEF0-1122-334455667788}.
        let guid = [
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        assert_eq!(format_rsds_guid(&guid), "123456789ABCDEF01122334455667788");
        assert_eq!(pdb_basename(r"C:\build\Release\app.pdb"), "app.pdb");
        assert_eq!(pdb_basename("/tmp/build/app.pdb"), "app.pdb");

        let (cache, servers) = parse_symbol_path(
            "SRV*/tmp/symcache*https://msdl.microsoft.com/download/symbols;/opt/local_syms",
        );
        assert_eq!(cache, Some(PathBuf::from("/tmp/symcache")));
        assert_eq!(
            servers,
            vec![
                "https://msdl.microsoft.com/download/symbols".to_string(),
                "/opt/local_syms".to_string(),
            ]
        );
    }
}
