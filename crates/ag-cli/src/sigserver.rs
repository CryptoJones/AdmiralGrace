//! The networked signature server (#395): one store of whole-function
//! signatures that several analysts push to, pull from and match against.
//!
//! `ag funcid serve` keeps a directory of signature files (`.agsig`) and
//! answers a small JSON protocol over HTTP/1.1; `ag funcid push`, `pull`,
//! `list --server` and the `--server` of `match` and `apply` are its
//! clients. Both ends are in this module so the protocol is in one place:
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /v1` | the service's name and protocol version |
//! | `GET /v1/libraries` | every library held: name, architecture, source, count |
//! | `GET /v1/libraries/LIBRARY/ARCH` | that library's signature file |
//! | `POST /v1/libraries` (a signature file) | merge it in; what was added, filled and known |
//! | `POST /v1/match` (`{"arch", "hashes"}`) | the signatures that carry those hashes, a signature file a library |
//!
//! A match sends **hashes only** — never the bytes of the program under
//! analysis — and gets back ordinary signature files cut down to the hashes
//! asked for, so the client matches against them exactly as it does a
//! `--sig` file.
//!
//! The server is deliberately small and standard-library only: one request a
//! connection, a thread a connection up to a cap, every size bounded. It
//! speaks plain HTTP, so it belongs on a loopback, a private network or the
//! far end of an SSH tunnel. A push needs the server's token; a server
//! started without one is read-only.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ag_image::funcid::{Merge, SignatureDb};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The port the server listens on, and a client dials, when none is said.
pub const DEFAULT_PORT: u16 = 7395;

/// The protocol version `GET /v1` reports.
const PROTOCOL: u32 = 1;

/// The environment variable a token is read from when `--token` is not
/// given, so it need not sit on a command line.
pub const TOKEN_ENV: &str = "AG_FUNCID_TOKEN";

/// The most a request's head — its request line and headers — may run to.
const MAX_HEAD: usize = 16 * 1024;
/// The largest signature file the server takes in a push. Only a request
/// that carries the server's token gets to send one.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// The largest body the server reads from anyone else: a match's hashes.
const MAX_QUERY: usize = 8 * 1024 * 1024;
/// The largest answer a client reads from a server.
const MAX_ANSWER: usize = 256 * 1024 * 1024;
/// The most hashes one match request may carry; a client sends more in
/// several requests.
const MAX_HASHES: usize = 100_000;
/// How many hashes a client puts in one match request.
const MATCH_BATCH: usize = 20_000;
/// The most connections served at once; one more is told to come back.
const MAX_CONNECTIONS: usize = 64;
/// How long a quiet connection is waited on.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest library or architecture name, and the longest strings a
/// signature may carry.
const MAX_NAME: usize = 64;
const MAX_SYMBOL: usize = 4096;
const MAX_TEXT: usize = 16 * 1024;

/// Whether `name` can name a library or an architecture: short, and made of
/// letters, digits and `. _ + -` only, not starting with a dot. The name
/// becomes part of a file name on the server and on a client that pulls, so
/// nothing that could leave the directory is let through.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Whether `hash` is a whole-function hash: 64 lowercase hex characters.
fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether a signature database is one the store can hold — and one a client
/// can trust the shape of: a library and an architecture that are plain
/// names, hashes that are hashes, and strings of a sane length.
pub fn validate(db: &SignatureDb) -> Result<(), String> {
    if !valid_name(&db.library) {
        return Err(format!(
            "the library name {:?} is not a plain name (letters, digits and . _ + -, at most {MAX_NAME})",
            db.library
        ));
    }
    if !valid_name(&db.arch) {
        return Err(format!(
            "the architecture {:?} is not a plain name",
            db.arch
        ));
    }
    if db.source.as_ref().is_some_and(|s| s.len() > MAX_TEXT) {
        return Err("the source is too long".to_string());
    }
    for signature in &db.signatures {
        if !valid_hash(&signature.hash) {
            return Err(format!(
                "{:?} is not a whole-function hash (64 lowercase hex characters)",
                signature.hash
            ));
        }
        if signature.name.trim().is_empty() || signature.name.len() > MAX_SYMBOL {
            return Err(format!(
                "the signature {} has no name, or one too long",
                signature.hash
            ));
        }
        let too_long = |text: &Option<String>| text.as_ref().is_some_and(|t| t.len() > MAX_TEXT);
        if too_long(&signature.prototype) || too_long(&signature.comment) {
            return Err(format!(
                "the signature {} carries a prototype or comment too long",
                signature.hash
            ));
        }
    }
    Ok(())
}

/// The file a library's signatures are kept in, on the server and where a
/// pull writes them: `libc@x86-64.agsig`. `@` is in no valid name, so the
/// two parts never run together.
pub fn file_name(library: &str, arch: &str) -> String {
    format!("{library}@{arch}.agsig")
}

/// One library a server holds, as `GET /v1/libraries` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryInfo {
    pub library: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub signatures: usize,
}

/// What a push did, as the server answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushReport {
    pub library: String,
    pub arch: String,
    /// Signatures the server did not hold, and now does.
    pub added: usize,
    /// Signatures it held that gained a prototype or a comment.
    pub filled: usize,
    /// Signatures it held already, left as they were.
    pub known: usize,
    /// How many signatures the library holds after the push.
    pub total: usize,
}

/// The body of `POST /v1/match`.
#[derive(Serialize, Deserialize)]
struct MatchRequest {
    arch: String,
    hashes: Vec<String>,
}

/// The answer to `POST /v1/match`: a signature database a library, holding
/// only the signatures whose hashes were asked for.
#[derive(Serialize, Deserialize)]
struct MatchAnswer {
    databases: Vec<SignatureDb>,
}

/// One library in the store, with its hashes indexed for matching.
struct Entry {
    db: SignatureDb,
    index: HashMap<String, usize>,
}

impl Entry {
    fn new(db: SignatureDb) -> Entry {
        let index = db
            .signatures
            .iter()
            .enumerate()
            .map(|(at, signature)| (signature.hash.clone(), at))
            .collect();
        Entry { db, index }
    }
}

/// The server's signatures: a directory of `.agsig` files, one a library and
/// architecture, held in memory and written back as pushes arrive.
pub struct Store {
    dir: PathBuf,
    libraries: BTreeMap<(String, String), Entry>,
}

impl Store {
    /// Open the store at `dir`, making the directory when it is not there.
    /// Every `.agsig` file in it is read — one an operator dropped in by
    /// hand as much as one a push wrote — and files naming the same library
    /// and architecture are merged.
    pub fn open(dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("making the signature store {}", dir.display()))?;
        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("reading the signature store {}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| path.extension().is_some_and(|e| e == "agsig") && path.is_file())
            .collect();
        paths.sort();
        let mut merged: BTreeMap<(String, String), SignatureDb> = BTreeMap::new();
        for path in paths {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading the signature file {}", path.display()))?;
            let db = SignatureDb::parse(&text)
                .and_then(|db| validate(&db).map(|()| db))
                .map_err(|e| anyhow!("reading the signature file {}: {e}", path.display()))?;
            let key = (db.library.clone(), db.arch.clone());
            match merged.get_mut(&key) {
                Some(held) => {
                    held.merge(&db);
                }
                None => {
                    // Merging into an empty database drops a file's own
                    // repeats of a hash, so the index has one place a hash.
                    let mut held = SignatureDb::new(&db.library, &db.arch);
                    held.merge(&db);
                    merged.insert(key, held);
                }
            }
        }
        Ok(Store {
            dir: dir.to_path_buf(),
            libraries: merged
                .into_iter()
                .map(|(key, db)| (key, Entry::new(db)))
                .collect(),
        })
    }

    /// The libraries held, in name order.
    pub fn list(&self) -> Vec<LibraryInfo> {
        self.libraries
            .values()
            .map(|entry| LibraryInfo {
                library: entry.db.library.clone(),
                arch: entry.db.arch.clone(),
                source: entry.db.source.clone(),
                signatures: entry.db.len(),
            })
            .collect()
    }

    /// One library's signatures, when the store holds it.
    pub fn get(&self, library: &str, arch: &str) -> Option<&SignatureDb> {
        self.libraries
            .get(&(library.to_string(), arch.to_string()))
            .map(|entry| &entry.db)
    }

    /// Merge a pushed database into the library it names and write the
    /// library's file. The file is written whole beside the old one and
    /// renamed over it, and the store only takes the merge once that has
    /// worked, so a failed write leaves memory and disk agreeing.
    pub fn push(&mut self, incoming: &SignatureDb) -> Result<PushReport> {
        validate(incoming).map_err(|e| anyhow!(e))?;
        let key = (incoming.library.clone(), incoming.arch.clone());
        let mut db = match self.libraries.get(&key) {
            Some(entry) => entry.db.clone(),
            None => SignatureDb::new(&incoming.library, &incoming.arch),
        };
        let Merge {
            added,
            filled,
            known,
        } = db.merge(incoming);
        if added > 0 || filled > 0 || !self.libraries.contains_key(&key) {
            let path = self.dir.join(file_name(&db.library, &db.arch));
            let scratch = path.with_extension("agsig.tmp");
            std::fs::write(&scratch, db.to_json())
                .and_then(|()| std::fs::rename(&scratch, &path))
                .with_context(|| format!("writing the signature file {}", path.display()))?;
        }
        let report = PushReport {
            library: db.library.clone(),
            arch: db.arch.clone(),
            added,
            filled,
            known,
            total: db.len(),
        };
        self.libraries.insert(key, Entry::new(db));
        Ok(report)
    }

    /// The signatures that carry any of `hashes` under `arch`: one database
    /// a library that knows at least one, in library order, each holding
    /// only what was asked for.
    pub fn matches(&self, arch: &str, hashes: &[String]) -> Vec<SignatureDb> {
        let mut out = Vec::new();
        for entry in self.libraries.values() {
            if entry.db.arch != arch {
                continue;
            }
            let mut found: Vec<usize> = hashes
                .iter()
                .filter_map(|hash| entry.index.get(hash).copied())
                .collect();
            found.sort_unstable();
            found.dedup();
            if found.is_empty() {
                continue;
            }
            let mut db = SignatureDb::new(&entry.db.library, &entry.db.arch);
            db.source = entry.db.source.clone();
            db.signatures = found
                .into_iter()
                .map(|at| entry.db.signatures[at].clone())
                .collect();
            out.push(db);
        }
        out
    }
}

/// How a server is run.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The token a push must carry. A server without one takes no pushes.
    pub token: Option<String>,
    /// Whether reading — listing, pulling, matching — needs the token too.
    pub private: bool,
}

struct State {
    store: Mutex<Store>,
    config: Config,
    active: AtomicUsize,
}

/// A bound signature server, ready to [`Server::run`].
pub struct Server {
    listener: TcpListener,
    state: Arc<State>,
}

impl Server {
    /// Bind `listen` (`127.0.0.1:7395`; port `0` takes a free one) over
    /// `store`.
    pub fn bind(listen: &str, store: Store, config: Config) -> Result<Server> {
        if config.private && config.token.is_none() {
            bail!("a private server needs a token: give --token or set {TOKEN_ENV}");
        }
        let listener =
            TcpListener::bind(listen).with_context(|| format!("listening on {listen}"))?;
        Ok(Server {
            listener,
            state: Arc::new(State {
                store: Mutex::new(store),
                config,
                active: AtomicUsize::new(0),
            }),
        })
    }

    /// The address the server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Serve until the process ends: a thread a connection, one request
    /// each.
    pub fn run(self) -> Result<()> {
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            let state = Arc::clone(&self.state);
            if state.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                state.active.fetch_sub(1, Ordering::SeqCst);
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut stream = stream;
                let _ = respond(&mut stream, &Answer::error(503, "the server is busy"));
                continue;
            }
            std::thread::spawn(move || {
                serve_connection(stream, &state);
                state.active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }
}

/// One parsed request.
struct Request {
    method: String,
    /// The path's segments, percent-decoded — read once, so the check of
    /// who may ask and the routing see the same path.
    segments: Vec<String>,
    token: Option<String>,
    body: Vec<u8>,
}

/// One answer: a status and a JSON body.
struct Answer {
    status: u16,
    body: String,
}

impl Answer {
    fn json(value: &impl Serialize) -> Answer {
        Answer {
            status: 200,
            body: serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
        }
    }

    fn error(status: u16, message: &str) -> Answer {
        Answer {
            status,
            body: serde_json::json!({ "error": message }).to_string(),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn respond(stream: &mut TcpStream, answer: &Answer) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        answer.status,
        reason(answer.status),
        answer.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(answer.body.as_bytes())?;
    stream.flush()
}

fn serve_connection(stream: TcpStream, state: &State) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let answer = match read_request(&mut reader, &state.config) {
        Ok(request) => handle(&request, state),
        Err(answer) => answer,
    };
    let _ = respond(&mut writer, &answer);
    // A request refused before its body was read still has bytes on the
    // way. Closing on them would reset the connection and could lose the
    // answer, so say we are done and let a little of the rest arrive.
    let _ = writer.shutdown(std::net::Shutdown::Write);
    let _ = writer.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = std::io::copy(&mut reader.take(1024 * 1024), &mut std::io::sink());
}

/// Read one line of a head, without its line ending, charging it to
/// `budget`. `None` when the connection ended, the line was not text, or
/// the head has run past its limit.
fn read_head_line(reader: &mut impl BufRead, budget: &mut usize) -> Option<String> {
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(*budget as u64 + 1)
        .read_until(b'\n', &mut line)
        .ok()?;
    if read == 0 || read > *budget || line.last() != Some(&b'\n') {
        return None;
    }
    *budget -= read;
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).ok()
}

/// The headers of a head, names lowercased, up to the blank line.
fn read_headers(reader: &mut impl BufRead, budget: &mut usize) -> Option<Vec<(String, String)>> {
    let mut headers = Vec::new();
    loop {
        let line = read_head_line(reader, budget)?;
        if line.is_empty() {
            return Some(headers);
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Whether a request changes the store. Reading is the short list — a `GET`
/// and the match — and anything else is held to the standard of a write.
fn is_write(method: &str, segments: &[String]) -> bool {
    let is_match = method == "POST" && segments.iter().map(String::as_str).eq(["v1", "match"]);
    method != "GET" && !is_match
}

/// Read one request. The head is read first and the request is authorized
/// on it, so a caller who may not ask is refused before any body is read,
/// and only a caller with the token gets to send a body the size of a push.
fn read_request(reader: &mut BufReader<TcpStream>, config: &Config) -> Result<Request, Answer> {
    let mut budget = MAX_HEAD;
    let too_large = || Answer::error(431, "the request head is malformed or too large");
    let line = read_head_line(reader, &mut budget).ok_or_else(too_large)?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Answer::error(400, "not an HTTP request"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Answer::error(400, "not an HTTP/1 request"));
    }
    let headers = read_headers(reader, &mut budget).ok_or_else(too_large)?;
    if header(&headers, "transfer-encoding").is_some() {
        return Err(Answer::error(411, "send the body with a Content-Length"));
    }
    let length = match header(&headers, "content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| Answer::error(400, "the Content-Length is not a number"))?,
        None => 0,
    };
    let token = header(&headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token.trim().to_string());
    // The query string, if any, is not part of any route.
    let segments: Option<Vec<String>> = target
        .split('?')
        .next()
        .unwrap_or(target)
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect();
    let mut request = Request {
        method: method.to_string(),
        segments: segments.ok_or_else(|| Answer::error(400, "the path is malformed"))?,
        token,
        body: Vec::new(),
    };
    let write = is_write(&request.method, &request.segments);
    authorize(&request, config, write)?;
    if length > if write { MAX_BODY } else { MAX_QUERY } {
        return Err(Answer::error(413, "the body is too large"));
    }
    // Read as the bytes arrive rather than setting the claimed length
    // aside, so a request costs only what it actually sends.
    let read = reader
        .by_ref()
        .take(length as u64)
        .read_to_end(&mut request.body);
    if read.ok() != Some(length) {
        return Err(Answer::error(400, "the body ended early"));
    }
    Ok(request)
}

/// Whether two tokens are the same, compared without stopping at the first
/// difference so the time taken does not say where they part.
fn same_token(given: &str, wanted: &str) -> bool {
    let (given, wanted) = (given.as_bytes(), wanted.as_bytes());
    let mut difference = given.len() ^ wanted.len();
    for (at, byte) in wanted.iter().enumerate() {
        difference |= usize::from(byte ^ given.get(at).copied().unwrap_or(0));
    }
    difference == 0
}

/// Whether the request may do what it asks: a write always needs the
/// server's token, a read only on a private server.
fn authorize(request: &Request, config: &Config, write: bool) -> Result<(), Answer> {
    if !write && !config.private {
        return Ok(());
    }
    let Some(wanted) = &config.token else {
        return Err(Answer::error(
            403,
            "this server is read-only: it was started without a token",
        ));
    };
    match &request.token {
        Some(given) if same_token(given, wanted) => Ok(()),
        _ => Err(Answer::error(401, "a valid token is needed")),
    }
}

/// `%41` read back to `A`. `None` for a malformed escape or bytes that are
/// not text.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = text.get(at + 1..at + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A path segment with everything but the unreserved characters escaped.
fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn handle(request: &Request, state: &State) -> Answer {
    let segments: Vec<&str> = request.segments.iter().map(String::as_str).collect();
    let method = request.method.as_str();
    let store = || state.store.lock().unwrap_or_else(|e| e.into_inner());
    // The request was authorized on its head, before its body was read.
    match (method, segments.as_slice()) {
        ("GET", [] | ["v1"]) => Answer::json(&serde_json::json!({
            "service": "admiralgrace-funcid",
            "protocol": PROTOCOL,
            "writable": state.config.token.is_some(),
            "private": state.config.private,
        })),
        ("GET", ["v1", "libraries"]) => Answer::json(&store().list()),
        ("GET", ["v1", "libraries", library, arch]) => match store().get(library, arch) {
            Some(db) => Answer::json(db),
            None => Answer::error(404, "the server holds no such library"),
        },
        ("POST", ["v1", "libraries"]) => {
            let parsed = std::str::from_utf8(&request.body)
                .map_err(|_| "the body is not text".to_string())
                .and_then(SignatureDb::parse)
                .and_then(|db| validate(&db).map(|()| db));
            match parsed {
                Err(e) => Answer::error(400, &e),
                Ok(db) => match store().push(&db) {
                    Ok(report) => Answer::json(&report),
                    Err(e) => {
                        eprintln!("ag funcid serve: {e:#}");
                        Answer::error(503, "the server could not store the signatures")
                    }
                },
            }
        }
        ("POST", ["v1", "match"]) => {
            let query: MatchRequest = match serde_json::from_slice(&request.body) {
                Ok(query) => query,
                Err(e) => return Answer::error(400, &format!("not a match request: {e}")),
            };
            if query.hashes.len() > MAX_HASHES {
                return Answer::error(413, "too many hashes in one request");
            }
            if !query.hashes.iter().all(|hash| valid_hash(hash)) {
                return Answer::error(400, "a hash is not 64 lowercase hex characters");
            }
            Answer::json(&MatchAnswer {
                databases: store().matches(&query.arch, &query.hashes),
            })
        }
        (_, [] | ["v1"] | ["v1", "libraries"] | ["v1", "libraries", _, _] | ["v1", "match"]) => {
            Answer::error(405, "the method is not one this path takes")
        }
        _ => Answer::error(404, "no such path"),
    }
}

/// A client of a signature server.
pub struct Client {
    /// `host:port`, as dialled and as the `Host` header says it.
    authority: String,
    /// The path the server's routes sit under, without a trailing slash;
    /// empty unless the URL named one.
    prefix: String,
    token: Option<String>,
    /// The URL as the analyst gave it, for messages.
    url: String,
}

impl Client {
    /// A client of the server at `url` — `http://host[:port][/prefix]`; the
    /// port is [`DEFAULT_PORT`] when not said. `https` is refused: the
    /// client speaks plain HTTP only.
    pub fn new(url: &str, token: Option<String>) -> Result<Client> {
        let trimmed = url.trim();
        if trimmed.starts_with("https://") {
            bail!(
                "{url}: the signature client speaks plain HTTP only; reach a remote server \
                 through an SSH tunnel or a private network and give its http:// address"
            );
        }
        let rest = trimmed
            .strip_prefix("http://")
            .unwrap_or(trimmed)
            .trim_end_matches('/');
        if rest.contains("://") {
            bail!("{url}: not an http:// address");
        }
        let (authority, prefix) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        if authority.is_empty() || authority.contains(['@', ' ', '\r', '\n']) {
            bail!("{url}: not a server address (http://host:port)");
        }
        if prefix.contains([' ', '\r', '\n', '?', '#']) {
            bail!("{url}: not a server address (http://host:port)");
        }
        // A port follows the last colon — unless that colon is inside an
        // IPv6 literal's brackets.
        let has_port = match authority.rfind(':') {
            Some(colon) => !authority[colon..].contains(']'),
            None => false,
        };
        let authority = if has_port {
            authority.to_string()
        } else {
            format!("{authority}:{DEFAULT_PORT}")
        };
        let token = token.filter(|t| !t.is_empty());
        if token
            .as_ref()
            .is_some_and(|t| t.contains(['\r', '\n']) || !t.is_ascii())
        {
            bail!("the token is not one a header can carry");
        }
        Ok(Client {
            authority,
            prefix: prefix.to_string(),
            token,
            url: url.to_string(),
        })
    }

    /// The libraries the server holds.
    pub fn libraries(&self) -> Result<Vec<LibraryInfo>> {
        let body = self.request("GET", "/v1/libraries", None)?;
        serde_json::from_slice(&body).with_context(|| self.garbled())
    }

    /// One library's signatures. What the server sends is checked like any
    /// other signature file — it is the server's word, not this program's.
    pub fn pull(&self, library: &str, arch: &str) -> Result<SignatureDb> {
        let path = format!(
            "/v1/libraries/{}/{}",
            percent_encode(library),
            percent_encode(arch)
        );
        let body = self.request("GET", &path, None)?;
        self.database(&body)
    }

    /// Push a signature database for the server to merge.
    pub fn push(&self, db: &SignatureDb) -> Result<PushReport> {
        validate(db).map_err(|e| anyhow!(e))?;
        let body = self.request("POST", "/v1/libraries", Some(db.to_json().into_bytes()))?;
        serde_json::from_slice(&body).with_context(|| self.garbled())
    }

    /// The signatures the server holds for any of `hashes` under `arch`: one
    /// database a library. Only the hashes leave this machine. Many hashes
    /// go in several requests, and a library answered in more than one comes
    /// back as one database.
    pub fn match_hashes(&self, arch: &str, hashes: &[String]) -> Result<Vec<SignatureDb>> {
        let mut out: Vec<SignatureDb> = Vec::new();
        for batch in hashes.chunks(MATCH_BATCH) {
            let query = MatchRequest {
                arch: arch.to_string(),
                hashes: batch.to_vec(),
            };
            let body = self.request("POST", "/v1/match", Some(serde_json::to_vec(&query)?))?;
            let answer: MatchAnswer =
                serde_json::from_slice(&body).with_context(|| self.garbled())?;
            for db in answer.databases {
                if db.format > ag_image::funcid::FORMAT {
                    bail!(
                        "{}: the server's signatures are in a format newer than this program reads",
                        self.url
                    );
                }
                validate(&db).map_err(|e| anyhow!("{}: {e}", self.url))?;
                match out.iter_mut().find(|held| held.library == db.library) {
                    Some(held) => {
                        held.merge(&db);
                    }
                    None => out.push(db),
                }
            }
        }
        Ok(out)
    }

    fn garbled(&self) -> String {
        format!(
            "{}: the server's answer is not one this program reads",
            self.url
        )
    }

    fn database(&self, body: &[u8]) -> Result<SignatureDb> {
        let text = std::str::from_utf8(body).with_context(|| self.garbled())?;
        SignatureDb::parse(text)
            .and_then(|db| validate(&db).map(|()| db))
            .map_err(|e| anyhow!("{}: {e}", self.url))
    }

    fn connect(&self) -> Result<TcpStream> {
        let addresses = self
            .authority
            .to_socket_addrs()
            .with_context(|| format!("finding the signature server {}", self.url))?;
        let mut last = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, Duration::from_secs(10)) {
                Ok(stream) => return Ok(stream),
                Err(e) => last = Some(e),
            }
        }
        match last {
            Some(e) => {
                Err(e).with_context(|| format!("connecting to the signature server {}", self.url))
            }
            None => bail!("{}: the address names no host", self.url),
        }
    }

    /// One request and its answer's body. An answer that is not a success
    /// is an error carrying what the server said.
    fn request(&self, method: &str, path: &str, body: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let mut stream = self.connect()?;
        stream.set_read_timeout(Some(IO_TIMEOUT * 2))?;
        stream.set_write_timeout(Some(IO_TIMEOUT * 2))?;
        let mut head = format!(
            "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n",
            self.prefix, self.authority
        );
        if let Some(token) = &self.token {
            head.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(body) = &body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        let talking = || format!("talking to the signature server {}", self.url);
        stream.write_all(head.as_bytes()).with_context(talking)?;
        if let Some(body) = &body {
            // The server may refuse and close before the whole body is
            // sent; its answer, read below, says why.
            let _ = stream.write_all(body);
        }
        let _ = stream.flush();

        let mut reader = BufReader::new(stream);
        let mut budget = MAX_HEAD;
        let garbled = || anyhow!("{}: not a signature server (no HTTP answer)", self.url);
        let status_line = read_head_line(&mut reader, &mut budget).ok_or_else(garbled)?;
        let status: u16 = status_line
            .strip_prefix("HTTP/1.")
            .and_then(|rest| rest.split(' ').nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or_else(garbled)?;
        let headers = read_headers(&mut reader, &mut budget).ok_or_else(garbled)?;
        let chunked = header(&headers, "transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
        let answer = if chunked {
            read_chunked(&mut reader)
        } else if let Some(length) = header(&headers, "content-length") {
            let length: usize = length.parse().map_err(|_| garbled())?;
            if length > MAX_ANSWER {
                bail!("{}: the server's answer is too large", self.url);
            }
            let mut answer = vec![0u8; length];
            reader.read_exact(&mut answer).map(|()| answer).ok()
        } else {
            let mut answer = Vec::new();
            reader
                .take(MAX_ANSWER as u64)
                .read_to_end(&mut answer)
                .map(|_| answer)
                .ok()
        };
        let answer = answer.ok_or_else(|| {
            anyhow!(
                "{}: the server's answer was cut short or too large",
                self.url
            )
        })?;
        if (200..300).contains(&status) {
            return Ok(answer);
        }
        let said = serde_json::from_slice::<serde_json::Value>(&answer)
            .ok()
            .and_then(|value| value["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| reason(status).to_string());
        if status == 401 {
            bail!(
                "{}: {said} (HTTP 401) — give --token or set {TOKEN_ENV}",
                self.url
            );
        }
        bail!("{}: {said} (HTTP {status})", self.url)
    }
}

/// A chunked body, as a proxy in front of the server may send it. `None`
/// when it is malformed, cut short or past the answer limit.
fn read_chunked(reader: &mut impl BufRead) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut budget = 256;
        let line = read_head_line(reader, &mut budget)?;
        let size = line.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        if out.len().checked_add(size)? > MAX_ANSWER {
            return None;
        }
        let start = out.len();
        out.resize(start + size, 0);
        reader.read_exact(&mut out[start..]).ok()?;
        let mut budget = 2;
        if !read_head_line(reader, &mut budget)?.is_empty() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_image::funcid::Signature;

    /// A fresh, empty directory for one test's store.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ag-sigserver-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn hash(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn signature(seed: u8, name: &str) -> Signature {
        Signature {
            hash: hash(seed),
            length: 8,
            name: name.to_string(),
            prototype: None,
            comment: None,
        }
    }

    fn database(library: &str, arch: &str, signatures: Vec<Signature>) -> SignatureDb {
        let mut db = SignatureDb::new(library, arch);
        db.signatures = signatures;
        db
    }

    /// A server over a fresh store, running on a free loopback port, and
    /// the address to reach it at.
    fn serve(tag: &str, config: Config) -> (String, PathBuf) {
        let dir = scratch(tag);
        let store = Store::open(&dir).expect("the store opens");
        let server = Server::bind("127.0.0.1:0", store, config).expect("the server binds");
        let url = format!("http://{}", server.local_addr().unwrap());
        std::thread::spawn(move || server.run());
        (url, dir)
    }

    fn token() -> Option<String> {
        Some("s3cret".to_string())
    }

    fn writable() -> Config {
        Config {
            token: token(),
            private: false,
        }
    }

    #[test]
    fn names_that_could_leave_the_store_are_refused() {
        for good in ["libc", "libstdc++", "x86-64", "msvcrt_14.2", "a"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", ".", "..", ".hidden", "a/b", "a\\b", "a@b", "a b", "ä"] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(!valid_name(&"a".repeat(MAX_NAME + 1)));
        let mut db = database("../etc", "x86-64", vec![]);
        assert!(validate(&db).is_err());
        db.library = "libc".to_string();
        assert!(validate(&db).is_ok());
        db.signatures.push(signature(1, "free"));
        assert!(validate(&db).is_ok());
        db.signatures[0].hash = "ABCD".to_string();
        assert!(validate(&db).is_err());
    }

    #[test]
    fn a_store_merges_pushes_and_reads_them_back_from_disk() {
        let dir = scratch("store");
        let mut store = Store::open(&dir).unwrap();
        let first = store
            .push(&database(
                "libc",
                "x86-64",
                vec![signature(1, "free"), signature(2, "malloc")],
            ))
            .unwrap();
        assert_eq!((first.added, first.known, first.total), (2, 0, 2));
        // A second push adds what is new and leaves the held name standing.
        let second = store
            .push(&database(
                "libc",
                "x86-64",
                vec![signature(2, "xmalloc"), signature(3, "strlen")],
            ))
            .unwrap();
        assert_eq!((second.added, second.known, second.total), (1, 1, 3));
        // The same library under another architecture is its own file.
        store
            .push(&database("libc", "x86", vec![signature(1, "free")]))
            .unwrap();
        assert!(dir.join("libc@x86-64.agsig").is_file());
        assert!(dir.join("libc@x86.agsig").is_file());

        let reopened = Store::open(&dir).unwrap();
        let listed = reopened.list();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1].arch, "x86-64");
        assert_eq!(listed[1].signatures, 3);
        let db = reopened.get("libc", "x86-64").unwrap();
        assert_eq!(db.signatures[1].name, "malloc");

        // A match answers only the hashes asked for, under the architecture
        // asked for.
        let found = reopened.matches("x86-64", &[hash(3), hash(9), hash(3)]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].library, "libc");
        assert_eq!(found[0].signatures.len(), 1);
        assert_eq!(found[0].signatures[0].name, "strlen");
        assert!(reopened.matches("aarch64", &[hash(3)]).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_pull_and_match_travel_over_the_wire() {
        let (url, dir) = serve("wire", writable());
        let client = Client::new(&url, token()).unwrap();
        assert!(client.libraries().unwrap().is_empty());

        let mut db = database(
            "libstdc++",
            "x86-64",
            vec![
                signature(1, "std::terminate()"),
                signature(2, "operator new"),
            ],
        );
        db.source = Some("a build".to_string());
        let report = client.push(&db).unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(report.total, 2);
        assert_eq!(client.push(&db).unwrap().added, 0);

        let listed = client.libraries().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].library, "libstdc++");
        assert_eq!(listed[0].signatures, 2);

        // The `+` of the name survives the path.
        let pulled = client.pull("libstdc++", "x86-64").unwrap();
        assert_eq!(pulled.signatures, db.signatures);
        assert_eq!(pulled.source, db.source);
        let missing = client.pull("libc", "x86-64").unwrap_err().to_string();
        assert!(missing.contains("404"), "{missing}");

        // A reader needs no token on a server that is not private.
        let reader = Client::new(&url, None).unwrap();
        let found = reader.match_hashes("x86-64", &[hash(2), hash(7)]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].signatures.len(), 1);
        assert_eq!(found[0].signatures[0].name, "operator new");
        assert!(reader.match_hashes("x86-64", &[]).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_push_needs_the_token_and_a_private_server_needs_it_to_read() {
        let db = database("libc", "x86-64", vec![signature(1, "free")]);

        // No token on the server: it takes no pushes at all.
        let (url, dir) = serve("readonly", Config::default());
        let refused = Client::new(&url, token()).unwrap().push(&db).unwrap_err();
        assert!(refused.to_string().contains("read-only"), "{refused}");
        assert!(Client::new(&url, None)
            .unwrap()
            .libraries()
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);

        // A token on the server: a push without it, or with another, is
        // refused and stores nothing.
        let (url, dir) = serve("token", writable());
        for wrong in [None, Some("s3cre".to_string()), Some("s3cret!".to_string())] {
            let refused = Client::new(&url, wrong).unwrap().push(&db).unwrap_err();
            assert!(refused.to_string().contains("401"), "{refused}");
        }
        assert!(Client::new(&url, None)
            .unwrap()
            .libraries()
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);

        // A private server: reading needs the token too.
        let (url, dir) = serve(
            "private",
            Config {
                token: token(),
                private: true,
            },
        );
        let anonymous = Client::new(&url, None).unwrap();
        assert!(anonymous.libraries().is_err());
        assert!(anonymous.match_hashes("x86-64", &[hash(1)]).is_err());
        let member = Client::new(&url, token()).unwrap();
        member.push(&db).unwrap();
        assert_eq!(member.match_hashes("x86-64", &[hash(1)]).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);

        // And a private server cannot be started without one.
        let store = Store::open(&scratch("private-no-token")).unwrap();
        let config = Config {
            token: None,
            private: true,
        };
        assert!(Server::bind("127.0.0.1:0", store, config).is_err());
    }

    /// Send raw bytes to the server and return the status of its answer.
    fn raw(url: &str, request: &[u8]) -> u16 {
        let mut stream = TcpStream::connect(url.trim_start_matches("http://")).unwrap();
        let _ = stream.write_all(request);
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    #[test]
    fn what_is_not_a_good_request_is_refused() {
        let (url, dir) = serve("refuse", writable());
        let client = Client::new(&url, token()).unwrap();

        // A library name that would leave the store never reaches the disk.
        let escape = serde_json::json!({
            "format": 1, "library": "../../escape", "arch": "x86-64", "signatures": []
        })
        .to_string();
        let refused = client
            .request("POST", "/v1/libraries", Some(escape.into_bytes()))
            .unwrap_err();
        assert!(refused.to_string().contains("400"), "{refused}");
        assert!(client.pull("..", "..").is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

        // A hash that is not a hash, and a body that is not a request.
        let bad = br#"{"arch":"x86-64","hashes":["nope"]}"#.to_vec();
        assert!(client.request("POST", "/v1/match", Some(bad)).is_err());
        assert!(client
            .request("POST", "/v1/match", Some(b"[]".to_vec()))
            .is_err());

        assert_eq!(raw(&url, b"GET /v1 HTTP/1.1\r\n\r\n"), 200);
        assert_eq!(raw(&url, b"GET /nowhere HTTP/1.1\r\n\r\n"), 404);
        // Anything that is not plainly a read is held to a write's
        // standard: the token first, and then it is still not a route. An
        // escaped path is the same path, not a way round the token.
        assert_eq!(raw(&url, b"DELETE /v1/libraries HTTP/1.1\r\n\r\n"), 401);
        assert_eq!(
            raw(
                &url,
                b"DELETE /v1/libraries HTTP/1.1\r\nAuthorization: Bearer s3cret\r\n\r\n"
            ),
            405
        );
        assert_eq!(
            raw(
                &url,
                b"POST /v1/librarie%73 HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
            ),
            401
        );
        assert_eq!(raw(&url, b"GET /v1/%zz HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(raw(&url, b"hello\r\n\r\n"), 400);
        // A body larger than the server reads is refused by its length,
        // before any of it is read.
        let huge = format!(
            "POST /v1/match HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_QUERY + 1
        );
        assert_eq!(raw(&url, huge.as_bytes()), 413);
        // A head that never ends is cut off at the limit.
        let mut long = b"GET /v1 HTTP/1.1\r\nX-Pad: ".to_vec();
        long.extend(vec![b'a'; MAX_HEAD + 16]);
        long.extend_from_slice(b"\r\n\r\n");
        assert_eq!(raw(&url, &long), 431);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_server_address_is_read_with_or_without_its_port() {
        let client = Client::new("http://sigs.example", None).unwrap();
        assert_eq!(client.authority, format!("sigs.example:{DEFAULT_PORT}"));
        let client = Client::new("sigs.example:9000/", None).unwrap();
        assert_eq!(client.authority, "sigs.example:9000");
        let client = Client::new("http://[::1]", None).unwrap();
        assert_eq!(client.authority, format!("[::1]:{DEFAULT_PORT}"));
        let client = Client::new("http://[::1]:9000/funcid/", None).unwrap();
        assert_eq!(client.authority, "[::1]:9000");
        assert_eq!(client.prefix, "/funcid");
        assert!(Client::new("https://sigs.example", None).is_err());
        assert!(Client::new("ftp://sigs.example", None).is_err());
        assert!(Client::new("http://", None).is_err());
        assert!(Client::new("http://ok", Some("a\r\nb".to_string())).is_err());
    }

    #[test]
    fn a_chunked_answer_is_read_whole() {
        let mut body = BufReader::new(&b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n"[..]);
        assert_eq!(read_chunked(&mut body).unwrap(), b"Wikipedia");
        let mut cut = BufReader::new(&b"9\r\nWiki"[..]);
        assert!(read_chunked(&mut cut).is_none());
    }

    #[test]
    fn tokens_are_compared_whole() {
        assert!(same_token("abc", "abc"));
        assert!(!same_token("abd", "abc"));
        assert!(!same_token("ab", "abc"));
        assert!(!same_token("abcd", "abc"));
        assert!(!same_token("", "abc"));
    }
}
