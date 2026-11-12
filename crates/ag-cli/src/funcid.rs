//! `ag funcid` — library identification by whole-function hash (#394).
//!
//! A library function is the same code in every program that links it, so it
//! can be named by a fingerprint of its body without lifting a line. These
//! subcommands make the signature files that hold the fingerprints
//! (`create`), read them back onto an image (`match`), and write what a match
//! knows — the name, the prototype, the comment — into a project (`apply`).
//! `list` reports the databases the engine ships.
//!
//! The signatures can also live on a shared server (#395, [`crate::sigserver`]):
//! `serve` runs one over a directory of signature files, `push` and `pull`
//! move files to and from it, and `--server` on `match`, `apply` and `list`
//! asks it — a match sends the functions' hashes, never their bytes.
//!
//! The fingerprint and its constraints are the engine's
//! ([`ag_image::funcid`]): the bytes that carry an address are masked before
//! hashing, so the same function matches at any load address. `create` takes
//! the prototypes from the built-in type libraries when a function's name is
//! one they know, so a libc signature carries `size_t strlen(const char *)`
//! and not just the name.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ag_image::funcid::{self, Signature, SignatureDb, SignatureSet};
use ag_image::Binary;
use anyhow::{Context, Result};
use clap::Subcommand;

use crate::project::RawArgs;
use crate::sigserver::{self, Client};

/// The server a command asks, and the token it shows.
#[derive(clap::Args, Clone, Default)]
pub struct ServerArgs {
    /// A signature server to ask as well: http://HOST[:PORT]. Only the
    /// functions' hashes are sent to it. May be repeated.
    #[arg(long = "server", value_name = "URL")]
    server: Vec<String>,
    /// The server's token, when it wants one to read. Better given in the
    /// AG_FUNCID_TOKEN environment variable than on a command line.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,
}

/// The token a command carries: `--token`, or the environment's.
fn token_of(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var(sigserver::TOKEN_ENV).ok())
        .filter(|token| !token.is_empty())
}

/// What to do with whole-function signatures.
#[derive(Subcommand)]
pub enum FuncidCmd {
    /// Write a signature file from an image whose functions are named: one
    /// whole-function hash a function, with its name and, when the type
    /// libraries know it, its prototype.
    Create {
        /// The program image to fingerprint — a library with symbols, such
        /// as libc.so.6, or any binary whose functions are named.
        binary: PathBuf,
        #[command(flatten)]
        raw: RawArgs,
        /// The signature file to write.
        #[arg(long, short)]
        out: PathBuf,
        /// The library's name; the file's stem when not said.
        #[arg(long)]
        library: Option<String>,
        /// Where the signatures came from, recorded in the file.
        #[arg(long)]
        source: Option<String>,
        /// Leave the prototypes out, even where the type libraries know them.
        #[arg(long)]
        no_types: bool,
        /// Report the summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Match an image's functions against signature files and report what
    /// each match knows. The built-in libc, libstdc++ and libgcc are read
    /// unless --no-builtin; --sig adds more. When several signatures know
    /// one function, the first is the match and the rest are named as
    /// alternatives.
    Match {
        /// The program image to identify.
        binary: PathBuf,
        #[command(flatten)]
        raw: RawArgs,
        /// A signature file to match against. May be repeated.
        #[arg(long = "sig", value_name = "FILE")]
        sig: Vec<PathBuf>,
        /// Leave the built-in databases out.
        #[arg(long)]
        no_builtin: bool,
        #[command(flatten)]
        server: ServerArgs,
        /// Report the matches as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write what the matches know into a project: the name, the prototype
    /// and the comment of each matched function. The analyst's own words are
    /// kept — a rename or a prototype already on a function stands.
    Apply {
        /// The program image to identify.
        binary: PathBuf,
        #[command(flatten)]
        raw: RawArgs,
        /// The project file the matches go to; made from the image when it
        /// is not there yet.
        #[arg(long)]
        project: PathBuf,
        /// A signature file to match against. May be repeated.
        #[arg(long = "sig", value_name = "FILE")]
        sig: Vec<PathBuf>,
        /// Leave the built-in databases out.
        #[arg(long)]
        no_builtin: bool,
        #[command(flatten)]
        server: ServerArgs,
        /// Report the summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The signature databases the engine ships, with their counts — or,
    /// with --server, the libraries a signature server holds.
    List {
        /// List what this signature server holds instead: http://HOST[:PORT].
        #[arg(long, value_name = "URL")]
        server: Option<String>,
        /// The server's token, when it wants one to read; AG_FUNCID_TOKEN
        /// when not given.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a signature server over a directory of signature files, for
    /// several analysts to push to, pull from and match against. Plain
    /// HTTP: keep it on a loopback, a private network or behind an SSH
    /// tunnel.
    Serve {
        /// The directory the server keeps its signature files in; made when
        /// not there. Signature files already in it are served.
        #[arg(long, value_name = "DIR")]
        store: PathBuf,
        /// The address to listen on.
        #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:7395")]
        listen: String,
        /// The token a push must carry; AG_FUNCID_TOKEN when not given. A
        /// server with no token is read-only.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// Ask for the token to list, pull and match as well as to push.
        #[arg(long)]
        private: bool,
    },
    /// Push signature files to a signature server, which merges each into
    /// the library it names: new hashes are added, and a hash the server
    /// already holds keeps its name.
    Push {
        /// The signature files to push.
        #[arg(required = true, value_name = "FILE")]
        files: Vec<PathBuf>,
        /// The signature server: http://HOST[:PORT].
        #[arg(long, value_name = "URL")]
        server: String,
        /// The server's token; AG_FUNCID_TOKEN when not given.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Pull a signature server's libraries into a directory as signature
    /// files, to match against offline with --sig.
    Pull {
        /// The signature server: http://HOST[:PORT].
        #[arg(long, value_name = "URL")]
        server: String,
        /// Pull only this library. May be repeated; all of them when not
        /// said.
        #[arg(long, value_name = "NAME")]
        library: Vec<String>,
        /// Pull only this architecture: x86-64, x86, aarch64, arm.
        #[arg(long, value_name = "ARCH")]
        arch: Option<String>,
        /// The directory the files are written to; made when not there.
        #[arg(long, short, value_name = "DIR", default_value = ".")]
        out: PathBuf,
        /// The server's token, when it wants one to read; AG_FUNCID_TOKEN
        /// when not given.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Run a `funcid` subcommand.
pub fn run(cmd: FuncidCmd) -> Result<i32> {
    match cmd {
        FuncidCmd::Create {
            binary,
            raw,
            out,
            library,
            source,
            no_types,
            json,
        } => create(&binary, raw, &out, library, source, !no_types, json),
        FuncidCmd::Match {
            binary,
            raw,
            sig,
            no_builtin,
            server,
            json,
        } => match_image(&binary, raw, &sig, !no_builtin, &server, json),
        FuncidCmd::Apply {
            binary,
            raw,
            project,
            sig,
            no_builtin,
            server,
            json,
        } => apply(&binary, raw, &project, &sig, !no_builtin, &server, json),
        FuncidCmd::List {
            server: None, json, ..
        } => list(json),
        FuncidCmd::List {
            server: Some(server),
            token,
            json,
        } => list_server(&server, token, json),
        FuncidCmd::Serve {
            store,
            listen,
            token,
            private,
        } => serve(&store, &listen, token, private),
        FuncidCmd::Push {
            files,
            server,
            token,
            json,
        } => push(&files, &server, token, json),
        FuncidCmd::Pull {
            server,
            library,
            arch,
            out,
            token,
            json,
        } => pull(&server, &library, arch.as_deref(), &out, token, json),
    }
}

/// One function's body, as the fingerprint reads it: its entry, its name and
/// its bytes from the entry to where the function ends.
struct Body {
    address: u64,
    name: String,
    bytes: Vec<u8>,
}

/// The bodies of the image's named functions, in address order. A function
/// runs to where the unwind data says it ends, or to the next function, or to
/// the end of its section — the same extent the listing reads. A name the
/// analysis made up (`sub_…`, `nullsub_…`) is left out: a signature is a
/// library's own name for a function, not a placeholder.
fn bodies(binary: &Binary) -> Vec<Body> {
    let mut functions: Vec<&ag_image::Function> = binary.functions().iter().collect();
    functions.sort_by_key(|f| f.address);
    functions.dedup_by_key(|f| f.address);
    let mut out = Vec::new();
    for (index, function) in functions.iter().enumerate() {
        if !is_library_name(&function.name) {
            continue;
        }
        let next = functions.get(index + 1).map(|f| f.address);
        let mut end = binary.function_end(function.address).unwrap_or(u64::MAX);
        if let Some(next) = next {
            end = end.min(next);
        }
        if let Some(section) = binary.section_of(function.address) {
            end = end.min(section.vma.saturating_add(section.size));
        }
        let length = end.saturating_sub(function.address) as usize;
        if length == 0 {
            continue;
        }
        if let Some(bytes) = binary.bytes_at(function.address, length) {
            out.push(Body {
                address: function.address,
                name: function.name.clone(),
                bytes,
            });
        }
    }
    out
}

/// Whether a function's name is one a signature can carry: a real name, not
/// the placeholder the analysis gives an unnamed function.
fn is_library_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && !name.starts_with("sub_")
        && !name.starts_with("nullsub_")
        && !name.starts_with("loc_")
        && !name.starts_with("unknown_")
}

/// Read one signature file.
fn read_sig(file: &Path) -> Result<SignatureDb> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading the signature file {}", file.display()))?;
    SignatureDb::parse(&text)
        .map_err(|e| anyhow::anyhow!("reading the signature file {}: {e}", file.display()))
}

/// The signature set the flags name: the built-ins unless told otherwise,
/// then each `--sig` file in order, then what each `--server` knows of the
/// image's functions. What is on this machine is consulted first, so a
/// server only adds to it — as the match of a function nothing local knows,
/// or as an alternative. A server is sent the hashes of the image's named
/// functions and nothing else.
fn load_set(
    image: &Binary,
    files: &[PathBuf],
    builtin: bool,
    server: &ServerArgs,
) -> Result<SignatureSet> {
    let mut databases = Vec::new();
    if builtin {
        databases.extend(SignatureSet::builtin().databases.iter().cloned());
    }
    for file in files {
        databases.push(read_sig(file)?);
    }
    if !server.server.is_empty() {
        let arch = funcid::arch_of_language(image.language());
        let hashes: Vec<String> = bodies(image)
            .iter()
            .map(|body| funcid::function_hash(&arch, &body.bytes, body.address))
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        let token = token_of(server.token.clone());
        for url in &server.server {
            let client = Client::new(url, token.clone())?;
            databases.extend(client.match_hashes(&arch, &hashes)?);
        }
    }
    Ok(SignatureSet::new(databases))
}

/// The C prototype of a known function, rendered from the type libraries'
/// own types: `size_t strlen(const char *s)`.
fn prototype_of(name: &str, model: ag_image::DataModel) -> Option<String> {
    let library = ag_image::propagate::library(model);
    let proto = library.prototype(name)?;
    let function = ag_image::Type::Function {
        ret: Box::new(proto.ret.clone()),
        params: proto.params.clone(),
        variadic: proto.variadic,
        attrs: proto.attrs.clone(),
    };
    Some(ag_image::types::declaration(
        &function,
        &proto.name,
        &library.store,
    ))
}

#[allow(clippy::too_many_arguments)]
fn create(
    binary: &Path,
    raw: RawArgs,
    out: &Path,
    library: Option<String>,
    source: Option<String>,
    types: bool,
    json: bool,
) -> Result<i32> {
    let image = crate::image::open_image(
        binary,
        raw.spec()?,
        raw.slice.clone(),
        None,
        Default::default(),
    )?;
    let arch = funcid::arch_of_language(image.language());
    let library = library.unwrap_or_else(|| {
        out.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "signatures".to_string())
    });
    let model = image.data_model();
    let mut db = SignatureDb::new(&library, &arch);
    db.source = source.or_else(|| Some(binary.display().to_string()));
    let mut seen = BTreeSet::new();
    let mut with_prototype = 0usize;
    for body in bodies(&image) {
        let hash = funcid::function_hash(&arch, &body.bytes, body.address);
        // Identical bodies — a thunk and its target, an alias — are one
        // signature; the first name at the first address keeps it.
        if !seen.insert(hash.clone()) {
            continue;
        }
        let prototype = if types {
            prototype_of(&body.name, model)
        } else {
            None
        };
        if prototype.is_some() {
            with_prototype += 1;
        }
        db.signatures.push(Signature {
            hash,
            length: body.bytes.len() as u64,
            name: body.name,
            prototype,
            comment: None,
        });
    }
    std::fs::write(out, db.to_json())
        .with_context(|| format!("writing the signature file {}", out.display()))?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "file": out.display().to_string(),
                "library": db.library,
                "arch": db.arch,
                "signatures": db.len(),
                "with_prototype": with_prototype,
            })
        );
    } else {
        println!(
            "{}: {} signatures ({} with a prototype), {} {}",
            out.display(),
            db.len(),
            with_prototype,
            db.library,
            db.arch,
        );
    }
    Ok(0)
}

/// One match, as the report and the JSON carry it: every signature that
/// knows the function, the first the one applied by default and the rest
/// the alternatives a chooser offers.
struct Matched<'a> {
    address: u64,
    image_name: String,
    candidates: Vec<funcid::Candidate<'a>>,
}

/// The image's functions that a signature knows, in address order.
fn matches<'a>(image: &Binary, set: &'a SignatureSet) -> Vec<Matched<'a>> {
    let arch = funcid::arch_of_language(image.language());
    let mut out = Vec::new();
    for body in bodies(image) {
        let candidates = set.match_candidates(&arch, &body.bytes, body.address);
        if !candidates.is_empty() {
            out.push(Matched {
                address: body.address,
                image_name: body.name,
                candidates,
            });
        }
    }
    out
}

fn match_image(
    binary: &Path,
    raw: RawArgs,
    files: &[PathBuf],
    builtin: bool,
    server: &ServerArgs,
    json: bool,
) -> Result<i32> {
    let image = crate::image::open_image(
        binary,
        raw.spec()?,
        raw.slice.clone(),
        None,
        Default::default(),
    )?;
    let set = load_set(&image, files, builtin, server)?;
    let found = matches(&image, &set);
    if json {
        let rows: Vec<serde_json::Value> = found
            .iter()
            .map(|m| {
                // The first candidate is the match applied by default; the
                // rest ride along as `alternatives` so a reader can choose.
                let first = m.candidates[0].signature;
                let alternatives: Vec<serde_json::Value> = m.candidates[1..]
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "library": c.library,
                            "name": c.signature.name,
                            "prototype": c.signature.prototype,
                            "comment": c.signature.comment,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "address": format!("{:#x}", m.address),
                    "image_name": m.image_name,
                    "name": first.name,
                    "prototype": first.prototype,
                    "comment": first.comment,
                    "hash": first.hash,
                    "library": m.candidates[0].library,
                    "alternatives": alternatives,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else if found.is_empty() {
        println!("{}: no library functions matched", binary.display());
    } else {
        println!(
            "{}: {} library functions matched",
            binary.display(),
            found.len()
        );
        for m in &found {
            let first = m.candidates[0].signature;
            print!("  {:#x}  {}", m.address, first.name);
            if let Some(prototype) = &first.prototype {
                print!("  {prototype}");
            }
            println!();
            // Several signatures know this function: name the alternatives
            // so the analyst can see there is a choice to make.
            for candidate in &m.candidates[1..] {
                println!(
                    "          also {} ({})",
                    candidate.signature.name, candidate.library
                );
            }
        }
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn apply(
    binary: &Path,
    raw: RawArgs,
    project: &Path,
    files: &[PathBuf],
    builtin: bool,
    server: &ServerArgs,
    json: bool,
) -> Result<i32> {
    use ag_corpus::project::{ProjectFile, Target, TargetKind};

    let file = if project.exists() {
        Some(ProjectFile::load(project).with_context(|| format!("reading {}", project.display()))?)
    } else {
        None
    };
    let image = crate::image::open_image(
        binary,
        raw.spec()?,
        raw.slice.clone(),
        file.as_ref(),
        Default::default(),
    )?;
    let set = load_set(&image, files, builtin, server)?;
    let found = matches(&image, &set);

    let mut file = file.unwrap_or_else(|| {
        let sha256 = ag_corpus::project::sha256_of(binary).ok();
        ProjectFile::new(Target {
            path: Some(binary.display().to_string()),
            sha256,
            raw: None,
            slice: None,
        })
    });
    let mut named = 0usize;
    let mut typed = 0usize;
    let mut commented = 0usize;
    for m in &found {
        // The first candidate is the one applied; the alternatives are the
        // workbench chooser's to offer, not the command line's to pick.
        let signature = m.candidates[0].signature;
        let key = format!("{:#x}", m.address);
        let annotation = file.annotation_mut(TargetKind::Function, &key);
        // The analyst's own words win: a rename or a prototype already on the
        // function stands, and a match only fills what is not said.
        if annotation.name.is_none() {
            annotation.name = Some(signature.name.clone());
            named += 1;
        }
        if annotation.prototype.is_none() {
            if let Some(prototype) = &signature.prototype {
                annotation.prototype = Some(prototype.clone());
                typed += 1;
            }
        }
        if annotation.comment.is_none() {
            if let Some(comment) = &signature.comment {
                annotation.comment = Some(comment.clone());
                commented += 1;
            }
        }
    }
    file.save(project)
        .with_context(|| format!("writing {}", project.display()))?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "project": project.display().to_string(),
                "matched": found.len(),
                "named": named,
                "typed": typed,
                "commented": commented,
            })
        );
    } else {
        println!(
            "{}: {} matched, {} named, {} typed, {} commented",
            project.display(),
            found.len(),
            named,
            typed,
            commented,
        );
    }
    Ok(0)
}

fn list(json: bool) -> Result<i32> {
    let set = SignatureSet::builtin();
    if json {
        let rows: Vec<serde_json::Value> = set
            .databases
            .iter()
            .map(|db| {
                serde_json::json!({
                    "library": db.library,
                    "arch": db.arch,
                    "source": db.source,
                    "signatures": db.len(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("built-in signature databases:");
        for db in &set.databases {
            println!(
                "  {:<12} {:<8} {} signatures",
                db.library,
                db.arch,
                db.len()
            );
            if let Some(source) = &db.source {
                println!("               from {source}");
            }
        }
    }
    Ok(0)
}

/// Run a signature server over `store` until the process is stopped.
fn serve(store: &Path, listen: &str, token: Option<String>, private: bool) -> Result<i32> {
    use std::io::Write as _;

    let token = token_of(token);
    let writable = token.is_some();
    let held = sigserver::Store::open(store)?;
    let (libraries, signatures) = {
        let listed = held.list();
        (
            listed.len(),
            listed.iter().map(|l| l.signatures).sum::<usize>(),
        )
    };
    let server = sigserver::Server::bind(listen, held, sigserver::Config { token, private })?;
    let address = server.local_addr()?;
    println!("signature server listening on http://{address}");
    println!(
        "  store {}: {libraries} libraries, {signatures} signatures",
        store.display()
    );
    println!(
        "  {}",
        match (writable, private) {
            (false, _) => "read-only: no token was given, so pushes are refused",
            (true, false) => "anyone may list, pull and match; a push needs the token",
            (true, true) => "private: every request needs the token",
        }
    );
    if !address.ip().is_loopback() {
        println!(
            "  note: plain HTTP on a non-loopback address — hashes, signatures and the token \
             travel unencrypted; keep this to a network you trust"
        );
    }
    // A reader waiting on the address — a script, a test — gets it now.
    std::io::stdout().flush()?;
    server.run()?;
    Ok(0)
}

fn push(files: &[PathBuf], server: &str, token: Option<String>, json: bool) -> Result<i32> {
    let client = Client::new(server, token_of(token))?;
    // Read every file before sending any, so a bad file stops the push
    // before the server has taken half of it.
    let databases: Vec<SignatureDb> = files
        .iter()
        .map(|file| {
            let db = read_sig(file)?;
            sigserver::validate(&db).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
            Ok(db)
        })
        .collect::<Result<_>>()?;
    let mut reports = Vec::new();
    for db in &databases {
        reports.push(client.push(db)?);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        for report in &reports {
            println!(
                "{} {}: {} added, {} filled, {} already known; the server holds {}",
                report.library,
                report.arch,
                report.added,
                report.filled,
                report.known,
                report.total,
            );
        }
    }
    Ok(0)
}

fn pull(
    server: &str,
    libraries: &[String],
    arch: Option<&str>,
    out: &Path,
    token: Option<String>,
    json: bool,
) -> Result<i32> {
    let client = Client::new(server, token_of(token))?;
    let wanted: Vec<sigserver::LibraryInfo> = client
        .libraries()?
        .into_iter()
        .filter(|held| libraries.is_empty() || libraries.contains(&held.library))
        .filter(|held| arch.is_none_or(|arch| held.arch == arch))
        .collect();
    if let Some(missing) = libraries
        .iter()
        .find(|name| !wanted.iter().any(|held| &held.library == *name))
    {
        anyhow::bail!("{server}: the server holds no library {missing} to pull");
    }
    std::fs::create_dir_all(out).with_context(|| format!("making {}", out.display()))?;
    let mut rows = Vec::new();
    for held in &wanted {
        // The names are the server's word, and they are about to name a
        // file: nothing that is not a plain name gets to.
        if !sigserver::valid_name(&held.library) || !sigserver::valid_name(&held.arch) {
            anyhow::bail!(
                "{server}: the server names a library {:?} ({:?}) that is not a plain name",
                held.library,
                held.arch
            );
        }
        let db = client.pull(&held.library, &held.arch)?;
        if db.library != held.library || db.arch != held.arch {
            anyhow::bail!(
                "{server}: asked for {} {} and was sent {} {}",
                held.library,
                held.arch,
                db.library,
                db.arch
            );
        }
        let path = out.join(sigserver::file_name(&db.library, &db.arch));
        std::fs::write(&path, db.to_json())
            .with_context(|| format!("writing the signature file {}", path.display()))?;
        rows.push((path, db));
    }
    if json {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(path, db)| {
                serde_json::json!({
                    "file": path.display().to_string(),
                    "library": db.library,
                    "arch": db.arch,
                    "source": db.source,
                    "signatures": db.len(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else if rows.is_empty() {
        println!("{server}: nothing to pull");
    } else {
        for (path, db) in &rows {
            println!(
                "{}: {} signatures, {} {}",
                path.display(),
                db.len(),
                db.library,
                db.arch
            );
        }
    }
    Ok(0)
}

/// The libraries a signature server holds.
fn list_server(server: &str, token: Option<String>, json: bool) -> Result<i32> {
    let held = Client::new(server, token_of(token))?.libraries()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&held)?);
    } else if held.is_empty() {
        println!("{server}: the server holds no signatures yet");
    } else {
        println!("{server}:");
        for library in &held {
            println!(
                "  {:<12} {:<8} {} signatures",
                library.library, library.arch, library.signatures
            );
            if let Some(source) = &library.source {
                println!("               from {source}");
            }
        }
    }
    Ok(0)
}
