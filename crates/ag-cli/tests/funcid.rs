//! `ag funcid`: whole-function library identification, run against the
//! fixtures. A signature file made from an image matches that image back,
//! and what a match knows lands in a project as the analyst's annotations.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ag-engine/tests/fixtures")
        .join(name)
}

/// A unique temporary path stem, so parallel tests do not share a file.
fn stem(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ag-cli-funcid-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ))
}

/// Run `ag` with `args`, returning its stdout, and assert it succeeded.
fn ag(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(args)
        .output()
        .expect("the ag binary runs");
    assert!(
        output.status.success(),
        "ag {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_signature_file_made_from_an_image_matches_it_back() {
    let sig = stem("roundtrip").with_extension("agsig");
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();

    // Make a signature file from the fixture's own named functions.
    let report = ag(&[
        "funcid",
        "create",
        binary,
        "-o",
        sig.to_str().unwrap(),
        "--library",
        "sample",
    ]);
    assert!(report.contains("signatures"), "{report}");
    let made = std::fs::read_to_string(&sig).expect("the signature file");
    let db: serde_json::Value = serde_json::from_str(&made).expect("the file is JSON");
    assert_eq!(db["library"], "sample");
    assert_eq!(db["arch"], "x86-64");
    let count = db["signatures"].as_array().expect("signatures").len();
    assert!(count > 0, "the fixture has named functions");

    // Match the fixture against its own signatures, built-ins left out so
    // only the file we just made answers.
    let json = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--sig",
        sig.to_str().unwrap(),
        "--json",
    ]);
    let matches: serde_json::Value = serde_json::from_str(&json).expect("matches are JSON");
    let matches = matches.as_array().expect("an array of matches");
    assert!(
        !matches.is_empty(),
        "the fixture matches its own signatures"
    );
    // Every matched name is one the signature file carries, and the hash is
    // the whole-function hash the file holds.
    let names: std::collections::BTreeSet<&str> = db["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    for m in matches {
        assert!(names.contains(m["name"].as_str().unwrap()), "{m}");
        assert_eq!(m["hash"].as_str().unwrap().len(), 64, "{m}");
    }
    // main is among the matched functions.
    assert!(matches.iter().any(|m| m["name"] == "main"), "{json}");

    let _ = std::fs::remove_file(&sig);
}

#[test]
fn apply_writes_what_a_match_knows_and_keeps_the_analysts_words() {
    let sig = stem("apply").with_extension("agsig");
    let project = stem("apply").with_extension("agproj");
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();
    let sig_arg = sig.to_str().unwrap();
    let project_arg = project.to_str().unwrap();

    ag(&[
        "funcid",
        "create",
        binary,
        "-o",
        sig_arg,
        "--library",
        "sample",
    ]);

    // Give main's signature a prototype and a comment, so the apply step is
    // tested on all three things a match can know — the name, the type and
    // the comment — without depending on the type libraries knowing the
    // fixture's own functions.
    let mut db: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig).expect("the signature file"))
            .expect("the file is JSON");
    for s in db["signatures"].as_array_mut().unwrap() {
        if s["name"] == "main" {
            s["prototype"] = serde_json::json!("int main(int argc, char **argv)");
            s["comment"] = serde_json::json!("the program entry point");
        }
    }
    std::fs::write(&sig, serde_json::to_string_pretty(&db).unwrap()).expect("write signatures");

    // Apply onto a project that does not exist yet: it is made, and the
    // matched functions take their names, prototypes and comments.
    let report = ag(&[
        "funcid",
        "apply",
        binary,
        "--project",
        project_arg,
        "--no-builtin",
        "--sig",
        sig_arg,
    ]);
    assert!(report.contains("matched"), "{report}");
    let text = std::fs::read_to_string(&project).expect("the project");
    let proj: serde_json::Value = serde_json::from_str(&text).expect("the project is JSON");
    let annotations = proj["annotations"].as_array().expect("annotations");
    let main = annotations
        .iter()
        .find(|a| a["kind"] == "function" && a["name"] == "main")
        .unwrap_or_else(|| panic!("main is named: {text}"));
    assert_eq!(
        main["prototype"], "int main(int argc, char **argv)",
        "{text}"
    );
    assert_eq!(main["comment"], "the program entry point", "{text}");

    // The analyst's words win: rename main, apply again, and the rename
    // stands — the second pass names nothing new.
    let mut proj = proj;
    for a in proj["annotations"].as_array_mut().unwrap() {
        if a["name"] == "main" {
            a["name"] = serde_json::json!("analyst_main");
        }
    }
    std::fs::write(&project, serde_json::to_string_pretty(&proj).unwrap()).expect("write project");
    let again = ag(&[
        "funcid",
        "apply",
        binary,
        "--project",
        project_arg,
        "--no-builtin",
        "--sig",
        sig_arg,
        "--json",
    ]);
    let summary: serde_json::Value = serde_json::from_str(&again).expect("summary is JSON");
    assert_eq!(summary["named"], 0, "the analyst's names stand: {again}");
    let text = std::fs::read_to_string(&project).expect("the project");
    assert!(text.contains("analyst_main"), "the rename is kept: {text}");

    let _ = std::fs::remove_file(&sig);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn several_signatures_for_one_function_are_reported_as_alternatives() {
    let alpha = stem("alt-alpha").with_extension("agsig");
    let beta = stem("alt-beta").with_extension("agsig");
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();

    // Two databases that carry the same whole-function hash for main under
    // different names and library labels: the ambiguity a chooser resolves.
    for (file, library) in [(&alpha, "alpha"), (&beta, "beta")] {
        ag(&[
            "funcid",
            "create",
            binary,
            "-o",
            file.to_str().unwrap(),
            "--library",
            library,
        ]);
    }
    let mut db: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&beta).expect("the beta file"))
            .expect("the file is JSON");
    for s in db["signatures"].as_array_mut().unwrap() {
        if s["name"] == "main" {
            s["name"] = serde_json::json!("main_beta");
        }
    }
    std::fs::write(&beta, serde_json::to_string_pretty(&db).unwrap()).expect("write beta");

    // Match against both, alpha consulted first: main matches alpha's name,
    // and beta's is named as an alternative.
    let json = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--sig",
        alpha.to_str().unwrap(),
        "--sig",
        beta.to_str().unwrap(),
        "--json",
    ]);
    let matches: serde_json::Value = serde_json::from_str(&json).expect("matches are JSON");
    let main = matches
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["image_name"] == "main")
        .unwrap_or_else(|| panic!("main matched: {json}"));
    assert_eq!(main["name"], "main", "the first database wins: {json}");
    assert_eq!(main["library"], "alpha", "{json}");
    let alternatives = main["alternatives"].as_array().expect("alternatives");
    assert!(
        alternatives
            .iter()
            .any(|a| a["name"] == "main_beta" && a["library"] == "beta"),
        "beta's name is an alternative: {json}"
    );

    // The text report names the alternative too.
    let text = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--sig",
        alpha.to_str().unwrap(),
        "--sig",
        beta.to_str().unwrap(),
    ]);
    assert!(text.contains("also main_beta (beta)"), "{text}");

    // Apply takes the first candidate, as before.
    let project = stem("alt-apply").with_extension("agproj");
    ag(&[
        "funcid",
        "apply",
        binary,
        "--project",
        project.to_str().unwrap(),
        "--no-builtin",
        "--sig",
        alpha.to_str().unwrap(),
        "--sig",
        beta.to_str().unwrap(),
    ]);
    let proj: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&project).expect("the project"))
            .expect("the project is JSON");
    let named = proj["annotations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["kind"] == "function" && a["name"] == "main");
    assert!(
        named.is_some(),
        "the first candidate's name is applied: {proj}"
    );

    let _ = std::fs::remove_file(&alpha);
    let _ = std::fs::remove_file(&beta);
    let _ = std::fs::remove_file(&project);
}

#[test]
fn the_builtin_databases_are_listed_with_their_counts() {
    let json = ag(&["funcid", "list", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&json).expect("list is JSON");
    let rows = rows.as_array().expect("an array of databases");
    for library in ["libc", "libstdc++", "libgcc"] {
        let db = rows
            .iter()
            .find(|d| d["library"] == library)
            .unwrap_or_else(|| panic!("the built-ins list {library}"));
        assert_eq!(db["arch"], "x86-64");
        assert!(
            db["signatures"].as_u64().unwrap() > 0,
            "{library} has signatures"
        );
    }
}

/// A running `ag funcid serve`, stopped when it goes out of scope.
struct SigServer {
    child: std::process::Child,
    url: String,
    store: PathBuf,
}

impl SigServer {
    /// Start a server over a fresh store on a free loopback port, taking
    /// pushes that carry `token`, and read its address off its first line.
    fn start(tag: &str, token: &str) -> SigServer {
        use std::io::BufRead;

        let store = stem(tag).with_extension("store");
        let _ = std::fs::remove_dir_all(&store);
        let mut child = Command::new(env!("CARGO_BIN_EXE_ag"))
            .args(["funcid", "serve", "--listen", "127.0.0.1:0", "--store"])
            .arg(&store)
            .env("AG_FUNCID_TOKEN", token)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("the server starts");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().expect("the server's stdout"))
            .read_line(&mut line)
            .expect("the server says where it listens");
        let url = line
            .trim()
            .rsplit(' ')
            .next()
            .expect("an address")
            .to_string();
        assert!(url.starts_with("http://127.0.0.1:"), "{line}");
        SigServer { child, url, store }
    }
}

impl Drop for SigServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.store);
    }
}

#[test]
fn signatures_are_pushed_to_pulled_from_and_matched_against_a_server() {
    let server = SigServer::start("server", "s3cret");
    let url = server.url.as_str();
    let sig = stem("server").with_extension("agsig");
    let sig_arg = sig.to_str().unwrap();
    let pulled = stem("server").with_extension("pulled");
    let binary = fixture("sample.elf");
    let binary = binary.to_str().unwrap();

    ag(&[
        "funcid",
        "create",
        binary,
        "-o",
        sig_arg,
        "--library",
        "sample",
    ]);
    let made: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig).unwrap()).unwrap();
    let count = made["signatures"].as_array().unwrap().len();

    // Nothing local knows the fixture, and the server holds nothing yet.
    let none = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--server",
        url,
        "--json",
    ]);
    assert_eq!(none.trim(), "[]", "{none}");

    // A push without the token is refused and stores nothing.
    let refused = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["funcid", "push", sig_arg, "--server", url])
        .env_remove("AG_FUNCID_TOKEN")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("token"), "{stderr}");
    let listed = ag(&["funcid", "list", "--server", url, "--json"]);
    assert_eq!(listed.trim(), "[]", "{listed}");

    // With it, the server takes every signature — once.
    let report = ag(&[
        "funcid", "push", sig_arg, "--server", url, "--token", "s3cret", "--json",
    ]);
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(report[0]["library"], "sample");
    assert_eq!(report[0]["added"], count);
    assert_eq!(report[0]["total"], count);
    let again = ag(&[
        "funcid", "push", sig_arg, "--server", url, "--token", "s3cret", "--json",
    ]);
    let again: serde_json::Value = serde_json::from_str(&again).unwrap();
    assert_eq!(again[0]["added"], 0);
    assert_eq!(again[0]["known"], count);

    // Anyone can now list it, and match against it with no signature file
    // on this machine: the server names the fixture's functions.
    let listed = ag(&["funcid", "list", "--server", url, "--json"]);
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed[0]["library"], "sample");
    assert_eq!(listed[0]["arch"], "x86-64");
    assert_eq!(listed[0]["signatures"], count);
    let json = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--server",
        url,
        "--json",
    ]);
    let matches: serde_json::Value = serde_json::from_str(&json).unwrap();
    let matches = matches.as_array().unwrap();
    assert!(matches.iter().any(|m| m["name"] == "main"), "{json}");
    assert!(matches.iter().all(|m| m["library"] == "sample"), "{json}");
    // The server answers what the file itself would.
    let local = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--sig",
        sig_arg,
        "--json",
    ]);
    assert_eq!(json, local);

    // apply reads the server the same way.
    let project = stem("server").with_extension("agproj");
    let project_arg = project.to_str().unwrap();
    let applied = ag(&[
        "funcid",
        "apply",
        binary,
        "--project",
        project_arg,
        "--no-builtin",
        "--server",
        url,
        "--json",
    ]);
    let applied: serde_json::Value = serde_json::from_str(&applied).unwrap();
    assert_eq!(applied["matched"], matches.len());
    assert!(applied["named"].as_u64().unwrap() > 0, "{applied}");

    // A pull brings the library back as a signature file that matches
    // offline, signature for signature what was pushed.
    let out = ag(&[
        "funcid",
        "pull",
        "--server",
        url,
        "-o",
        pulled.to_str().unwrap(),
        "--json",
    ]);
    let out: serde_json::Value = serde_json::from_str(&out).unwrap();
    let file = pulled.join("sample@x86-64.agsig");
    assert_eq!(out[0]["file"], file.to_str().unwrap());
    let back: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(back["signatures"], made["signatures"]);
    let offline = ag(&[
        "funcid",
        "match",
        binary,
        "--no-builtin",
        "--sig",
        file.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(offline, local);
    // A library the server does not hold is an error, not an empty pull.
    let missing = Command::new(env!("CARGO_BIN_EXE_ag"))
        .args(["funcid", "pull", "--server", url, "--library", "nope", "-o"])
        .arg(&pulled)
        .output()
        .unwrap();
    assert!(!missing.status.success());

    let _ = std::fs::remove_file(&sig);
    let _ = std::fs::remove_file(&project);
    let _ = std::fs::remove_dir_all(&pulled);
}
