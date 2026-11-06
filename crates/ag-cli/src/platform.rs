//! `ag platform` — the platform types an image reads under (#378).
//!
//! A platform is an OS and an architecture (`windows/x86-64`,
//! `linux/aarch64`, `macos/arm64`); each ships default C types in
//! [`ag_image::platform_types`]. The analyst extends them in a file per
//! platform under `$XDG_CONFIG_HOME/ag/platform/<platform>.h` (or
//! `~/.config/ag/platform/`). `list` names the platforms the engine
//! knows, `show` prints one's defaults and its user types, `path`
//! prints where the analyst edits them.

use anyhow::{Context, Result};
use clap::Subcommand;

use ag_image::platform_types::{self as engine_platform, Os, Platform};

/// Everything the engine knows about a platform.
const KNOWN: [Platform; 6] = [
    Platform { os: Os::Windows, arch: "x86-64" },
    Platform { os: Os::Windows, arch: "x86" },
    Platform { os: Os::Linux, arch: "x86-64" },
    Platform { os: Os::Linux, arch: "aarch64" },
    Platform { os: Os::Macos, arch: "x86-64" },
    Platform { os: Os::Macos, arch: "aarch64" },
];

#[derive(Subcommand)]
pub enum PlatformCmd {
    /// List the platforms the engine ships defaults for.
    List {
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show one platform's defaults and the user types layered on them.
    Show {
        /// The platform: `windows/x86-64`, `linux/aarch64`, `macos/arm64`.
        platform: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the file the platform's user types live in, and create it
    /// with a comment when it is not there.
    Path {
        /// The platform: `windows/x86-64`, `linux/aarch64`, `macos/arm64`.
        platform: String,
    },
}

pub fn run(cmd: PlatformCmd) -> Result<i32> {
    match cmd {
        PlatformCmd::List { json } => {
            if json {
                let rows: Vec<serde_json::Value> = KNOWN
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "platform": p.name(),
                            "os": p.os.as_str(),
                            "arch": p.arch,
                            "data_model": p.data_model().name,
                            "user_path": engine_platform::user_path(*p).map(|x| x.to_string_lossy().into_owned()),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for p in KNOWN {
                    println!(
                        "{}  {}  user types: {}",
                        p.name(),
                        p.data_model().name,
                        engine_platform::user_path(p).map(|x| x.display().to_string()).unwrap_or_else(|| "(no home)".to_string())
                    );
                }
            }
            Ok(0)
        }
        PlatformCmd::Show { platform, json } => {
            let p = Platform::parse(&platform)
                .ok_or_else(|| anyhow::anyhow!("{platform:?} is not a platform: try windows/x86-64, linux/aarch64 or macos/arm64"))?;
            let defaults = engine_platform::defaults(p);
            let mut user: Vec<ag_image::TypeText> = Vec::new();
            for candidate in p.candidates() {
                user.extend(engine_platform::user_definitions(candidate));
            }
            let user = engine_platform::merged(&[&user]);
            if json {
                let show = |defs: &[ag_image::TypeText]| -> Vec<serde_json::Value> {
                    defs.iter().map(|d| serde_json::json!({"name": d.name, "c": d.c})).collect()
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "platform": p.name(),
                        "data_model": p.data_model().name,
                        "defaults": show(&defaults),
                        "user": show(&user),
                        "user_path": engine_platform::user_path(p).map(|x| x.to_string_lossy().into_owned()),
                    }))?
                );
            } else {
                println!("platform: {}", p.name());
                println!("data model: {}", p.data_model().name);
                println!("user types: {}", engine_platform::user_path(p).map(|x| x.display().to_string()).unwrap_or_else(|| "(no home)".to_string()));
                println!();
                if defaults.is_empty() {
                    println!("(no default types for this platform)");
                }
                for d in &defaults {
                    println!("{}\n", d.c);
                }
                if !user.is_empty() {
                    println!("--- user types ---");
                    for d in &user {
                        println!("{}\n", d.c);
                    }
                }
            }
            Ok(0)
        }
        PlatformCmd::Path { platform } => {
            let p = Platform::parse(&platform)
                .ok_or_else(|| anyhow::anyhow!("{platform:?} is not a platform: try windows/x86-64, linux/aarch64 or macos/arm64"))?;
            let path = engine_platform::user_path(p).ok_or_else(|| anyhow::anyhow!("no home directory to put the user types in"))?;
            if !path.exists() {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
                }
                std::fs::write(&path, format!(
                    "// {} user types (#378).\n// Added to the platform's default types on every read;\n// a definition here wins over a default of the same name.\n",
                    p.name()
                ))
                .with_context(|| format!("writing {}", path.display()))?;
            }
            println!("{}", path.display());
            Ok(0)
        }
    }
}
