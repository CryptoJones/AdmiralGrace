//! `ag plugins` and `ag tool`: what the plugins add, and a plugin's tool
//! run from the command line.

use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};

use anyhow::Result;
use serde_json::{json, Value};

use ag_image::plugin::Manifest;

fn remembered() -> &'static Mutex<Vec<Manifest>> {
    static MANIFESTS: OnceLock<Mutex<Vec<Manifest>>> = OnceLock::new();
    MANIFESTS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Keep the manifests read as the program started, for the listing.
pub fn remember(manifests: Vec<Manifest>) {
    *remembered().lock().unwrap_or_else(PoisonError::into_inner) = manifests;
}

/// List the plugins: every loader, architecture, tool and rewriter
/// registered, and the manifests they were read from.
pub fn list(json: bool) -> Result<i32> {
    let manifests = remembered()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let loaders: Vec<String> = ag_image::plugin::loaders()
        .iter()
        .map(|loader| loader.name().to_string())
        .collect();
    let architectures: Vec<Value> = ag_image::plugin::architectures()
        .iter()
        .map(|arch| {
            json!({
                "name": arch.name(),
                "languages": arch.languages(),
                "lifts": arch.languages().iter().any(|language| arch.lifts(language)),
            })
        })
        .collect();
    let tools: Vec<Value> = ag_image::plugin::tools()
        .iter()
        .map(|tool| json!({ "name": tool.name(), "description": tool.description() }))
        .collect();
    let rewriters: Vec<String> = ag_image::plugin::rewriters()
        .iter()
        .map(|rewriter| rewriter.name().to_string())
        .collect();
    if json {
        let report = json!({
            "directories": ag_image::plugin::manifest_dirs(),
            "manifests": manifests.iter().map(|manifest| json!({
                "name": manifest.name,
                "path": manifest.path,
                "loaders": manifest.loaders.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
                "architectures": manifest.architectures.iter().map(|a| a.name.clone()).collect::<Vec<_>>(),
                "tools": manifest.tools.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
                "rewriters": manifest.rewriters.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
            })).collect::<Vec<Value>>(),
            "loaders": loaders,
            "architectures": architectures,
            "tools": tools,
            "rewriters": rewriters,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }
    println!("plugin directories:");
    for dir in ag_image::plugin::manifest_dirs() {
        println!("  {}", dir.display());
    }
    if manifests.is_empty() {
        println!("manifests: none");
    } else {
        println!("manifests:");
        for manifest in &manifests {
            println!("  {} ({})", manifest.name, manifest.path.display());
        }
    }
    let listed = |what: &str, names: Vec<String>| {
        if names.is_empty() {
            println!("{what}: none");
        } else {
            println!("{what}: {}", names.join(", "));
        }
    };
    listed("loaders", loaders);
    listed(
        "architectures",
        architectures
            .iter()
            .map(|arch| {
                format!(
                    "{} ({})",
                    arch["name"].as_str().unwrap_or_default(),
                    arch["languages"]
                        .as_array()
                        .map(|languages| languages
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", "))
                        .unwrap_or_default()
                )
            })
            .collect(),
    );
    if tools.is_empty() {
        println!("tools: none");
    } else {
        println!("tools:");
        for tool in &tools {
            println!(
                "  {}: {}",
                tool["name"].as_str().unwrap_or_default(),
                tool["description"].as_str().unwrap_or_default()
            );
        }
    }
    listed("rewriters", rewriters);
    Ok(0)
}

/// Run the tool `name` over the image, with `arguments` as `name=value`
/// pairs, and print its answer: JSON pretty, or the text it is.
pub fn tool(
    name: &str,
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&Path>,
    options: Vec<String>,
    arguments: &[String],
) -> Result<i32> {
    let tool = ag_image::plugin::tool(name).ok_or_else(|| {
        anyhow::anyhow!("no tool is called {name:?}; `ag plugins` lists the tools")
    })?;
    let mut given = serde_json::Map::new();
    for argument in arguments {
        let (key, value) = argument
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("an argument reads name=value, not {argument:?}"))?;
        let value =
            serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()));
        given.insert(key.trim().to_string(), value);
    }
    let options =
        ag_image::Options::from_flat(&options).map_err(|error| anyhow::anyhow!("{error}"))?;
    let project_file = match project {
        Some(path) if path.exists() => Some(ag_corpus::project::ProjectFile::load(path)?),
        _ => None,
    };
    let image = crate::image::open_image(binary, raw, slice, project_file.as_ref(), options)?;
    let context = ag_image::plugin::ToolContext {
        image_path: Some(binary.to_path_buf()),
        project_path: project.map(Path::to_path_buf),
    };
    match tool.run(&image, &context, &Value::Object(given)) {
        Ok(Value::String(text)) => {
            println!("{text}");
            Ok(0)
        }
        Ok(answer) => {
            println!("{}", serde_json::to_string_pretty(&answer)?);
            Ok(0)
        }
        Err(error) => {
            eprintln!("error: {name}: {error}");
            Ok(1)
        }
    }
}
