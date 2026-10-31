//! The tools of plugins: an analysis of its own over an open image, run
//! from the command line (`ag tool`) or called by a language model through
//! the MCP server, beside the tools the image has of itself.
//!
//! A tool is written one of two ways. In Rust, a crate that builds on this
//! one implements [`Tool`] and registers it ([`register_tool`]). In any
//! language, a tool is a command declared in a plugin manifest
//! (`ag_engine::plugin`): it is given the image's path, the project file's
//! and its arguments as JSON on its standard input, and what it prints is
//! its answer — JSON when it is JSON, text otherwise. The loaders and
//! architectures of a manifest are the engine's to register; its tools are
//! registered here ([`install`]), where the image they read is.

use std::sync::{Arc, PoisonError, RwLock};

use ag_engine::plugin::ExternalTool;
// The engine's side of the SDK, reachable from here so a crate that builds
// on the image alone has the whole of it.
pub use ag_engine::plugin::{
    architecture_for, architectures, loader_for, loaders, manifest_dirs, read_manifest,
    register_architecture, register_loader, register_rewriter, rewriters, Architecture,
    DecodedSection, ExternalRewriter, LoadedImage, Loader, Manifest, Rewrite, Rewriter,
};

use crate::Binary;

/// What a tool is told besides its arguments: where the image came from,
/// and the project file in use.
#[derive(Debug, Clone, Default)]
pub struct ToolContext {
    /// The path the image was opened from.
    pub image_path: Option<std::path::PathBuf>,
    /// The project file, when there is one.
    pub project_path: Option<std::path::PathBuf>,
}

/// An analysis of its own over an open image.
pub trait Tool: Send + Sync {
    /// The tool's name, as it is called by: letters, digits, `_` and `-`.
    fn name(&self) -> &str;
    /// What the tool does, for the one calling it.
    fn description(&self) -> &str;
    /// The JSON Schema of the tool's arguments; any object unless said.
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({ "type": "object" })
    }
    /// Run the tool: its answer, or its own failure.
    fn run(
        &self,
        image: &Binary,
        context: &ToolContext,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

fn registry() -> &'static RwLock<Vec<Arc<dyn Tool>>> {
    static REGISTRY: std::sync::OnceLock<RwLock<Vec<Arc<dyn Tool>>>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

/// Add a tool; one of the same name is replaced.
pub fn register_tool(tool: Arc<dyn Tool>) {
    let mut tools = registry().write().unwrap_or_else(PoisonError::into_inner);
    let name = tool.name().to_string();
    tools.retain(|known| known.name() != name);
    tools.push(tool);
}

/// The tools registered, in the order they were.
pub fn tools() -> Vec<Arc<dyn Tool>> {
    registry()
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The tool called `name`, when one is registered.
pub fn tool(name: &str) -> Option<Arc<dyn Tool>> {
    tools().into_iter().find(|tool| tool.name() == name)
}

/// Register the tools the manifests declare, as commands.
pub fn install(manifests: &[Manifest]) {
    for manifest in manifests {
        for tool in &manifest.tools {
            register_tool(Arc::new(CommandTool(tool.clone())));
        }
    }
}

/// Read every manifest in the plugin directories, registering the loaders
/// and architectures with the engine and the tools here; the manifests,
/// and what did not read.
pub fn load_all() -> (Vec<Manifest>, Vec<String>) {
    let (manifests, problems) =
        ag_engine::plugin::load_manifests(&ag_engine::plugin::manifest_dirs());
    install(&manifests);
    (manifests, problems)
}

/// A tool that is a command, as a manifest declares it.
struct CommandTool(ExternalTool);

impl Tool for CommandTool {
    fn name(&self) -> &str {
        &self.0.name
    }

    fn description(&self) -> &str {
        &self.0.description
    }

    fn input_schema(&self) -> serde_json::Value {
        self.0
            .input_schema
            .clone()
            .unwrap_or_else(|| serde_json::json!({ "type": "object" }))
    }

    fn run(
        &self,
        _image: &Binary,
        context: &ToolContext,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let request = serde_json::json!({
            "tool": self.0.name,
            "image": context.image_path.as_ref().map(|path| path.display().to_string()),
            "project": context.project_path.as_ref().map(|path| path.display().to_string()),
            "arguments": arguments,
        });
        let output = ag_engine::plugin::run_command(
            &self.0.command,
            request.to_string().as_bytes(),
            self.0.timeout,
        )?;
        // JSON when the command answers with JSON; its text otherwise.
        Ok(serde_json::from_slice(&output).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&output).trim_end().to_string())
        }))
    }
}

/// Run the tool `name` over `image`.
pub fn run_tool(
    name: &str,
    image: &Binary,
    context: &ToolContext,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let tool = tool(name).ok_or_else(|| format!("no tool is called {name:?}"))?;
    tool.run(image, context, arguments)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    struct Counting;

    impl Tool for Counting {
        fn name(&self) -> &str {
            "count_functions"
        }
        fn description(&self) -> &str {
            "How many functions the image has."
        }
        fn run(
            &self,
            image: &Binary,
            _context: &ToolContext,
            arguments: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            let at_least = arguments
                .get("at_least")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let count = image.functions().len() as u64;
            if count < at_least {
                return Err(format!("only {count} functions"));
            }
            Ok(serde_json::json!({ "functions": count }))
        }
    }

    fn fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ag-engine/tests/fixtures/sample.elf")
    }

    #[test]
    fn a_registered_tool_runs_over_the_image_and_a_command_tool_answers_with_its_output() {
        register_tool(Arc::new(Counting));
        let image = Binary::open(&fixture()).expect("the fixture opens");
        let context = ToolContext {
            image_path: Some(fixture()),
            project_path: None,
        };
        let answer = run_tool("count_functions", &image, &context, &serde_json::json!({})).unwrap();
        assert!(answer["functions"].as_u64().unwrap() > 5);
        let refused = run_tool(
            "count_functions",
            &image,
            &context,
            &serde_json::json!({ "at_least": 10_000 }),
        )
        .unwrap_err();
        assert!(refused.contains("only"), "{refused}");
        assert!(run_tool("no_such_tool", &image, &context, &serde_json::json!({})).is_err());
        assert!(tools().iter().any(|tool| tool.name() == "count_functions"));

        // A command tool is given the request on its input, and its output
        // is its answer: JSON, or text.
        let echo = CommandTool(ExternalTool {
            name: "echo_request".to_string(),
            description: "Echoes.".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "cat".to_string()],
            timeout: ag_engine::plugin::DEFAULT_TIMEOUT,
            input_schema: None,
        });
        let answer = echo
            .run(&image, &context, &serde_json::json!({ "k": 1 }))
            .unwrap();
        assert_eq!(answer["tool"], "echo_request");
        assert_eq!(answer["arguments"]["k"], 1);
        assert_eq!(answer["image"], fixture().display().to_string());
        assert!(answer["project"].is_null());
        let words = CommandTool(ExternalTool {
            name: "words".to_string(),
            description: "Says.".to_string(),
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "cat >/dev/null; echo hello".to_string(),
            ],
            timeout: ag_engine::plugin::DEFAULT_TIMEOUT,
            input_schema: None,
        });
        assert_eq!(
            words.run(&image, &context, &serde_json::json!({})).unwrap(),
            serde_json::Value::String("hello".to_string())
        );
        assert_eq!(echo.input_schema(), serde_json::json!({ "type": "object" }));
    }
}
