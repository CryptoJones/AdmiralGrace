//! `ag install-skill` — the agent skill, compiled into the binary.
//!
//! Like `ag docs`, the skill is `include_str!`-ed, so a downloaded release
//! binary is the whole distribution: no checkout, no network. Installing from
//! the binary also keeps the skill's advice matched to the `ag` that runs it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::ValueEnum;

/// The skill, compiled into the binary.
pub const BODY: &str = include_str!("../../../skills/ag/SKILL.md");

/// The agents the skill can be installed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    /// Claude Code.
    Claude,
    /// OpenAI Codex.
    Codex,
    /// opencode.
    Opencode,
    /// Every one of them.
    All,
}

impl Agent {
    /// The agents `All` stands for.
    const EVERY: [Agent; 3] = [Agent::Claude, Agent::Codex, Agent::Opencode];

    /// The agent's own name.
    fn label(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Opencode => "opencode",
            Agent::All => "all",
        }
    }

    /// The directory the agent keeps its configuration in.
    ///
    /// The agent's own environment variable wins; opencode falls back to the
    /// XDG configuration directory before the one under the home directory.
    fn config_dir(self) -> Option<PathBuf> {
        let (var, default) = match self {
            Agent::Claude => ("CLAUDE_CONFIG_DIR", ".claude"),
            Agent::Codex => ("CODEX_HOME", ".codex"),
            Agent::Opencode => ("OPENCODE_CONFIG_DIR", ".config/opencode"),
            Agent::All => return None,
        };

        if let Some(value) = std::env::var_os(var).filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(value));
        }

        if self == Agent::Opencode {
            if let Some(value) =
                std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
            {
                return Some(PathBuf::from(value).join("opencode"));
            }
        }

        home_dir().map(|home| home.join(default))
    }

    /// The directory the agent keeps its project files in.
    fn project_dir(self) -> &'static str {
        match self {
            Agent::Claude => ".claude",
            Agent::Codex => ".agents",
            Agent::Opencode => ".opencode",
            Agent::All => "",
        }
    }
}

/// Install the skill.
///
/// The exit code is 0 when the skill was installed or was already current, 1
/// when a write failed or a differing copy was kept, and 2 when there was
/// nobody to install for.
pub fn run(
    agent: Option<Agent>,
    project: bool,
    dir: Option<PathBuf>,
    force: bool,
    print: bool,
) -> i32 {
    if print {
        if agent.is_some() || project || dir.is_some() || force {
            eprintln!("error: --print installs nothing and takes no other flag");
            return 2;
        }

        print!("{BODY}");
        return 0;
    }

    if dir.is_some() && (agent.is_some() || project) {
        eprintln!("error: --dir names the skills directory itself; drop --agent/--project");
        return 2;
    }

    let name = skill_name();
    let targets: Vec<(&str, PathBuf)> = match dir {
        Some(dir) => vec![("dir", dir)],
        None => {
            let chosen: Vec<Agent> = match agent {
                Some(Agent::All) => Agent::EVERY.to_vec(),
                Some(agent) => vec![agent],
                None => Agent::EVERY
                    .into_iter()
                    .filter(|agent| agent.config_dir().is_some_and(|dir| dir.is_dir()))
                    .collect(),
            };

            if chosen.is_empty() {
                eprintln!(
                    "error: found no agent config directory (~/.claude, ~/.codex, \
                     ~/.config/opencode); pass --agent claude|codex|opencode, or --dir DIR for \
                     another agent (--print shows the skill)"
                );
                return 2;
            }

            let mut targets = Vec::new();
            for agent in chosen {
                let root = if project {
                    Some(PathBuf::from(agent.project_dir()))
                } else {
                    agent.config_dir()
                };

                match root {
                    Some(root) => targets.push((agent.label(), root.join("skills"))),
                    None => {
                        eprintln!("error: {}: cannot locate the home directory", agent.label());
                        return 2;
                    }
                }
            }

            targets
        }
    };

    let mut status = 0;
    let mut wrote = false;
    let mut report = String::new();

    for (label, skills) in targets {
        let path = skills.join(name).join("SKILL.md");

        match install(&path, force) {
            Ok(verdict) => {
                wrote |= verdict != "current";
                let _ = writeln!(report, "{verdict:<10} {label:<9} {}", path.display());
            }
            Err(message) => {
                eprintln!("error: {label}: {}: {message}", path.display());
                status = 1;
            }
        }
    }

    print!("{report}");

    if !report.is_empty() {
        if wrote {
            eprintln!("agents load skills at session start; begin a new session to use `{name}`");
        }
        if !on_path("ag") {
            let exe = std::env::current_exe().map(|path| path.display().to_string());
            eprintln!(
                "note: `ag` is not on PATH, and the skill invokes it by that name; put this \
                 binary ({}) on PATH",
                exe.as_deref().unwrap_or("ag")
            );
        }
    }

    status
}

/// Write the skill to `path`, returning the verdict word for the report.
fn install(path: &Path, force: bool) -> Result<&'static str, String> {
    let verdict = match std::fs::read(path) {
        Ok(existing) if existing == BODY.as_bytes() => return Ok("current"),
        Ok(_) if !force => {
            return Err(
                "an installed copy differs (another ag version or local edits); rerun with \
                        --force to replace it"
                    .into(),
            )
        }
        Ok(_) => "updated",
        Err(_) => "installed",
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }

    std::fs::write(path, BODY).map_err(|error| error.to_string())?;
    Ok(verdict)
}

/// The frontmatter `name:`, which the Agent Skills layout requires the
/// skill's directory to match.
pub fn skill_name() -> &'static str {
    let mut lines = BODY.lines().map(str::trim);

    if lines.next() != Some("---") {
        return "ag";
    }

    lines
        .take_while(|line| *line != "---")
        .find_map(|line| line.strip_prefix("name:"))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("ag")
}

/// The home directory of the user running the CLI.
fn home_dir() -> Option<PathBuf> {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(std::env::var_os)
        .find(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Whether a program is on the PATH.
fn on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&path).any(|dir| {
        dir.join(program).is_file()
            || (cfg!(windows) && dir.join(format!("{program}.exe")).is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A temporary directory that cleans itself up.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "ag-cli-skill-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&path).expect("a temporary directory");
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_embedded_skill_names_itself() {
        assert_eq!(
            BODY.lines().next().map(str::trim),
            Some("---"),
            "SKILL.md lost its frontmatter"
        );
        assert_eq!(skill_name(), "admiralgrace");
    }

    #[test]
    fn the_skill_is_short_and_task_focused() {
        let lines = BODY.lines().count();
        assert!(lines <= 150, "the skill is {lines} lines long");
    }

    #[test]
    fn the_skill_names_the_commands_it_teaches() {
        for command in ["ag corpus --root", "ag docs", "decompile-index.json"] {
            assert!(BODY.contains(command), "the skill never mentions {command}");
        }
    }

    #[test]
    fn installing_writes_the_skill_and_leaves_a_current_copy_alone() {
        let dir = TempDir::new("install");
        let path = dir.0.join("admiralgrace").join("SKILL.md");

        assert_eq!(install(&path, false).expect("an install"), "installed");
        assert_eq!(fs::read_to_string(&path).expect("the skill"), BODY);

        assert_eq!(install(&path, false).expect("a second install"), "current");
    }

    #[test]
    fn a_differing_copy_is_kept_unless_it_is_forced() {
        let dir = TempDir::new("differing");
        let path = dir.0.join("admiralgrace").join("SKILL.md");

        fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        fs::write(&path, "someone else's skill\n").expect("the skill");

        assert!(install(&path, false).is_err(), "the copy is kept");
        assert_eq!(
            fs::read_to_string(&path).expect("the skill"),
            "someone else's skill\n"
        );

        assert_eq!(install(&path, true).expect("a forced install"), "updated");
        assert_eq!(fs::read_to_string(&path).expect("the skill"), BODY);
    }

    #[test]
    fn the_agents_know_where_their_skills_live() {
        assert_eq!(Agent::Claude.project_dir(), ".claude");
        assert_eq!(Agent::Codex.project_dir(), ".agents");
        assert_eq!(Agent::Opencode.project_dir(), ".opencode");
    }
}
