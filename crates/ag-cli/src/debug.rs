//! `ag debug`: the program run under a debugger from the command line,
//! stopping at the breakpoints the analyst names and printing where it is.
//!
//! The workbench drives the same session with its panes; this is the
//! headless shape of it — a batch that runs a program to each breakpoint
//! and prints the registers and the stack there, in the image's addresses,
//! then lets it go on, until it ends.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use ag_debug::{Debugger, Event, Session, State};
use ag_image::Binary;

/// Run `binary` under the debugger, stopping at `breakpoints` (functions by
/// address or name), with `arguments`; the program's exit status.
#[allow(clippy::too_many_arguments)]
pub fn run(
    binary: &Path,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    project: Option<&Path>,
    options: Vec<String>,
    debugger: Debugger,
    breakpoints: &[String],
    arguments: &[String],
) -> Result<i32> {
    anyhow::ensure!(
        debugger.available(),
        "{} is not on this machine, or does not answer `--version`",
        debugger.command()[0]
    );
    let options =
        ag_image::Options::from_flat(&options).map_err(|error| anyhow::anyhow!("{error}"))?;
    let project_file = match project {
        Some(path) if path.exists() => Some(ag_corpus::project::ProjectFile::load(path)?),
        _ => None,
    };
    let image = crate::image::open_image(binary, raw, slice, project_file.as_ref(), options)?;
    let stops: Vec<u64> = breakpoints
        .iter()
        .map(|target| crate::image::resolve(&image, target))
        .collect::<Result<_>>()?;
    let mut session = Session::launch(debugger, binary, image.base().unwrap_or(0))
        .with_context(|| format!("starting {}", debugger.name()))?;
    for address in &stops {
        session
            .add_breakpoint(*address)
            .with_context(|| format!("setting a breakpoint at {address:#x}"))?;
    }
    session.start(arguments).context("starting the program")?;
    println!(
        "{} started {} under {}{}",
        debugger.name(),
        binary.display(),
        match session.slide() {
            Some(slide) => format!("a slide of {slide:#x}"),
            None => "no slide".to_string(),
        },
        if stops.is_empty() {
            String::new()
        } else {
            format!(
                ", stopping at {}",
                stops
                    .iter()
                    .map(|address| format!("{address:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    // The program is stopped at its first instruction: let it run, and
    // report every stop until it ends.
    session.resume().context("running the program")?;
    loop {
        for event in session.poll(Duration::from_millis(200)) {
            match event {
                Event::Stopped {
                    reason,
                    pc,
                    runtime_pc,
                    ..
                } => {
                    report_stop(&image, &mut session, &reason, pc, runtime_pc);
                    if reason == "breakpoint-hit"
                        || reason == "end-stepping-range"
                        || reason == "function-finished"
                    {
                        session.resume().context("running the program on")?;
                    } else {
                        // A signal, a fault: the program is left where it
                        // is for the debugger to say more; here, it ends.
                        println!("the program stopped for {reason}; ending it");
                        let _ = session.kill();
                        return Ok(1);
                    }
                }
                Event::Exited { code } => {
                    println!(
                        "the program exited with code {}",
                        code.map_or("?".to_string(), |code| code.to_string())
                    );
                    return Ok(code.map_or(1, |code| (code & 0xff) as i32));
                }
                Event::Output(text) => println!("| {text}"),
                Event::Log(text) => eprintln!("{}: {text}", debugger.name()),
                Event::Running | Event::Console(_) => {}
            }
        }
        if matches!(session.state(), State::Exited { .. }) {
            return Ok(1);
        }
    }
}

/// Print where the program stopped: the address in the image's terms and
/// the function there, the registers, and the stack.
fn report_stop(
    image: &Binary,
    session: &mut Session,
    reason: &str,
    pc: Option<u64>,
    runtime_pc: Option<u64>,
) {
    let place = match (pc, runtime_pc) {
        (Some(pc), Some(runtime)) => {
            let name = image
                .function_name(pc)
                .map(|name| format!(" ({name})"))
                .or_else(|| {
                    image
                        .functions()
                        .iter()
                        .rev()
                        .find(|function| function.address <= pc)
                        .filter(|_| image.section_of(pc).is_some())
                        .map(|function| {
                            format!(" ({}+{:#x})", function.name, pc - function.address)
                        })
                })
                .unwrap_or_default();
            if pc == runtime {
                format!("{pc:#x}{name}")
            } else {
                format!("{pc:#x}{name}, running at {runtime:#x}")
            }
        }
        _ => "an unknown address".to_string(),
    };
    println!("stopped: {reason} at {place}");
    if let Ok(registers) = session.registers() {
        let mut line = String::new();
        for (name, value) in registers.iter().take(24) {
            let cell = format!("{name}={value:#x}");
            if line.len() + cell.len() > 76 && !line.is_empty() {
                println!("  {line}");
                line.clear();
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&cell);
        }
        if !line.is_empty() {
            println!("  {line}");
        }
    }
    if let Ok(frames) = session.frames() {
        for frame in frames.iter().take(8) {
            println!(
                "  #{} {:#x}{}",
                frame.level,
                frame.pc,
                frame
                    .function
                    .as_deref()
                    .or_else(|| image.function_name(frame.pc))
                    .map(|name| format!(" {name}"))
                    .unwrap_or_default()
            );
        }
    }
}
