//! The AdmiralGrace desktop workbench.

mod app;
mod data;
mod model;
mod theme;
mod views;

use std::path::PathBuf;

use ag_image::Options;
use app::{App, Config};

const USAGE: &str = "\
AdmiralGrace workbench

Usage: ag-ui [options]

Options:
  --corpus PATH     Open a decompilation corpus (a directory with decompile-index.json)
  --kuna PATH       Open a kuna project export (a directory with the .c, .h and .asm files)
  --binary PATH     Open a program image (an ELF, PE, COFF or Mach-O file)
  --methods PATH    Overlay an Objective-C method map
  --shift ADDR      Image-base shift applied to Objective-C IMP addresses (default 0x0)
  --option NAME VALUE
                    Set an engine option for the pseudocode of a program image, such as
                    `--option loop-form while`; may be repeated. `ag catalog` lists them.
  -h, --help        Show this help
";

fn main() -> iced::Result {
    // The plugins of the plugin directories: a loader for the program about
    // to be opened, an architecture for its code.
    let (_, problems) = ag_image::plugin::load_all();
    for problem in problems {
        eprintln!("warning: plugins: {problem}");
    }
    let config = match parse_args() {
        Ok(Some(config)) => config,
        Ok(None) => {
            print!("{USAGE}");
            return Ok(());
        }
        Err(error) => {
            eprintln!("error: {error}");
            print!("{USAGE}");
            return Ok(());
        }
    };

    if let Some(root) = &config.corpus {
        if !crate::data::is_corpus(root) {
            eprintln!(
                "error: {} does not contain a decompile-index.json",
                root.display()
            );
            std::process::exit(1);
        }
    }

    if let Some(root) = &config.kuna {
        if !crate::data::is_kuna_export(root) {
            eprintln!("error: {} does not contain a kuna export", root.display());
            std::process::exit(1);
        }
    }

    if let Some(path) = &config.binary {
        if !path.is_file() {
            eprintln!("error: {} is not a file", path.display());
            std::process::exit(1);
        }
    }

    iced::application(move || App::boot(config.clone()), App::update, App::view)
        .title(|app: &App| app.window_title())
        .theme(|_: &App| theme::theme())
        .subscription(App::subscription)
        .window_size((1440.0, 900.0))
        .run()
}

/// Parse the command line.
fn parse_args() -> Result<Option<Config>, String> {
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);
    let mut options: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--corpus" => {
                config.corpus = Some(PathBuf::from(args.next().ok_or("--corpus needs a path")?));
            }
            "--kuna" => {
                config.kuna = Some(PathBuf::from(args.next().ok_or("--kuna needs a path")?));
            }
            "--binary" => {
                config.binary = Some(PathBuf::from(args.next().ok_or("--binary needs a path")?));
            }
            "--methods" => {
                config.methods = Some(PathBuf::from(args.next().ok_or("--methods needs a path")?));
            }
            "--shift" => {
                let value = args.next().ok_or("--shift needs an address")?;
                config.shift =
                    ag_corpus::parse_addr(&value).map_err(|_| format!("bad address {value:?}"))?;
            }
            "--option" => {
                let name = args.next().ok_or("--option needs a name and a value")?;
                let value = args
                    .next()
                    .ok_or_else(|| format!("--option {name} needs a value"))?;
                options.push(name);
                options.push(value);
            }
            "-h" | "--help" => return Ok(None),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    config.options = Options::from_flat(&options).map_err(|error| error.to_string())?;
    Ok(Some(config))
}
