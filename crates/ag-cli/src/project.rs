//! `ag project` — the portable project file.
//!
//! A project file (`.agproj`) records what was analysed — the target's path
//! and SHA-256 — the analysis options the run used, and the analyst's own
//! changes. This command creates one from a target (`save`), reads one back
//! (`show`), adds one annotation at a time (`rename`, `comment`, `bookmark`,
//! `tag`, `color`, `xref`, `mark`, `operand`, `switch`, `inline`, `merge`,
//! `split`, `version`, `value`, `stack-var`, `patch`, `asm`, `nop`,
//! `opaque`) so a script or an agent can build a project without editing
//! JSON by hand, and reports the tags the analyst gave (`tags`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};

use ag_corpus::project::{
    parse_color, parse_tags, sha256_of, Annotation, ByteType, JumpTableNote, OperandFormat,
    ProjectFile, Target, TargetKind,
};

/// What to do with a project file.
#[derive(Subcommand)]
pub enum ProjectCmd {
    /// Create a project file for a target binary.
    Save {
        /// Where to write the project file.
        #[arg(long)]
        out: PathBuf,
        /// The analysis options to record, as `NAME=VALUE` (repeatable).
        #[arg(long = "option-pair")]
        options: Vec<String>,
        /// Write over an existing file, which `save` would otherwise replace
        /// without warning.
        #[arg(long)]
        force: bool,
    },
    /// Report what a project file holds.
    Show {
        /// The project file to read.
        file: PathBuf,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Record a name for the function at an address.
    Rename {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The name to record.
        name: String,
    },
    /// Record a comment at an address.
    Comment {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The comment to record.
        text: String,
        /// Stand the comment on its own line above the instruction, rather
        /// than inline at the end of it.
        #[arg(long)]
        above: bool,
    },
    /// Flip a bookmark on a function.
    Bookmark {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
    },
    /// Attach tags to, or take them off, the thing at an address.
    Tag {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The tags to attach, one word each; `a,b` is two.
        #[arg(required = true)]
        tags: Vec<String>,
        /// Take the tags off instead of attaching them.
        #[arg(long)]
        remove: bool,
        /// What the tags are on: the function entered at the address, the
        /// block of bytes starting there, or the one address.
        #[arg(long, value_enum, default_value_t = On::Address)]
        on: On,
    },
    /// Set or clear a highlight color on the thing at an address.
    Color {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The color: a name such as `red` or `amber`, `#rrggbb`, or `none`
        /// to clear it.
        color: String,
        /// What the color is on: the function entered at the address, the
        /// block of bytes starting there, or the one address.
        #[arg(long, value_enum, default_value_t = On::Address)]
        on: On,
    },
    /// Record, or take back, a cross reference the analysis cannot see.
    Xref {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address the reference leaves from, with its space when it
        /// names one.
        from: String,
        /// The address it reaches.
        to: String,
        /// Take the reference back instead of recording it.
        #[arg(long)]
        remove: bool,
    },
    /// Say how the bytes at an address are read, correcting the analysis.
    Mark {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// How the bytes are read: `code`, `function`, `string`,
        /// `undefined`, `data`, `data:W` for `W` of 1, 2, 4 or 8 bytes each,
        /// `data:W[N]` for an array of `N`, or `none` to take the mark off.
        kind: String,
    },
    /// Say how the constants in an instruction's operands are shown.
    Operand {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The instruction's address, with its space when it names one.
        address: String,
        /// The format: `hex`, `signed`, `decimal`, `octal` or `address`;
        /// `hex` is how the analysis prints them and clears the record.
        format: String,
    },
    /// Say where the jump table an indirect `jmp` reads is, when the
    /// analysis cannot work it out from the code.
    Switch {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address of the `jmp`, with its space when it names one.
        address: String,
        /// The address of the table's first entry; `none` takes the note
        /// off.
        table: String,
        /// How many entries the table has; needed unless the table is
        /// `none`.
        count: Option<u32>,
        /// How many bytes one entry takes: 4 or 8. Eight when unsaid, or
        /// four for offsets.
        #[arg(long)]
        width: Option<u8>,
        /// The entries are offsets from the table rather than addresses.
        #[arg(long)]
        relative: bool,
    },
    /// Allow or prevent one of the lift's judgment calls at an address: a
    /// branch read as a guard, a condition folded to a constant, a condition
    /// turned round, an indirect jump read as a switch — or one of the
    /// walk's: a branch followed to its target, an instruction followed by
    /// the next. A side the walk does not follow is not analyzed; the walk
    /// also halts by itself at a target that does not decode.
    Override {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address of the instruction the call is made at — the branch,
        /// the compare, the indirect jump — with its space when it names one.
        address: String,
        /// The judgment call: `guard`, `fold`, `invert`, `switch`, `taken`
        /// (the branch's target) or `next` (the instruction after).
        kind: String,
        /// `on` to allow it, `off` to prevent it, `clear` to leave it to
        /// the lift.
        state: String,
    },
    /// Say whether a function is inlined into its callers' pseudocode: a
    /// call to it reads as its own body, where the body can stand there,
    /// and the caller says why where it cannot.
    Inline {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// `on` to inline it, `off` never to, `clear` to leave it to the
        /// analysis, which inlines nothing by itself.
        state: String,
    },
    /// Say what the global pointer register — MIPS's `gp` — holds: in every
    /// function, or in one with `--function`, over what the image says (a
    /// function's prologue, the `_gp` symbol, the GOT). The operands read
    /// through it name the addresses it makes them.
    GlobalPointer {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The value, such as `0x418ff0`, or `clear` to take the word back.
        value: String,
        /// The function the value is for: its name, or its address. Every
        /// function the analyst said nothing more of when left out.
        #[arg(long)]
        function: Option<String>,
    },
    /// Merge two of a function's variables: every occurrence of `GONE`
    /// reads `KEEP`, and `GONE` is no longer declared. A merge that changes
    /// the meaning is made, and the function says so.
    Merge {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable kept, as the lift declares it.
        keep: String,
        /// The variable merged into it, as the lift declares it.
        gone: String,
    },
    /// Take back the merge of a function's variable into another.
    Unmerge {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable merged away, as the lift declares it.
        gone: String,
    },
    /// Split a function's variable at one of its definitions: the statement
    /// assigning it at the address, and the uses that assignment reaches,
    /// take a fresh name, `VAR_2`.
    Split {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable, as the lift declares it.
        variable: String,
        /// The address of the statement assigning it.
        address: String,
    },
    /// Take back the split of a function's variable at a definition.
    Unsplit {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable, as the lift declares it.
        variable: String,
        /// The address of the statement the split is at.
        address: String,
    },
    /// Force a new version of a function's variable at an address where
    /// nothing assigns it — the start of an `if`'s arm, past a join: a
    /// definition `VAR_2 = VAR;` goes before the first statement whose line
    /// carries the address, and the uses it reaches read `VAR_2`.
    Version {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable, as the lift declares it.
        variable: String,
        /// The address of the statement the new definition goes before.
        address: String,
    },
    /// Make a variable in a function's stack frame: the bytes from OFFSET,
    /// counted from the stack pointer at the function's entry as the lift's
    /// `local_<hex>` names count them, for SIZE bytes, read as one variable
    /// — whole, by element in an array, or at byte offsets. `clear` in
    /// place of SIZE takes the variable at OFFSET back.
    StackVar {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The offset from the stack pointer at entry: `-0x20`, `-32`, `8`.
        #[arg(allow_hyphen_values = true)]
        offset: String,
        /// The size in bytes, or `clear`.
        size: String,
        /// The variable's name, which renames and merges key on; the lift's
        /// `local_<hex>` when absent.
        #[arg(long)]
        name: Option<String>,
        /// The variable's C type: `int`, `char *`, `char[16]`, `int[]`; one
        /// of the size when absent.
        #[arg(long = "type", value_name = "TYPE")]
        ty: Option<String>,
    },
    /// Give a function's variable a C type — `struct point *`, `enum
    /// state`, `uint32_t` — by its lift name: it is declared so, a load or
    /// store through a typed pointer reads as the member it is, `p->x`, and
    /// a constant compared with or assigned to an enumeration's variable as
    /// its enumerator. The type must be a scalar of the variable's width,
    /// or, for a parameter, a structure passed by value in its registers,
    /// which read as its members, `p.y`; one that is not is refused with a
    /// note in the pseudocode. The variable `return` types what the
    /// function returns, a structure its callers read as its members.
    /// `clear` in place of TYPE takes the type back
    VarType {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable, as the lift declares it, or `return`.
        variable: String,
        /// The C type, or `clear`.
        #[arg(value_name = "TYPE")]
        ty: String,
    },
    /// Make a structure from the accesses through a pointer variable — one
    /// member each offset and width the function reads or writes through
    /// it, sized by its allocation or the accesses' extent (`ag image …
    /// struct-from` shows the draft) — add it to the project's types and
    /// give the variable a pointer to it, so the pseudocode reads
    /// `p->field_8`. With `--update STRUCT`, the structure already defined
    /// gains a member for each access in bytes none of its members holds;
    /// none is renamed or retyped, and an access that meets one at other
    /// bytes is a note. `types remove` and `var-type … clear` take it back
    StructFrom {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The pointer variable, by its lift name or the project's rename.
        variable: String,
        /// The structure's tag; `struct_<function>_<variable>` when absent.
        #[arg(long, conflicts_with = "update")]
        name: Option<String>,
        /// The structure to add the accesses' members to, in place of a new
        /// one.
        #[arg(long, value_name = "STRUCT")]
        update: Option<String>,
        /// Show what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// The project's types — structures, unions, enumerations and typedefs,
    /// written as C — added, replaced, removed, shown with their layout
    /// under the image's data model, or searched by name, member or text
    Types {
        /// The project file to read or change.
        #[arg(long)]
        file: PathBuf,
        #[command(subcommand)]
        cmd: TypesCmd,
    },
    /// Pin a function's variable to a value or an inclusive range, for the
    /// whole function or from an address on: the uses it settles read the
    /// value, the conditions it decides are constants, and a `switch` on it
    /// keeps the cases in range. At an indirect `jmp`, a range on the
    /// register indexing its table bounds the table.
    Value {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable, as the lift declares it, or the register a table's
        /// `jmp` reads.
        variable: String,
        /// `5`, `-1` or `0x10`; an inclusive range `MIN..MAX`; or `clear`
        /// to take the word back.
        #[arg(allow_hyphen_values = true)]
        value: String,
        /// The address of the statement the word holds from; the whole
        /// function, from its entry, when absent.
        #[arg(long)]
        at: Option<String>,
    },
    /// Take back a new version of a function's variable at an address.
    Unversion {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function: its name, or its address with its space when it
        /// names one.
        function: String,
        /// The variable, as the lift declares it.
        variable: String,
        /// The address the new version is at.
        address: String,
    },
    /// Write bytes over the image's at an address: a patch the image is
    /// read with. The file on disk is not changed.
    Patch {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address of the first byte, with its space when it names one.
        address: String,
        /// The bytes, as hex pairs — `B8 01 00 00 00` or `b801000000` — or
        /// `none` to take the patch off.
        bytes: String,
    },
    /// Assemble an instruction and write it over the image's bytes at an
    /// address, warning when it is longer than the instruction it replaces.
    Asm {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address the instruction goes at, with its space when it
        /// names one.
        address: String,
        /// The instruction, in Intel syntax: `mov eax, 1`.
        text: String,
    },
    /// Fill a run of bytes with the architecture's no-op: the instruction
    /// at an address, or as many bytes as said.
    Nop {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address of the first byte, with its space when it names one.
        address: String,
        /// How many bytes to fill; without it, the instruction at the
        /// address, as long as it is.
        #[arg(long, conflicts_with = "to")]
        len: Option<usize>,
        /// Fill up to, not including, this address.
        #[arg(long)]
        to: Option<String>,
    },
    /// Patch out the opaque predicates of functions: each conditional
    /// branch decided whatever the input becomes, in the same bytes, a
    /// `jmp` to its target when it is always taken and `nop`s when it is
    /// never taken. The patches are the project's like any other: they
    /// show, come off and write out the same way.
    Opaque {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The functions: addresses such as `0x1149`, or names. Every
        /// function of the image when `--all`.
        functions: Vec<String>,
        /// Every function of the image.
        #[arg(long)]
        all: bool,
        /// Print the patches without saving them.
        #[arg(long = "dry-run")]
        dry_run: bool,
    },
    /// Write a copy of the target with the project's patches in it, leaving
    /// the target as it is.
    WritePatched {
        /// The project file whose patches are written.
        #[arg(long)]
        file: PathBuf,
        /// Where the copy goes.
        #[arg(long)]
        out: PathBuf,
        /// Write over an existing copy.
        #[arg(long)]
        force: bool,
    },
    /// Say which instruction set the code from an address onward decodes
    /// in, on an architecture with more than one: `arm`, `thumb`, or `none`
    /// to let the image say.
    Mode {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address the mode starts at.
        address: String,
        /// `arm`, `thumb` or `none`.
        mode: String,
    },
    /// Move the whole image to a new base address, or put it back.
    Rebase {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address the image's lowest mapped page goes to, or `none`.
        base: String,
    },
    /// Add, remove or rename a segment of the image.
    Segment {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The edit.
        #[command(subcommand)]
        edit: SegmentCmd,
    },
    /// Report the tags the project holds, or the places carrying one tag.
    Tags {
        /// The project file to read.
        file: PathBuf,
        /// A tag: list the places carrying it rather than every tag.
        tag: Option<String>,
    },
    /// Record a name for the label at an address.
    ///
    /// The entry label of a function and the function's name are the same
    /// record; `label` is the spelling for a name at an address that is not
    /// a function entry.
    Label {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The address, with its space when it names one.
        address: String,
        /// The name to record.
        name: String,
    },
    /// Record a name for a local variable of the function at an address.
    Var {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The variable's declared name, as the pseudocode writes it.
        variable: String,
        /// The name to record.
        name: String,
    },
    /// Say whether the stores to a local variable that nothing reads are
    /// taken out of the pseudocode even when the dead code is kept.
    Stores {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The variable's declared name, as the pseudocode writes it.
        variable: String,
        /// `drop` to take its dead stores out, `keep` to leave them in.
        state: String,
    },
    /// Record a name for a register as one function prints it.
    Reg {
        /// The project file to change.
        #[arg(long)]
        file: PathBuf,
        /// The function's address, with its space when it names one.
        address: String,
        /// The register's name, as the listing spells it: `rax`, `ebp`.
        register: String,
        /// The name to record.
        name: String,
    },
}

/// Run `ag project <target> …`: the target is the binary the project describes.
pub fn run(
    target: PathBuf,
    raw: Option<ag_image::RawSpec>,
    slice: Option<String>,
    cmd: ProjectCmd,
) -> Result<i32> {
    // The flags that say how raw bytes load, or which slice the target is,
    // are recorded when the project is made, so every command after reads
    // the target the same way.
    RAW.with(|held| *held.borrow_mut() = raw);
    SLICE.with(|held| *held.borrow_mut() = slice);
    match cmd {
        ProjectCmd::Save {
            out,
            options,
            force,
        } => save(&target, &out, options, force),
        ProjectCmd::Show { file, json } => show(&target, &file, json),
        ProjectCmd::Mode {
            file,
            address,
            mode,
        } => {
            let mode = match mode.trim().to_ascii_lowercase().as_str() {
                "none" => None,
                text => Some(
                    ag_image::ArmMode::parse(text)
                        .with_context(|| format!("{mode:?} is not a mode: arm, thumb or none"))?
                        .label()
                        .to_string(),
                ),
            };
            edit(&target, &file, TargetKind::Address, &address, |a| {
                a.set_mode(mode.as_deref())
            })
        }
        ProjectCmd::Rebase { file, base } => rebase(&target, &file, &base),
        ProjectCmd::Segment { file, edit } => segment(&target, &file, edit),
        ProjectCmd::WritePatched { file, out, force } => write_patched(&target, &file, &out, force),
        ProjectCmd::Opaque {
            file,
            functions,
            all,
            dry_run,
        } => patch_opaque(&target, &file, &functions, all, dry_run),
        ProjectCmd::Rename {
            file,
            address,
            name,
        } => edit(&target, &file, TargetKind::Function, &address, |a| {
            a.name = Some(name);
        }),
        ProjectCmd::Comment {
            file,
            address,
            text,
            above,
        } => edit(&target, &file, TargetKind::Address, &address, |a| {
            // An empty note is no note: it clears the comment the way the
            // workbench's empty submit does, rather than recording "".
            a.set_comment((!text.is_empty()).then_some(text), above);
        }),
        ProjectCmd::Bookmark { file, address } => {
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.bookmark = !a.bookmark;
            })
        }
        ProjectCmd::Tag {
            file,
            address,
            tags,
            remove,
            on,
        } => edit(&target, &file, on.into(), &address, |a| {
            // Each argument reads the way the workbench's prompt does, so
            // `crypto,parser` is two tags here as it is there.
            for tag in tags.iter().flat_map(|tag| parse_tags(tag)) {
                if remove {
                    a.remove_tag(&tag);
                } else {
                    a.add_tag(&tag);
                }
            }
        }),
        ProjectCmd::Xref {
            file,
            from,
            to,
            remove,
        } => {
            // The address reached must be one before the file is touched.
            let reaches = ag_corpus::project::canonical_address(&to)
                .with_context(|| format!("{to:?} is not an address"))?;
            edit(&target, &file, TargetKind::Address, &from, |a| {
                if remove {
                    a.remove_reference(&reaches);
                } else {
                    a.add_reference(&reaches);
                }
            })
        }
        ProjectCmd::Mark {
            file,
            address,
            kind,
        } => {
            // The mark must be one this program reads before the file is
            // touched, so a typo is refused rather than recorded.
            let mark = if kind.trim().eq_ignore_ascii_case("none") {
                None
            } else {
                Some(ByteType::parse(&kind).with_context(|| {
                    format!(
                        "{kind:?} is not a byte type; use code, function, string, undefined, data, data:W or data:W[N]"
                    )
                })?)
            };
            // A function mark says what the place is; any other mark is on
            // the address.
            let on = if mark == Some(ByteType::Function) {
                TargetKind::Function
            } else {
                TargetKind::Address
            };
            edit(&target, &file, on, &address, |a| a.set_byte_type(mark))
        }
        ProjectCmd::Operand {
            file,
            address,
            format,
        } => {
            let format = OperandFormat::parse(&format).with_context(|| {
                format!(
                    "{format:?} is not an operand format; use hex, signed, decimal, octal or address"
                )
            })?;
            edit(&target, &file, TargetKind::Address, &address, |a| {
                a.set_operand_format(Some(format))
            })
        }
        ProjectCmd::Switch {
            file,
            address,
            table,
            count,
            width,
            relative,
        } => {
            // `none` clears; otherwise the note must read back before the
            // file is touched.
            let note = if table.trim().eq_ignore_ascii_case("none") {
                None
            } else {
                let count = count.context("COUNT is needed: how many entries the table has")?;
                let width = width.unwrap_or(if relative { 4 } else { 8 });
                let text = format!(
                    "{table} {width} {count}{}",
                    if relative { " rel" } else { "" }
                );
                Some(JumpTableNote::parse(&text).with_context(|| {
                    format!(
                        "{text:?} is not a jump table: TABLE is an address, COUNT at least 1, --width 4 or 8"
                    )
                })?)
            };
            edit(&target, &file, TargetKind::Address, &address, |a| {
                a.set_jump_table(note)
            })
        }
        ProjectCmd::Override {
            file,
            address,
            kind,
            state,
        } => {
            let kind = kind.trim().to_ascii_lowercase();
            anyhow::ensure!(
                Annotation::OVERRIDE_KINDS.contains(&kind.as_str()),
                "the kind is guard, fold, invert, switch, taken or next, not {kind:?}"
            );
            let on = match state.trim().to_ascii_lowercase().as_str() {
                "on" | "allow" | "yes" | "true" => Some(true),
                "off" | "prevent" | "no" | "false" => Some(false),
                "clear" | "none" => None,
                other => anyhow::bail!("the state is on, off or clear, not {other:?}"),
            };
            edit(&target, &file, TargetKind::Address, &address, |a| {
                a.set_override(&kind, on);
            })
        }
        ProjectCmd::Inline {
            file,
            function,
            state,
        } => {
            let on = match state.trim().to_ascii_lowercase().as_str() {
                "on" | "yes" | "true" => Some(true),
                "off" | "no" | "false" => Some(false),
                "clear" | "none" => None,
                other => anyhow::bail!("the state is on, off or clear, not {other:?}"),
            };
            let address = function_key(&target, &file, &function)?;
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.inline = on;
            })
        }
        ProjectCmd::GlobalPointer {
            file,
            value,
            function,
        } => global_pointer(&target, &file, &value, function.as_deref()),
        ProjectCmd::Merge {
            file,
            function,
            keep,
            gone,
        } => {
            let (keep, gone) = (keep.trim().to_string(), gone.trim().to_string());
            anyhow::ensure!(keep != gone, "{keep} cannot be merged into itself");
            let address = function_key(&target, &file, &function)?;
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.merge_variables(&keep, &gone);
            })
        }
        ProjectCmd::Unmerge {
            file,
            function,
            gone,
        } => {
            let address = function_key(&target, &file, &function)?;
            let gone = gone.trim().to_string();
            let mut had = false;
            let code = edit(&target, &file, TargetKind::Function, &address, |a| {
                had = a.unmerge_variable(&gone);
            })?;
            if !had {
                eprintln!("{gone} was not merged in {address}");
            }
            Ok(code)
        }
        ProjectCmd::Split {
            file,
            function,
            variable,
            address: at,
        } => {
            let at = ag_corpus::project::canonical_address(&at)
                .ok_or_else(|| anyhow::anyhow!("{at:?} is not an address"))?;
            let address = function_key(&target, &file, &function)?;
            let variable = variable.trim().to_string();
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.split_variable(&variable, &at);
            })
        }
        ProjectCmd::Unsplit {
            file,
            function,
            variable,
            address: at,
        } => {
            let at = ag_corpus::project::canonical_address(&at)
                .ok_or_else(|| anyhow::anyhow!("{at:?} is not an address"))?;
            let address = function_key(&target, &file, &function)?;
            let variable = variable.trim().to_string();
            let mut had = false;
            let code = edit(&target, &file, TargetKind::Function, &address, |a| {
                had = a.unsplit_variable(&variable, &at);
            })?;
            if !had {
                eprintln!("{variable} was not split at {at} in {address}");
            }
            Ok(code)
        }
        ProjectCmd::Version {
            file,
            function,
            variable,
            address: at,
        } => {
            let at = ag_corpus::project::canonical_address(&at)
                .ok_or_else(|| anyhow::anyhow!("{at:?} is not an address"))?;
            let address = function_key(&target, &file, &function)?;
            let variable = variable.trim().to_string();
            edit(&target, &file, TargetKind::Function, &address, |a| {
                a.version_variable(&variable, &at);
            })
        }
        ProjectCmd::Value {
            file,
            function,
            variable,
            value,
            at,
        } => {
            let at = at
                .map(|at| {
                    ag_corpus::project::canonical_address(&at)
                        .ok_or_else(|| anyhow::anyhow!("{at:?} is not an address"))
                })
                .transpose()?;
            let clear = value.trim().eq_ignore_ascii_case("clear");
            let range = if clear {
                None
            } else {
                Some(ag_corpus::project::parse_value_or_range(&value).map_err(anyhow::Error::msg)?)
            };
            let address = function_key(&target, &file, &function)?;
            let variable = variable.trim().to_string();
            let mut had = true;
            let code = edit(
                &target,
                &file,
                TargetKind::Function,
                &address,
                |a| match range {
                    Some((min, max)) => a.set_variable_value(&variable, at.as_deref(), min, max),
                    None => had = a.clear_variable_value(&variable, at.as_deref()),
                },
            )?;
            if !had {
                match &at {
                    Some(at) => eprintln!("{variable} had no value pinned at {at} in {address}"),
                    None => eprintln!("{variable} had no value pinned in {address}"),
                }
            }
            Ok(code)
        }
        ProjectCmd::VarType {
            file,
            function,
            variable,
            ty,
        } => var_type(&target, &file, &function, &variable, &ty),
        ProjectCmd::Types { file, cmd } => types(&target, &file, cmd),
        ProjectCmd::StructFrom {
            file,
            function,
            variable,
            name,
            update,
            dry_run,
        } => struct_from(
            &target,
            &file,
            &function,
            &variable,
            name.as_deref(),
            update.as_deref(),
            dry_run,
        ),
        ProjectCmd::StackVar {
            file,
            function,
            offset,
            size,
            name,
            ty,
        } => {
            let offset = ag_corpus::project::parse_offset(&offset).map_err(anyhow::Error::msg)?;
            let clear = size.trim().eq_ignore_ascii_case("clear");
            let size = if clear {
                None
            } else {
                let text = size.trim();
                let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => text.parse::<u32>(),
                };
                match parsed {
                    Ok(0) | Err(_) => {
                        anyhow::bail!(
                            "{text:?} is not a size in bytes such as 4 or 0x10, nor clear"
                        )
                    }
                    Ok(size) => Some(size),
                }
            };
            let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
            let ty = ty.map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
            if let Some(ty) = &ty {
                let project = open_project(&target, &file)?;
                let image = image_under(&target, &project)?;
                let (store, _) =
                    ag_image::ctype::build(image.data_model(), &crate::types::texts(&project))
                        .unwrap_or_default();
                ag_image::parse_type_in(&store, ty).map_err(anyhow::Error::msg)?;
            }
            let address = function_key(&target, &file, &function)?;
            let mut had = true;
            let code = edit(
                &target,
                &file,
                TargetKind::Function,
                &address,
                |a| match size {
                    Some(size) => a.set_stack_var(offset, size, name.as_deref(), ty.as_deref()),
                    None => had = a.clear_stack_var(offset),
                },
            )?;
            if !had {
                eprintln!(
                    "no stack variable was made at {} in {address}",
                    stack_offset_text(offset)
                );
            }
            Ok(code)
        }
        ProjectCmd::Unversion {
            file,
            function,
            variable,
            address: at,
        } => {
            let at = ag_corpus::project::canonical_address(&at)
                .ok_or_else(|| anyhow::anyhow!("{at:?} is not an address"))?;
            let address = function_key(&target, &file, &function)?;
            let variable = variable.trim().to_string();
            let mut had = false;
            let code = edit(&target, &file, TargetKind::Function, &address, |a| {
                had = a.unversion_variable(&variable, &at);
            })?;
            if !had {
                eprintln!("{variable} had no new version at {at} in {address}");
            }
            Ok(code)
        }
        ProjectCmd::Patch {
            file,
            address,
            bytes,
        } => {
            let patch = if bytes.trim().eq_ignore_ascii_case("none") {
                None
            } else {
                Some(
                    ag_corpus::project::bytes_of_hex(&bytes)
                        .with_context(|| format!("{bytes:?} is not hex pairs"))?,
                )
            };
            edit_patch(
                &target,
                &file,
                &address,
                patch.as_deref().map(|bytes| (bytes, None)),
            )
        }
        ProjectCmd::Asm {
            file,
            address,
            text,
        } => {
            // The target says how wide the code is and how long the
            // instruction being replaced is; without it the patch cannot
            // be assembled. It is read under the project's layout, so a
            // moved address is the instruction's.
            let image = image_under(&target, &open_project(&target, &file)?)?;
            let bitness = image
                .bitness()
                .context("the target is not x86, so nothing is assembled for it")?;
            let at = image_address(&address)?;
            let bytes = ag_image::assemble(&text, at, bitness)?;
            if let Some(replaced) = image.instruction_length_at(at) {
                if bytes.len() > replaced {
                    eprintln!(
                        "warning: {} bytes written over a {replaced}-byte instruction at {at:#x}: the instruction after it is overwritten",
                        bytes.len()
                    );
                }
            }
            edit_patch(&target, &file, &address, Some((&bytes, Some(text.trim()))))
        }
        ProjectCmd::Nop {
            file,
            address,
            len,
            to,
        } => {
            let at = image_address(&address)?;
            // The image says how long the instruction is and where its
            // section ends: a run past the end has nothing to fill. It is
            // read under the project's layout, so a moved address is the
            // instruction's.
            let image = image_under(&target, &open_project(&target, &file)?)?;
            // The no-op is x86's; an image of another architecture has
            // instruction lengths now, but no `nop` of this spelling.
            anyhow::ensure!(
                image.bitness().is_some(),
                "the target is not x86, so it has no no-op here"
            );
            let len = match (len, to) {
                (Some(len), _) => len,
                (None, Some(to)) => {
                    let end = ag_corpus::parse_addr_space(&to)
                        .map(|(value, _)| value)
                        .map_err(|_| anyhow::anyhow!("{to:?} is not an address"))?;
                    usize::try_from(end.checked_sub(at).context("--to is before the address")?)?
                }
                (None, None) => image.instruction_length_at(at).with_context(|| {
                    format!("no instruction starts at {at:#x}; say --len or --to")
                })?,
            };
            anyhow::ensure!(len > 0, "nothing to fill");
            let section_end = image
                .section_of(at)
                .map(|section| section.vma.saturating_add(section.size))
                .with_context(|| format!("{at:#x} is outside every section"))?;
            anyhow::ensure!(
                at.saturating_add(len as u64) <= section_end,
                "{len} bytes from {at:#x} run past the end of the section at {section_end:#x}"
            );
            let bytes = ag_image::no_ops(len);
            let text = if len == 1 {
                "nop".to_string()
            } else {
                format!("nop x{len}")
            };
            edit_patch(&target, &file, &address, Some((&bytes, Some(&text))))
        }
        ProjectCmd::Tags { file, tag } => tags(&target, &file, tag.as_deref()),
        ProjectCmd::Color {
            file,
            address,
            color,
            on,
        } => {
            // `none` clears; anything else must be a color before the file
            // is touched, so a typo is refused rather than recorded.
            let value = if color.trim().is_empty() || color.trim().eq_ignore_ascii_case("none") {
                None
            } else {
                Some(parse_color(&color).with_context(|| {
                    format!("{color:?} is not a color; use a name such as red or amber, or #rrggbb")
                })?)
            };
            edit(&target, &file, on.into(), &address, |a| a.color = value)
        }
        ProjectCmd::Label {
            file,
            address,
            name,
        } => edit(&target, &file, TargetKind::Address, &address, |a| {
            a.name = Some(name);
        }),
        ProjectCmd::Var {
            file,
            address,
            variable,
            name,
        } => edit_named(
            &target,
            &file,
            Named::Variable,
            &address,
            &variable,
            |a| a.name = Some(name),
        ),
        ProjectCmd::Stores {
            file,
            address,
            variable,
            state,
        } => {
            let drop = match state.trim().to_ascii_lowercase().as_str() {
                "drop" => true,
                "keep" => false,
                other => anyhow::bail!("the state is drop or keep, not {other:?}"),
            };
            edit_named(
                &target,
                &file,
                Named::Variable,
                &address,
                &variable,
                |a| a.drop_stores = drop,
            )
        }
        ProjectCmd::Reg {
            file,
            address,
            register,
            name,
        } => edit_named(
            &target,
            &file,
            Named::Register,
            &address,
            &register,
            |a| a.name = Some(name),
        ),
    }
}

/// What a tag or a color is on: the record's kind, as the command line
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum On {
    /// The one address.
    Address,
    /// The function entered at the address.
    Function,
    /// The block of bytes starting at the address.
    Block,
}

impl From<On> for TargetKind {
    fn from(on: On) -> TargetKind {
        match on {
            On::Address => TargetKind::Address,
            On::Function => TargetKind::Function,
            On::Block => TargetKind::Region,
        }
    }
}

/// Which keyed-on-one-thing record an edit reaches.
enum Named {
    /// A local variable of the function at the address.
    Variable,
    /// A register as the function at the address prints it.
    Register,
}

impl Named {
    /// The kind's label, as the report prints it.
    fn label(self) -> &'static str {
        match self {
            Named::Variable => "variable",
            Named::Register => "register",
        }
    }
}

thread_local! {
    /// How the command line said the target loads as raw bytes, for the
    /// project made or opened by this run.
    static RAW: std::cell::RefCell<Option<ag_image::RawSpec>> = const { std::cell::RefCell::new(None) };
    /// Which slice of a universal Mach-O the command line said the target
    /// is, likewise.
    static SLICE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The target as this run was told to read it, with the raw flags folded
/// in when they were given.
fn target_of(target: &Path, sha256: Option<String>) -> Target {
    let raw = RAW.with(|held| held.borrow().clone());
    let slice = SLICE.with(|held| held.borrow().clone());
    target_for(target, sha256, raw.as_ref(), slice.as_deref())
}

/// The target as a run reads it: the raw flags and the slice folded in when
/// they were given, so a project made here opens the same bytes later.
pub(crate) fn target_for(
    target: &Path,
    sha256: Option<String>,
    raw: Option<&ag_image::RawSpec>,
    slice: Option<&str>,
) -> Target {
    Target {
        path: Some(target.display().to_string()),
        sha256,
        slice: slice.map(str::to_string),
        raw: raw.map(|spec| {
            let arch = ag_image::raw_arch(&spec.language)
                .expect("a raw language the command line handed out has its word");
            RawArgs::target(spec, arch)
        }),
    }
}

/// Create a project file for `target`, recording the option pairs.
///
/// A `save` onto an existing file replaces it — and with it every annotation
/// it holds — so the file is refused unless `--force` says the analyst meant
/// it, the way `ag image export` refuses a non-empty directory.
fn save(target: &Path, out: &Path, options: Vec<String>, force: bool) -> Result<i32> {
    if out.exists() && !force {
        anyhow::bail!(
            "{} exists; its annotations would be replaced. Pass --force to write it anyway.",
            out.display()
        );
    }
    let sha256 = sha256_of(target)?;
    // A slice the file does not have would make a project nothing reads;
    // so would a universal file with no slice named.
    if SLICE.with(|held| held.borrow().is_none()) {
        if let Some(slices) = ag_image::Binary::slices_of(target)? {
            anyhow::bail!(
                "{} is a universal Mach-O with the slices {}: say which one with --slice",
                target.display(),
                slices
                    .iter()
                    .map(|slice| slice.arch.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if let Some(slice) = SLICE.with(|held| held.borrow().clone()) {
        let slices = ag_image::Binary::slices_of(target)?.with_context(|| {
            format!(
                "{} is not a universal Mach-O: it has no slices",
                target.display()
            )
        })?;
        anyhow::ensure!(
            ag_image::resolve_slice(&slices, &slice).is_some(),
            "{} has no slice {slice:?}; its slices are {}",
            target.display(),
            slices
                .iter()
                .enumerate()
                .map(|(index, slice)| format!("{index}: {}", slice.arch))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let mut project = ProjectFile::new(target_of(target, Some(sha256)));
    for pair in options {
        let (name, value) = pair
            .split_once('=')
            .with_context(|| format!("--option-pair {pair:?} is not NAME=VALUE"))?;
        project.options.insert(name.to_string(), value.to_string());
    }
    project.save(out)?;
    println!(
        "wrote {} ({} bytes of target, {} options)",
        out.display(),
        std::fs::metadata(target)?.len(),
        project.options.len()
    );
    Ok(0)
}

/// How to read the target as raw bytes, when it has no container to say
/// where it loads: `--raw ARCH --base ADDRESS`, with the entry, the offset
/// into the file and the length when they apply.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct RawArgs {
    /// Read the target as raw bytes of this architecture: x86-64, x86,
    /// arm, thumb or aarch64.
    #[arg(long, value_name = "ARCH")]
    pub raw: Option<String>,
    /// The address the bytes load at (with --raw).
    #[arg(long, requires = "raw")]
    pub base: Option<String>,
    /// The entry point (with --raw).
    #[arg(long, requires = "raw")]
    pub entry: Option<String>,
    /// Where in the file the bytes start (with --raw); the start of it
    /// otherwise.
    #[arg(long, requires = "raw")]
    pub offset: Option<String>,
    /// How many bytes (with --raw); the rest of the file otherwise.
    #[arg(long, requires = "raw")]
    pub length: Option<String>,
    /// Which slice of a universal Mach-O to read: an architecture, such as
    /// `arm64` or `x86_64`, or its position from 0.
    #[arg(long, conflicts_with = "raw")]
    pub slice: Option<String>,
}

impl RawArgs {
    /// What the flags say, when `--raw` is given.
    pub fn spec(&self) -> Result<Option<ag_image::RawSpec>> {
        let Some(arch) = &self.raw else {
            return Ok(None);
        };
        let language = ag_image::raw_language(arch).with_context(|| {
            format!(
                "{arch:?} is not an architecture raw bytes are read as: {}",
                ag_image::RAW_ARCHITECTURES
            )
        })?;
        let base = self
            .base
            .as_deref()
            .context("raw bytes need --base, the address they load at")?;
        Ok(Some(ag_image::RawSpec {
            language: language.to_string(),
            base: number(base)?,
            entry: self.entry.as_deref().map(number).transpose()?,
            offset: self.offset.as_deref().map(number).transpose()?.unwrap_or(0),
            length: self.length.as_deref().map(number).transpose()?,
        }))
    }

    /// The flags as the project file records them.
    pub fn target(spec: &ag_image::RawSpec, arch: &str) -> ag_corpus::project::RawTarget {
        ag_corpus::project::RawTarget {
            arch: arch.to_string(),
            base: format!("{:#x}", spec.base),
            entry: spec.entry.map(|entry| format!("{entry:#x}")),
            offset: (spec.offset != 0).then(|| format!("{:#x}", spec.offset)),
            length: spec.length.map(|length| format!("{length:#x}")),
        }
    }
}

/// How raw bytes were said to load, in a sentence.
pub fn describe_raw(spec: &ag_image::RawSpec) -> String {
    format!(
        "as {} at {:#x}{}{}{}",
        ag_image::raw_arch(&spec.language).unwrap_or(&spec.language),
        spec.base,
        spec.entry
            .map_or(String::new(), |entry| format!(", entry {entry:#x}")),
        if spec.offset != 0 {
            format!(", from offset {:#x}", spec.offset)
        } else {
            String::new()
        },
        spec.length
            .map_or(String::new(), |length| format!(", {length} bytes")),
    )
}

/// How a project's target loads as raw bytes, when it says it does, in the
/// image's terms.
pub fn raw_of_project(project: &ProjectFile) -> Result<Option<ag_image::RawSpec>> {
    let Some(raw) = &project.target.raw else {
        return Ok(None);
    };
    let language = ag_image::raw_language(&raw.arch).with_context(|| {
        format!(
            "the project's raw target names {:?}, not an architecture raw bytes are read as: {}",
            raw.arch,
            ag_image::RAW_ARCHITECTURES
        )
    })?;
    Ok(Some(ag_image::RawSpec {
        language: language.to_string(),
        base: number(&raw.base)?,
        entry: raw.entry.as_deref().map(number).transpose()?,
        offset: raw.offset.as_deref().map(number).transpose()?.unwrap_or(0),
        length: raw.length.as_deref().map(number).transpose()?,
    }))
}

/// Read `target` as the project says — raw bytes when its target says so —
/// under `layout`.
pub fn open_target(
    target: &Path,
    raw: Option<&ag_image::RawSpec>,
    slice: Option<&str>,
    layout: &ag_image::Layout,
) -> Result<ag_image::Binary> {
    match (raw, slice) {
        (Some(_), Some(_)) => {
            anyhow::bail!("a target is raw bytes or a slice of a universal Mach-O, not both")
        }
        (Some(spec), None) => ag_image::Binary::open_raw_with_layout(target, spec, layout),
        (None, Some(slice)) => ag_image::Binary::open_slice_with_layout(target, slice, layout),
        (None, None) => ag_image::Binary::open_with_layout(target, layout),
    }
    .with_context(|| format!("reading {}", target.display()))
}

/// One edit to the image's segments.
/// What `ag project … types` does.
#[derive(Subcommand)]
pub enum TypesCmd {
    /// Add the definitions of C source, each declaration a definition of its
    /// own: `struct point { int x, y; };`, `typedef struct node node_t;`
    Add {
        /// The C source; read from `--from` when absent.
        source: Option<String>,
        /// A file the C source is read from.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Replace the definition NAME with C source, in its place
    Replace {
        /// The definition: `struct point`, `point`, `node_t`.
        name: String,
        /// The C source; read from `--from` when absent.
        source: Option<String>,
        /// A file the C source is read from.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Remove the definition NAME; refused while another definition or a
    /// variable's type names what it defines
    Remove {
        /// The definition: `struct point`, `point`, `node_t`.
        name: String,
    },
    /// Show the definitions, or one, as C with their layout: each member's
    /// offset, the padding, the size and the alignment
    Show {
        /// The definition; every one when absent.
        name: Option<String>,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The definitions whose name, members or C hold TEXT, in any case
    Search {
        /// The text looked for.
        text: String,
        /// Where to look: `name`, `member`, `text` or `any`.
        #[arg(long = "in", value_name = "WHERE", default_value = "any")]
        within: String,
        /// Report as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum SegmentCmd {
    /// Add a segment the loader missed.
    Add {
        /// Its name.
        name: String,
        /// The address it maps to, in the moved image's addresses.
        address: String,
        /// Its size in memory, in bytes (`16` or `0x10`).
        size: String,
        /// Where its bytes start in the file, when the file holds them.
        #[arg(long)]
        file_offset: Option<String>,
        /// The segment holds code.
        #[arg(long)]
        exec: bool,
    },
    /// Take a segment out of the image.
    Remove {
        /// Its name.
        name: String,
    },
    /// Call a segment something else.
    Rename {
        /// Its name.
        name: String,
        /// Its new name.
        to: String,
    },
}

/// The layout `project` records, in the image's terms, or why it does not
/// read as one.
pub fn layout_of(project: &ProjectFile) -> Result<ag_image::Layout> {
    let address = |text: &str| -> Result<u64> {
        ag_corpus::parse_addr_space(text)
            .map(|(value, _)| value)
            .map_err(|_| anyhow::anyhow!("{text:?} in the layout is not an address"))
    };
    let base = project.layout.base.as_deref().map(address).transpose()?;
    let mut segments = Vec::new();
    for edit in &project.layout.segments {
        segments.push(match edit {
            ag_corpus::project::SegmentEdit::Add {
                name,
                address: at,
                size,
                file_offset,
                executable,
            } => ag_image::SegmentEdit::Add {
                name: name.clone(),
                vma: address(at)?,
                size: *size,
                file_offset: file_offset.as_deref().map(address).transpose()?,
                executable: *executable,
            },
            ag_corpus::project::SegmentEdit::Remove { name } => {
                ag_image::SegmentEdit::Remove { name: name.clone() }
            }
            ag_corpus::project::SegmentEdit::Rename { name, to } => ag_image::SegmentEdit::Rename {
                name: name.clone(),
                to: to.clone(),
            },
        });
    }
    Ok(ag_image::Layout { base, segments })
}

/// A number as the command line spells it: decimal, or hex with `0x`.
fn number(text: &str) -> Result<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .with_context(|| format!("{text:?} is not a number"))
}

/// Read `target` as the project says — raw bytes when its target says so
/// — under the layout it records.
fn image_under(target: &Path, project: &ProjectFile) -> Result<ag_image::Binary> {
    let layout = layout_of(project)?;
    open_target(
        target,
        raw_of_project(project)?.as_ref(),
        project.target.slice.as_deref(),
        &layout,
    )
}

/// Read `target` under the layout `project` now records, so a layout the
/// image cannot take is refused before it is written.
fn check_layout(target: &Path, project: &ProjectFile) -> Result<()> {
    image_under(target, project).map(|_| ())
}

/// An address of the image as the command line spells it: a bare one, not
/// one with an address space, since the layout is the image's own.
fn image_address(text: &str) -> Result<u64> {
    match ag_corpus::parse_addr_space(text) {
        Ok((value, None)) => Ok(value),
        _ => anyhow::bail!("{text:?} is not an address of the image"),
    }
}

/// Say the global pointer's value, for the whole image or for one
/// function, or take the word back with `clear`.
fn global_pointer(target: &Path, file: &Path, value: &str, function: Option<&str>) -> Result<i32> {
    let value = match value.trim() {
        "clear" | "none" => None,
        text => Some(format!("{:#x}", image_address(text)?)),
    };
    if value.is_some() {
        let image = image_under(target, &open_project(target, file)?)?;
        anyhow::ensure!(
            image.global_pointer_convention().is_some(),
            "{} keeps no global pointer the engine follows: only 32-bit MIPS's gp is",
            image.language()
        );
    }
    match function {
        Some(function) => {
            let address = function_key(target, file, function)?;
            edit(target, file, TargetKind::Function, &address, |a| {
                a.global_pointer = value;
            })
        }
        None => {
            let mut project = open_project(target, file)?;
            project.global_pointer = value.clone();
            project.save(file)?;
            match value {
                Some(value) => println!(
                    "{}: the global pointer is {value} in every function the project says nothing more of",
                    file.display()
                ),
                None => println!(
                    "{}: the global pointer is what the image says",
                    file.display()
                ),
            }
            Ok(0)
        }
    }
}

/// Give `variable` of `function` the C type `ty`, or take it back with
/// `clear`. The type is read against the project's types.
fn var_type(target: &Path, file: &Path, function: &str, variable: &str, ty: &str) -> Result<i32> {
    let variable = variable.trim().to_string();
    anyhow::ensure!(!variable.is_empty(), "the variable is empty");
    let ty = ty.trim();
    let address = function_key(target, file, function)?;
    if ty.eq_ignore_ascii_case("clear") {
        let mut had = false;
        let code = edit(target, file, TargetKind::Function, &address, |a| {
            had = a.clear_var_type(&variable);
        })?;
        if !had {
            eprintln!("{variable} had no type given in {address}");
        }
        return Ok(code);
    }
    let project = open_project(target, file)?;
    let image = image_under(target, &project)?;
    let (store, _) = ag_image::ctype::build(image.data_model(), &crate::types::texts(&project))
        .map_err(|why| anyhow::anyhow!("the project's types are not read: {why}"))?;
    let parsed = ag_image::ctype::parse_type(&store, ty)
        .map_err(|error| anyhow::anyhow!("{ty} is not a type: {}", error.message))?;
    let spelled = parsed.spelled(&store);
    edit(target, file, TargetKind::Function, &address, |a| {
        a.set_var_type(&variable, &spelled);
    })
}

/// `ag project TARGET struct-from`: a structure made from the accesses
/// through a pointer, or one updated from them, and the pointer given a
/// pointer to it.
fn struct_from(
    target: &Path,
    file: &Path,
    function: &str,
    variable: &str,
    name: Option<&str>,
    update: Option<&str>,
    dry_run: bool,
) -> Result<i32> {
    let address = function_key(target, file, function)?;
    let mut project = open_project(target, file)?;
    let image = crate::image::open_image(
        target,
        None,
        None,
        Some(&project),
        ag_image::Options::default(),
    )?;
    anyhow::ensure!(
        image.supports_pseudocode(),
        "the lifter reads x86-64 code, and this image is {}",
        image.language()
    );
    let entry = ag_corpus::parse_addr(&address)?;
    let (lift, applied) =
        crate::types::struct_from(&image, &project, entry, variable, name, update)
            .map_err(anyhow::Error::msg)?;
    match &applied.draft {
        Some(draft) => print!("{}", crate::types::draft_text(draft)),
        None => {
            println!("{}\n", applied.c);
            print!("{}", crate::types::added_text(&applied));
        }
    }
    if dry_run {
        println!("{}: nothing changed (--dry-run)", file.display());
        return Ok(0);
    }
    project.types = crate::types::definitions(&applied.definitions);
    project
        .annotation_mut(TargetKind::Function, &address)
        .set_var_type(&lift, &applied.pointer);
    project.prune();
    project.save(file)?;
    println!(
        "{}: {} {}, {lift} of {address} typed {}",
        file.display(),
        applied.key,
        if applied.draft.is_some() {
            "defined"
        } else {
            "updated"
        },
        applied.pointer
    );
    Ok(0)
}

/// The C source an edit of the types gives: the argument, or the file.
fn type_source(source: Option<String>, from: Option<PathBuf>) -> Result<String> {
    match (source, from) {
        (Some(source), None) => Ok(source),
        (None, Some(from)) => {
            std::fs::read_to_string(&from).with_context(|| format!("reading {}", from.display()))
        }
        (Some(_), Some(_)) => anyhow::bail!("give the C source or --from, not both"),
        (None, None) => anyhow::bail!("give the C source, or --from FILE"),
    }
}

/// `ag project TARGET types …`.
fn types(target: &Path, file: &Path, cmd: TypesCmd) -> Result<i32> {
    let mut project = open_project(target, file)?;
    let image = image_under(target, &project)?;
    let model = image.data_model();
    let held = crate::types::texts(&project);
    let notes = |notes: &[String]| {
        for note in notes {
            eprintln!("note: {note}");
        }
    };
    match cmd {
        TypesCmd::Add { source, from } => {
            let source = type_source(source, from)?;
            let (defined, added, said) =
                ag_image::ctype::add(model, &held, &source).map_err(anyhow::Error::msg)?;
            notes(&said);
            project.types = crate::types::definitions(&defined);
            project.save(file)?;
            println!("{}: {} defined", file.display(), added.join(", "));
            Ok(0)
        }
        TypesCmd::Replace { name, source, from } => {
            let source = type_source(source, from)?;
            let (defined, said) = ag_image::ctype::replace(model, &held, &name, &source)
                .map_err(anyhow::Error::msg)?;
            notes(&said);
            project.types = crate::types::definitions(&defined);
            project.save(file)?;
            println!("{}: {} replaced", file.display(), name.trim());
            Ok(0)
        }
        TypesCmd::Remove { name } => {
            let users = crate::types::users(&project, &image);
            let (defined, gone) =
                ag_image::ctype::remove(model, &held, &name, &users).map_err(anyhow::Error::msg)?;
            project.types = crate::types::definitions(&defined);
            project.save(file)?;
            println!("{}: {gone} removed", file.display());
            Ok(0)
        }
        TypesCmd::Show { name, json } => {
            let (store, _) = ag_image::ctype::build(model, &held).map_err(anyhow::Error::msg)?;
            let keys: Vec<String> = match &name {
                Some(name) => vec![store
                    .key_of(name)
                    .ok_or_else(|| anyhow::anyhow!("no type is named {}", name.trim()))?],
                None => store.names().into_iter().map(str::to_string).collect(),
            };
            if json {
                let shown: Vec<serde_json::Value> = keys
                    .iter()
                    .map(|key| crate::types::type_json(&store, key))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&shown)?);
                return Ok(0);
            }
            if keys.is_empty() {
                println!("{}: no types are defined", file.display());
            }
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    println!();
                }
                if let Some(text) = store.definition_text(key, true) {
                    println!("{text}");
                }
            }
            Ok(0)
        }
        TypesCmd::Search { text, within, json } => {
            let within = ag_image::TypeSearch::parse(&within).ok_or_else(|| {
                anyhow::anyhow!("{within:?} is not where a search looks: name, member, text or any")
            })?;
            let (store, _) = ag_image::ctype::build(model, &held).map_err(anyhow::Error::msg)?;
            let found = store.search(&text, within);
            if json {
                let shown: Vec<serde_json::Value> = found
                    .iter()
                    .map(|key| crate::types::type_json(&store, key))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&shown)?);
                return Ok(0);
            }
            if found.is_empty() {
                println!("no type matches {:?}", text);
            }
            for key in &found {
                println!("{}", crate::types::summary(&store, key));
            }
            Ok(0)
        }
    }
}

/// Move the image to `base`, or put it back with `none`.
fn rebase(target: &Path, file: &Path, base: &str) -> Result<i32> {
    let mut project = open_project(target, file)?;
    let base = match base {
        "none" => None,
        text => Some(image_address(text)?),
    };
    project.set_base(base);
    check_layout(target, &project)?;
    project.save(file)?;
    match base {
        Some(base) => println!("{}: the image is read at {base:#x}", file.display()),
        None => println!(
            "{}: the image is read where the loader puts it",
            file.display()
        ),
    }
    Ok(0)
}

/// Add, remove or rename a segment.
fn segment(target: &Path, file: &Path, edit: SegmentCmd) -> Result<i32> {
    use ag_corpus::project::SegmentEdit;
    let mut project = open_project(target, file)?;
    let (edit, said) = match edit {
        SegmentCmd::Add {
            name,
            address,
            size,
            file_offset,
            exec,
        } => {
            let at = image_address(&address)?;
            let size = number(&size)?;
            let offset = file_offset.as_deref().map(number).transpose()?;
            let said = format!("segment {name} added at {at:#x}, {size} bytes");
            (
                SegmentEdit::Add {
                    name,
                    address: format!("{at:#x}"),
                    size,
                    file_offset: offset.map(|offset| format!("{offset:#x}")),
                    executable: exec,
                },
                said,
            )
        }
        SegmentCmd::Remove { name } => {
            let said = format!("segment {name} removed");
            (SegmentEdit::Remove { name }, said)
        }
        SegmentCmd::Rename { name, to } => {
            let said = format!("segment {name} renamed {to}");
            (SegmentEdit::Rename { name, to }, said)
        }
    };
    project
        .edit_segment(edit)
        .map_err(|reason| anyhow::anyhow!("{reason}"))?;
    check_layout(target, &project)?;
    project.save(file)?;
    println!("{}: {said}", file.display());
    Ok(0)
}

/// Patch the opaque predicates of the functions named, or of every one,
/// into the project of `target`, or only say what would be patched.
fn patch_opaque(
    target: &Path,
    file: &Path,
    functions: &[String],
    all: bool,
    dry_run: bool,
) -> Result<i32> {
    let mut project = open_project(target, file)?;
    // The image is read with the patches the project holds already, so a
    // branch patched before is not found again.
    let raw = RAW.with(|held| held.borrow().clone());
    let slice = SLICE.with(|held| held.borrow().clone());
    let image = crate::image::open_image(
        target,
        raw,
        slice,
        Some(&project),
        ag_image::Options::default(),
    )?;
    let addresses = crate::image::opaque_functions(&image, functions, all)?;
    let rows = crate::image::opaque_rows(&image, &addresses);
    let mut patched = 0;
    for row in &rows {
        let site = row.opaque.site;
        let Some((bytes, text)) = &row.patch else {
            println!(
                "{site:#x}  {}  {}: not patched, the target {:#x} is out of the jump's reach",
                row.function,
                crate::image::taken_words(row.opaque.always),
                row.opaque.target
            );
            continue;
        };
        println!(
            "{site:#x}  {}  {}  {}  ->  {} ({text})",
            row.function,
            crate::image::taken_words(row.opaque.always),
            row.opaque.why,
            ag_corpus::project::hex_of_bytes(bytes),
        );
        if !dry_run {
            project.write_patch(
                TargetKind::Address,
                &format!("{site:#x}"),
                Some((bytes, Some(text))),
            );
        }
        patched += 1;
    }
    if rows.is_empty() {
        println!("no opaque predicates");
        return Ok(0);
    }
    if dry_run {
        println!(
            "{patched} patch{} not saved (--dry-run)",
            if patched == 1 { "" } else { "es" }
        );
    } else if patched > 0 {
        project.save(file)?;
        println!(
            "{}: {patched} opaque predicate{} patched",
            file.display(),
            if patched == 1 { "" } else { "s" }
        );
    }
    Ok(0)
}

/// Write a copy of `target` with the patches `file` holds in it.
fn write_patched(target: &Path, file: &Path, out: &Path, force: bool) -> Result<i32> {
    let project = load_project(target, file)?;
    let patches = project.patches();
    anyhow::ensure!(!patches.is_empty(), "{} holds no patches", file.display());
    // The target is never written, nor the project file: the copy goes
    // somewhere else. A link to either is the same file.
    anyhow::ensure!(
        out != target && !ag_image::same_file(out, target),
        "{} is the target itself",
        out.display()
    );
    anyhow::ensure!(
        out != file && !ag_image::same_file(out, file),
        "{} is the project file",
        out.display()
    );
    if out.exists() && !force {
        anyhow::bail!("{} exists. Pass --force to write over it.", out.display());
    }
    // Patches were made against the bytes the project hashed: written into
    // a target rebuilt since, they would land on the wrong bytes.
    if let (Some(recorded), false) = (project.target.sha256.as_deref(), force) {
        let now = sha256_of(target)?;
        anyhow::ensure!(
            now == recorded,
            "{} has changed since the project was made: its SHA-256 is not the one recorded. Pass --force to write anyway.",
            target.display()
        );
    }
    // Under the project's layout, so the patches' addresses are the
    // image's and an added segment's bytes are in the file where it says.
    let image = image_under(target, &project)?;
    let count = patches.len();
    let bytes: usize = patches.values().map(Vec::len).sum();
    image.set_patches(patches);
    let original =
        std::fs::read(target).with_context(|| format!("reading {}", target.display()))?;
    let written = image.patched_file(&original)?;
    // The copy runs as the target does, and is whole or not there.
    ag_image::write_copy(target, out, &written)
        .with_context(|| format!("writing {}", out.display()))?;
    println!(
        "wrote {} ({} bytes; {count} patch{} over {bytes} byte{})",
        out.display(),
        written.len(),
        if count == 1 { "" } else { "es" },
        if bytes == 1 { "" } else { "s" },
    );
    Ok(0)
}

/// Print what the project file of `target` holds.
fn show(target: &Path, file: &Path, json: bool) -> Result<i32> {
    let project = load_project(target, file)?;
    if json {
        print!("{}", project.to_json()?);
        return Ok(0);
    }
    let target_field = project
        .target
        .path
        .as_deref()
        .unwrap_or("(no path recorded)");
    println!("project of {target_field}");
    if let Some(sha) = &project.target.sha256 {
        println!("  sha256  {sha}");
    }
    for (name, value) in &project.options {
        println!("  option  {name} = {value}");
    }
    for annotation in &project.annotations {
        // A variable or register record says which thing it names; the
        // address alone would not tell it from the function's own record.
        let target = match (&annotation.variable, &annotation.register) {
            (Some(variable), _) => format!("{}::{variable}", annotation.address),
            (_, Some(register)) => format!("{}::{register}", annotation.address),
            (None, None) => annotation.address.clone(),
        };
        println!(
            "  {:9} {:>16}  {}",
            annotation.kind.label(),
            target,
            summarize(annotation)
        );
    }
    if project.annotations.is_empty() {
        println!("  (no annotations)");
    }
    // The target argument is the file the project describes; say when it
    // no longer matches what was recorded.
    if let Some(recorded) = &project.target.sha256 {
        match sha256_of(target) {
            Ok(current) if &current != recorded => {
                println!("  note: {target:?} now hashes to {current}, not {recorded}")
            }
            Err(_) => println!("  note: {target:?} cannot be read to check its hash"),
            _ => {}
        }
    }
    Ok(0)
}

/// Print the tags of the project file, or the places carrying `tag`.
///
/// Without a tag, one line per tag with how many places carry it. With
/// one, one line per place, in address order, in the shape `show` prints a
/// record — the kind, the address, and what the record carries.
fn tags(target: &Path, file: &Path, tag: Option<&str>) -> Result<i32> {
    let project = load_project(target, file)?;
    match tag {
        None => {
            let index = project.tags();
            for (tag, places) in &index {
                println!(
                    "  {tag:20} {places} place{}",
                    if *places == 1 { "" } else { "s" }
                );
            }
            if index.is_empty() {
                println!("  (no tags)");
            }
        }
        Some(tag) => {
            let places = project.tagged(tag);
            for annotation in &places {
                println!(
                    "  {:9} {:>16}  {}",
                    annotation.kind.label(),
                    annotation.address,
                    summarize(annotation)
                );
            }
            if places.is_empty() {
                println!("  (nothing carries the tag {tag:?})");
            }
        }
    }
    Ok(0)
}

/// Write a patch into the project of `target` — taking off the patches it
/// overlaps, as the workbench does — then save it back and report.
fn edit_patch(
    target: &Path,
    file: &Path,
    address: &str,
    patch: Option<(&[u8], Option<&str>)>,
) -> Result<i32> {
    let mut project = open_project(target, file)?;
    project.write_patch(TargetKind::Address, address, patch);
    project.save(file)?;
    let key = ag_corpus::project::canonical_address(address).unwrap_or_else(|| address.to_string());
    match project.annotation_for(&key) {
        Some(a) => println!("{}: address {key} now {}", file.display(), summarize(a)),
        None => println!("{}: address {key} cleared", file.display()),
    }
    Ok(0)
}

/// Change one annotation of the project of `target`, then save it back.
/// The record key of the function `function` names: an address spelled
/// `0x…` or with its space is taken as it is; anything else is a name the
/// image says the address of first, so a function called `beef` is not the
/// address 0xbeef.
fn function_key(target: &Path, file: &Path, function: &str) -> Result<String> {
    let name = function.trim();
    let spelled = name.to_ascii_lowercase().starts_with("0x") || name.contains(':');
    Ok(match ag_corpus::project::canonical_address(name) {
        Some(address) if spelled => address,
        bare => {
            let image = image_under(target, &open_project(target, file)?)?;
            let found = image
                .functions()
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.address)
                .or_else(|| image.address_of_mangled(name));
            match (found, bare) {
                (Some(found), _) => format!("{found:#x}"),
                (None, Some(address)) => address,
                (None, None) => anyhow::bail!("no function is named {name:?}"),
            }
        }
    })
}

fn edit(
    target: &Path,
    file: &Path,
    kind: TargetKind,
    address: &str,
    change: impl FnOnce(&mut Annotation),
) -> Result<i32> {
    let mut project = open_project(target, file)?;
    change(project.annotation_mut(kind, address));
    project.prune();
    project.save(file)?;
    let key = ag_corpus::project::canonical_address(address).unwrap_or_else(|| address.to_string());
    // A block's record stands apart from the address's own, so the report
    // reads back the one the edit reached.
    let kept = if kind == TargetKind::Region {
        project.block_for(&key)
    } else {
        project.annotation_for(&key)
    };
    match kept {
        Some(a) => println!(
            "{}: {} {key} now {}",
            file.display(),
            kind.label(),
            summarize(a)
        ),
        None => println!("{}: {} {key} cleared", file.display(), kind.label()),
    }
    Ok(0)
}

/// Change the record that names one thing — a variable, a register — at
/// `address`, keyed on `thing` beside it.
///
/// The two records are the same shape: a name at one address, told apart
/// from the address's own record by a key of their own. The caller says
/// which record to reach and what to call the kind in the report.
fn edit_named(
    target: &Path,
    file: &Path,
    named: Named,
    address: &str,
    thing: &str,
    change: impl FnOnce(&mut Annotation),
) -> Result<i32> {
    let mut project = open_project(target, file)?;
    let key = ag_corpus::project::canonical_address(address)
        .unwrap_or_else(|| address.to_string());
    match named {
        Named::Variable => change(project.variable_mut(&key, thing)),
        Named::Register => change(project.register_mut(&key, thing)),
    }
    project.prune();
    project.save(file)?;
    let kept = match named {
        Named::Variable => project.variable_for(&key, thing),
        Named::Register => project.register_for(&key, thing),
    };
    let label = named.label();
    match kept {
        Some(a) => println!(
            "{}: {label} {key}::{thing} now {}",
            file.display(),
            summarize(a)
        ),
        None => println!("{}: {label} {key}::{thing} cleared", file.display()),
    }
    Ok(0)
}

/// The project says how its target loads; `--raw` flags that say otherwise
/// would read other bytes under the same records, and are refused.
fn check_raw_flags(project: &ProjectFile, file: &Path) -> Result<()> {
    let flags = RAW.with(|held| held.borrow().clone());
    if let Some(flags) = flags {
        let recorded = raw_of_project(project)?;
        anyhow::ensure!(
            recorded.as_ref() == Some(&flags),
            "the --raw flags say the target loads {}, but {} says {}: drop the flags, or make a new project",
            describe_raw(&flags),
            file.display(),
            recorded
                .as_ref()
                .map_or("it is not raw bytes".to_string(), describe_raw)
        );
    }
    Ok(())
}

/// The project says which slice of a universal Mach-O its target is; a
/// `--slice` that names another — by whatever spelling — would read another
/// image under the same records, and is refused. The flag and the record
/// are the same slice when they resolve to the same place in the file.
pub fn check_slice_flag(
    target: &Path,
    flag: Option<&str>,
    recorded: Option<&str>,
    file: &Path,
) -> Result<()> {
    let Some(flag) = flag else {
        return Ok(());
    };
    let slices = ag_image::Binary::slices_of(target)?.unwrap_or_default();
    let place = |selector: &str| {
        ag_image::resolve_slice(&slices, selector)
            .map(|slice| slice.offset)
            .with_context(|| format!("{} has no slice {selector:?}", target.display()))
    };
    let wanted = place(flag)?;
    match recorded {
        Some(recorded) if place(recorded)? == wanted => Ok(()),
        Some(recorded) => anyhow::bail!(
            "the --slice flag says the target is the {flag} slice, but {} says {recorded}: drop the flag, or make a new project",
            file.display()
        ),
        None => anyhow::bail!(
            "the --slice flag says the target is the {flag} slice, but {} says it is the whole file: drop the flag, or make a new project",
            file.display()
        ),
    }
}

/// Read the project at `file`, which has to exist, with the flags checked.
fn load_project(target: &Path, file: &Path) -> Result<ProjectFile> {
    let project = ProjectFile::load(file)?;
    check_raw_flags(&project, file)?;
    let flag = SLICE.with(|held| held.borrow().clone());
    check_slice_flag(
        target,
        flag.as_deref(),
        project.target.slice.as_deref(),
        file,
    )?;
    Ok(project)
}

/// The project of `file`, created from `target` when the file is not there.
fn open_project(target: &Path, file: &Path) -> Result<ProjectFile> {
    // The project may not exist yet: the first edit creates it from the target.
    match ProjectFile::load(file) {
        Ok(project) => {
            check_raw_flags(&project, file)?;
            let flag = SLICE.with(|held| held.borrow().clone());
            check_slice_flag(
                target,
                flag.as_deref(),
                project.target.slice.as_deref(),
                file,
            )?;
            Ok(project)
        }
        Err(_) if !file.exists() => {
            let sha256 = match sha256_of(target) {
                Ok(sha) => Some(sha),
                Err(error) => {
                    eprintln!("note: {target:?} cannot be hashed to record: {error:#}");
                    None
                }
            };
            Ok(ProjectFile::new(target_of(target, sha256)))
        }
        Err(error) => Err(error),
    }
}

/// What an annotation carries, as one comma-separated line.
///
/// `show` prints an annotation with this, and `edit` confirms with it, so the
/// two can never disagree about what a record holds.
/// A stack offset as the frame spells it: `-0x20`, `+0x8`.
fn stack_offset_text(offset: i64) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    format!("{sign}{:#x}", offset.unsigned_abs())
}

fn summarize(annotation: &Annotation) -> String {
    let mut parts = Vec::new();
    if let Some(name) = &annotation.name {
        parts.push(format!("name {name}"));
    }
    if let Some(comment) = &annotation.comment {
        // The placement is part of what the record says, so the report
        // names it: an above-comment is not the same note as an inline one.
        if annotation.comment_above {
            parts.push(format!("comment above {comment:?}"));
        } else {
            parts.push(format!("comment {comment:?}"));
        }
    }
    if annotation.bookmark {
        parts.push("bookmark".to_string());
    }
    if !annotation.tags.is_empty() {
        parts.push(format!("tags {}", annotation.tags.join(",")));
    }
    if !annotation.references.is_empty() {
        parts.push(format!("refs {}", annotation.references.join(",")));
    }
    if let Some(color) = &annotation.color {
        parts.push(format!("color {color}"));
    }
    if let Some(byte_type) = &annotation.byte_type {
        parts.push(format!("type {byte_type}"));
    }
    if let Some(format) = &annotation.operand_format {
        parts.push(format!("operands {format}"));
    }
    if let Some(table) = &annotation.jump_table {
        parts.push(format!("switch {table}"));
    }
    if annotation.drop_stores {
        parts.push("dead stores dropped".to_string());
    }
    if !annotation.overrides.is_empty() {
        parts.push(format!("override {}", annotation.overrides_label()));
    }
    match annotation.inline {
        Some(true) => parts.push("inline on".to_string()),
        Some(false) => parts.push("inline off".to_string()),
        None => {}
    }
    if let Some(value) = &annotation.global_pointer {
        parts.push(format!("global pointer {value}"));
    }
    for (keep, gone) in &annotation.merges {
        parts.push(format!("merge {gone} into {keep}"));
    }
    for split in &annotation.splits {
        parts.push(format!("split {} at {}", split.variable, split.at));
    }
    for version in &annotation.versions {
        parts.push(format!("version {} at {}", version.variable, version.at));
    }
    for value in &annotation.values {
        let at = value
            .at
            .as_ref()
            .map(|at| format!(" at {at}"))
            .unwrap_or_default();
        parts.push(format!(
            "value {} = {}{at}",
            value.variable,
            value.spelled()
        ));
    }
    for word in &annotation.var_types {
        parts.push(format!("variable {} of type {}", word.variable, word.ty));
    }
    for variable in &annotation.stack_vars {
        let mut text = format!(
            "stack variable {} at {}",
            variable.name.as_deref().unwrap_or("(unnamed)"),
            variable.spelled()
        );
        if let Some(ty) = &variable.ty {
            text.push_str(&format!(" of {ty}"));
        }
        parts.push(text);
    }
    if let Some(patch) = &annotation.patch {
        match &annotation.patch_text {
            Some(text) => parts.push(format!("patch {patch} ({text})")),
            None => parts.push(format!("patch {patch}")),
        }
    }
    if let Some(mode) = &annotation.mode {
        parts.push(format!("mode {mode}"));
    }
    if parts.is_empty() {
        "(empty)".to_string()
    } else {
        parts.join(", ")
    }
}
