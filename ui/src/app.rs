//! Application state, messages, and the update loop.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iced::keyboard::{self, Key};
use iced::{Element, Subscription, Task};

use crate::data::binary::BinaryProvider;
use crate::data::corpus::CorpusProvider;
use crate::data::empty::EmptyProvider;
use crate::data::kuna::{KunaProvider, SharedCache};
use crate::data::kuna_json::{
    self, Direction, FunctionJson, KunaCli, StringJson, SummaryJson, XrefJson,
};
use crate::data::sample::SampleProvider;
use crate::data::{
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, Graph, GraphBlock, ListingLine, Problem,
    Provider, Reference, ReferenceKind, SearchHit, SectionCounts, StringEntry,
};
use crate::model::{Capabilities, History, Project, Selection};
use crate::views::bottom_panel::BottomTab;
use crate::views::navigator::Section;
use crate::views::work_surface::{LowerTab, ViewTab};

/// Everything the workbench can react to.
#[derive(Debug, Clone)]
pub enum Message {
    /// The navigator filter text changed.
    NavigatorFilterChanged(String),
    /// A navigator section was opened.
    SectionSelected(Section),
    /// A function row was activated.
    FunctionSelected(u64),
    /// An address inside the current function was activated.
    AddressSelected(u64),
    /// A string in the strings list was picked.
    StringSelected(u64),
    /// A piece of data in the navigator was picked.
    DataSelected(u64),
    /// The filter of the strings list changed.
    StringFilterChanged(String),
    /// A center work surface tab was activated.
    ViewTabSelected(ViewTab),
    /// Show or hide the statements whose results nothing uses, in the
    /// pseudocode: the engine's `dead-code` option, flipped, and the image
    /// read again under it.
    ToggleDeadCode,
    /// A lower work surface tab was activated.
    LowerTabSelected(LowerTab),
    /// A bottom workspace tab was activated.
    BottomTabSelected(BottomTab),
    /// The global command/search field changed.
    GlobalQueryChanged(String),
    /// The global search field was submitted.
    SearchSubmitted,
    /// The global search field was submitted with the deep-search modifier.
    DeepSearchSubmitted,
    /// Prompt for a corpus directory.
    FileOpenCorpus,
    /// Prompt for a kuna project export directory.
    FileOpenKuna,
    /// Prompt for a program image.
    FileOpenBinary,
    /// Prompt for an Objective-C method map.
    FileOpenMethods,
    /// Prompt for a project file to open.
    FileOpenProject,
    /// Save the analyst's changes to the project file.
    FileSaveProject,
    /// Prompt for a project file to save to.
    FileSaveProjectAs,
    /// Write a copy of the program with the patches in it.
    FileWritePatched,
    /// Write the graph of the function on screen as an SVG or PDF picture.
    FileExportGraph,
    /// Show the active pane — the listing or the graph — at the next level
    /// of the lift, or back at the disassembly.
    ViewCycleLevel,
    /// Show the active pane's level in SSA form, or out of it.
    ViewToggleSsa,
    /// Show, or stop showing, one of the notes beside a level's items.
    ViewToggleIlOption(IlOption),
    /// Run the program under the debugger, stopped at its first instruction.
    DebugStart,
    /// Ask for a process to attach the debugger to.
    DebugAttach,
    /// Let the stopped program run on.
    DebugContinue,
    /// Run one instruction, into a call.
    DebugStep,
    /// Run one instruction, over a call.
    DebugNext,
    /// Run until the current function returns.
    DebugFinish,
    /// Stop the running program where it is.
    DebugInterrupt,
    /// End the program and the debugger.
    DebugStop,
    /// Put a breakpoint at the address, or at the selection, or take it off.
    DebugToggleBreakpoint(Option<u64>),
    /// Look at what the debugger said since the last look.
    DebugPoll,
    /// Open a file as raw bytes, loaded where the analyst says.
    FileOpenRaw,
    /// Say which instruction set the code from the selection onward is in.
    EditMode,
    /// Move the whole image to a new base address.
    EditRebase,
    /// Add a segment the loader missed.
    EditSegmentAdd,
    /// Take a segment out of the image.
    EditSegmentRemove,
    /// Call a segment something else.
    EditSegmentRename,
    /// Reload the open project.
    FileReload,
    /// Close the open project.
    FileClose,
    /// Quit the application.
    FileQuit,
    /// Rename the selected function.
    EditRename,
    /// Rename the label at the selected address.
    EditRenameLabel,
    /// Rename a local variable of the function at the selection.
    EditRenameVariable,
    /// Rename a register as the function at the selection prints it.
    EditRenameRegister,
    /// Comment the selected address, inline at the end of its line.
    EditComment,
    /// Comment the selected address, on its own line above the instruction.
    EditCommentAbove,
    /// Toggle a bookmark on the selection.
    EditBookmark,
    /// Jump to a bookmarked place from the navigator's list.
    BookmarkSelected(u64),
    /// Edit the tags on the selection.
    EditTags,
    /// Set or clear the highlight color on the selection.
    EditColor,
    /// Set or clear the highlight color on the block holding the selection.
    EditColorBlock,
    /// Set or clear the analyst's text on the block holding the selection:
    /// its title in the graph.
    EditBlockText,
    /// Put the block holding the selection in a group, or take it out: the
    /// blocks of a group are one node of the graph.
    EditGroup,
    /// Move the selection to a neighbouring block of the graph.
    GraphMove(crate::views::graph::Direction),
    /// Record a cross reference from the selection that the analysis
    /// cannot see.
    EditReference,
    /// Take back a cross reference the analyst recorded from the selection.
    EditReferenceRemove,
    /// Jump to a place: a function opens, any other address is selected.
    JumpTo(u64),
    /// Say how the bytes at the selection are read.
    EditMark(Mark),
    /// Say where the jump table the selected `jmp` reads is.
    EditSwitch,
    /// Allow or prevent one of the lift's judgment calls at the selected
    /// address.
    EditOverride,
    /// Assemble an instruction over the bytes at the selection.
    EditAssemble,
    /// Fill the selected instruction with the architecture's no-op.
    EditNop,
    /// Edit the bytes at the selection, as hex pairs.
    EditBytes,
    /// Fill a run of bytes from the selection with the no-op.
    EditNopRange,
    /// Show the constants in the selected instruction's operands the next
    /// way round: hex, signed, decimal, octal, as an address.
    EditOperandFormat,
    /// Take back the analyst's last change.
    EditUndo,
    /// Put back the change last taken back.
    EditRedo,
    /// Filter the function list to the places carrying a tag.
    TagSelected(String),
    /// Show or hide the navigator.
    ViewToggleNavigator,
    /// Show or hide the inspector.
    ViewToggleInspector,
    /// Show or hide the bottom panel.
    ViewToggleBottom,
    /// Restore the default layout.
    ViewResetLayout,
    /// Restart the analysis.
    AnalysisRestart,
    /// Show the analysis log.
    AnalysisShowLog,
    /// Show the keyboard shortcuts.
    HelpShortcuts,
    /// Show the about dialog.
    HelpAbout,
    /// Close the about dialog.
    AboutClose,
    /// Open the repository in the system browser.
    AboutOpenRepository,
    /// Dismiss whatever is on top.
    Dismiss,
    /// The path prompt text changed.
    PromptChanged(String),
    /// The path prompt was submitted.
    PromptSubmit,
    /// The path prompt was dismissed.
    PromptCancel,
    /// Step back through the shared navigation history.
    Back,
    /// Step forward through the shared navigation history.
    Forward,
    /// Pin or unpin the current location so synchronization stops moving it.
    TogglePin,
    /// A key press that maps to no command.
    Ignore,
    /// The kuna CLI answered with the shape of the program.
    KunaSummaryReady(Result<SummaryJson, String>),
    /// The kuna CLI answered with the program's strings.
    KunaStringsReady(Result<Vec<StringJson>, String>),
    /// The kuna CLI answered with one function's decompilation.
    KunaFunctionReady(u64, Result<FunctionJson, String>),
    /// The kuna CLI answered with one function's cross references.
    KunaXrefsReady(u64, Direction, Result<Vec<XrefJson>, String>),
    /// The calls between the functions of a program image have been worked out.
    BinaryIndexReady,
}

/// The kuna CLI a kuna project can be asked, and the answers it has given.
pub struct KunaState {
    /// The CLI itself, when the export names a binary that is still there.
    pub cli: Option<KunaCli>,
    /// Where its answers are kept.
    pub cache: SharedCache,
}

/// What the workbench still has to ask the kuna CLI about a function.
///
/// Every answer the CLI gives costs a process run against the binary, so an
/// answer already in the cache is not asked for again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct KunaAsks {
    /// The decompilation of the function.
    decompile: bool,
    /// The references the function makes.
    xrefs_from: bool,
    /// The references made to the function.
    xrefs_to: bool,
}

/// What the path prompt is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// A corpus directory.
    Corpus,
    /// A kuna project export directory.
    Kuna,
    /// A program image.
    Binary,
    /// An Objective-C method map.
    Methods,
    /// A project file to open.
    ProjectOpen,
    /// A project file to save to.
    ProjectSave,
    /// Where the copy of the program with the patches in it goes.
    WritePatched,
    /// Where the picture of the graph goes: a `.svg` or a `.pdf` path.
    ExportGraph,
    /// Raw bytes to open: `PATH ARCH BASE [entry=ADDRESS] [offset=N] [length=N]`.
    Raw,
    /// The instruction set from the selection onward: `arm`, `thumb`, or
    /// `none` to let the image say.
    Mode,
    /// A word on a judgment call at the selection: `KIND on|off|clear`.
    Override,
    /// The address the image is moved to, or `none`.
    Rebase,
    /// A segment to add: `NAME ADDRESS SIZE [file:OFFSET] [exec]`.
    SegmentAdd,
    /// The name of the segment to take out.
    SegmentRemove,
    /// A segment's name and its new one: `NAME NEW`.
    SegmentRename,
    /// The new name of the selected function.
    Rename,
    /// The new name of the label at the selected address.
    Label,
    /// The new name of a local variable, as `DECLARED=NAME`.
    Variable,
    /// The new name of a register within one function, as `REGISTER=NAME`.
    Register,
    /// A comment for the selection: inline, or on the line above.
    Comment {
        /// Whether the comment stands above the instruction.
        above: bool,
    },
    /// The tags on the selection, as words separated by spaces or commas.
    Tags,
    /// The analyst's text on the block holding the selection.
    BlockText,
    /// The group the block holding the selection is in.
    Group,
    /// A highlight color: on the selection, or on the block holding it.
    Color {
        /// Whether the color goes on the block rather than the one place.
        block: bool,
    },
    /// The address a cross reference from the selection reaches.
    Reference {
        /// Whether the reference is being taken back rather than recorded.
        remove: bool,
    },
    /// Where the jump table the selected `jmp` reads is: `TABLE [WIDTH]
    /// COUNT [rel]`.
    Switch,
    /// An instruction to assemble over the bytes at the selection.
    Assemble,
    /// How far from the selection to fill with the no-op: an address to
    /// stop before, or `+N` bytes.
    Nop,
    /// The id of the process the debugger attaches to.
    AttachPid,
    /// The bytes at the selection, as hex pairs.
    Bytes,
}

/// How the analyst marks the bytes at the selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// An instruction.
    Code,
    /// The entry of a function.
    Function,
    /// Data; marking data again makes each item one step wider.
    Data,
    /// A string of bytes ending in a zero.
    String,
    /// Bytes with no meaning given.
    Undefined,
}

/// An inline prompt for a filesystem path.
#[derive(Debug, Clone)]
pub struct Prompt {
    /// What the prompt is asking for.
    pub kind: PromptKind,
    /// The heading shown above the field.
    pub title: &'static str,
    /// The current text in the field.
    pub value: String,
}

/// Startup configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Corpus directory to open.
    pub corpus: Option<PathBuf>,
    /// Kuna project export directory to open.
    pub kuna: Option<PathBuf>,
    /// Program image to open.
    pub binary: Option<PathBuf>,
    /// Objective-C method map to overlay.
    pub methods: Option<PathBuf>,
    /// Image-base shift applied to Objective-C IMP addresses.
    pub shift: u64,
    /// The engine's options, for the pseudocode of a program image.
    pub options: ag_image::Options,
}

/// The left navigator's list and selection.
#[derive(Debug, Default)]
pub struct Navigator {
    /// Current filter text.
    pub filter: String,
    /// Which section is open.
    pub section: Section,
    /// Rows matching the current filter.
    pub rows: Vec<FunctionRow>,
    /// Address of the selected function.
    pub selected: Option<u64>,
    /// Counts for the explore sections.
    pub counts: SectionCounts,
    /// Every tag in the project with what carries it, in tag order,
    /// worked out when the function list is.
    pub tags: BTreeMap<String, TagCount>,
}

/// What carries one tag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TagCount {
    /// How many functions carry it: what filtering by the tag lists.
    pub functions: usize,
    /// How many other places carry it — a bare address, a block of bytes —
    /// which the function list cannot show.
    pub places: usize,
}

/// What a listing or graph pane shows: the disassembly, or the lift at
/// one of its levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaneLevel {
    /// The machine's instructions, as the decoder prints them.
    #[default]
    Disassembly,
    /// The lift at a level, in SSA form when `ssa`.
    Il { level: ag_image::Level, ssa: bool },
}

impl PaneLevel {
    /// The next level round: the disassembly, then each level of the lift
    /// from the lowest, and back; the SSA choice is kept.
    pub fn cycled(self) -> PaneLevel {
        match self {
            PaneLevel::Disassembly => PaneLevel::Il {
                level: ag_image::Level::Lifted,
                ssa: false,
            },
            PaneLevel::Il { level, ssa } => {
                let levels = ag_image::Level::ALL;
                let at = levels.iter().position(|l| *l == level).unwrap_or(0);
                match levels.get(at + 1) {
                    Some(next) => PaneLevel::Il { level: *next, ssa },
                    None => PaneLevel::Disassembly,
                }
            }
        }
    }

    /// The same level, the SSA form the other way; the disassembly has
    /// none.
    pub fn ssa_toggled(self) -> PaneLevel {
        match self {
            PaneLevel::Il { level, ssa } => PaneLevel::Il { level, ssa: !ssa },
            PaneLevel::Disassembly => PaneLevel::Disassembly,
        }
    }

    /// The level's name, for the pane and the status line.
    pub fn label(self) -> String {
        match self {
            PaneLevel::Disassembly => "disassembly".to_string(),
            PaneLevel::Il { level, ssa } => {
                format!("{} IL{}", level.name(), if ssa { ", SSA form" } else { "" })
            }
        }
    }
}

/// What a level's rows can show beside each item, and the casts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IlOption {
    Opcodes,
    Flags,
    StackPointer,
    Types,
    Casts,
}

impl IlOption {
    pub const ALL: [IlOption; 5] = [
        IlOption::Opcodes,
        IlOption::Flags,
        IlOption::StackPointer,
        IlOption::Types,
        IlOption::Casts,
    ];

    /// The option's name, for the menu and the status line.
    pub fn label(self) -> &'static str {
        match self {
            IlOption::Opcodes => "Opcodes",
            IlOption::Flags => "Flag use",
            IlOption::StackPointer => "Stack pointer",
            IlOption::Types => "Types",
            IlOption::Casts => "Explicit casts",
        }
    }
}

/// The center work surface.
#[derive(Debug, Default)]
pub struct WorkSurface {
    /// Active top tab.
    pub tab: ViewTab,
    /// Active lower tab.
    pub lower: LowerTab,
    /// Whether the current location is pinned.
    pub pinned: bool,
    /// Detail of the selected function.
    pub detail: Option<FunctionDetail>,
    /// The function the listing, graph and pseudocode were read for.
    ///
    /// The selection can move to a string or a piece of data without the
    /// listing moving along; a register rename belongs to the function the
    /// listing was read for, not to whatever the selection points at now.
    pub listing_of: Option<u64>,
    /// Listing lines of the selected function.
    pub listing: Vec<ListingLine>,
    /// What the listing pane shows: the disassembly, or a level of the lift.
    pub listing_level: PaneLevel,
    /// What the graph pane's blocks hold.
    pub graph_level: PaneLevel,
    /// What the listing pane shows: its level when the lifter read the
    /// function, the disassembly otherwise.
    pub listing_shown: PaneLevel,
    /// What the graph pane shows.
    pub graph_shown: PaneLevel,
    /// The graph of the level the graph pane shows, when it is at one;
    /// `graph` stays the disassembly's, which the arrows, the block lookups
    /// and the block edits read.
    pub il_graph: Option<Graph>,
    /// What a level's rows show beside each item: opcodes, flags, the stack
    /// pointer, types.
    pub render: ag_image::Render,
    /// Whether a level spells its casts: every constant with its width.
    pub casts: bool,
    /// The control-flow graph of the selected function.
    pub graph: Graph,
    /// Pseudocode of the selected function.
    pub pseudocode: Option<String>,
    /// The addresses each line of the pseudocode came from.
    ///
    /// The keys are line numbers counted from zero, so they line up with the
    /// lines of [`WorkSurface::pseudocode`].
    pub line_addresses: BTreeMap<usize, Vec<u64>>,
    /// Byte rows around the selection.
    pub bytes: Vec<ByteLine>,
    /// References to and from the selection.
    pub references: Vec<Reference>,
    /// The filter of the strings list.
    pub string_filter: String,
    /// The Objective-C header of the image, when it has any: what the
    /// Header tab shows, and whether the tab is offered at all.
    pub objc_header: Option<String>,
}

impl WorkSurface {
    /// The graph the graph pane draws: the level's when it is at one, the
    /// disassembly's otherwise.
    pub fn shown_graph(&self) -> &Graph {
        self.il_graph.as_ref().unwrap_or(&self.graph)
    }

    /// Whether a level's option is on.
    pub fn il_option(&self, option: IlOption) -> bool {
        match option {
            IlOption::Opcodes => self.render.opcodes,
            IlOption::Flags => self.render.flags,
            IlOption::StackPointer => self.render.stack_pointer,
            IlOption::Types => self.render.types,
            IlOption::Casts => self.casts,
        }
    }

    fn toggle_il_option(&mut self, option: IlOption) -> bool {
        let slot = match option {
            IlOption::Opcodes => &mut self.render.opcodes,
            IlOption::Flags => &mut self.render.flags,
            IlOption::StackPointer => &mut self.render.stack_pointer,
            IlOption::Types => &mut self.render.types,
            IlOption::Casts => &mut self.casts,
        };
        *slot = !*slot;
        *slot
    }
}

/// The bottom workspace.
#[derive(Debug, Default)]
pub struct BottomPanel {
    /// Active tab.
    pub tab: BottomTab,
    /// Search results.
    pub hits: Vec<SearchHit>,
    /// Diagnostics.
    pub problems: Vec<Problem>,
    /// Analysis log lines.
    pub log: Vec<String>,
}

/// The names a view replaces as it draws.
///
/// Function and label renames key on the address; a register rename keys
/// on the register's spelling and belongs to the function on screen,
/// because the same register means something different in the next
/// function.
#[derive(Debug, Default)]
pub(crate) struct Renames {
    /// Function and label renames, keyed by the bare hex address.
    addresses: std::collections::HashMap<String, String>,
    /// The register renames of the function on screen, by spelling.
    registers: std::collections::HashMap<String, String>,
    /// The analyst's comments, keyed by the bare hex address, each with
    /// whether it stands on the line above.
    comments: std::collections::HashMap<String, Comment>,
    /// The analyst's highlights on addresses, keyed by the bare hex
    /// address. The one on a function's entry is the function's.
    colors: std::collections::HashMap<String, iced::Color>,
    /// The analyst's highlights on blocks, keyed by the bare hex address
    /// the block starts at.
    block_colors: std::collections::HashMap<String, iced::Color>,
    /// The highlight on the function on screen, when the analyst gave it
    /// one: the color every line of it falls back to.
    function_color: Option<iced::Color>,
    /// The analyst's text on blocks, keyed by the bare hex address the
    /// block starts at: the block's title in the graph.
    block_labels: std::collections::HashMap<String, String>,
    /// The groups blocks are drawn in, keyed the same way: every block of
    /// a function in one group is one node of the graph.
    block_groups: std::collections::HashMap<String, String>,
}

impl Renames {
    /// Put the block starting at `from` in `group`, as the analyst would.
    #[cfg(test)]
    pub(crate) fn set_block_group(&mut self, from: u64, group: &str) {
        self.block_groups
            .insert(format!("{from:#x}"), group.to_string());
    }

    /// Put `label` on the block starting at `from`, as the analyst would.
    #[cfg(test)]
    pub(crate) fn set_block_label(&mut self, from: u64, label: &str) {
        self.block_labels
            .insert(format!("{from:#x}"), label.to_string());
    }
}

/// One analyst comment, with where it stands.
#[derive(Debug, Clone)]
pub(crate) struct Comment {
    /// The note itself.
    pub(crate) text: String,
    /// Whether it stands on its own line above the instruction.
    pub(crate) above: bool,
}

impl Renames {
    /// A rename set carrying one comment at one address.
    #[cfg(test)]
    pub(crate) fn with_comment(address: u64, comment: &str, above: bool) -> Self {
        Self {
            comments: std::collections::HashMap::from([(
                format!("{address:#x}"),
                Comment {
                    text: comment.to_string(),
                    above,
                },
            )]),
            ..Self::default()
        }
    }

    /// The analyst's note at `address`, when one is there.
    ///
    /// A listing or graph line names its instruction's address, so the view
    /// asks for the note by that address; the pseudocode asks for every
    /// address a line maps to.
    pub(crate) fn comment_for(&self, address: u64) -> Option<&Comment> {
        self.comments.get(&format!("{address:#x}"))
    }

    /// A rename set carrying one highlight of kind `kind` at one address:
    /// on the block starting there for `Region`, on the address otherwise,
    /// and the function's own when it is a function's.
    #[cfg(test)]
    pub(crate) fn with_color(
        address: u64,
        hex: &str,
        kind: ag_corpus::project::TargetKind,
    ) -> Self {
        use ag_corpus::project::TargetKind;
        let color = crate::theme::hex_color(hex).expect("a test color");
        let one = std::collections::HashMap::from([(format!("{address:#x}"), color)]);
        let (colors, block_colors) = if kind == TargetKind::Region {
            (std::collections::HashMap::new(), one)
        } else {
            (one, std::collections::HashMap::new())
        };
        Self {
            colors,
            block_colors,
            function_color: (kind == TargetKind::Function).then_some(color),
            ..Self::default()
        }
    }

    /// The analyst's highlight on the one line at `address`.
    pub(crate) fn address_color(&self, address: u64) -> Option<iced::Color> {
        self.colors.get(&format!("{address:#x}")).copied()
    }

    /// The analyst's text on the block starting at `from`, when there is one.
    pub(crate) fn block_label(&self, from: u64) -> Option<&str> {
        self.block_labels
            .get(&format!("{from:#x}"))
            .map(String::as_str)
    }

    /// The group the block starting at `from` is drawn in, when it is in one.
    pub(crate) fn block_group(&self, from: u64) -> Option<&str> {
        self.block_groups
            .get(&format!("{from:#x}"))
            .map(String::as_str)
    }

    /// The analyst's highlight on the block starting at `from`.
    pub(crate) fn block_color(&self, from: u64) -> Option<iced::Color> {
        self.block_colors.get(&format!("{from:#x}")).copied()
    }

    /// The analyst's highlight on the function on screen.
    pub(crate) fn function_color(&self) -> Option<iced::Color> {
        self.function_color
    }

    /// The color a line at `address` is drawn in, given the block holding
    /// it: its own highlight first, then its block's, then its function's.
    ///
    /// The nearest mark wins, so a block colored green with one red line in
    /// it reads as the analyst meant: the block is green and that line is
    /// red.
    pub(crate) fn line_color(&self, address: u64, block: Option<u64>) -> Option<iced::Color> {
        self.address_color(address)
            .or_else(|| block.and_then(|from| self.block_color(from)))
            .or(self.function_color)
    }
}

/// The whole workbench.
pub struct App {
    /// Data source for the open project.
    pub provider: Box<dyn Provider>,
    /// Identity of the open project.
    pub project: Project,
    /// Which artifacts the provider can supply.
    pub capabilities: Capabilities,
    /// Left navigator.
    pub navigator: Navigator,
    /// Center work surface.
    pub work: WorkSurface,
    /// Bottom workspace.
    pub bottom: BottomPanel,
    /// Shared navigation history.
    pub history: History<Selection>,
    /// The shared selection.
    pub selection: Selection,
    /// The piece of data that is open, when one is.
    ///
    /// A piece of data is not a function, so the references pane is about
    /// the data and not about a function.
    pub data_selection: Option<u64>,
    /// Text in the global command field.
    pub global_query: String,
    /// Transient message shown in the status bar.
    pub notice: Option<String>,
    /// Whether the navigator is visible.
    pub show_navigator: bool,
    /// Whether the inspector is visible.
    pub show_inspector: bool,
    /// Whether the bottom workspace is visible.
    pub show_bottom: bool,
    /// Whether the about dialog is open.
    pub show_about: bool,
    /// An open path prompt, when one is active.
    pub prompt: Option<Prompt>,
    /// The corpus directory currently open.
    pub corpus_root: Option<PathBuf>,
    /// The kuna export directory currently open.
    pub kuna_root: Option<PathBuf>,
    /// The debugger: its session, the breakpoints, and what the program
    /// showed when it last stopped.
    pub debug: crate::debug::DebugState,
    /// The program image currently open.
    pub binary_path: Option<PathBuf>,
    /// How the program is read as raw bytes, when it is: a file with no
    /// container to say where it loads.
    pub raw: Option<ag_image::RawSpec>,
    /// Which slice of a universal Mach-O the program is, when it is one.
    pub slice: Option<String>,
    /// The file the next submit of the patched-program prompt writes over,
    /// once the analyst has been told it is there.
    pub confirm_write: Option<PathBuf>,
    /// Why the project's layout was not applied when the program was last
    /// read, when it was not: the program is read as the loader reads it.
    pub layout_failed: Option<String>,
    /// The engine's options, for the pseudocode of a program image.
    pub options: ag_image::Options,
    /// The Objective-C method map currently open.
    pub methods_path: Option<PathBuf>,
    /// Image-base shift applied to Objective-C IMP addresses.
    pub shift: u64,
    /// The kuna CLI of an open kuna project, and the answers it has given.
    pub kuna: Option<KunaState>,
    /// The analyst's changes, keyed by the address as the source wrote it.
    ///
    /// These are the workbench's own annotations, held in the open project
    /// file's shape so a save writes them out unchanged. A rename here wins
    /// over the analysis's name wherever the workbench shows one.
    pub annotations: ag_corpus::project::ProjectFile,
    /// Where the open project file was last read from or written to.
    pub project_path: Option<PathBuf>,
    /// The analysis root the annotations belong to.
    ///
    /// An annotation is about one analysis: a rename of `0x1198` means that
    /// address in *this* binary. Opening a different analysis drops the
    /// annotations rather than carry them onto a binary they never described;
    /// reloading the same one keeps them. `None` is the sample project, which
    /// has no root of its own.
    pub annotations_root: Option<PathBuf>,
    /// The analyst's changes, most recent last, each as the annotations
    /// before and after it, so undo is a swap rather than an inverse.
    pub undo: Vec<Change>,
    /// The changes taken back, most recently taken back last, until a new
    /// change makes them unreachable.
    pub redo: Vec<Change>,
}

/// One change to the analyst's annotations, as undo records it.
///
/// A change is the whole annotation list before and after, not a patch:
/// the list is the analyst's own marks, a few hundred records at most, so
/// the copy is cheap and the restore cannot drift from what was there.
#[derive(Debug, Clone)]
pub struct Change {
    /// What the change was, as the notice said it: `Renamed 0x1198`.
    pub label: String,
    /// The annotations before the change.
    before: Vec<ag_corpus::project::Annotation>,
    /// The annotations after it.
    after: Vec<ag_corpus::project::Annotation>,
}

/// How many changes undo remembers.
const UNDO_DEPTH: usize = 200;

impl App {
    /// Build the application state from the startup configuration.
    pub fn boot(config: Config) -> (Self, Task<Message>) {
        let mut app = Self {
            provider: Box::new(SampleProvider::new()),
            project: Project {
                name: "No project".into(),
                kind: crate::model::ProjectKind::Binary,
                root: None,
                target_sha256: None,
                provider: "none".into(),
                architecture: None,
                format: None,
            },
            capabilities: Capabilities::NONE,
            navigator: Navigator {
                filter: String::new(),
                section: Section::Functions,
                rows: Vec::new(),
                selected: None,
                counts: SectionCounts::default(),
                tags: BTreeMap::new(),
            },
            work: WorkSurface::default(),
            bottom: BottomPanel {
                tab: BottomTab::SearchResults,
                hits: Vec::new(),
                problems: Vec::new(),
                log: vec!["Workbench started.".into()],
            },
            history: History::new(64),
            selection: Selection::None,
            data_selection: None,
            global_query: String::new(),
            notice: None,
            show_navigator: true,
            show_inspector: true,
            show_bottom: true,
            show_about: false,
            prompt: None,
            corpus_root: config.corpus.clone(),
            kuna_root: config.kuna.clone(),
            debug: crate::debug::DebugState::default(),
            binary_path: config.binary.clone(),
            raw: None,
            slice: None,
            confirm_write: None,
            layout_failed: None,
            options: config.options,
            methods_path: config.methods.clone(),
            shift: config.shift,
            kuna: None,
            annotations: ag_corpus::project::ProjectFile::new(
                ag_corpus::project::Target::default(),
            ),
            project_path: None,
            annotations_root: None,
            undo: Vec::new(),
            redo: Vec::new(),
        };

        let task = if config.corpus.is_some() || config.kuna.is_some() || config.binary.is_some() {
            app.load_project()
        } else {
            app.use_sample()
        };

        (app, task)
    }

    /// Load the open project into the workbench.
    ///
    /// A kuna export takes precedence over a corpus, and a corpus over a
    /// program image: the three are different shapes of the same analysis,
    /// and only one of them is open at a time.
    fn load_project(&mut self) -> Task<Message> {
        if let Some(root) = self.kuna_root.clone() {
            return self.load_kuna(&root);
        }

        if let Some(root) = self.corpus_root.clone() {
            return self.load_corpus(&root);
        }

        let Some(path) = self.binary_path.clone() else {
            return self.use_sample();
        };

        self.load_binary(&path)
    }

    /// Load a corpus into the workbench.
    fn load_corpus(&mut self, root: &Path) -> Task<Message> {
        match CorpusProvider::load(root, self.methods_path.as_deref(), self.shift) {
            Ok(provider) => {
                self.provider = Box::new(provider);
                self.notice = Some(format!("Opened {}", root.display()));
                return self.adopt_provider();
            }
            Err(error) => {
                let _ = self.use_sample();
                self.notice = Some(format!("Could not open {}: {error:#}", root.display()));
            }
        }

        Task::none()
    }

    /// Load a program image into the workbench.
    fn load_binary(&mut self, path: &Path) -> Task<Message> {
        // The analyst's layout is read under when the annotations are this
        // program's; a program opened in place of another starts as the
        // loader reads it.
        let (layout, mut layout_failed) = if self.annotations_root.as_deref() == Some(path)
            && !self.annotations.layout.is_empty()
        {
            match layout_of(&self.annotations) {
                Ok(layout) => (layout, None),
                Err(reason) => (ag_image::Layout::default(), Some(reason)),
            }
        } else {
            (ag_image::Layout::default(), None)
        };
        let raw = self.raw.clone();
        let slice = self.slice.clone();
        let loaded = match BinaryProvider::load_with(
            path,
            self.options,
            &layout,
            raw.as_ref(),
            slice.as_deref(),
        ) {
            // When the layout is what the image cannot take, the program
            // is read as the loader reads it, and the analyst is told.
            Err(error) if layout != ag_image::Layout::default() => {
                layout_failed = Some(error.to_string());
                BinaryProvider::load_with(
                    path,
                    self.options,
                    &ag_image::Layout::default(),
                    raw.as_ref(),
                    slice.as_deref(),
                )
            }
            loaded => loaded,
        };
        self.layout_failed = layout_failed;
        match loaded {
            Ok(provider) => {
                let binary = provider.binary();
                self.provider = Box::new(provider);
                self.notice = Some(match &self.layout_failed {
                    Some(reason) => format!(
                        "Opened {} as the loader reads it: the project's layout could not be applied ({reason})",
                        path.display()
                    ),
                    None => format!("Opened {}", path.display()),
                });

                let adopted = self.adopt_provider();

                // Who calls what is only known once the whole program has been
                // read, and that is not the UI thread's work.
                let indexed = Task::perform(
                    async move {
                        binary.call_graph();
                        // The strings each function uses are found the same
                        // way: over the whole program.
                        let _ = binary.string_users();
                        // And so is the data each function uses.
                        let _ = binary.data_users();
                    },
                    |_| Message::BinaryIndexReady,
                );

                Task::batch(vec![adopted, indexed])
            }
            Err(error) => {
                let _ = self.use_sample();
                self.notice = Some(format!("Could not open {}: {error:#}", path.display()));
                Task::none()
            }
        }
    }

    /// Load a kuna project export into the workbench.
    fn load_kuna(&mut self, root: &Path) -> Task<Message> {
        // The cache is kept only when the same export is being reloaded: the
        // answers belong to one binary, and another export is another binary.
        let same_project = self.provider.project().root.as_deref() == Some(root);
        let cache = if same_project {
            self.kuna.as_ref().map(|state| Arc::clone(&state.cache))
        } else {
            None
        };

        match KunaProvider::load(root, KunaCli::program(), cache) {
            Ok(provider) => {
                let cli = provider.cli().cloned();
                let cache = provider.cache();

                self.kuna = Some(KunaState { cli, cache });
                self.provider = Box::new(provider);
                self.notice = Some(format!("Opened {}", root.display()));

                let adopted = self.adopt_provider();
                let asked = self.ask_kuna_about_the_program();
                Task::batch(vec![adopted, asked])
            }
            Err(error) => {
                let _ = self.use_sample();
                self.notice = Some(format!("Could not open {}: {error:#}", root.display()));
                Task::none()
            }
        }
    }

    /// Fall back to the bundled sample project.
    fn use_sample(&mut self) -> Task<Message> {
        self.provider = Box::new(SampleProvider::new());
        self.kuna = None;
        self.notice = Some("No corpus supplied — showing sample data".into());
        self.adopt_provider()
    }

    /// Close the open project.
    fn close_project(&mut self) -> Task<Message> {
        self.provider = Box::new(EmptyProvider::new());
        self.corpus_root = None;
        self.kuna_root = None;
        self.binary_path = None;
        self.raw = None;
        self.methods_path = None;
        self.kuna = None;
        self.annotations =
            ag_corpus::project::ProjectFile::new(ag_corpus::project::Target::default());
        self.forget_changes();
        self.project_path = None;
        self.annotations_root = None;
        self.notice = Some("Project closed".into());
        self.adopt_provider()
    }

    /// Re-read the project identity and lists after the provider changed.
    fn adopt_provider(&mut self) -> Task<Message> {
        self.project = self.provider.project();
        self.capabilities = self.provider.capabilities();
        self.navigator.counts = self.provider.counts();
        self.bottom.problems = self.provider.problems();
        self.selection = Selection::None;
        self.work = WorkSurface::default();
        self.work.objc_header = self.provider.objc_header();
        // Annotations belong to the analysis they were made against. Opening
        // a different binary or corpus drops them — a rename of `0x1198`
        // means that address in the other file, not this one — while a
        // reload of the same root keeps them. The project file path goes with
        // them: saving onto the old file after a switch would overwrite the
        // wrong project.
        let root = self.analysis_root();
        let kept = root == self.annotations_root;
        if !kept {
            self.annotations =
                ag_corpus::project::ProjectFile::new(ag_corpus::project::Target::default());
            self.forget_changes();
            self.project_path = None;
            self.annotations_root = root;
        }
        self.refresh_functions();
        let task = self.select_first_function();
        // A reload of the same analysis is a new image that knows nothing
        // of the analyst's patches and notes: it is told them again.
        if kept {
            self.tell_patches();
            self.tell_modes();
            self.tell_jump_tables();
            self.tell_overrides();
        }
        task
    }

    /// The root of the open analysis, the identity annotations belong to.
    fn analysis_root(&self) -> Option<PathBuf> {
        self.corpus_root
            .clone()
            .or_else(|| self.kuna_root.clone())
            .or_else(|| self.binary_path.clone())
    }

    /// The window title.
    pub fn window_title(&self) -> String {
        format!("AdmiralGrace — {}", self.project.name)
    }

    /// The current analysis state.
    pub fn analysis_state(&self) -> AnalysisState {
        self.provider.analysis_state()
    }

    /// Reload the function list, apply the analyst's renames, then the filter.
    ///
    /// A name the analyst recorded wins over the analysis's own wherever the
    /// workbench shows one, so the rename is applied before the filter reads
    /// it. The provider's row is otherwise untouched.
    fn refresh_functions(&mut self) {
        let filter = self.navigator.filter.trim().to_lowercase();
        // A filter that starts with `#` names a tag rather than a piece of a
        // name: `#crypto` keeps the functions carrying that tag, the
        // analyst's own or an automatic one. The tag is matched as it is
        // stored — spelled the same, case and all — so the filter agrees
        // with the Tags section, which lists `Crypto` and `crypto` apart.
        let tag = self
            .navigator
            .filter
            .trim()
            .strip_prefix('#')
            .map(ag_corpus::project::normalize_tag);
        let entry = self.entry_address();
        let mut functions = self.provider.functions();
        // The functions the analyst marked take their place among the
        // analysis's, in address order.
        let marked = self.marked_functions(&functions);
        if !marked.is_empty() {
            functions.extend(marked);
            functions.sort_by_key(|row| row.address);
        }
        self.navigator.tags = self.tag_index_of(&functions, entry);
        let rows = functions
            .into_iter()
            .filter(|row| match &tag {
                Some(Some(tag)) => self.function_tags(row, entry).contains(tag),
                // A bare `#` names no tag and matches nothing.
                Some(None) => false,
                None => true,
            })
            .map(|mut row| {
                if let Some(name) = self.annotation_name(&row.display_address()) {
                    row.name = name;
                }
                row
            })
            .filter(|row| {
                tag.is_some() || filter.is_empty() || row.name.to_lowercase().contains(&filter)
            })
            .collect();

        self.navigator.rows = rows;
    }

    /// The program's entry point, when the analysis reported one.
    fn entry_address(&self) -> Option<u64> {
        self.provider
            .summary()
            .and_then(|summary| summary.entry.map(|(_, address)| address))
    }

    /// The tags on the function `row`: the analyst's own, then the automatic
    /// ones the analysis implies, each once.
    fn function_tags(&self, row: &FunctionRow, entry: Option<u64>) -> Vec<String> {
        let mut tags = self
            .annotations
            .annotation_for(&row.display_address())
            .map(|a| a.tags.clone())
            .unwrap_or_default();
        for tag in automatic_tags(row, entry) {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags
    }

    /// The tags on the place at `address`, the analyst's own and the
    /// automatic ones, each once.
    pub(crate) fn tags_at(&self, address: u64) -> Vec<String> {
        let entry = self.entry_address();
        let functions = self.provider.functions();
        match functions.iter().find(|row| row.address == address) {
            Some(row) => self.function_tags(row, entry),
            None => self
                .annotations
                .annotation_for(&self.annotation_key(address))
                .map(|a| a.tags.clone())
                .unwrap_or_default(),
        }
    }

    /// Every tag in the project with what carries it, in tag order: the
    /// analyst's own tags on any place, and the automatic tags on the
    /// functions.
    ///
    /// A tag is counted on functions apart from other places because the
    /// function list is what filtering by the tag shows; a tag on a bare
    /// address or a block of bytes is counted beside it so the section
    /// does not promise a row the list cannot give.
    fn tag_index_of(
        &self,
        functions: &[FunctionRow],
        entry: Option<u64>,
    ) -> BTreeMap<String, TagCount> {
        let mut index: BTreeMap<String, TagCount> = BTreeMap::new();
        let mut function_keys = std::collections::HashSet::new();
        for row in functions {
            let written = row.display_address();
            function_keys
                .insert(ag_corpus::project::canonical_address(&written).unwrap_or(written));
            for tag in self.function_tags(row, entry) {
                index.entry(tag).or_default().functions += 1;
            }
        }
        for (tag, places) in self.annotations.tags() {
            // The analyst's tags on functions were counted with the rows;
            // what is left is the places that are not functions.
            let on_functions = self
                .annotations
                .tagged(&tag)
                .iter()
                .filter(|a| function_keys.contains(&a.address))
                .count();
            let elsewhere = places.saturating_sub(on_functions);
            if elsewhere > 0 {
                index.entry(tag).or_default().places += elsewhere;
            }
        }
        index
    }

    /// The analyst's recorded name for the address `key`, when there is one.
    fn annotation_name(&self, key: &str) -> Option<String> {
        self.annotations
            .annotation_for(key)
            .and_then(|a| a.name.clone())
    }

    /// The name to show for a bookmarked place: the analyst's own name for
    /// the address when there is one, the analysis's name for the function
    /// there when the address is a function entry, and the address itself
    /// when nothing names the place.
    ///
    /// A bookmark is a mark on a place, so it borrows the place's name;
    /// naming a bookmark means naming the place, which is what a label
    /// (F3) does for an address the analysis named nothing at.
    pub(crate) fn place_name(&self, address: u64) -> String {
        let key = self.annotation_key(address);
        if let Some(name) = self.annotation_name(&key) {
            return name;
        }
        if let Some(row) = self
            .provider
            .functions()
            .iter()
            .find(|row| row.address == address)
        {
            return row.name.clone();
        }
        format!("{address:#x}")
    }

    /// The name to show for the function or label at `address`: the
    /// analyst's rename when there is one, the provider's own name otherwise.
    ///
    /// Every view that prints one function name asks here, so a rename made
    /// once shows in the navigator, the listing, the graph, the pseudocode
    /// and the references together.
    pub(crate) fn shown_name(&self, address: u64, fallback: &str) -> String {
        let key = self.annotation_key(address);
        self.annotation_name(&key)
            .unwrap_or_else(|| fallback.to_string())
    }

    /// Every rename of a function or label, keyed by the bare hex address.
    ///
    /// A label at an address the analysis named no function for still
    /// carries a record, so it is keyed here too — the way a listing line
    /// names its call target. (A spaced address like `EXTERNAL:0x1` keys as
    /// its bare value; no provider that writes listings also names a space,
    /// so no two rows collide today.)
    pub(crate) fn renamed_names(&self) -> std::collections::HashMap<String, String> {
        let mut renamed: std::collections::HashMap<String, String> = self
            .provider
            .functions()
            .iter()
            .filter_map(|row| {
                let key = format!("{:#x}", row.address);
                self.annotation_name(&row.display_address())
                    .map(|name| (key, name))
            })
            .collect();
        for annotation in &self.annotations.annotations {
            if annotation.variable.is_some()
                || annotation.register.is_some()
                || annotation.address.contains(':')
                || annotation.name.is_none()
            {
                continue;
            }
            if let Some(name) = &annotation.name {
                renamed
                    .entry(annotation.address.clone())
                    .or_insert_with(|| name.clone());
            }
        }
        renamed
    }

    /// The names and notes a listing, graph, or pseudocode view draws: every
    /// function and label rename by address, the register renames of the
    /// function on screen, and every comment by address.
    ///
    /// A view that prints many rows builds this once per render rather than
    /// asking the provider row by row.
    pub(crate) fn renames(&self) -> Renames {
        let (colors, block_colors) = self.address_colors();
        // A color on a function's entry is the function's: it reaches every
        // line of the function on screen, whatever the record was called.
        let function_color = self
            .work
            .listing_of
            .and_then(|function| colors.get(&format!("{function:#x}")).copied());
        let (block_labels, block_groups) = self.block_texts();
        Renames {
            addresses: self.renamed_names(),
            registers: self.renamed_registers(),
            comments: self.address_comments(),
            colors,
            block_colors,
            function_color,
            block_labels,
            block_groups,
        }
    }

    /// The analyst's text on blocks and the groups they are in, keyed by
    /// the bare hex address each block starts at.
    #[allow(clippy::type_complexity)]
    pub(crate) fn block_texts(
        &self,
    ) -> (
        std::collections::HashMap<String, String>,
        std::collections::HashMap<String, String>,
    ) {
        let mut labels = std::collections::HashMap::new();
        let mut groups = std::collections::HashMap::new();
        for annotation in &self.annotations.annotations {
            if !annotation.block {
                continue;
            }
            let key = ag_corpus::parse_addr_space(&annotation.address)
                .map(|(value, _)| format!("{value:#x}"))
                .unwrap_or_else(|_| annotation.address.clone());
            if let Some(label) = &annotation.label {
                labels.insert(key.clone(), label.clone());
            }
            if let Some(group) = &annotation.group {
                groups.insert(key, group.clone());
            }
        }
        (labels, groups)
    }

    /// Every highlight the analyst set, keyed by the bare hex address: the
    /// ones on addresses, and apart from them the ones on blocks.
    ///
    /// A spaced record keys on its bare value, the way a comment does, so
    /// a view asks by the address it prints. A record whose color is not a
    /// `#rrggbb` — a hand-edited file — is skipped rather than drawn wrong.
    #[allow(clippy::type_complexity)]
    pub(crate) fn address_colors(
        &self,
    ) -> (
        std::collections::HashMap<String, iced::Color>,
        std::collections::HashMap<String, iced::Color>,
    ) {
        let mut colors = std::collections::HashMap::new();
        let mut block_colors = std::collections::HashMap::new();
        for annotation in &self.annotations.annotations {
            if annotation.variable.is_some() || annotation.register.is_some() {
                continue;
            }
            let Some(color) = annotation
                .color
                .as_deref()
                .and_then(crate::theme::hex_color)
            else {
                continue;
            };
            let key = ag_corpus::parse_addr_space(&annotation.address)
                .map(|(value, _)| format!("{value:#x}"))
                .unwrap_or_else(|_| annotation.address.clone());
            if annotation.block {
                block_colors.insert(key, color);
            } else {
                colors.insert(key, color);
            }
        }
        (colors, block_colors)
    }

    /// The first address of the block of the function on screen that holds
    /// `address`, when one does.
    /// The level a pane is set to; none for a pane without levels.
    fn pane_level(&self, tab: ViewTab) -> Option<PaneLevel> {
        match tab {
            ViewTab::Listing => Some(self.work.listing_level),
            ViewTab::Graph => Some(self.work.graph_level),
            _ => None,
        }
    }

    /// The level a pane shows.
    fn pane_shown(&self, tab: ViewTab) -> Option<PaneLevel> {
        match tab {
            ViewTab::Listing => Some(self.work.listing_shown),
            ViewTab::Graph => Some(self.work.graph_shown),
            _ => None,
        }
    }

    fn set_pane_level(&mut self, tab: ViewTab, level: PaneLevel) {
        match tab {
            ViewTab::Listing => self.work.listing_level = level,
            ViewTab::Graph => self.work.graph_level = level,
            _ => {}
        }
    }

    pub(crate) fn block_of(&self, address: u64) -> Option<u64> {
        self.work
            .graph
            .blocks
            .iter()
            .find(|block| block.from <= address && address < block.to)
            .map(|block| block.from)
    }

    /// What a mark at `address` is on: the function entered there, or the
    /// one address anywhere else.
    pub(crate) fn kind_at(&self, address: u64) -> ag_corpus::project::TargetKind {
        if self
            .provider
            .functions()
            .iter()
            .any(|row| row.address == address)
        {
            ag_corpus::project::TargetKind::Function
        } else {
            ag_corpus::project::TargetKind::Address
        }
    }

    /// Open the cross-reference prompt for the selection: the address the
    /// selection reaches that the analysis cannot see, or, taking one
    /// back, the one to forget.
    fn reference_prompt(&mut self, remove: bool) -> Task<Message> {
        let Some(address) = self.selection.address() else {
            self.notice = Some("Select the place the reference leaves from".into());
            return Task::none();
        };
        let key = self.annotation_key(address);
        let recorded = self
            .annotations
            .annotation_for(&key)
            .map(|a| a.references.clone())
            .unwrap_or_default();
        if remove && recorded.is_empty() {
            self.notice = Some(format!("No manual reference leaves {key}"));
            return Task::none();
        }
        // Taking one back, the prompt offers the one there is when there is
        // only one; recording one, it starts empty.
        let value = match (remove, recorded.as_slice()) {
            (true, [only]) => only.clone(),
            _ => String::new(),
        };
        self.prompt = Some(Prompt {
            kind: PromptKind::Reference { remove },
            title: if remove {
                "Remove cross reference to (address)"
            } else {
                "Add cross reference to (address)"
            },
            value,
        });
        Task::none()
    }

    /// The cross references the analyst recorded at the selection: the
    /// places it reaches that the analysis cannot see, and the places
    /// recorded as reaching it.
    ///
    /// Each is labelled by the place's name and its address, the way a
    /// bookmark names a place, so a reference to a renamed function reads
    /// by the analyst's name.
    pub(crate) fn manual_references(&self) -> Vec<Reference> {
        let Some(address) = self.selection.address() else {
            return Vec::new();
        };
        let key = self.annotation_key(address);
        let mut references = Vec::new();
        if let Some(record) = self.annotations.annotation_for(&key) {
            for target in &record.references {
                if let Ok((value, _)) = ag_corpus::parse_addr_space(target) {
                    references.push(Reference {
                        address: value,
                        label: format!("{} {target}", self.place_name(value)),
                        kind: ReferenceKind::Manual,
                    });
                }
            }
        }
        // The place's own key, canonical, is what a source recorded.
        for source in self.annotations.referrers_of(&self.canonical_key(address)) {
            if let Ok((value, _)) = ag_corpus::parse_addr_space(&source.address) {
                references.push(Reference {
                    address: value,
                    label: format!("{} {}", self.place_name(value), source.address),
                    kind: ReferenceKind::ManualFrom,
                });
            }
        }
        references
    }

    /// Ask for the text on the block holding the selection, or for its
    /// group, with what it has now.
    fn block_text_prompt(&mut self, group: bool) -> Task<Message> {
        let Some(address) = self.selection.address() else {
            self.notice = Some(if group {
                "Select a block to group".into()
            } else {
                "Select a block to label".into()
            });
            return Task::none();
        };
        let Some(from) = self.block_of(address) else {
            self.notice = Some("No block of the function on screen holds the selection".into());
            return Task::none();
        };
        let record = self.annotations.block_for(&self.annotation_key(from));
        let current = if group {
            record.and_then(|a| a.group.clone())
        } else {
            record.and_then(|a| a.label.clone())
        }
        .unwrap_or_default();
        self.prompt = Some(Prompt {
            kind: if group {
                PromptKind::Group
            } else {
                PromptKind::BlockText
            },
            title: if group {
                "Group (a name shared by the blocks drawn as one, or empty to take the block out)"
            } else {
                "Block text (the block's title in the graph, or empty to clear)"
            },
            value: current,
        });
        Task::none()
    }

    /// Start the program under the debugger — or the session a test put in
    /// place, not yet started — stopped at its first instruction, with the
    /// breakpoints set.
    fn debug_start(&mut self) -> Task<Message> {
        let Some(binary) = self.binary_path.clone() else {
            self.notice = Some("Running under the debugger needs a program image".into());
            return Task::none();
        };
        let mut session = match self.debug.session.take() {
            Some(session) if matches!(session.state(), ag_debug::State::Idle) => session,
            Some(session) if !matches!(session.state(), ag_debug::State::Exited { .. }) => {
                self.debug.session = Some(session);
                self.notice = Some("The program is already under the debugger".into());
                return Task::none();
            }
            _ => {
                let debugger = self.debug.debugger();
                if !debugger.available() {
                    self.notice = Some(format!(
                        "{} is not on this machine: install it, or choose the other debugger",
                        debugger.command()[0]
                    ));
                    return Task::none();
                }
                match ag_debug::Session::launch(
                    debugger,
                    &binary,
                    self.provider.image_base().unwrap_or(0),
                ) {
                    Ok(session) => session,
                    Err(error) => {
                        self.notice = Some(format!("Could not start the debugger: {error:#}"));
                        return Task::none();
                    }
                }
            }
        };
        for address in self.debug.breakpoints.clone() {
            if let Err(error) = session.add_breakpoint(address) {
                self.debug
                    .note(format!("breakpoint at {address:#x}: {error:#}"));
            }
        }
        if let Err(error) = session.start(&[]) {
            self.notice = Some(format!("Could not start the program: {error:#}"));
            return Task::none();
        }
        self.debug.note(format!(
            "started {}{}",
            binary.display(),
            session
                .slide()
                .map(|slide| format!(" with a slide of {slide:#x}"))
                .unwrap_or_default()
        ));
        self.debug.session = Some(session);
        self.debug.status = crate::debug::Status::Stopped;
        self.debug
            .refresh(&|address| self.provider.contains_address(address));
        self.work.lower = LowerTab::Debug;
        if let Some(pc) = self.debug.pc {
            self.follow_pc(pc);
        }
        self.notice = Some("Stopped at the first instruction".into());
        Task::none()
    }

    /// Attach the debugger to the process `pid`.
    fn debug_attach(&mut self, pid: u64) -> Task<Message> {
        let Some(binary) = self.binary_path.clone() else {
            self.notice = Some("Attaching the debugger needs a program image".into());
            return Task::none();
        };
        let debugger = self.debug.debugger();
        if !debugger.available() {
            self.notice = Some(format!("{} is not on this machine", debugger.command()[0]));
            return Task::none();
        }
        let mut session = match ag_debug::Session::launch(
            debugger,
            &binary,
            self.provider.image_base().unwrap_or(0),
        ) {
            Ok(session) => session,
            Err(error) => {
                self.notice = Some(format!("Could not start the debugger: {error:#}"));
                return Task::none();
            }
        };
        for address in self.debug.breakpoints.clone() {
            let _ = session.add_breakpoint(address);
        }
        if let Err(error) = session.attach(pid) {
            self.notice = Some(format!("Could not attach to {pid}: {error:#}"));
            return Task::none();
        }
        self.debug.note(format!("attached to process {pid}"));
        self.debug.session = Some(session);
        self.debug.status = crate::debug::Status::Stopped;
        self.debug
            .refresh(&|address| self.provider.contains_address(address));
        self.work.lower = LowerTab::Debug;
        if let Some(pc) = self.debug.pc {
            self.follow_pc(pc);
        }
        self.notice = Some(format!("Attached to process {pid}"));
        Task::none()
    }

    /// Let the stopped program run by `command`, and look for its stop.
    fn debug_run(
        &mut self,
        command: impl FnOnce(&mut ag_debug::Session) -> anyhow::Result<()>,
        what: &str,
    ) -> Task<Message> {
        if !self.debug.is_stopped() {
            self.notice = Some("The program is not stopped under the debugger".into());
            return Task::none();
        }
        let Some(session) = self.debug.session.as_mut() else {
            return Task::none();
        };
        if let Err(error) = command(session) {
            self.notice = Some(format!("{what} failed: {error:#}"));
            return Task::none();
        }
        self.debug.status = crate::debug::Status::Running;
        self.debug.pc = None;
        self.notice = Some(format!("{what}…"));
        Self::debug_poll_later()
    }

    /// A look at the debugger a moment from now.
    fn debug_poll_later() -> Task<Message> {
        Task::perform(
            async { std::thread::sleep(std::time::Duration::from_millis(120)) },
            |_| Message::DebugPoll,
        )
    }

    /// Bring the listing to `pc`: the function it is in, and the
    /// instruction. A stop adds nothing to the history, so Back after a
    /// run of steps goes where the analyst was, not through every step.
    fn follow_pc(&mut self, pc: u64) {
        let function = self
            .provider
            .functions()
            .into_iter()
            .filter(|row| row.address <= pc)
            .max_by_key(|row| row.address)
            .filter(|row| {
                row.size
                    .is_none_or(|size| pc < row.address.saturating_add(size))
            })
            .map(|row| row.address);
        if let Some(function) = function {
            if self.work.listing_of != Some(function) {
                let _ = self.select_function(function, false);
            }
        }
        self.selection = Selection::Address(pc);
        self.refresh_bytes();
    }

    /// Write the graph on screen — the blocks as the tab draws them,
    /// groups, text and highlights and all — as the picture the path's
    /// extension names: `.svg`, or `.pdf`. A file already there is written
    /// over on a second submit of the same path.
    fn export_graph_to(&mut self, path: &Path) {
        let Some(function) = self.work.listing_of else {
            self.notice = Some("Select a function to export its graph".into());
            return;
        };
        // Neither the program nor the project file is written over, even
        // when the program was opened from a picture's path.
        if let Some(binary) = self.binary_path.as_deref() {
            if path == binary || ag_image::same_file(path, binary) {
                self.notice = Some(format!("{} is the program itself", path.display()));
                return;
            }
        }
        if self
            .project_path
            .as_deref()
            .is_some_and(|project| project == path || ag_image::same_file(path, project))
        {
            self.notice = Some(format!("{} is the project file", path.display()));
            return;
        }
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        let pdf = match extension.as_deref() {
            Some("svg") => false,
            Some("pdf") => true,
            _ => {
                self.notice = Some(format!(
                    "{} is neither a .svg nor a .pdf path",
                    path.display()
                ));
                return;
            }
        };
        if path.exists() && self.confirm_write.as_deref() != Some(path) {
            self.confirm_write = Some(path.to_path_buf());
            self.prompt = Some(Prompt {
                kind: PromptKind::ExportGraph,
                title: "Export the graph to (.svg or .pdf)",
                value: path.display().to_string(),
            });
            self.notice = Some(format!(
                "{} exists; submit again to write over it",
                path.display()
            ));
            return;
        }
        self.confirm_write = None;
        let layout = crate::views::graph::layout(self.work.shown_graph(), &self.renames());
        let title = format!("{} at {function:#x}", self.place_name(function));
        let drawing = crate::views::graph::drawing(&layout, title, self.selection.address());
        let bytes = if pdf {
            ag_image::graph_export::pdf(&drawing)
        } else {
            ag_image::graph_export::svg(&drawing).into_bytes()
        };
        self.notice = Some(match std::fs::write(path, &bytes) {
            Ok(()) => format!(
                "Wrote {} ({} bytes, {} block{})",
                path.display(),
                bytes.len(),
                drawing.nodes.len(),
                if drawing.nodes.len() == 1 { "" } else { "s" }
            ),
            Err(error) => format!("Could not write {}: {error}", path.display()),
        });
    }

    /// Open the highlight prompt for the selection, or for the block
    /// holding it.
    fn color_prompt(&mut self, block: bool) -> Task<Message> {
        let Some(address) = self.selection.address() else {
            self.notice = Some("Select something to highlight".into());
            return Task::none();
        };
        // The block's own record, not the entry's beneath it, when the
        // color goes on the block.
        let current = if block {
            let Some(from) = self.block_of(address) else {
                self.notice = Some("No block of the function on screen holds the selection".into());
                return Task::none();
            };
            self.annotations
                .block_for(&self.annotation_key(from))
                .and_then(|a| a.color.clone())
        } else {
            self.annotations
                .annotation_for(&self.annotation_key(address))
                .and_then(|a| a.color.clone())
        }
        .unwrap_or_default();
        self.prompt = Some(Prompt {
            kind: PromptKind::Color { block },
            title: if block {
                "Highlight block (a color name, #rrggbb, or empty to clear)"
            } else {
                "Highlight (a color name, #rrggbb, or empty to clear)"
            },
            value: current,
        });
        Task::none()
    }

    /// Every comment the analyst left, keyed by the bare hex address.
    ///
    /// A comment belongs to the address it was made at, the way a label
    /// does; a variable or register record carries a name, not a note, so
    /// its comment — if one were ever recorded there — keys the same way.
    ///
    /// A spaced record keys on its bare value, the way a rename of the same
    /// import does: a view asks by the address it prints, and an import
    /// commented as `EXTERNAL:0x1` must answer to `0x1`. No provider that
    /// writes listings also names a space, so no two rows collide today.
    pub(crate) fn address_comments(
        &self,
    ) -> std::collections::HashMap<String, Comment> {
        self.annotations
            .annotations
            .iter()
            .filter_map(|annotation| {
                let text = annotation.comment.as_ref()?;
                let key = ag_corpus::parse_addr_space(&annotation.address)
                    .map(|(value, _)| format!("{value:#x}"))
                    .unwrap_or_else(|_| annotation.address.clone());
                Some((
                    key,
                    Comment {
                        text: text.clone(),
                        above: annotation.comment_above,
                    },
                ))
            })
            .collect()
    }

    /// The register renames of the function on screen, keyed by the
    /// register's own spelling.
    ///
    /// A register rename belongs to one function — `rax` in `add` is not
    /// `rax` in `main` — so the map is read against the function whose
    /// listing, graph and pseudocode are on screen. That is the function the
    /// listing was read for, not the current selection: clicking a string
    /// moves the selection but leaves the listing standing.
    pub(crate) fn renamed_registers(&self) -> std::collections::HashMap<String, String> {
        let Some(function) = self.work.listing_of else {
            return std::collections::HashMap::new();
        };
        // Records are stored under the canonical spelling of the address;
        // the provider row may write its space differently, so compare
        // canonical to canonical.
        let key = self.canonical_key(function);
        self.annotations
            .annotations
            .iter()
            .filter(|annotation| {
                annotation.register.is_some() && annotation.address == key
            })
            .filter_map(|annotation| {
                let name = annotation.name.as_ref()?;
                Some((annotation.register.clone()?, name.clone()))
            })
            .collect()
    }

    /// The operand text of a listing line, with the callee's rename and the
    /// function's register renames in place.
    ///
    /// A call names one function; the analyst's name for it replaces the
    /// analysis's own, so the listing and the graph read as one. The
    /// registers the line names — in an operand or inside `[rbp-0x8]` —
    /// are then replaced as whole words, so a renamed `rbp` reads
    /// `[frame-0x8]`. Any other text the provider wrote is kept.
    pub(crate) fn shown_operands(line: &ListingLine, renamed: &Renames) -> String {
        let base = match line.call_target {
            Some(target) => {
                let key = format!("{target:#x}");
                renamed
                    .addresses
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| line.operands.clone())
            }
            None => line.operands.clone(),
        };
        if line.registers.is_empty() || renamed.registers.is_empty() {
            return base;
        }
        let pairs: Vec<(&str, &str)> = line
            .registers
            .iter()
            .filter_map(|spelled| {
                renamed
                    .registers
                    .get(spelled)
                    .map(|name| (spelled.as_str(), name.as_str()))
            })
            .collect();
        replace_words(&base, &pairs)
    }

    /// The reference labels with the analyst's renames in place.
    ///
    /// A reference is labeled by the name of the function it points at, or
    /// by the address when the analysis had no name; a rename replaces that
    /// stem and keeps whatever the provider added after it — the stem must
    /// end where a word ends, so renaming `add` does not touch `address`.
    /// A label that names something else is left alone.
    pub(crate) fn shown_reference_labels(&self, references: &[Reference]) -> Vec<String> {
        references
            .iter()
            .map(|reference| {
                let row = self.provider_row(reference.address);
                let key = row
                    .as_ref()
                    .map(|row| row.display_address())
                    .unwrap_or_else(|| format!("{:#x}", reference.address));
                let Some(renamed) = self.annotation_name(&key) else {
                    return reference.label.clone();
                };
                let stem = row
                    .map(|row| row.name)
                    .unwrap_or_else(|| format!("{:#x}", reference.address));
                let hex = format!("{:#x}", reference.address);
                match Self::stem_suffix(&reference.label, &stem).or_else(|| {
                    Self::stem_suffix(&reference.label, &hex)
                }) {
                    Some(suffix) => format!("{renamed}{suffix}"),
                    None => reference.label.clone(),
                }
            })
            .collect()
    }

    /// The part of `label` after `stem`, when the label is the stem plus a
    /// non-word tail — `add (tail call)` after `add`, never `address`
    /// after `add`.
    fn stem_suffix<'a>(label: &'a str, stem: &str) -> Option<&'a str> {
        label.strip_prefix(stem).filter(|rest| {
            rest.chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
    }

    /// The declared local variables of the function on screen, as the
    /// pseudocode writes them.
    ///
    /// The declaration lines are the ones the lifter prints — `long v2;`,
    /// `int local_14;` — so the names come from the body the analyst is
    /// reading, not from a guess. A pointer or array declaration names its
    /// variable through a `*` or a `[4]`; both are stripped. A provider
    /// whose pseudocode declares nothing offers nothing to rename.
    pub(crate) fn declared_variables(&self) -> Vec<String> {
        let Some(body) = self.work.pseudocode.as_deref() else {
            return Vec::new();
        };
        let mut names = Vec::new();
        let keep = |name: &str, names: &mut Vec<String>| {
            if !name.is_empty()
                && name.starts_with(|c: char| c.is_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !names.iter().any(|known| known == name)
            {
                names.push(name.to_string());
            }
        };
        for line in body.lines() {
            let trimmed = line.trim();
            // Python declares nothing; the emitter notes the locals as
            // `# locals: int i, long total`.
            if let Some(locals) = trimmed.strip_prefix("# locals:") {
                for local in locals.split(',') {
                    if let Some(name) = local.split_whitespace().last() {
                        keep(name.trim_start_matches('*'), &mut names);
                    }
                }
                continue;
            }
            let Some(rest) = trimmed.strip_suffix(';') else {
                continue;
            };
            // Rust: `let mut local_14: i32;`.
            if let Some(binding) = rest.strip_prefix("let ") {
                let binding = binding.strip_prefix("mut ").unwrap_or(binding);
                if let Some((name, _ty)) = binding.split_once(':') {
                    keep(name.trim(), &mut names);
                }
                continue;
            }
            // A declaration is exactly two words: a type and a name.
            // `x = 5;` is three, and its last word is a value, not a name.
            let mut words = rest.split_whitespace();
            let (Some(type_name), Some(declared), None) =
                (words.next(), words.next(), words.next())
            else {
                continue;
            };
            // `return x;` reads as a declaration of `x` by type; the known
            // statement keywords are not locals.
            if matches!(type_name, "return" | "if" | "for" | "while" | "else" | "goto") {
                continue;
            }
            let name = declared
                .strip_prefix('*')
                .unwrap_or(declared)
                .split('[')
                .next()
                .unwrap_or("");
            if !type_name.contains(char::is_alphabetic) || type_name.contains('(') {
                continue;
            }
            keep(name, &mut names);
        }
        names
    }

    /// The registers the function on screen prints, in the order its
    /// listing first names them.
    ///
    /// The disassembler spells each register the way the operand text does,
    /// so what the analyst types matches what the listing shows. A provider
    /// that names no registers offers nothing to rename.
    pub(crate) fn listing_registers(&self) -> Vec<String> {
        let mut named: Vec<String> = Vec::new();
        for line in &self.work.listing {
            for register in &line.registers {
                if !named.contains(register) {
                    named.push(register.clone());
                }
            }
        }
        named
    }

    /// The name pairs the pseudocode view replaces: every renamed function
    /// or label — the one on screen and every callee it names — and every
    /// renamed local and register of the function on screen.
    ///
    /// The body text is the provider's and is never rewritten in place;
    /// this is display only.
    pub(crate) fn rename_pairs(&self) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for row in self.provider.functions() {
            if let Some(name) = self.annotation_name(&row.display_address()) {
                if !row.name.is_empty() && row.name != name {
                    pairs.push((row.name, name));
                }
            }
        }
        if let Some(function) = self.work.detail.as_ref().and_then(|d| d.start) {
            let key = self.annotation_key(function);
            for variable in self.declared_variables() {
                if let Some(renamed) = self.annotations.variable_name(&key, &variable) {
                    pairs.push((variable, renamed));
                }
            }
        }
        // The register renames key on the function the listing was read
        // for, so they keep drawing while the selection sits on a string
        // or a piece of data; renamed_registers answers empty when no
        // function is on screen.
        for (register, name) in self.renamed_registers() {
            pairs.push((register, name));
        }
        pairs
    }

    /// The provider's row for `address`, when the analysis has one.
    fn provider_row(&self, address: u64) -> Option<crate::data::FunctionRow> {
        self.provider
            .functions()
            .into_iter()
            .find(|row| row.address == address)
    }

    /// The navigator row the selection points at, when it points at one.
    fn selected_row(&self) -> Option<crate::data::FunctionRow> {
        let address = self.selection.address()?;
        self.navigator.rows.iter().find(|row| row.address == address).cloned()
    }

    /// The key an annotation on `address` is stored under: the address as the
    /// source wrote it, so a corpus function and its `EXTERNAL` twin key apart.
    ///
    /// The space comes from the provider's own rows, not the filtered
    /// navigator: a comment made while a filter hides the row must still key
    /// on the row's space, or it would be lost once the filter clears.
    pub(crate) fn annotation_key(&self, address: u64) -> String {
        self.provider
            .functions()
            .iter()
            .find(|row| row.address == address)
            .map(|row| row.display_address())
            .unwrap_or_else(|| format!("{address:#x}"))
    }

    /// The annotation key of `address` in the spelling records are stored
    /// under.
    ///
    /// [`App::annotation_key`] answers as the source wrote the address; a
    /// record is keyed on the canonical spelling, so a view that compares
    /// keys directly rather than asking the format owner canonicalizes first.
    pub(crate) fn canonical_key(&self, address: u64) -> String {
        let written = self.annotation_key(address);
        ag_corpus::project::canonical_address(&written).unwrap_or(written)
    }

    /// Open the comment prompt for the selection.
    ///
    /// `above` says where the note will stand: on its own line over the
    /// instruction, or inline at the end of it. The prompt prefills the
    /// comment already there, wherever it stands, so the analyst moves a
    /// comment between the two by re-submitting it.
    fn comment_prompt(&mut self, above: bool) -> Task<Message> {
        let Some(address) = self.selection.address() else {
            self.notice = Some("Select something to comment".into());
            return Task::none();
        };
        let key = self.annotation_key(address);
        let current = self
            .annotations
            .annotation_for(&key)
            .and_then(|a| a.comment.clone())
            .unwrap_or_default();
        self.prompt = Some(Prompt {
            kind: PromptKind::Comment { above },
            title: if above {
                "Add comment above"
            } else {
                "Add comment inline"
            },
            value: current,
        });
        Task::none()
    }

    /// The name of the segment the selection is in, when it is in one.
    fn segment_at_selection(&self) -> Option<String> {
        let address = self.selection.address()?;
        self.provider
            .segments()
            .into_iter()
            .filter(|segment| segment.vma != 0)
            .find(|segment| segment.vma <= address && address < segment.vma + segment.size)
            .map(|segment| segment.name)
    }

    /// Read the program again under the layout the annotations now
    /// record, and say `said`; when the image cannot take the layout, put
    /// `previous` back and say why instead. The annotations stay: the
    /// root is the same.
    fn relayout(&mut self, previous: ag_corpus::project::Layout, said: String) -> Task<Message> {
        let Some(path) = self.binary_path.clone() else {
            self.annotations.layout = previous;
            self.notice = Some("Changing the layout needs a program image".into());
            return Task::none();
        };
        // Tried on the side first, so a layout the image cannot take
        // leaves the program on screen as it is.
        let tried = layout_of(&self.annotations).and_then(|layout| {
            ag_image::Binary::open_with_layout(&path, &layout).map_err(|error| error.to_string())
        });
        if let Err(reason) = tried {
            self.annotations.layout = previous;
            self.notice = Some(reason);
            return Task::none();
        }
        let task = self.load_binary(&path);
        self.notice = Some(said);
        task
    }

    /// Write a copy of the program with the patches in it to `path`, and
    /// say what was done. The program itself is never written, nor the
    /// project file; a file already there is written over on a second
    /// submit of the same path; and the copy is whole or not there.
    fn write_patched_to(&mut self, path: &Path) {
        let Some(binary) = self.binary_path.clone() else {
            self.notice = Some("Writing a patched program needs a program image".into());
            return;
        };
        if path == binary || ag_image::same_file(path, &binary) {
            self.notice = Some(format!("{} is the program itself", path.display()));
            return;
        }
        if self
            .project_path
            .as_deref()
            .is_some_and(|project| project == path || ag_image::same_file(path, project))
        {
            self.notice = Some(format!("{} is the project file", path.display()));
            return;
        }
        // Patches were made against the bytes the project hashed: written
        // into a program rebuilt since, they would land on the wrong bytes.
        if let Some(recorded) = self.annotations.target.sha256.as_deref() {
            if ag_corpus::project::sha256_of(&binary).ok().as_deref() != Some(recorded) {
                self.notice = Some(format!(
                    "{} has changed since the project was made: its hash is not the one recorded",
                    binary.display()
                ));
                return;
            }
        }
        if path.exists() && self.confirm_write.as_deref() != Some(path) {
            self.confirm_write = Some(path.to_path_buf());
            self.prompt = Some(Prompt {
                kind: PromptKind::WritePatched,
                title: "Write the patched program to",
                value: path.display().to_string(),
            });
            self.notice = Some(format!(
                "{} exists; submit again to write over it",
                path.display()
            ));
            return;
        }
        self.confirm_write = None;
        let count = self.annotations.patches().len();
        match self.provider.write_patched(path) {
            Some(Ok(len)) => {
                self.notice = Some(format!(
                    "Wrote {} ({len} bytes, {count} patch{})",
                    path.display(),
                    if count == 1 { "" } else { "es" }
                ));
            }
            Some(Err(error)) => self.notice = Some(error),
            None => {
                self.notice = Some("Writing a patched program needs a program image".into());
            }
        }
    }

    /// Write the analyst's changes to `path`, recording it as the project file.
    fn save_project_to(&mut self, path: &Path) {
        // The target identity comes from the open project, not the last save.
        // A program image knows its own hash only when the reader computed
        // one, so the save asks the format owner for it here rather than
        // write a project that cannot say what it describes.
        let sha256 = self.project.target_sha256.clone().or_else(|| {
            self.project
                .root
                .as_ref()
                .filter(|root| root.is_file())
                .and_then(|root| ag_corpus::project::sha256_of(root).ok())
        });
        self.annotations.target = ag_corpus::project::Target {
            path: self
                .project
                .root
                .as_ref()
                .map(|root| root.display().to_string()),
            sha256,
            raw: self.raw.as_ref().map(raw_target_of),
            slice: self.slice.clone(),
        };
        match self.annotations.save(path) {
            Ok(()) => {
                self.project_path = Some(path.to_path_buf());
                self.notice = Some(format!("Saved project {}", path.display()));
            }
            Err(error) => {
                self.notice = Some(format!("Could not save {}: {error:#}", path.display()));
            }
        }
    }

    /// Select the first function in the list, if there is one.
    fn select_first_function(&mut self) -> Task<Message> {
        if let Some(first) = self.navigator.rows.first() {
            let address = first.address;
            return self.select_function(address, false);
        }

        Task::none()
    }

    /// Move the shared selection to a function.
    pub fn select_function(&mut self, address: u64, record_history: bool) -> Task<Message> {
        self.selection = Selection::Function(address);
        self.navigator.selected = Some(address);
        self.data_selection = None;

        // A function the analyst marked where the analysis found none is
        // described by the mark, since the analysis has nothing to say.
        self.work.detail = self
            .provider
            .function_detail(address)
            .or_else(|| self.marked_function_detail(address));
        self.work.listing_of = Some(address);
        self.refresh_listing();
        self.work.pseudocode = self.provider.pseudocode(address);
        self.work.bytes = self.provider.bytes(address).unwrap_or_default();
        self.work.references = self.provider.references(address);
        self.work.line_addresses = self.provider.line_addresses(address);

        if record_history {
            self.history.push(self.selection);
        }

        // A function the CLI has already answered for keeps its line mapping.
        if let Some(function) = self.cached_kuna_function(address) {
            self.apply_kuna_line_addresses(address, &function);
        }

        self.refresh_problems();

        self.ask_kuna_about_the_function(address)
    }

    /// Read the listing and the graph of the function on screen again, with
    /// the analyst's marks applied: where the analyst said the bytes are
    /// data, a string or undefined, those lines stand in place of the
    /// instructions the analysis decoded there.
    fn refresh_listing(&mut self) {
        let Some(function) = self.work.listing_of else {
            return;
        };
        let listing = self.provider.listing(function).unwrap_or_default();
        let mut graph = self.provider.graph(function).unwrap_or_default();
        // The marks are read once for the whole function, keyed by the
        // address value, so a long listing costs one pass over the marks
        // and one over the lines.
        let marks = self.marks_by_address();
        // A block is where the graph cuts the listing, so a mark stops at a
        // block's start the way the graph's does, and the two agree.
        let stops: std::collections::HashSet<u64> =
            graph.blocks.iter().map(|block| block.from).collect();
        // The operand formats are read the same way, once per function.
        let formats = self.formats_by_address();
        self.work.listing = self.formatted(marked(listing, &marks, &stops), &formats);
        for block in &mut graph.blocks {
            block.instructions = self.formatted(
                marked(std::mem::take(&mut block.instructions), &marks, &stops),
                &formats,
            );
        }
        self.work.graph = graph;
        self.work.il_graph = None;
        self.work.listing_shown = PaneLevel::Disassembly;
        self.work.graph_shown = PaneLevel::Disassembly;
        // A pane set to a level of the lift shows that instead, when the
        // lifter reads the function; otherwise the disassembly stands and
        // the status line says so. One lift serves both panes at one level.
        let mut lifted: Option<(PaneLevel, ag_image::IlFunction)> = None;
        if let PaneLevel::Il { level, ssa } = self.work.listing_level {
            match self.provider.il(function, level, ssa, self.work.casts) {
                Some(il) => {
                    self.work.listing = il_rows(&il, &self.work.render);
                    self.work.listing_shown = self.work.listing_level;
                    lifted = Some((self.work.listing_level, il));
                }
                None => {
                    self.notice = Some(
                        "Listing: the lifter does not read this function; showing the disassembly"
                            .into(),
                    );
                }
            }
        }
        if let PaneLevel::Il { level, ssa } = self.work.graph_level {
            let il = match lifted {
                Some((at, il)) if at == self.work.graph_level => Some(il),
                _ => self.provider.il(function, level, ssa, self.work.casts),
            };
            match il {
                Some(il) => {
                    self.work.il_graph = Some(il_graph(&il, &self.work.graph, &self.work.render));
                    self.work.graph_shown = self.work.graph_level;
                }
                None => {
                    self.notice = Some(
                        "Graph: the lifter does not read this function; showing the disassembly"
                            .into(),
                    );
                }
            }
        }
    }

    /// The analyst's operand formats by the value of the address they are
    /// at.
    fn formats_by_address(
        &self,
    ) -> std::collections::HashMap<u64, ag_corpus::project::OperandFormat> {
        self.annotations
            .annotations
            .iter()
            .filter(|a| a.variable.is_none() && a.register.is_none() && !a.block)
            .filter_map(|a| {
                let format = a.operand_format()?;
                let (value, _) = ag_corpus::parse_addr_space(&a.address).ok()?;
                Some((value, format))
            })
            .collect()
    }

    /// The listing `lines` with the analyst's operand `formats` applied: the
    /// constants of an instruction the analyst chose a format for are
    /// rewritten in it, and an address format names the place a constant
    /// points at when the analysis or the analyst named one.
    fn formatted(
        &self,
        mut lines: Vec<ListingLine>,
        formats: &std::collections::HashMap<u64, ag_corpus::project::OperandFormat>,
    ) -> Vec<ListingLine> {
        if formats.is_empty() {
            return lines;
        }
        for line in &mut lines {
            let Some(&format) = formats.get(&line.address) else {
                continue;
            };
            let name_of = |value: u64| self.named_place(value);
            line.operands = reformat_operands(&line.operands, format, &name_of);
        }
        lines
    }

    /// The name of the place at `address`, when the analysis or the analyst
    /// gave it one: a function's name, or a label.
    fn named_place(&self, address: u64) -> Option<String> {
        let key = self.annotation_key(address);
        if let Some(name) = self.annotation_name(&key) {
            return Some(name);
        }
        self.provider
            .functions()
            .iter()
            .find(|row| row.address == address)
            .map(|row| row.name.clone())
    }

    /// The analyst's marks that stand in for instructions — data, a string,
    /// undefined — by the value of the address they are at. A function or
    /// code mark changes no line, so it is not here.
    fn marks_by_address(&self) -> std::collections::HashMap<u64, ag_corpus::project::ByteType> {
        use ag_corpus::project::ByteType;
        self.annotations
            .annotations
            .iter()
            .filter(|a| a.variable.is_none() && a.register.is_none() && !a.block)
            .filter_map(|a| {
                let mark = a.byte_type()?;
                if !matches!(
                    mark,
                    ByteType::Data { .. } | ByteType::String | ByteType::Undefined
                ) {
                    return None;
                }
                let (value, _) = ag_corpus::parse_addr_space(&a.address).ok()?;
                Some((value, mark))
            })
            .collect()
    }

    /// Whether the analysis decoded an instruction starting at `address` in
    /// the function on screen: where a mark can stand.
    fn instruction_starts_at(&self, address: u64) -> bool {
        self.work
            .listing_of
            .and_then(|function| self.provider.listing(function))
            .is_some_and(|lines| lines.iter().any(|line| line.address == address))
    }

    /// The detail of a function the analyst marked at `address`, when the
    /// analysis found none there.
    fn marked_function_detail(&self, address: u64) -> Option<FunctionDetail> {
        let record = self
            .annotations
            .annotation_for(&self.annotation_key(address))?;
        if record.byte_type() != Some(ag_corpus::project::ByteType::Function) {
            return None;
        }
        Some(FunctionDetail {
            name: record
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{address:x}")),
            status: "Marked".into(),
            start: Some(address),
            end: None,
            provenance: "Analyst".into(),
            mangled: None,
            summary: "The analyst marked these bytes as a function; the analysis found none here."
                .into(),
        })
    }

    /// The functions the analyst marked that the analysis did not list, as
    /// rows of the function list, named by the analyst or `sub_` and the
    /// address.
    fn marked_functions(&self, known: &[FunctionRow]) -> Vec<FunctionRow> {
        self.annotations
            .annotations
            .iter()
            .filter(|a| {
                a.variable.is_none()
                    && a.register.is_none()
                    && !a.block
                    && a.byte_type() == Some(ag_corpus::project::ByteType::Function)
            })
            .filter_map(|a| {
                let (address, space) = ag_corpus::parse_addr_space(&a.address).ok()?;
                if known.iter().any(|row| row.address == address) {
                    return None;
                }
                Some(FunctionRow {
                    address,
                    space,
                    name: a.name.clone().unwrap_or_else(|| format!("sub_{address:x}")),
                    status: "Marked".into(),
                    size: None,
                    objc: false,
                })
            })
            .collect()
    }

    /// Reload the bytes around the selection.
    ///
    /// The byte pane follows the selection: it shows the bytes of the file
    /// around the address the reader is looking at. A provider that only
    /// knows the bytes of a whole function shows those when the selection
    /// is an address inside one; a provider that answers with no bytes at
    /// all has nothing to show, and says so.
    fn refresh_bytes(&mut self) {
        let Some(address) = self.selection.address() else {
            self.work.bytes.clear();
            return;
        };

        self.work.bytes = match self.provider.bytes(address) {
            Some(bytes) => bytes,
            None => match self.containing_function(address) {
                Some(function) => self.provider.bytes(function).unwrap_or_default(),
                None => Vec::new(),
            },
        };
    }

    /// Apply a selection without recording it in the history.
    fn apply_history_selection(&mut self, selection: Selection) -> Task<Message> {
        match selection {
            Selection::Function(address) => self.select_function(address, false),
            Selection::Address(address) => {
                if let Some(function) = self.containing_function(address) {
                    let _ = self.select_function(function, false);
                }
                self.selection = Selection::Address(address);
                // A piece of data is not a function, so it is opened on its
                // own, the way it was when it was picked.
                if let Some(detail) = self.detail_of_data(address) {
                    self.data_selection = Some(address);
                    self.work.detail = Some(detail);
                    self.work.references = self.provider.references(address);
                }
                self.refresh_bytes();
                Task::none()
            }
            Selection::ByteRange { start, .. } => {
                if let Some(function) = self.containing_function(start) {
                    let _ = self.select_function(function, false);
                }
                self.selection = Selection::ByteRange { start, len: 0 };
                self.refresh_bytes();
                Task::none()
            }
            Selection::None => {
                self.selection = Selection::None;
                Task::none()
            }
        }
    }

    /// The function that contains an address, when one is known.
    fn containing_function(&self, address: u64) -> Option<u64> {
        self.navigator
            .rows
            .iter()
            .filter(|row| row.address <= address)
            .max_by_key(|row| row.address)
            .map(|row| row.address)
    }

    /// Ask the kuna CLI about the program as a whole.
    ///
    /// The CLI answers about the binary the export was made from, so these
    /// two questions — the shape of the program and the strings it holds —
    /// are asked once, when the project opens.
    fn ask_kuna_about_the_program(&mut self) -> Task<Message> {
        let Some(cli) = self.kuna.as_ref().and_then(|state| state.cli.clone()) else {
            return Task::none();
        };

        let summary = cli.clone();
        let strings = cli.clone();

        Task::batch(vec![
            Task::perform(
                async move { summary.summary().map_err(|error| format!("{error:#}")) },
                Message::KunaSummaryReady,
            ),
            Task::perform(
                async move { strings.strings().map_err(|error| format!("{error:#}")) },
                Message::KunaStringsReady,
            ),
        ])
    }

    /// Ask the kuna CLI about one function.
    ///
    /// The decompilation carries the mapping from the body's lines to the
    /// addresses they came from; the cross references say what the function
    /// touches and what touches it.
    ///
    /// A question the cache has already answered is not asked again: every
    /// answer is a process run against the binary, and running it a second
    /// time only repeats what is already known.
    fn ask_kuna_about_the_function(&mut self, address: u64) -> Task<Message> {
        let Some(cli) = self.kuna.as_ref().and_then(|state| state.cli.clone()) else {
            return Task::none();
        };

        let asks = self.kuna_asks(address);
        let mut tasks = Vec::new();

        if asks.decompile {
            let decompile = cli.clone();
            tasks.push(Task::perform(
                async move {
                    decompile
                        .decompile(address)
                        .map_err(|error| format!("{error:#}"))
                },
                move |result| Message::KunaFunctionReady(address, result),
            ));
        }

        for (direction, wanted) in [
            (Direction::From, asks.xrefs_from),
            (Direction::To, asks.xrefs_to),
        ] {
            if !wanted {
                continue;
            }

            let xrefs = cli.clone();
            tasks.push(Task::perform(
                async move {
                    xrefs
                        .xrefs(address, direction)
                        .map_err(|error| format!("{error:#}"))
                },
                move |result| Message::KunaXrefsReady(address, direction, result),
            ));
        }

        Task::batch(tasks)
    }

    /// What the workbench still has to ask the kuna CLI about a function.
    fn kuna_asks(&self, address: u64) -> KunaAsks {
        let Some(state) = &self.kuna else {
            return KunaAsks::default();
        };

        let Ok(cache) = state.cache.lock() else {
            // A cache that cannot be read is a cache that cannot answer, so
            // everything is asked again.
            return KunaAsks {
                decompile: true,
                xrefs_from: true,
                xrefs_to: true,
            };
        };

        KunaAsks {
            decompile: cache.function(address).is_none(),
            xrefs_from: cache.xrefs(address, Direction::From).is_none(),
            xrefs_to: cache.xrefs(address, Direction::To).is_none(),
        }
    }

    /// Throw away what the kuna CLI has already answered.
    ///
    /// The answers are held for the life of the project; a reload is how the
    /// workbench asks the same questions again.
    fn clear_kuna_cache(&mut self) {
        if let Some(state) = &self.kuna {
            if let Ok(mut cache) = state.cache.lock() {
                cache.clear();
            }
        }
    }

    /// The decompilation the CLI has already given for a function.
    fn cached_kuna_function(&self, address: u64) -> Option<FunctionJson> {
        let state = self.kuna.as_ref()?;
        let cache = state.cache.lock().ok()?;
        cache.functions.get(&address).cloned()
    }

    /// Map the lines of the displayed body to the addresses they came from.
    fn apply_kuna_line_addresses(&mut self, address: u64, function: &FunctionJson) {
        if self.navigator.selected != Some(address) {
            return;
        }

        let Some(body) = self.work.pseudocode.as_deref() else {
            return;
        };
        let Some(code) = function.code.as_deref() else {
            return;
        };

        self.work.line_addresses = kuna_json::line_addresses(body, code, &function.line_mappings);
    }

    /// Rebuild the problem list from the provider and the selection.
    fn refresh_problems(&mut self) {
        let mut problems = self.provider.problems();

        if let Some(address) = self.navigator.selected {
            problems.extend(self.provider.function_problems(address));
        }

        self.bottom.problems = problems;
    }

    /// The detail of a string, for the inspector.
    ///
    /// A string is not a function, so the inspector is told what it is
    /// instead of what was done to it.
    fn detail_of_string(&self, address: u64) -> Option<FunctionDetail> {
        let string = self
            .provider
            .strings()
            .into_iter()
            .find(|string| string.address == address)?;

        Some(FunctionDetail {
            name: string.text.clone(),
            status: "String".into(),
            start: Some(string.address),
            end: None,
            provenance: "String scan".into(),
            mangled: None,
            summary: match &string.section {
                Some(section) => format!("The string lives in {section}."),
                None => "The string lives in the program image.".to_string(),
            },
        })
    }

    /// The detail of a piece of data, for the inspector.
    ///
    /// A piece of data is not a function, so the inspector is told what it
    /// is instead of what was done to it.
    fn detail_of_data(&self, address: u64) -> Option<FunctionDetail> {
        let symbol = self
            .provider
            .data_symbols()
            .into_iter()
            .find(|symbol| symbol.address == address)?;

        Some(FunctionDetail {
            name: symbol.name.clone(),
            status: "Data".into(),
            start: Some(symbol.address),
            end: symbol.size.map(|size| symbol.address.saturating_add(size)),
            provenance: "Program image".into(),
            mangled: self.provider.mangled_name(symbol.address),
            summary: match &symbol.section {
                Some(section) => format!("The data lives in {section}."),
                None => "The data lives in the program image.".to_string(),
            },
        })
    }

    /// Fill the cross references of the current selection again.
    ///
    /// The references that go the other way arrive after the project opens,
    /// so they are asked for again when the index has landed.
    fn refresh_references(&mut self) {
        if let Some(address) = self.data_selection {
            self.work.references = self.provider.references(address);
            return;
        }

        if let Some(address) = self.navigator.selected {
            self.work.references = self.provider.references(address);
        }
    }

    /// Handle a message.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        // The annotations change through two doors: a prompt submitted
        // for one of the analyst's marks, and the bookmark toggle. The list
        // is read before either and compared after, and a difference is
        // one change undo remembers, labelled by what the notice said.
        let edits = match &message {
            Message::EditBookmark
            | Message::EditMark(_)
            | Message::EditOperandFormat
            | Message::EditNop => true,
            Message::PromptSubmit => self.prompt.as_ref().is_some_and(|prompt| {
                matches!(
                    prompt.kind,
                    PromptKind::Rename
                        | PromptKind::Label
                        | PromptKind::Variable
                        | PromptKind::Register
                        | PromptKind::Comment { .. }
                        | PromptKind::Tags
                        | PromptKind::Color { .. }
                        | PromptKind::Reference { .. }
                        | PromptKind::Switch
                        | PromptKind::Assemble
                        | PromptKind::Nop
                        | PromptKind::Bytes
                        | PromptKind::Mode
                )
            }),
            _ => false,
        };
        let before = edits.then(|| self.annotations.annotations.clone());
        let task = self.apply(message);
        if let Some(before) = before {
            if before != self.annotations.annotations {
                self.record_change(before);
                self.tell_patches();
                self.tell_modes();
                self.tell_jump_tables();
                self.tell_overrides();
            }
        }
        task
    }

    /// `len` bytes from `address` as the image reads them now, patches
    /// and all, when the image holds that run.
    fn bytes_at(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let rows = self.provider.bytes(address)?;
        let mut out = Vec::with_capacity(len);
        for offset in 0..len as u64 {
            let at = address + offset;
            let byte = rows.iter().find_map(|row| {
                (row.address <= at && at < row.address + row.bytes.len() as u64)
                    .then(|| row.bytes[(at - row.address) as usize])
            })?;
            out.push(byte);
        }
        Some(out)
    }

    /// Fill `len` bytes from `address` with the no-op, as a patch that says
    /// so, and say what was done.
    fn nop_at(&mut self, address: u64, len: usize) {
        // A run that leaves the section has nothing to fill past its end,
        // and a slip of the finger would fill gigabytes: refused.
        let Some(end) = self.provider.section_end(address) else {
            self.notice = Some(format!("No section holds {address:#x}"));
            return;
        };
        if address.saturating_add(len as u64) > end {
            self.notice = Some(format!(
                "{len} bytes from {address:#x} run past the end of the section at {end:#x}"
            ));
            return;
        }
        let key = self.annotation_key(address);
        let kind = self.kind_at(address);
        let bytes = ag_image::no_ops(len);
        let text = if len == 1 {
            "nop".to_string()
        } else {
            format!("nop x{len}")
        };
        // Written through the same door as every patch, so one it overlaps
        // comes off.
        self.annotations
            .write_patch(kind, &key, Some((&bytes, Some(&text))));
        self.notice = Some(format!(
            "Filled {len} byte{} at {key} with nop",
            if len == 1 { "" } else { "s" }
        ));
    }

    /// Tell the analysis which bytes the analyst wrote over the image's,
    /// and read the function on screen again when that changed anything:
    /// a patch changes the instructions, so every view follows.
    fn tell_patches(&mut self) {
        if !self.provider.set_patches(self.annotations.patches()) {
            return;
        }
        self.refresh_functions();
        self.refresh_listing();
        if let Some(function) = self.work.listing_of {
            self.work.pseudocode = self.provider.pseudocode(function);
            self.work.line_addresses = self.provider.line_addresses(function);
        }
        self.refresh_bytes();
    }

    /// Tell the analysis which instruction set the analyst's marks put each
    /// address onward in, and read the function on screen again when that
    /// changed anything: every line of it may read differently.
    fn tell_modes(&mut self) {
        if !self.provider.set_modes(self.annotations.modes()) {
            return;
        }
        self.refresh_functions();
        self.refresh_listing();
        if let Some(function) = self.work.listing_of {
            self.work.pseudocode = self.provider.pseudocode(function);
            self.work.line_addresses = self.provider.line_addresses(function);
        }
        self.refresh_bytes();
    }

    /// Tell the analysis the analyst's words on the sites, and read the
    /// function on screen again when that changed anything.
    fn tell_overrides(&mut self) {
        let overrides = self
            .annotations
            .overrides()
            .into_iter()
            .map(|(address, words)| {
                let mut word = ag_image::SiteOverride::default();
                for (kind, on) in &words {
                    word.set(kind, Some(*on));
                }
                (address, word)
            })
            .collect();
        if !self.provider.set_site_overrides(overrides) {
            return;
        }
        self.refresh_listing();
        if let Some(function) = self.work.listing_of {
            self.work.pseudocode = self.provider.pseudocode(function);
            self.work.line_addresses = self.provider.line_addresses(function);
        }
    }

    /// Tell the analysis where the analyst's jump tables are, and read the
    /// function on screen again if the analysis is one that walks code:
    /// a table it is told grows a graph by its cases.
    fn tell_jump_tables(&mut self) {
        let hints = self
            .annotations
            .jump_tables()
            .into_iter()
            .map(|(site, note)| {
                (
                    site,
                    ag_image::JumpTableHint {
                        table: note.table,
                        width: note.width,
                        count: note.count,
                        relative: note.relative,
                    },
                )
            })
            .collect();
        if !self.provider.set_jump_table_hints(hints) {
            return;
        }
        self.refresh_listing();
        if let Some(function) = self.work.listing_of {
            self.work.pseudocode = self.provider.pseudocode(function);
            self.work.line_addresses = self.provider.line_addresses(function);
        }
    }

    /// Remember the change that took the annotations from `before` to what
    /// they are now, and forget the changes taken back: they led from a
    /// state that is gone.
    fn record_change(&mut self, before: Vec<ag_corpus::project::Annotation>) {
        self.undo.push(Change {
            label: self.notice.clone().unwrap_or_else(|| "Edit".into()),
            before,
            after: self.annotations.annotations.clone(),
        });
        if self.undo.len() > UNDO_DEPTH {
            let overflow = self.undo.len() - UNDO_DEPTH;
            self.undo.drain(0..overflow);
        }
        self.redo.clear();
    }

    /// Forget every change: the annotations they were made to are gone.
    fn forget_changes(&mut self) {
        self.undo.clear();
        self.redo.clear();
    }

    /// Carry out one message.
    fn apply(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::EditBytes => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select the bytes to edit".into());
                    return Task::none();
                };
                if self.provider.bitness().is_none() {
                    self.notice = Some("Editing bytes needs a program image".into());
                    return Task::none();
                }
                // The prompt starts from what is there: the patch written
                // here before, else the bytes of the instruction the
                // selection sits on as the image reads them now, else the
                // one byte.
                let key = self.annotation_key(address);
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.patch.clone())
                    .or_else(|| {
                        let len = self.provider.instruction_length_at(address).unwrap_or(1);
                        self.bytes_at(address, len)
                            .map(|bytes| ag_corpus::project::hex_of_bytes(&bytes))
                    })
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::Bytes,
                    title: "Bytes here (hex pairs; empty takes the patch off)",
                    value: current,
                });
            }

            Message::EditNop => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select the instruction to fill with nop".into());
                    return Task::none();
                };
                if self.provider.bitness().is_none() {
                    self.notice = Some("Filling with nop needs a program image".into());
                    return Task::none();
                }
                let Some(len) = self.provider.instruction_length_at(address) else {
                    self.notice = Some(format!(
                        "No instruction starts at {address:#x}; NOP a range to say how far"
                    ));
                    return Task::none();
                };
                self.nop_at(address, len);
            }

            Message::EditNopRange => {
                if self.selection.address().is_none() {
                    self.notice = Some("Select where the nops start".into());
                    return Task::none();
                }
                if self.provider.bitness().is_none() {
                    self.notice = Some("Filling with nop needs a program image".into());
                    return Task::none();
                }
                self.prompt = Some(Prompt {
                    kind: PromptKind::Nop,
                    title: "Fill with nop up to (an address to stop before, or +N bytes)",
                    value: String::new(),
                });
            }

            Message::EditAssemble => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select the instruction to write over".into());
                    return Task::none();
                };
                if self.provider.bitness().is_none() {
                    self.notice = Some("Assembling needs a program image".into());
                    return Task::none();
                }
                let key = self.annotation_key(address);
                // The prompt offers the instruction the analyst wrote here
                // before, so a patch is edited rather than retyped.
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.patch_text.clone())
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::Assemble,
                    title: "Assemble over the bytes here (Intel syntax; empty takes the patch off)",
                    value: current,
                });
            }

            Message::EditSwitch => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select the jmp that reads the table".into());
                    return Task::none();
                };
                let key = self.annotation_key(address);
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.jump_table.clone())
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::Switch,
                    title: "Jump table (TABLE [WIDTH] COUNT [rel]; empty clears)",
                    value: current,
                });
            }

            Message::EditOverride => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some(
                        "Select the instruction the call is made at: the branch, the compare, the jump".into(),
                    );
                    return Task::none();
                };
                let key = self.annotation_key(address);
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .map(|a| a.overrides_label())
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::Override,
                    title: "Override (guard|fold|invert|switch on|off|clear)",
                    value: current,
                });
            }

            Message::EditMark(mark) => {
                use ag_corpus::project::{ByteType, TargetKind};
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select the bytes to mark".into());
                    return Task::none();
                };
                // A mark that stands in for an instruction stands where the
                // analysis decoded one; a function may start anywhere.
                if mark != Mark::Function && !self.instruction_starts_at(address) {
                    self.notice = Some(format!(
                        "Marks start at an instruction; {address:#x} is not one"
                    ));
                    return Task::none();
                }
                let key = self.annotation_key(address);
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.byte_type());
                let next = match mark {
                    // The analysis already shows an instruction here, so
                    // code is the mark coming off, not a mark going on.
                    Mark::Code => None,
                    Mark::Function => Some(ByteType::Function),
                    Mark::String => Some(ByteType::String),
                    Mark::Undefined => Some(ByteType::Undefined),
                    // Marking data where data is marked makes each item one
                    // step wider; anywhere else it starts at a byte.
                    Mark::Data => Some(match current {
                        Some(data @ ByteType::Data { .. }) => data.next_width(),
                        _ => ByteType::Data { width: 1, count: 1 },
                    }),
                };
                // A function mark says what the place is.
                let kind = if next == Some(ByteType::Function) {
                    TargetKind::Function
                } else {
                    self.kind_at(address)
                };
                let annotation = self.annotations.annotation_mut(kind, &key);
                annotation.set_byte_type(next);
                self.annotations.prune();
                self.notice = Some(match next {
                    Some(next) => format!("Marked {key} as {}", next.label()),
                    None => format!("Mark taken off {key}: code"),
                });
                self.refresh_functions();
                self.refresh_listing();
            }

            Message::EditOperandFormat => {
                use ag_corpus::project::OperandFormat;
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select an instruction to format".into());
                    return Task::none();
                };
                let key = self.annotation_key(address);
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.operand_format())
                    .unwrap_or(OperandFormat::Hex);
                let next = current.next();
                let kind = self.kind_at(address);
                self.annotations
                    .annotation_mut(kind, &key)
                    .set_operand_format(Some(next));
                self.annotations.prune();
                self.notice = Some(format!("Operands of {key} shown as {}", next.label()));
                self.refresh_listing();
            }

            Message::EditUndo => {
                // While the analyst is typing into a prompt, the chord is
                // about the typing, not the marks beneath it.
                if self.prompt.is_some() {
                    return Task::none();
                }
                let Some(change) = self.undo.pop() else {
                    self.notice = Some("Nothing to undo".into());
                    return Task::none();
                };
                self.annotations.annotations = change.before.clone();
                self.notice = Some(format!("Undid: {}", change.label));
                self.redo.push(change);
                self.refresh_functions();
                self.refresh_listing();
                self.tell_patches();
                self.tell_modes();
                self.tell_jump_tables();
                self.tell_overrides();
            }

            Message::EditRedo => {
                if self.prompt.is_some() {
                    return Task::none();
                }
                let Some(change) = self.redo.pop() else {
                    self.notice = Some("Nothing to redo".into());
                    return Task::none();
                };
                self.annotations.annotations = change.after.clone();
                self.notice = Some(format!("Redid: {}", change.label));
                self.undo.push(change);
                self.refresh_functions();
                self.refresh_listing();
                self.tell_patches();
                self.tell_modes();
                self.tell_jump_tables();
                self.tell_overrides();
            }

            Message::NavigatorFilterChanged(filter) => {
                self.navigator.filter = filter;
                self.refresh_functions();
            }

            Message::SectionSelected(section) => {
                self.navigator.section = section;
            }

            Message::FunctionSelected(address) => {
                if !self.work.pinned {
                    return self.select_function(address, true);
                } else {
                    self.navigator.selected = Some(address);
                }
            }

            Message::AddressSelected(address) => {
                self.selection = Selection::Address(address);
                self.history.push(self.selection);
                // A provider that knows the address says what it is; one
                // that does not leaves the last detail alone.
                if let Some(detail) = self.provider.function_detail(address) {
                    self.work.detail = Some(detail);
                }
                // The byte pane follows the selection to the address.
                self.refresh_bytes();
            }

            Message::StringSelected(address) => {
                self.selection = Selection::Address(address);
                self.history.push(self.selection);
                self.work.detail = self.detail_of_string(address);
                self.work.references = references_of_string(
                    &self.provider.strings(),
                    &self.provider.functions(),
                    address,
                );
            }

            Message::DataSelected(address) => {
                self.selection = Selection::Address(address);
                self.data_selection = Some(address);
                self.history.push(self.selection);
                self.work.detail = self.detail_of_data(address);
                self.work.references = self.provider.references(address);
                self.refresh_bytes();
            }

            Message::StringFilterChanged(filter) => {
                self.work.string_filter = filter;
            }

            Message::ViewTabSelected(tab) => {
                self.work.tab = tab;
            }

            Message::ToggleDeadCode => {
                let dropping = self.options.get("dead-code").as_deref() == Some("drop");
                let value = if dropping { "keep" } else { "drop" };
                if self.options.set("dead-code", value).is_err() {
                    return Task::none();
                }
                // The image is lifted under the options it was opened with,
                // so it is opened again; the function on screen is kept,
                // and nothing is added to the history.
                let Some(path) = self.binary_path.clone() else {
                    return Task::none();
                };
                let function = self.work.listing_of.or(self.navigator.selected);
                let task = self.load_binary(&path);
                self.work.tab = ViewTab::Pseudocode;
                if let Some(address) = function {
                    let _ = self.select_function(address, false);
                    self.work.tab = ViewTab::Pseudocode;
                }
                return task;
            }

            Message::LowerTabSelected(tab) => {
                self.work.lower = tab;
            }

            Message::BottomTabSelected(tab) => {
                self.bottom.tab = tab;
            }

            Message::GlobalQueryChanged(query) => {
                self.bottom.hits = self.provider.search(&query, false);
                self.global_query = query;
                self.bottom.tab = BottomTab::SearchResults;
            }

            Message::SearchSubmitted => {
                self.bottom.hits = self.provider.search(&self.global_query, false);
                self.bottom.tab = BottomTab::SearchResults;
            }

            Message::DeepSearchSubmitted => {
                self.bottom.hits = self.provider.search(&self.global_query, true);
                self.bottom.tab = BottomTab::SearchResults;
            }

            Message::Back => {
                if let Some(selection) = self.history.back().copied() {
                    return self.apply_history_selection(selection);
                }
            }

            Message::Forward => {
                if let Some(selection) = self.history.forward().copied() {
                    return self.apply_history_selection(selection);
                }
            }

            Message::FileOpenCorpus => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Corpus,
                    title: "Open corpus directory",
                    value: self
                        .corpus_root
                        .as_ref()
                        .map(|root| root.display().to_string())
                        .unwrap_or_default(),
                });
            }

            Message::FileOpenKuna => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Kuna,
                    title: "Open kuna project export directory",
                    value: self
                        .kuna_root
                        .as_ref()
                        .map(|root| root.display().to_string())
                        .unwrap_or_default(),
                });
            }

            Message::FileOpenMethods => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Methods,
                    title: "Open Objective-C method map (JSON)",
                    value: self
                        .methods_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                });
            }

            Message::FileOpenRaw => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Raw,
                    title: "Open raw bytes: PATH ARCH BASE [entry=ADDRESS] [offset=N] [length=N]",
                    value: self
                        .binary_path
                        .as_ref()
                        .map(|path| format!("{} ", path.display()))
                        .unwrap_or_default(),
                });
            }

            Message::FileOpenBinary => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Binary,
                    title: "Open a program image: PATH [slice=ARCH]",
                    value: self
                        .binary_path
                        .as_ref()
                        .map(|path| match &self.slice {
                            Some(slice) => format!("{} slice={slice}", path.display()),
                            None => path.display().to_string(),
                        })
                        .unwrap_or_default(),
                });
            }

            Message::PromptChanged(value) => {
                if let Some(prompt) = &mut self.prompt {
                    prompt.value = value;
                }
            }

            Message::PromptSubmit => {
                let Some(prompt) = self.prompt.take() else {
                    return Task::none();
                };

                let path = PathBuf::from(prompt.value.trim());

                match prompt.kind {
                    PromptKind::Corpus => {
                        if !crate::data::is_corpus(&path) {
                            self.notice =
                                Some(format!("{} has no decompile-index.json", path.display()));
                        } else {
                            self.corpus_root = Some(path);
                            self.kuna_root = None;
                            self.raw = None;
                            return self.load_project();
                        }
                    }
                    PromptKind::Kuna => {
                        if !crate::data::is_kuna_export(&path) {
                            self.notice = Some(format!(
                                "{} holds no kuna export (no .c file)",
                                path.display()
                            ));
                        } else {
                            self.kuna_root = Some(path);
                            self.corpus_root = None;
                            self.raw = None;
                            return self.load_project();
                        }
                    }
                    PromptKind::Methods => {
                        self.methods_path = Some(path);
                        return self.load_project();
                    }
                    PromptKind::Binary => {
                        // The path — spaces and all — and `slice=ARCH` after
                        // it for a universal Mach-O.
                        let text = prompt.value.trim();
                        let (path, slice) = match text.rsplit_once(char::is_whitespace) {
                            Some((head, tail)) if tail.starts_with("slice=") => (
                                PathBuf::from(head.trim_end()),
                                Some(tail["slice=".len()..].to_string()),
                            ),
                            _ => (PathBuf::from(text), None),
                        };
                        if slice.as_deref() == Some("") {
                            self.notice =
                                Some("slice= needs the slice's architecture or position".into());
                            return Task::none();
                        }
                        if !path.is_file() {
                            self.notice = Some(format!("{} is not a file", path.display()));
                        } else {
                            self.binary_path = Some(path);
                            self.raw = None;
                            self.slice = slice;
                            self.corpus_root = None;
                            self.kuna_root = None;
                            return self.load_project();
                        }
                    }
                    PromptKind::Raw => {
                        let words: Vec<&str> = prompt.value.split_whitespace().collect();
                        let [path, arch, base, rest @ ..] = words.as_slice() else {
                            self.notice = Some(
                                "Raw bytes are PATH ARCH BASE, with entry=, offset= and length= after when they apply"
                                    .into(),
                            );
                            return Task::none();
                        };
                        let path = PathBuf::from(path);
                        if !path.is_file() {
                            self.notice = Some(format!("{} is not a file", path.display()));
                            return Task::none();
                        }
                        let Some(language) = ag_image::raw_language(arch) else {
                            self.notice = Some(format!(
                                "Not an architecture raw bytes are read as: {arch:?} ({})",
                                ag_image::RAW_ARCHITECTURES
                            ));
                            return Task::none();
                        };
                        let Some(base) = parse_number(base) else {
                            self.notice = Some(format!("Not an address: {base:?}"));
                            return Task::none();
                        };
                        let mut spec = ag_image::RawSpec {
                            language: language.to_string(),
                            base,
                            entry: None,
                            offset: 0,
                            length: None,
                        };
                        for word in rest {
                            let Some((key, value)) = word.split_once('=') else {
                                self.notice = Some(format!(
                                    "Not part of raw bytes: {word:?} (entry=, offset= or length=)"
                                ));
                                return Task::none();
                            };
                            let Some(number) = parse_number(value) else {
                                self.notice = Some(format!("Not a number: {value:?}"));
                                return Task::none();
                            };
                            match key {
                                "entry" => spec.entry = Some(number),
                                "offset" => spec.offset = number,
                                "length" => spec.length = Some(number),
                                _ => {
                                    self.notice = Some(format!(
                                        "Not part of raw bytes: {key:?} (entry=, offset= or length=)"
                                    ));
                                    return Task::none();
                                }
                            }
                        }
                        self.binary_path = Some(path);
                        self.raw = Some(spec);
                        self.slice = None;
                        self.corpus_root = None;
                        self.kuna_root = None;
                        return self.load_project();
                    }
                    PromptKind::ProjectOpen => {
                        if !path.is_file() {
                            self.notice = Some(format!("{} is not a file", path.display()));
                        } else {
                            match ag_corpus::project::ProjectFile::load(&path) {
                                Ok(project) => {
                                    // A project of raw bytes says how its
                                    // program loads; the program is read
                                    // that way, as the project's.
                                    let raw = match project.target.raw.as_ref().map(raw_of_target) {
                                        Some(Ok(spec)) => Some(spec),
                                        Some(Err(reason)) => {
                                            self.notice = Some(format!(
                                                "Could not open {}: {reason}",
                                                path.display()
                                            ));
                                            return Task::none();
                                        }
                                        None => None,
                                    };
                                    // A project with no program open names
                                    // its own: it is opened.
                                    if self.binary_path.is_none() && raw.is_some() {
                                        if let Some(target) = project
                                            .target
                                            .path
                                            .as_deref()
                                            .map(PathBuf::from)
                                            .filter(|target| target.is_file())
                                        {
                                            self.binary_path = Some(target);
                                            self.corpus_root = None;
                                            self.kuna_root = None;
                                        }
                                    }
                                    let slice = project.target.slice.clone();
                                    let reread = (raw != self.raw || slice != self.slice)
                                        && self.binary_path.is_some();
                                    self.raw = raw;
                                    self.slice = slice;
                                    self.annotations = project;
                                    self.forget_changes();
                                    self.project_path = Some(path.clone());
                                    if reread {
                                        if let Some(binary) = self.binary_path.clone() {
                                            // The annotations are this
                                            // program's, read anew.
                                            self.annotations_root = Some(binary.clone());
                                            let task = self.load_binary(&binary);
                                            self.notice = Some(format!(
                                                "Opened project {} and read {} as it says",
                                                path.display(),
                                                binary.display()
                                            ));
                                            return task;
                                        }
                                    }
                                    // A project with a layout reads the
                                    // program again under it; the reload
                                    // tells the patches and notes itself.
                                    if !self.annotations.layout.is_empty() {
                                        if let Some(binary) = self.binary_path.clone() {
                                            let task = self.load_binary(&binary);
                                            if self.layout_failed.is_none() {
                                                self.notice = Some(format!(
                                                    "Opened project {} and read {} under its layout",
                                                    path.display(),
                                                    binary.display()
                                                ));
                                            }
                                            return task;
                                        }
                                    }
                                    self.tell_patches();
                                    self.tell_modes();
                                    self.tell_jump_tables();
                                    self.tell_overrides();
                                    self.refresh_functions();
                                    self.notice =
                                        Some(format!("Opened project {}", path.display()));
                                }
                                Err(error) => {
                                    self.notice = Some(format!(
                                        "Could not open {}: {error:#}",
                                        path.display()
                                    ));
                                }
                            }
                        }
                    }
                    PromptKind::ProjectSave => {
                        self.save_project_to(&path);
                    }
                    PromptKind::WritePatched => {
                        self.write_patched_to(&path);
                    }
                    PromptKind::ExportGraph => {
                        self.export_graph_to(&path);
                    }
                    PromptKind::AttachPid => {
                        return match prompt.value.trim().parse::<u64>() {
                            Ok(pid) => self.debug_attach(pid),
                            Err(_) => {
                                self.notice =
                                    Some(format!("{:?} is not a process id", prompt.value.trim()));
                                Task::none()
                            }
                        };
                    }
                    PromptKind::Mode => {
                        let text = prompt.value.trim().to_ascii_lowercase();
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            let kind = self.kind_at(address);
                            let mode = match text.as_str() {
                                "" | "none" => None,
                                text => match ag_image::ArmMode::parse(text) {
                                    Some(mode) => Some(mode.label().to_string()),
                                    None => {
                                        self.notice = Some(format!(
                                            "Not an instruction set: {text:?} (arm, thumb or none)"
                                        ));
                                        return Task::none();
                                    }
                                },
                            };
                            self.annotations
                                .annotation_mut(kind, &key)
                                .set_mode(mode.as_deref());
                            self.annotations.prune();
                            self.notice = Some(match &mode {
                                Some(mode) => format!("From {key} the code decodes as {mode}"),
                                None => format!("From {key} the code decodes as the image says"),
                            });
                        }
                    }
                    PromptKind::Rebase => {
                        let text = prompt.value.trim();
                        let base = if text.eq_ignore_ascii_case("none") {
                            None
                        } else {
                            match ag_corpus::parse_addr_space(text) {
                                Ok((value, None)) => Some(value),
                                _ => {
                                    self.notice =
                                        Some(format!("Not an address of the image: {text:?}"));
                                    return Task::none();
                                }
                            }
                        };
                        let previous = self.annotations.layout.clone();
                        self.annotations.set_base(base);
                        let said = match base {
                            Some(base) => format!("The image is read at {base:#x}"),
                            None => "The image is read where the loader puts it".to_string(),
                        };
                        return self.relayout(previous, said);
                    }
                    PromptKind::SegmentAdd => {
                        let words: Vec<&str> = prompt.value.split_whitespace().collect();
                        let [name, address, size, rest @ ..] = words.as_slice() else {
                            self.notice = Some(
                                "A segment is NAME ADDRESS SIZE, with file:OFFSET and exec after when they apply"
                                    .into(),
                            );
                            return Task::none();
                        };
                        let Ok((at, None)) = ag_corpus::parse_addr_space(address) else {
                            self.notice = Some(format!("Not an address of the image: {address:?}"));
                            return Task::none();
                        };
                        let Some(size) = parse_number(size) else {
                            self.notice = Some(format!("Not a size: {size:?}"));
                            return Task::none();
                        };
                        let mut file_offset = None;
                        let mut executable = false;
                        for word in rest {
                            if let Some(offset) = word.strip_prefix("file:") {
                                let Some(offset) = parse_number(offset) else {
                                    self.notice = Some(format!("Not a file offset: {offset:?}"));
                                    return Task::none();
                                };
                                file_offset = Some(format!("{offset:#x}"));
                            } else if word.eq_ignore_ascii_case("exec") {
                                executable = true;
                            } else {
                                self.notice = Some(format!(
                                    "Not part of a segment: {word:?} (file:OFFSET or exec)"
                                ));
                                return Task::none();
                            }
                        }
                        let previous = self.annotations.layout.clone();
                        let edit = ag_corpus::project::SegmentEdit::Add {
                            name: name.to_string(),
                            address: format!("{at:#x}"),
                            size,
                            file_offset,
                            executable,
                        };
                        if let Err(reason) = self.annotations.edit_segment(edit) {
                            self.notice = Some(reason);
                            return Task::none();
                        }
                        return self.relayout(
                            previous,
                            format!("Segment {name} added at {at:#x}, {size} bytes"),
                        );
                    }
                    PromptKind::SegmentRemove => {
                        let name = prompt.value.trim();
                        if name.is_empty() {
                            self.notice = Some("Name the segment to remove".into());
                            return Task::none();
                        }
                        let previous = self.annotations.layout.clone();
                        let edit = ag_corpus::project::SegmentEdit::Remove {
                            name: name.to_string(),
                        };
                        if let Err(reason) = self.annotations.edit_segment(edit) {
                            self.notice = Some(reason);
                            return Task::none();
                        }
                        return self.relayout(previous, format!("Segment {name} removed"));
                    }
                    PromptKind::SegmentRename => {
                        let words: Vec<&str> = prompt.value.split_whitespace().collect();
                        let [name, to] = words.as_slice() else {
                            self.notice = Some("A rename is NAME NEW".into());
                            return Task::none();
                        };
                        let previous = self.annotations.layout.clone();
                        let edit = ag_corpus::project::SegmentEdit::Rename {
                            name: name.to_string(),
                            to: to.to_string(),
                        };
                        if let Err(reason) = self.annotations.edit_segment(edit) {
                            self.notice = Some(reason);
                            return Task::none();
                        }
                        return self.relayout(previous, format!("Segment {name} renamed {to}"));
                    }
                    PromptKind::Rename => {
                        let name = prompt.value.trim().to_string();
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            // The comparison is against the analysis's own
                            // name, not the displayed one: re-entering the
                            // analyst's own name keeps the rename rather
                            // than erasing it.
                            let original = self
                                .provider
                                .functions()
                                .into_iter()
                                .find(|row| row.address == address)
                                .map(|row| row.name);
                            if let Some(original) = original {
                                let annotation = self.annotations.annotation_mut(
                                    ag_corpus::project::TargetKind::Function,
                                    &key,
                                );
                                annotation.name =
                                    (!name.is_empty() && name != original).then_some(name);
                                self.annotations.prune();
                                self.refresh_functions();
                                self.notice = Some(format!("Renamed {key}"));
                            }
                        }
                    }
                    PromptKind::Label => {
                        let name = prompt.value.trim().to_string();
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            let original = self
                                .provider
                                .functions()
                                .into_iter()
                                .find(|row| row.address == address)
                                .map(|row| row.name);
                            let annotation = self.annotations.annotation_mut(
                                ag_corpus::project::TargetKind::Address,
                                &key,
                            );
                            // Returning the analysis's own name clears the
                            // rename, as a function rename does.
                            annotation.name = (!name.is_empty()
                                && Some(&name) != original.as_ref())
                                .then_some(name);
                            self.annotations.prune();
                            self.refresh_functions();
                            self.notice = Some(format!("Renamed {key}"));
                        }
                    }
                    PromptKind::Tags => {
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            let kind = self.kind_at(address);
                            let tags = ag_corpus::project::parse_tags(&prompt.value);
                            let annotation = self.annotations.annotation_mut(kind, &key);
                            annotation.set_tags(&tags);
                            self.annotations.prune();
                            self.refresh_functions();
                            self.notice = Some(if tags.is_empty() {
                                format!("Tags cleared at {key}")
                            } else {
                                format!("Tagged {key} {}", tags.join(" "))
                            });
                        }
                    }
                    PromptKind::BlockText | PromptKind::Group => {
                        let text = prompt.value.trim();
                        let group = prompt.kind == PromptKind::Group;
                        if let Some(address) = self.selection.address() {
                            let Some(from) = self.block_of(address) else {
                                self.notice = Some(
                                    "No block of the function on screen holds the selection".into(),
                                );
                                return Task::none();
                            };
                            let key = self.annotation_key(from);
                            let value = (!text.is_empty()).then(|| text.to_string());
                            let annotation = self
                                .annotations
                                .annotation_mut(ag_corpus::project::TargetKind::Region, &key);
                            annotation.block = true;
                            if group {
                                annotation.group = value.clone();
                            } else {
                                annotation.label = value.clone();
                            }
                            self.annotations.prune();
                            self.notice = Some(match (group, value) {
                                (true, Some(name)) => format!("Grouped {key} as {name}"),
                                (true, None) => format!("Ungrouped {key}"),
                                (false, Some(_)) => format!("Labelled {key}"),
                                (false, None) => format!("Label cleared at {key}"),
                            });
                        }
                    }
                    PromptKind::Color { block } => {
                        let text = prompt.value.trim();
                        if let Some(address) = self.selection.address() {
                            let (key, kind) = if block {
                                let Some(from) = self.block_of(address) else {
                                    self.notice = Some(
                                        "No block of the function on screen holds the selection"
                                            .into(),
                                    );
                                    return Task::none();
                                };
                                (
                                    self.annotation_key(from),
                                    ag_corpus::project::TargetKind::Region,
                                )
                            } else {
                                (self.annotation_key(address), self.kind_at(address))
                            };
                            // Nothing, or `none`, clears; anything else must
                            // be a color before the record changes.
                            let color = if text.is_empty() || text.eq_ignore_ascii_case("none") {
                                None
                            } else {
                                match ag_corpus::project::parse_color(text) {
                                    Some(color) => Some(color),
                                    None => {
                                        self.notice = Some(format!(
                                            "Not a color: {text:?} (try red, amber, green, cyan, blue, purple, or #rrggbb)"
                                        ));
                                        return Task::none();
                                    }
                                }
                            };
                            let annotation = self.annotations.annotation_mut(kind, &key);
                            annotation.color = color.clone();
                            self.annotations.prune();
                            self.notice = Some(match color {
                                Some(color) => format!("Highlighted {key} {color}"),
                                None => format!("Highlight cleared at {key}"),
                            });
                        }
                    }
                    PromptKind::Reference { remove } => {
                        let text = prompt.value.trim();
                        if let Some(address) = self.selection.address() {
                            // The address reached must be one before the
                            // record changes. It is stored under the key the
                            // place's own record uses: typed bare, as the
                            // listing prints it, it takes the space the
                            // analysis gave the place — `0x1` reaches the
                            // import `EXTERNAL:0x1` — so the place finds it
                            // from its own end.
                            let Ok((value, space)) = ag_corpus::parse_addr_space(text) else {
                                self.notice = Some(format!("Not an address: {text:?}"));
                                return Task::none();
                            };
                            let target = match space {
                                Some(_) => ag_corpus::project::canonical_address(text)
                                    .unwrap_or_else(|| text.to_string()),
                                None => self.canonical_key(value),
                            };
                            let key = self.annotation_key(address);
                            if remove
                                && !self
                                    .annotations
                                    .annotation_for(&key)
                                    .is_some_and(|a| a.references.contains(&target))
                            {
                                self.notice =
                                    Some(format!("No manual reference from {key} to {target}"));
                                return Task::none();
                            }
                            let kind = self.kind_at(address);
                            let annotation = self.annotations.annotation_mut(kind, &key);
                            if remove {
                                annotation.remove_reference(&target);
                            } else {
                                annotation.add_reference(&target);
                            }
                            self.annotations.prune();
                            self.notice = Some(if remove {
                                format!("Reference {key} → {target} removed")
                            } else {
                                format!("Referenced {key} → {target}")
                            });
                        }
                    }
                    PromptKind::Bytes => {
                        let text = prompt.value.trim();
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            let kind = self.kind_at(address);
                            if text.is_empty() {
                                let had_patch = self
                                    .annotations
                                    .annotation_for(&key)
                                    .is_some_and(|a| a.patch.is_some());
                                self.annotations.write_patch(kind, &key, None);
                                self.notice = Some(if had_patch {
                                    format!("Patch taken off {key}")
                                } else {
                                    format!("No patch at {key}")
                                });
                            } else {
                                let Some(bytes) = ag_corpus::project::bytes_of_hex(text) else {
                                    self.notice = Some(format!(
                                        "Not bytes: {text:?} (hex pairs, such as 90 or B8 01 00 00 00)"
                                    ));
                                    return Task::none();
                                };
                                // Bytes past the section's end have nowhere to go.
                                let Some(end) = self.provider.section_end(address) else {
                                    self.notice = Some(format!("No section holds {key}"));
                                    return Task::none();
                                };
                                if address.saturating_add(bytes.len() as u64) > end {
                                    self.notice = Some(format!(
                                        "{} bytes from {key} run past the end of the section at {end:#x}",
                                        bytes.len()
                                    ));
                                    return Task::none();
                                }
                                // The prompt submitted as it came up is no
                                // edit: the bytes stand, and so does the text
                                // of an instruction assembled there.
                                let current = self
                                    .annotations
                                    .annotation_for(&key)
                                    .and_then(|a| a.patch_bytes())
                                    .or_else(|| self.bytes_at(address, bytes.len()));
                                if current.as_deref() == Some(bytes.as_slice()) {
                                    self.notice = Some(format!("No change at {key}"));
                                    return Task::none();
                                }
                                // Through the same door as every patch, so one
                                // it overlaps comes off.
                                self.annotations
                                    .write_patch(kind, &key, Some((&bytes, None)));
                                self.notice = Some(format!(
                                    "Wrote {} at {key}",
                                    ag_corpus::project::hex_of_bytes(&bytes)
                                ));
                            }
                        }
                    }
                    PromptKind::Nop => {
                        let text = prompt.value.trim();
                        if let Some(address) = self.selection.address() {
                            let len = if let Some(count) = text.strip_prefix('+') {
                                count.trim().parse::<usize>().ok()
                            } else {
                                ag_corpus::parse_addr_space(text)
                                    .ok()
                                    .and_then(|(end, _)| end.checked_sub(address))
                                    .and_then(|len| usize::try_from(len).ok())
                            };
                            match len {
                                Some(len) if len > 0 => self.nop_at(address, len),
                                _ => {
                                    self.notice = Some(format!(
                                        "Not a reach: {text:?} (an address after {address:#x} to stop before, or +N bytes)"
                                    ));
                                    return Task::none();
                                }
                            }
                        }
                    }
                    PromptKind::Assemble => {
                        let text = prompt.value.trim();
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            let kind = self.kind_at(address);
                            if text.is_empty() {
                                let had_patch = self
                                    .annotations
                                    .annotation_for(&key)
                                    .is_some_and(|a| a.patch.is_some());
                                self.annotations.write_patch(kind, &key, None);
                                self.notice = Some(if had_patch {
                                    format!("Patch taken off {key}")
                                } else {
                                    format!("No patch at {key}")
                                });
                            } else {
                                let Some(bitness) = self.provider.bitness() else {
                                    self.notice = Some("Assembling needs a program image".into());
                                    return Task::none();
                                };
                                let bytes = match ag_image::assemble(text, address, bitness) {
                                    Ok(bytes) => bytes,
                                    Err(error) => {
                                        self.notice = Some(error.to_string());
                                        return Task::none();
                                    }
                                };
                                // Longer than the instruction it replaces,
                                // the patch runs into the next one: said,
                                // not refused — that may be what is meant.
                                let replaced = self.provider.instruction_length_at(address);
                                let warning = match replaced {
                                    Some(replaced) if bytes.len() > replaced => format!(
                                        "; {} bytes longer than the {replaced}-byte instruction it replaces, so the next instruction is overwritten",
                                        bytes.len() - replaced
                                    ),
                                    _ => String::new(),
                                };
                                self.notice = Some(format!(
                                    "Wrote {} at {key}{warning}",
                                    ag_corpus::project::hex_of_bytes(&bytes)
                                ));
                                self.annotations
                                    .write_patch(kind, &key, Some((&bytes, Some(text))));
                            }
                        }
                    }
                    PromptKind::Override => {
                        let text = prompt.value.trim().to_ascii_lowercase();
                        if let Some(address) = self.selection.address() {
                            let mut words = text.split_whitespace();
                            let (Some(kind), Some(state)) = (words.next(), words.next()) else {
                                self.notice = Some(
                                    "An override is KIND on|off|clear: guard, fold, invert or switch".into(),
                                );
                                return Task::none();
                            };
                            let on = match state {
                                "on" | "allow" => Some(true),
                                "off" | "prevent" => Some(false),
                                "clear" | "none" => None,
                                other => {
                                    self.notice = Some(format!("The state is on, off or clear, not {other:?}"));
                                    return Task::none();
                                }
                            };
                            let key = self.annotation_key(address);
                            let kind_at = self.kind_at(address);
                            if !self.annotations.annotation_mut(kind_at, &key).set_override(kind, on) {
                                self.notice = Some(format!(
                                    "The kind is guard, fold, invert or switch, not {kind:?}"
                                ));
                                self.annotations.prune();
                                return Task::none();
                            }
                            self.annotations.prune();
                            self.notice = Some(match on {
                                Some(true) => format!("{kind} allowed at {key}"),
                                Some(false) => format!("{kind} prevented at {key}"),
                                None => format!("{kind} left to the lift at {key}"),
                            });
                            self.tell_overrides();
                        }
                    }
                    PromptKind::Switch => {
                        let text = prompt.value.trim();
                        if let Some(address) = self.selection.address() {
                            let note = if text.is_empty() {
                                None
                            } else {
                                match ag_corpus::project::JumpTableNote::parse(text) {
                                    Some(note) => Some(note),
                                    None => {
                                        self.notice = Some(format!(
                                            "Not a jump table: {text:?} (TABLE COUNT, or TABLE WIDTH COUNT with a width of 4 or 8, and rel after for offsets)"
                                        ));
                                        return Task::none();
                                    }
                                }
                            };
                            let key = self.annotation_key(address);
                            let kind = self.kind_at(address);
                            self.annotations
                                .annotation_mut(kind, &key)
                                .set_jump_table(note);
                            self.annotations.prune();
                            self.notice = Some(match note {
                                Some(note) => format!("Jump table at {key}: {}", note.label()),
                                None => format!("Jump table note taken off {key}"),
                            });
                        }
                    }
                    PromptKind::Variable => {
                        // `DECLARED=NAME`: the declared name the pseudocode
                        // writes, and the name to show for it. An empty
                        // right side returns the declared name.
                        let (declared, name) = match prompt.value.split_once('=') {
                            Some((declared, name)) => (declared.trim(), name.trim()),
                            None => {
                                self.notice = Some(
                                    "A variable rename reads name=new name".into(),
                                );
                                return Task::none();
                            }
                        };
                        // The variable belongs to the function whose body
                        // declares it, which is the function on screen.
                        let Some(address) =
                            self.work.detail.as_ref().and_then(|detail| detail.start)
                        else {
                            self.notice = Some("Open a function to rename its variables".into());
                            return Task::none();
                        };
                        if declared.is_empty() {
                            self.notice = Some("Name which variable to rename".into());
                            return Task::none();
                        }
                        let key = self.annotation_key(address);
                        let annotation = self.annotations.variable_mut(&key, declared);
                        annotation.name = (!name.is_empty()).then_some(name.to_string());
                        self.annotations.prune();
                        self.notice = Some(format!("Renamed {declared} of {key}"));
                    }
                    PromptKind::Register => {
                        // `REGISTER=NAME`, the same shape a variable rename
                        // takes: the register the listing spells, and the
                        // name to show for it. An empty right side clears.
                        let (register, name) = match prompt.value.split_once('=') {
                            Some((register, name)) => (register.trim(), name.trim()),
                            None => {
                                self.notice =
                                    Some("A register rename reads register=new name".into());
                                return Task::none();
                            }
                        };
                        // The rename belongs to the function whose listing
                        // is on screen; a register means that register only
                        // within it.
                        let Some(address) = self.work.listing_of else {
                            self.notice =
                                Some("Open a function to rename its registers".into());
                            return Task::none();
                        };
                        if register.is_empty() {
                            self.notice = Some("Name which register to rename".into());
                            return Task::none();
                        }
                        let key = self.annotation_key(address);
                        let annotation = self.annotations.register_mut(&key, register);
                        annotation.name = (!name.is_empty()).then_some(name.to_string());
                        self.annotations.prune();
                        self.notice = Some(format!("Renamed {register} in {key}"));
                    }
                    PromptKind::Comment { above } => {
                        let text = prompt.value.trim().to_string();
                        if let Some(address) = self.selection.address() {
                            let key = self.annotation_key(address);
                            let annotation = self.annotations.annotation_mut(
                                ag_corpus::project::TargetKind::Address,
                                &key,
                            );
                            annotation.set_comment(
                                (!text.is_empty()).then_some(text),
                                above,
                            );
                            self.annotations.prune();
                            self.notice = Some(format!("Commented {key}"));
                        }
                    }
                }
            }

            Message::FileOpenProject => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::ProjectOpen,
                    title: "Open project file",
                    value: self
                        .project_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                });
            }

            Message::FileSaveProject => {
                let Some(path) = self.project_path.clone() else {
                    self.prompt = Some(Prompt {
                        kind: PromptKind::ProjectSave,
                        title: "Save project file",
                        value: "project.agproj".into(),
                    });
                    return Task::none();
                };
                self.save_project_to(&path);
                return Task::none();
            }

            Message::EditMode => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select where the instruction set changes".into());
                    return Task::none();
                };
                let Some(current) = self.provider.mode_at(address) else {
                    self.notice =
                        Some("Choosing the instruction set needs a 32-bit ARM image".into());
                    return Task::none();
                };
                let key = self.annotation_key(address);
                let marked = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.mode.clone());
                self.prompt = Some(Prompt {
                    kind: PromptKind::Mode,
                    title: "Decode from here as (arm, thumb, or none to let the image say)",
                    value: marked.unwrap_or(current),
                });
            }

            Message::EditRebase => {
                if self.binary_path.is_none() || self.provider.segments().is_empty() {
                    self.notice = Some("Moving the image needs a program image".into());
                    return Task::none();
                }
                // The prompt offers the base the image is read at now: the
                // one the layout says, else the one its format states.
                let base = self
                    .annotations
                    .layout
                    .base
                    .as_deref()
                    .and_then(|base| ag_corpus::parse_addr_space(base).ok())
                    .map(|(value, _)| value)
                    .or_else(|| self.provider.base())
                    .unwrap_or(0);
                self.prompt = Some(Prompt {
                    kind: PromptKind::Rebase,
                    title: "Move the image to (an address, or none)",
                    value: format!("{base:#x}"),
                });
            }

            Message::EditSegmentAdd => {
                if self.binary_path.is_none() || self.provider.segments().is_empty() {
                    self.notice = Some("Adding a segment needs a program image".into());
                    return Task::none();
                }
                self.prompt = Some(Prompt {
                    kind: PromptKind::SegmentAdd,
                    title: "Add segment: NAME ADDRESS SIZE [file:OFFSET] [exec]",
                    value: String::new(),
                });
            }

            Message::EditSegmentRemove => {
                if self.binary_path.is_none() || self.provider.segments().is_empty() {
                    self.notice = Some("Removing a segment needs a program image".into());
                    return Task::none();
                }
                self.prompt = Some(Prompt {
                    kind: PromptKind::SegmentRemove,
                    title: "Remove segment",
                    value: self.segment_at_selection().unwrap_or_default(),
                });
            }

            Message::EditSegmentRename => {
                if self.binary_path.is_none() || self.provider.segments().is_empty() {
                    self.notice = Some("Renaming a segment needs a program image".into());
                    return Task::none();
                }
                self.prompt = Some(Prompt {
                    kind: PromptKind::SegmentRename,
                    title: "Rename segment: NAME NEW",
                    value: self
                        .segment_at_selection()
                        .map(|name| format!("{name} "))
                        .unwrap_or_default(),
                });
            }

            Message::FileWritePatched => {
                let Some(binary) = self.binary_path.clone() else {
                    self.notice = Some("Writing a patched program needs a program image".into());
                    return Task::none();
                };
                if self.annotations.patches().is_empty() {
                    self.notice = Some("No patches to write".into());
                    return Task::none();
                }
                // A file already there takes a second submit of its path,
                // and that starts over with every opening of the prompt.
                self.confirm_write = None;
                self.prompt = Some(Prompt {
                    kind: PromptKind::WritePatched,
                    title: "Write the patched program to",
                    value: format!("{}.patched", binary.display()),
                });
            }

            Message::ViewCycleLevel | Message::ViewToggleSsa => {
                let cycle = matches!(message, Message::ViewCycleLevel);
                let tab = self.work.tab;
                let Some(current) = self.pane_level(tab) else {
                    self.notice = Some("The Listing and Graph panes show the lift's levels".into());
                    return Task::none();
                };
                let next = if cycle {
                    current.cycled()
                } else {
                    current.ssa_toggled()
                };
                if next != PaneLevel::Disassembly && self.work.listing_of.is_none() {
                    self.notice = Some("Select a function to show a level of its lift".into());
                    return Task::none();
                }
                self.set_pane_level(tab, next);
                self.refresh_listing();
                if self.pane_shown(tab) == Some(next) {
                    self.notice = Some(format!("{}: {}", tab.label(), next.label()));
                } else {
                    // The lifter does not read the function there: the pane
                    // keeps what it had.
                    self.set_pane_level(tab, current);
                    self.refresh_listing();
                    self.notice = Some(if current == PaneLevel::Disassembly {
                        "The lift has no levels for this function: the lifter does not read it, or this project has no engine".into()
                    } else {
                        format!(
                            "The lifter does not read this function at the {}; keeping the {}",
                            next.label(),
                            current.label()
                        )
                    });
                }
            }
            Message::ViewToggleIlOption(option) => {
                let on = self.work.toggle_il_option(option);
                self.refresh_listing();
                self.notice = Some(format!(
                    "{}: {} — {}",
                    option.label(),
                    if on { "on" } else { "off" },
                    if option == IlOption::Casts {
                        "a level's constants spelled with their widths"
                    } else {
                        "shown beside a level's items"
                    }
                ));
            }
            Message::DebugStart => return self.debug_start(),
            Message::DebugAttach => {
                if self.binary_path.is_none() {
                    self.notice = Some("Attaching the debugger needs a program image".into());
                    return Task::none();
                }
                self.prompt = Some(Prompt {
                    kind: PromptKind::AttachPid,
                    title: "Attach the debugger to the process with id",
                    value: String::new(),
                });
            }
            Message::DebugContinue => {
                return self.debug_run(|session| session.resume(), "Continuing")
            }
            Message::DebugStep => {
                return self.debug_run(|session| session.step_instruction(), "Stepping into")
            }
            Message::DebugNext => {
                return self.debug_run(|session| session.next_instruction(), "Stepping over")
            }
            Message::DebugFinish => return self.debug_run(|session| session.finish(), "Finishing"),
            Message::DebugInterrupt => {
                if !self.debug.is_running() {
                    self.notice = Some("The program is not running".into());
                    return Task::none();
                }
                if let Some(session) = self.debug.session.as_mut() {
                    if let Err(error) = session.interrupt() {
                        self.notice = Some(format!("Could not interrupt: {error:#}"));
                        return Task::none();
                    }
                }
                self.debug.note("interrupting");
                return Self::debug_poll_later();
            }
            Message::DebugStop => {
                if self.debug.session.is_none() {
                    self.notice = Some("No debugger is running".into());
                    return Task::none();
                }
                self.debug.stop();
                self.debug.note("the debugger was stopped");
                self.notice = Some("Debugger stopped".into());
            }
            Message::DebugToggleBreakpoint(address) => {
                let Some(address) = address
                    .or_else(|| self.selection.address())
                    .or(self.work.listing_of)
                else {
                    self.notice = Some("Select an instruction to set a breakpoint on".into());
                    return Task::none();
                };
                if self.debug.breakpoints.remove(&address) {
                    if let Some(session) = self.debug.session.as_mut() {
                        if let Err(error) = session.remove_breakpoint(address) {
                            self.notice =
                                Some(format!("Could not remove the breakpoint: {error:#}"));
                            return Task::none();
                        }
                    }
                    self.notice = Some(format!("Breakpoint at {address:#x} removed"));
                } else {
                    if let Some(session) = self.debug.session.as_mut() {
                        if let Err(error) = session.add_breakpoint(address) {
                            self.notice = Some(format!("Could not set the breakpoint: {error:#}"));
                            return Task::none();
                        }
                    }
                    self.debug.breakpoints.insert(address);
                    self.notice = Some(format!("Breakpoint at {address:#x}"));
                }
            }
            Message::DebugPoll => {
                if self.debug.session.is_none() {
                    return Task::none();
                }
                let events = self
                    .debug
                    .poll(&|address| self.provider.contains_address(address));
                let stopped = events
                    .iter()
                    .any(|event| matches!(event, ag_debug::Event::Stopped { .. }));
                if stopped {
                    if let Some(pc) = self.debug.pc {
                        self.follow_pc(pc);
                    }
                    self.notice = Some(
                        self.debug
                            .log
                            .iter()
                            .rev()
                            .find(|line| line.starts_with("stopped"))
                            .cloned()
                            .unwrap_or_else(|| "Stopped".into()),
                    );
                }
                if let crate::debug::Status::Exited(code) = self.debug.status {
                    self.notice = Some(match code {
                        Some(code) => format!("The program exited with code {code}"),
                        None => "The program ended".into(),
                    });
                }
                if self.debug.is_running() {
                    return Self::debug_poll_later();
                }
            }

            Message::FileExportGraph => {
                let Some(function) = self.work.listing_of else {
                    self.notice = Some("Select a function to export its graph".into());
                    return Task::none();
                };
                if self.work.shown_graph().blocks.is_empty() {
                    self.notice = Some("The function has no graph to export".into());
                    return Task::none();
                }
                // A path beside the program, named for the function; the
                // extension picks the picture. A file already there takes
                // a second submit of its path.
                self.confirm_write = None;
                // The function's name as a file name: anything but letters,
                // digits and underscores becomes one underscore, and a long
                // demangled name is cut, so the name fits a file system.
                let mut name = String::new();
                for c in self.place_name(function).chars() {
                    if c.is_ascii_alphanumeric() {
                        name.push(c);
                    } else if !name.ends_with('_') {
                        name.push('_');
                    }
                    if name.len() >= 100 {
                        break;
                    }
                }
                let name = name.trim_matches('_');
                let name = if name.is_empty() {
                    format!("{function:#x}")
                } else {
                    name.to_string()
                };
                let beside = self
                    .binary_path
                    .as_deref()
                    .or(self.project_path.as_deref())
                    .and_then(Path::parent)
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::ExportGraph,
                    title: "Export the graph to (.svg or .pdf)",
                    value: beside.join(format!("{name}.svg")).display().to_string(),
                });
            }

            Message::FileSaveProjectAs => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::ProjectSave,
                    title: "Save project file",
                    value: self
                        .project_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "project.agproj".into()),
                });
            }

            Message::PromptCancel => {
                self.prompt = None;
                self.confirm_write = None;
            }

            Message::FileReload => {
                if self.corpus_root.is_some()
                    || self.kuna_root.is_some()
                    || self.binary_path.is_some()
                {
                    // A reload asks the CLI again: the export may have been
                    // written since, and the binary behind it may have
                    // changed under it.
                    self.clear_kuna_cache();
                    return self.load_project();
                } else {
                    self.notice = Some("Nothing to reload".into());
                }
            }

            Message::FileClose => {
                return self.close_project();
            }

            Message::FileQuit => {
                return iced::exit();
            }

            Message::EditRename => {
                let Some(row) = self.selected_row() else {
                    self.notice = Some("Select a function to rename".into());
                    return Task::none();
                };
                self.prompt = Some(Prompt {
                    kind: PromptKind::Rename,
                    title: "Rename function",
                    value: row.name.clone(),
                });
            }

            Message::EditRenameLabel => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select an address to rename".into());
                    return Task::none();
                };
                let key = self.annotation_key(address);
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .and_then(|a| a.name.clone())
                    .or_else(|| {
                        self.provider
                            .functions()
                            .iter()
                            .find(|row| row.address == address)
                            .map(|row| row.name.clone())
                    })
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::Label,
                    title: "Rename label",
                    value: current,
                });
            }

            Message::EditRenameVariable => {
                // The variables to offer are the ones the function on screen
                // declares, wherever in it the selection sits.
                let Some(address) = self.work.detail.as_ref().and_then(|detail| detail.start)
                else {
                    self.notice = Some("Open a function to rename its variables".into());
                    return Task::none();
                };
                let declared = self.declared_variables();
                if declared.is_empty() {
                    self.notice =
                        Some("This function declares no local variables to rename".into());
                    return Task::none();
                }
                let key = self.annotation_key(address);
                // Offer the first declared local the analyst has not named
                // yet; the prompt takes `DECLARED=NAME`.
                let next = declared
                    .iter()
                    .find(|name| self.annotations.variable_for(&key, name).is_none())
                    .cloned()
                    .unwrap_or_else(|| declared[0].clone());
                let current = match self.annotations.variable_for(&key, &next) {
                    Some(a) => format!("{next}={}", a.name.clone().unwrap_or_default()),
                    None => format!("{next}="),
                };
                self.prompt = Some(Prompt {
                    kind: PromptKind::Variable,
                    title: "Rename local variable (declared=new name)",
                    value: current,
                });
            }

            Message::EditRenameRegister => {
                // The registers to offer are the ones the function on screen
                // prints, read from its listing rather than guessed. The
                // rename keys on that same function, not on the selection:
                // clicking a string moves the selection but leaves the
                // listing standing.
                let Some(address) = self.work.listing_of else {
                    self.notice = Some("Open a function to rename its registers".into());
                    return Task::none();
                };
                let named = self.listing_registers();
                if named.is_empty() {
                    self.notice = Some("This function names no registers to rename".into());
                    return Task::none();
                }
                let key = self.annotation_key(address);
                let next = named
                    .iter()
                    .find(|register| self.annotations.register_for(&key, register).is_none())
                    .cloned()
                    .unwrap_or_else(|| named[0].clone());
                let current = match self.annotations.register_for(&key, &next) {
                    Some(a) => format!("{next}={}", a.name.clone().unwrap_or_default()),
                    None => format!("{next}="),
                };
                self.prompt = Some(Prompt {
                    kind: PromptKind::Register,
                    title: "Rename register (register=new name)",
                    value: current,
                });
            }

            Message::EditComment => return self.comment_prompt(false),

            Message::EditCommentAbove => return self.comment_prompt(true),

            Message::EditBookmark => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select something to bookmark".into());
                    return Task::none();
                };
                let key = self.annotation_key(address);
                let kind = self.kind_at(address);
                let annotation = self.annotations.annotation_mut(kind, &key);
                annotation.bookmark = !annotation.bookmark;
                self.annotations.prune();
                let on = self
                    .annotations
                    .annotation_for(&key)
                    .is_some_and(|a| a.bookmark);
                self.notice = Some(format!(
                    "Bookmark {} {key}",
                    if on { "added at" } else { "cleared at" }
                ));
            }

            Message::BookmarkSelected(address) | Message::JumpTo(address) => {
                // A bookmark marks a place. If that place is a function
                // entry, open the function the way the navigator does; if
                // it is any other address, move the selection there. The
                // two are different because a function fills the work
                // surface while a bare address only moves the panes that
                // follow the selection.
                if self.provider.function_detail(address).is_some() {
                    return self.select_function(address, true);
                }
                self.selection = Selection::Address(address);
                self.history.push(self.selection);
                self.refresh_bytes();
            }

            Message::EditTags => {
                let Some(address) = self.selection.address() else {
                    self.notice = Some("Select something to tag".into());
                    return Task::none();
                };
                let key = self.annotation_key(address);
                // The prompt holds the analyst's own tags; an automatic tag
                // is the analysis's and is not theirs to take off.
                let current = self
                    .annotations
                    .annotation_for(&key)
                    .map(|a| a.tags.join(" "))
                    .unwrap_or_default();
                self.prompt = Some(Prompt {
                    kind: PromptKind::Tags,
                    title: "Tags (separate with spaces)",
                    value: current,
                });
            }

            Message::EditColor => return self.color_prompt(false),

            Message::EditColorBlock => return self.color_prompt(true),

            Message::EditBlockText => return self.block_text_prompt(false),

            Message::EditGroup => return self.block_text_prompt(true),

            Message::GraphMove(direction) => {
                // The keys reach every pane; only the graph moves by them,
                // and not while a prompt is being typed.
                if self.work.tab != ViewTab::Graph || self.prompt.is_some() {
                    return Task::none();
                }
                let Some(current) = self.selection.address().or(self.work.listing_of) else {
                    return Task::none();
                };
                let layout = crate::views::graph::layout(self.work.shown_graph(), &self.renames());
                if let Some(next) = crate::views::graph::neighbour(&layout, current, direction) {
                    return self.update(Message::AddressSelected(next));
                }
            }

            Message::EditReference => return self.reference_prompt(false),

            Message::EditReferenceRemove => return self.reference_prompt(true),

            Message::TagSelected(tag) => {
                // The tag becomes the filter, spelled the way the analyst
                // could have typed it, and the function list shows the
                // result.
                self.navigator.filter = format!("#{tag}");
                self.navigator.section = Section::Functions;
                self.refresh_functions();
            }

            Message::ViewToggleNavigator => {
                self.show_navigator = !self.show_navigator;
            }

            Message::ViewToggleInspector => {
                self.show_inspector = !self.show_inspector;
            }

            Message::ViewToggleBottom => {
                self.show_bottom = !self.show_bottom;
            }

            Message::ViewResetLayout => {
                self.show_navigator = true;
                self.show_inspector = true;
                self.show_bottom = true;
                self.notice = Some("Layout reset".into());
            }

            Message::AnalysisRestart => {
                self.notice = Some("Analysis restart needs the binary pipeline".into());
            }

            Message::AnalysisShowLog => {
                self.bottom.tab = BottomTab::AnalysisLog;
                self.show_bottom = true;
            }

            Message::HelpShortcuts => {
                self.notice = Some(
                    "Ctrl+O open corpus · Ctrl+B navigator · Ctrl+Shift+B bookmark · Ctrl+T tags · Ctrl+H highlight · Ctrl+X xref · Ctrl+Z undo · Ctrl+I inspector · Ctrl+J bottom panel · F2 rename · F5 reload"
                        .into(),
                );
            }

            Message::HelpAbout => {
                self.show_about = true;
            }

            Message::AboutClose => {
                self.show_about = false;
            }

            Message::AboutOpenRepository => {
                crate::views::about::open_repository();
            }

            Message::Dismiss => {
                if self.show_about {
                    self.show_about = false;
                } else if self.prompt.is_some() {
                    self.prompt = None;
                }
            }

            Message::Ignore => {}

            Message::KunaSummaryReady(result) => {
                let Some(state) = &self.kuna else {
                    return Task::none();
                };

                match result {
                    Ok(summary) => {
                        if let Ok(mut cache) = state.cache.lock() {
                            cache.summary = Some(summary);
                        }
                    }
                    Err(error) => {
                        self.notice =
                            Some(format!("kuna could not summarize the program: {error}"));
                    }
                }
            }

            Message::KunaStringsReady(result) => {
                let Some(state) = &self.kuna else {
                    return Task::none();
                };

                match result {
                    Ok(strings) => {
                        if let Ok(mut cache) = state.cache.lock() {
                            cache.strings = strings;
                        }
                        self.navigator.counts = self.provider.counts();
                    }
                    Err(error) => {
                        self.notice = Some(format!("kuna could not list the strings: {error}"));
                    }
                }
            }

            Message::KunaFunctionReady(address, result) => {
                let Some(state) = &self.kuna else {
                    return Task::none();
                };

                match result {
                    Ok(function) => {
                        if let Ok(mut cache) = state.cache.lock() {
                            cache.functions.insert(address, function.clone());
                        }
                        self.apply_kuna_line_addresses(address, &function);
                        self.refresh_problems();
                    }
                    Err(error) => {
                        self.notice =
                            Some(format!("kuna could not decompile the function: {error}"));
                    }
                }
            }

            Message::KunaXrefsReady(address, direction, result) => {
                let Some(state) = &self.kuna else {
                    return Task::none();
                };

                match result {
                    Ok(xrefs) => {
                        if let Ok(mut cache) = state.cache.lock() {
                            match direction {
                                Direction::From => cache.xrefs_from.insert(address, xrefs),
                                Direction::To => cache.xrefs_to.insert(address, xrefs),
                            };
                        }
                        if self.navigator.selected == Some(address) {
                            self.work.references = self.provider.references(address);
                        }
                    }
                    Err(error) => {
                        self.notice =
                            Some(format!("kuna could not find the cross references: {error}"));
                    }
                }
            }

            Message::BinaryIndexReady => {
                // The callers of a function are known now, so the pane is
                // filled in again.
                self.provider.mark_references_ready();
                self.refresh_references();
            }

            Message::TogglePin => {
                self.work.pinned = !self.work.pinned;
                let state = if self.work.pinned {
                    "pinned"
                } else {
                    "unpinned"
                };
                self.notice = Some(format!("Location {state}"));
            }
        }

        Task::none()
    }

    /// Build the workbench.
    pub fn view(&self) -> Element<'_, Message> {
        crate::views::layout(self)
    }

    /// The keyboard shortcuts advertised by the menu bar.
    pub fn subscription(&self) -> Subscription<Message> {
        keyboard::listen().map(shortcut)
    }
}

/// The items of a level of the lift as the listing's rows: each with the
/// first address it came from — or the row before's, for an item with
/// none — its text in the operands column indented by its depth, and
/// nothing in the columns a machine instruction fills.
pub(crate) fn il_rows(il: &ag_image::IlFunction, render: &ag_image::Render) -> Vec<ListingLine> {
    let mut rows = Vec::new();
    for block in &il.blocks {
        let mut last = block.address;
        for id in &block.items {
            let item = &il.items[*id];
            let address = item.addresses.first().copied().unwrap_or(last);
            last = address;
            rows.push(ListingLine {
                address,
                bytes: String::new(),
                mnemonic: String::new(),
                operands: format!(
                    "{}{}",
                    "    ".repeat(item.depth),
                    il.item_text(item, render)
                ),
                call_target: None,
                tail: false,
                registers: Vec::new(),
                comment: None,
            });
        }
    }
    rows
}

/// The blocks of a level of the lift as the graph's: one per block of the
/// level, its items as its lines, its successors by address. A block ends
/// where the `disassembly`'s block holding its last instruction ends, so
/// an edge to the block after it is the fall-through it is.
pub(crate) fn il_graph(
    il: &ag_image::IlFunction,
    disassembly: &Graph,
    render: &ag_image::Render,
) -> Graph {
    let blocks: Vec<GraphBlock> = il
        .blocks
        .iter()
        .map(|block| {
            let mut last = block.address;
            let instructions: Vec<ListingLine> = block
                .items
                .iter()
                .map(|id| {
                    let item = &il.items[*id];
                    let address = item.addresses.first().copied().unwrap_or(last);
                    last = address;
                    ListingLine {
                        address,
                        bytes: String::new(),
                        mnemonic: String::new(),
                        operands: il.item_text(item, render),
                        call_target: None,
                        tail: false,
                        registers: Vec::new(),
                        comment: None,
                    }
                })
                .collect();
            let end = instructions
                .iter()
                .map(|line| line.address)
                .max()
                .unwrap_or(block.address);
            let to = disassembly
                .blocks
                .iter()
                .find(|block| block.from <= end && end < block.to)
                .map(|block| block.to)
                .unwrap_or_else(|| end.saturating_add(1))
                .max(block.address.saturating_add(1));
            GraphBlock {
                from: block.address,
                to,
                successors: block
                    .successors
                    .iter()
                    .filter_map(|id| il.blocks.get(*id).map(|block| block.address))
                    .collect(),
                instructions,
            }
        })
        .collect();
    let edges = Graph::edges_of_blocks(&blocks);
    Graph { blocks, edges }
}

/// `text` with every whole-word use of each name replaced in one pass.
///
/// A whole word is bounded by characters that cannot spell an identifier,
/// so renaming `add` does not reach into `address` or `dadd`. The scan
/// never reads what it already wrote, so a name that itself contains the
/// word — `add` to `addX` — is not reached into twice.
///
/// One pass matters when two renames are in flight at once: renaming
/// `local_10` to `count` and `local_14` to `local_10` must render the
/// first as `count` and the second as `local_10`, not both as `count`.
/// The earliest match is taken first, and among matches starting at the
/// same point the longest word wins, so a declared name that starts with
/// another — `v1` and `v10` — still keys on the whole word it found.
pub(crate) fn replace_words(text: &str, pairs: &[(&str, &str)]) -> String {
    let pairs: Vec<&(&str, &str)> = pairs.iter().filter(|(word, _)| !word.is_empty()).collect();
    if pairs.is_empty() {
        return text.to_string();
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    // The character of the original text just before `rest`, so a word
    // boundary is read from what the provider wrote, never from what the
    // replacement put down.
    let mut prev: Option<char> = None;
    'scan: while !rest.is_empty() {
        // The earliest whole-word match, longest word among equals.
        let best = pairs
            .iter()
            .filter_map(|(word, name)| rest.find(word).map(|found| (found, *word, *name)))
            .min_by(|(left_found, left_word, _), (right_found, right_word, _)| {
                left_found.cmp(right_found).then(right_word.len().cmp(&left_word.len()))
            });
        if let Some((found, word, name)) = best {
            let before = rest[..found]
                .chars()
                .next_back()
                .or(prev)
                .is_none_or(|c| !is_word(c));
            let after_index = found + word.len();
            let after = rest[after_index..]
                .chars()
                .next()
                .is_none_or(|c| !is_word(c));
            out.push_str(&rest[..found]);
            if before && after {
                out.push_str(name);
            } else {
                out.push_str(word);
            }
            prev = word.chars().next_back();
            rest = &rest[after_index..];
            continue 'scan;
        }
        let width = rest.chars().next().expect("nonempty").len_utf8();
        out.push_str(&rest[..width]);
        prev = rest.chars().next();
        rest = &rest[width..];
    }
    out
}

/// How far a string mark reads when no zero ends it.
const STRING_REACH: usize = 256;

/// The listing `lines` with the analyst's `marks` applied.
///
/// A line whose address the analyst marked as data, a string or undefined
/// is replaced by what the mark says the bytes are, and the bytes come
/// from the instructions the analysis decoded there: a mark that reaches
/// past one instruction takes the next ones' bytes too, as long as each
/// starts where the last ended and none is a block's start in `stops` — a
/// gap, a line with no bytes, or the next block ends the mark. A data mark
/// takes exactly its span and leaves the rest of the last instruction it
/// touched as bytes; a string runs to its zero, or as far as
/// [`STRING_REACH`]; an undefined mark covers the one instruction. The
/// first line that stands in keeps the comment of the line it replaced,
/// so a block's header stays.
fn marked(
    lines: Vec<ListingLine>,
    marks: &std::collections::HashMap<u64, ag_corpus::project::ByteType>,
    stops: &std::collections::HashSet<u64>,
) -> Vec<ListingLine> {
    use ag_corpus::project::ByteType;
    if marks.is_empty() {
        return lines;
    }
    let mut out = Vec::with_capacity(lines.len());
    let mut at = 0;
    while at < lines.len() {
        let line = &lines[at];
        let Some(&mark) = marks.get(&line.address) else {
            out.push(line.clone());
            at += 1;
            continue;
        };
        let enough = |bytes: &[u8]| match mark {
            ByteType::Data { .. } => bytes.len() >= mark.span().unwrap_or(0),
            ByteType::String => bytes.contains(&0) || bytes.len() >= STRING_REACH,
            _ => true,
        };
        let mut bytes: Vec<u8> = hex_bytes(&line.bytes);
        let mut next = at + 1;
        while !bytes.is_empty()
            && !enough(&bytes)
            && next < lines.len()
            && lines[next].address == line.address + bytes.len() as u64
            && !stops.contains(&lines[next].address)
            && !hex_bytes(&lines[next].bytes).is_empty()
        {
            bytes.extend(hex_bytes(&lines[next].bytes));
            next += 1;
        }
        if bytes.is_empty() {
            // A provider that prints no bytes leaves nothing to re-read.
            out.push(line.clone());
            at += 1;
            continue;
        }
        let mut shown = data_lines(line.address, &bytes, mark);
        if let Some(first) = shown.first_mut() {
            first.comment = line.comment.clone();
        }
        out.extend(shown);
        at = next;
    }
    out
}

/// The operand text `operands` with every constant shown as `format` says.
///
/// A constant is a hexadecimal literal as a disassembler prints one: `0x30`
/// as the sample and a kuna export spell it, or `30h` / `0Ch` as iced's
/// Intel syntax spells it for a program image — a run of hex digits that
/// starts with a decimal digit and ends in `h`. Either way no word character
/// may run into it, so a label such as `loc_0x10` or `sub_1149h` is left
/// whole. Hex leaves the text as it is. Signed reads a value in the width it
/// is printed in — two digits a byte, four a word, eight a double word, else
/// a quad word — so `0xff` is `-0x1`; a constant the analysis already
/// printed with a sign, `[rbp-0x88]` or `[rbp+0x10]`, is signed already and
/// is left as it is. Decimal and octal print the value as a number. Address
/// shows the name `name_of` gives the value, and leaves a value it names
/// nothing for as it was. Anything that is not a constant — a register, a
/// label, a mnemonic suffix — is left alone.
pub(crate) fn reformat_operands(
    operands: &str,
    format: ag_corpus::project::OperandFormat,
    name_of: &dyn Fn(u64) -> Option<String>,
) -> String {
    use ag_corpus::project::OperandFormat;
    if format == OperandFormat::Hex {
        return operands.to_string();
    }
    let bytes = operands.as_bytes();
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut out = String::with_capacity(operands.len());
    let mut at = 0;
    while at < bytes.len() {
        let word_before = at > 0 && is_word(bytes[at - 1]);
        // The literal at `at`, as (end, digits, spelled with `0x`), when
        // one starts here and nothing runs into it on either side.
        let literal = if word_before {
            None
        } else if bytes[at..].starts_with(b"0x") {
            let mut end = at + 2;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            let digits = &operands[at + 2..end];
            (!digits.is_empty() && !(end < bytes.len() && is_word(bytes[end])))
                .then_some((end, digits, true))
        } else if bytes[at].is_ascii_digit() {
            let mut end = at;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            let suffixed = end < bytes.len()
                && bytes[end] == b'h'
                && !(end + 1 < bytes.len() && is_word(bytes[end + 1]));
            suffixed.then_some((end + 1, &operands[at..end], false))
        } else {
            None
        };
        let Some((end, digits, prefixed)) = literal else {
            out.push(bytes[at] as char);
            at += 1;
            continue;
        };
        let Ok(value) = u64::from_str_radix(digits, 16) else {
            out.push_str(&operands[at..end]);
            at = end;
            continue;
        };
        // A sign the analysis printed — `-0x88`, `+ 0x10` — makes the
        // constant signed already: its value is what it says.
        let signed_already = out.trim_end().ends_with(['-', '+']);
        let hex = |value: u64| {
            if prefixed {
                format!("{value:#x}")
            } else {
                format!("{value:X}h")
            }
        };
        let shown = match format {
            OperandFormat::Hex => unreachable!("hex returns above"),
            OperandFormat::Signed if signed_already => operands[at..end].to_string(),
            OperandFormat::Signed => {
                // iced leads a constant that starts with a letter with a
                // zero, `0FFh`, which is spelling, not width.
                let printed = if prefixed {
                    digits.len()
                } else {
                    digits.trim_start_matches('0').len().max(1)
                };
                let width_bits = match printed {
                    0..=2 => 8,
                    3..=4 => 16,
                    5..=8 => 32,
                    _ => 64,
                };
                let signed = if width_bits == 64 {
                    value as i64
                } else if value & (1u64 << (width_bits - 1)) != 0 {
                    (value as i64) - (1i64 << width_bits)
                } else {
                    value as i64
                };
                if signed < 0 {
                    format!("-{}", hex(signed.unsigned_abs()))
                } else {
                    hex(value)
                }
            }
            OperandFormat::Decimal => value.to_string(),
            OperandFormat::Octal => format!("{value:#o}"),
            OperandFormat::Address => match name_of(value) {
                Some(name) if !signed_already => name,
                _ => operands[at..end].to_string(),
            },
        };
        out.push_str(&shown);
        at = end;
    }
    out
}

/// The bytes a listing line prints, `FD 03 00 91`, as values; anything that
/// is not a pair of hex digits — the mark a cut-short line ends in — is
/// passed over.
fn hex_bytes(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
        .collect()
}

/// The listing lines that show `bytes`, starting at `address`, as the mark
/// says they are read.
///
/// Data is one line per item — `db`, `dw`, `dd` or `dq` with the value,
/// little-endian — for as many items as the mark covers, and whatever is
/// left of the last instruction the mark touched as bytes. A string is one
/// line, its printable runs quoted and the rest as values, up to and with
/// its zero. Undefined bytes are shown eight to a line.
fn data_lines(address: u64, bytes: &[u8], mark: ag_corpus::project::ByteType) -> Vec<ListingLine> {
    use ag_corpus::project::ByteType;
    let line = |at: u64, mnemonic: &str, chunk: &[u8], operands: String| ListingLine {
        address: at,
        bytes: chunk
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        mnemonic: mnemonic.to_string(),
        operands,
        call_target: None,
        tail: false,
        registers: Vec::new(),
        comment: None,
    };
    let raw = |at: u64, chunk: &[u8]| {
        line(
            at,
            "db",
            chunk,
            chunk
                .iter()
                .map(|byte| format!("{byte:#04x}"))
                .collect::<Vec<_>>()
                .join(", "),
        )
    };
    let mut out = Vec::new();
    let mut at = address;
    let mut rest = bytes;
    match mark {
        ByteType::Data { width, count } => {
            let width = width as usize;
            let mnemonic = match width {
                1 => "db",
                2 => "dw",
                4 => "dd",
                _ => "dq",
            };
            for _ in 0..count {
                if rest.len() < width {
                    break;
                }
                let (item, after) = rest.split_at(width);
                let value = item
                    .iter()
                    .rev()
                    .fold(0u64, |value, byte| (value << 8) | *byte as u64);
                out.push(line(
                    at,
                    mnemonic,
                    item,
                    format!("{value:#0w$x}", w = 2 + width * 2),
                ));
                at += width as u64;
                rest = after;
            }
        }
        ByteType::String => {
            let end = rest
                .iter()
                .position(|b| *b == 0)
                .map(|i| i + 1)
                .unwrap_or(rest.len());
            let (text, after) = rest.split_at(end);
            let mut parts = Vec::new();
            let mut run = String::new();
            for byte in text {
                if (0x20..0x7f).contains(byte) && *byte != b'"' {
                    run.push(*byte as char);
                } else {
                    if !run.is_empty() {
                        parts.push(format!("\"{run}\""));
                        run.clear();
                    }
                    parts.push(if *byte == 0 {
                        "0".to_string()
                    } else {
                        format!("{byte:#04x}")
                    });
                }
            }
            if !run.is_empty() {
                parts.push(format!("\"{run}\""));
            }
            out.push(line(at, "db", text, parts.join(", ")));
            at += text.len() as u64;
            rest = after;
        }
        _ => {}
    }
    // What is left — the tail of an instruction a data mark cut into, or
    // every byte of an undefined mark — is shown as bytes, eight to a line.
    for chunk in rest.chunks(8) {
        out.push(raw(at, chunk));
        at += chunk.len() as u64;
    }
    out
}

/// The tags the analysis implies for the function `row`, given the
/// program's entry point when it has one.
///
/// `entry` marks the function the program starts in. `objc:Class` marks a
/// method the Objective-C method map named, by the class in `-[Class
/// method]` or `+[Class method]`, so one class's methods gather under one
/// tag. Nothing is stored: the tags are read off the analysis each time.
pub(crate) fn automatic_tags(row: &FunctionRow, entry: Option<u64>) -> Vec<String> {
    let mut tags = Vec::new();
    if entry == Some(row.address) {
        tags.push("entry".to_string());
    }
    if row.objc {
        if let Some(class) = objc_class(&row.name) {
            tags.push(format!("objc:{class}"));
        }
    }
    tags
}

/// The class in an Objective-C method name, `-[Class method]` or
/// `+[Class method]`, when the name has that shape; a category's
/// `Class(Category)` is its class.
fn objc_class(name: &str) -> Option<&str> {
    let rest = name
        .strip_prefix("-[")
        .or_else(|| name.strip_prefix("+["))?;
    let class = rest.split([' ', ']']).next()?;
    let class = class.split('(').next()?;
    (!class.is_empty()).then_some(class)
}

/// Map a key press onto a workbench command.
fn shortcut(event: keyboard::Event) -> Message {
    let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
        return Message::Ignore;
    };

    match (key.as_ref(), modifiers.command(), modifiers.shift()) {
        (Key::Character("o"), true, false) => Message::FileOpenCorpus,
        (Key::Character("q"), true, _) => Message::FileQuit,
        // The plain chord shows or hides the navigator; Shift marks the
        // selection with a bookmark.
        (Key::Character("b"), true, false) => Message::ViewToggleNavigator,
        (Key::Character("b"), true, true) => Message::EditBookmark,
        (Key::Character("i"), true, _) => Message::ViewToggleInspector,
        (Key::Character("j"), true, false) => Message::ViewToggleBottom,
        (Key::Character("t"), true, _) => Message::EditTags,
        // The plain chord highlights the selection; Shift highlights the
        // block holding it.
        (Key::Character("h"), true, false) => Message::EditColor,
        (Key::Character("h"), true, true) => Message::EditColorBlock,
        // Text on the block holding the selection; a group for it.
        (Key::Character("l"), true, true) => Message::EditBlockText,
        (Key::Character("g"), true, false) => Message::EditGroup,
        // The arrows walk the graph from block to block.
        (Key::Named(keyboard::key::Named::ArrowUp), false, false) => {
            Message::GraphMove(crate::views::graph::Direction::Up)
        }
        (Key::Named(keyboard::key::Named::ArrowDown), false, false) => {
            Message::GraphMove(crate::views::graph::Direction::Down)
        }
        (Key::Named(keyboard::key::Named::ArrowLeft), false, false) => {
            Message::GraphMove(crate::views::graph::Direction::Left)
        }
        (Key::Named(keyboard::key::Named::ArrowRight), false, false) => {
            Message::GraphMove(crate::views::graph::Direction::Right)
        }
        // The plain chord records a cross reference from the selection;
        // Shift takes one back.
        (Key::Character("x"), true, false) => Message::EditReference,
        (Key::Character("x"), true, true) => Message::EditReferenceRemove,
        // How the bytes at the selection are read: code, a function, data
        // (again for a wider item), a string, or nothing.
        (Key::Character("c"), true, true) => Message::EditMark(Mark::Code),
        (Key::Character("f"), true, true) => Message::EditMark(Mark::Function),
        (Key::Character("d"), true, true) => Message::EditMark(Mark::Data),
        (Key::Character("a"), true, true) => Message::EditMark(Mark::String),
        (Key::Character("u"), true, true) => Message::EditMark(Mark::Undefined),
        // The constants of the selected instruction, the next way round.
        (Key::Character("n"), true, true) => Message::EditOperandFormat,
        // Where the jump table the selected jmp reads is.
        (Key::Character("j"), true, true) => Message::EditSwitch,
        // An instruction written over the bytes at the selection.
        (Key::Character("e"), true, true) => Message::EditAssemble,
        // The bytes at the selection, edited as hex.
        (Key::Character("y"), true, true) => Message::EditBytes,
        // The selected instruction, or a run from it, filled with nop.
        (Key::Character("o"), true, true) => Message::EditNop,
        (Key::Character("r"), true, true) => Message::EditNopRange,
        // The plain chord takes a change back; Shift puts it back.
        (Key::Character("z"), true, false) => Message::EditUndo,
        (Key::Character("z"), true, true) => Message::EditRedo,
        // The plain chord comments inline; Shift stands the note on its
        // own line above the instruction.
        (Key::Character("/"), true, false) => Message::EditComment,
        (Key::Character("/"), true, true) => Message::EditCommentAbove,
        (Key::Character("r"), true, false) => Message::FileReload,
        (Key::Character("s"), true, _) => Message::FileSaveProject,
        (Key::Named(keyboard::key::Named::F2), true, _) => Message::EditRenameVariable,
        (Key::Named(keyboard::key::Named::F2), false, _) => Message::EditRename,
        (Key::Named(keyboard::key::Named::F3), true, _) => Message::EditRenameRegister,
        (Key::Named(keyboard::key::Named::F3), false, _) => Message::EditRenameLabel,
        (Key::Named(keyboard::key::Named::F5), _, _) => Message::FileReload,
        // The debugger: run, step, and a breakpoint on the selection.
        (Key::Named(keyboard::key::Named::F8), false, false) => Message::DebugContinue,
        (Key::Named(keyboard::key::Named::F9), false, false) => {
            Message::DebugToggleBreakpoint(None)
        }
        (Key::Named(keyboard::key::Named::F10), false, false) => Message::DebugNext,
        (Key::Named(keyboard::key::Named::F11), false, false) => Message::DebugStep,
        (Key::Named(keyboard::key::Named::F11), false, true) => Message::DebugFinish,
        (Key::Named(keyboard::key::Named::F6), false, false) => Message::DebugStart,
        // The pane's level of the lift, and its SSA form.
        (Key::Named(keyboard::key::Named::F7), false, false) => Message::ViewCycleLevel,
        (Key::Named(keyboard::key::Named::F7), false, true) => Message::ViewToggleSsa,
        (Key::Named(keyboard::key::Named::Escape), _, _) => Message::Dismiss,
        _ => Message::Ignore,
    }
}

/// The references of a string: the functions that use it.
///
/// A string is used rather than called, so the inspector is told who
/// uses it instead of who it calls.
fn references_of_string(
    strings: &[StringEntry],
    functions: &[FunctionRow],
    address: u64,
) -> Vec<Reference> {
    let Some(string) = strings.iter().find(|string| string.address == address) else {
        return Vec::new();
    };

    string
        .functions
        .iter()
        .filter_map(|user| {
            let row = functions.iter().find(|row| row.address == *user)?;

            Some(Reference {
                address: row.address,
                label: row.name.clone(),
                kind: ReferenceKind::UsedBy,
            })
        })
        .collect()
}

/// The layout `project` records, in the image's terms, or why it does not
/// read as one.
fn layout_of(project: &ag_corpus::project::ProjectFile) -> Result<ag_image::Layout, String> {
    use ag_corpus::project::SegmentEdit;
    let address = |text: &str| -> Result<u64, String> {
        ag_corpus::parse_addr_space(text)
            .map(|(value, _)| value)
            .map_err(|_| format!("{text:?} in the layout is not an address"))
    };
    let base = project.layout.base.as_deref().map(address).transpose()?;
    let mut segments = Vec::new();
    for edit in &project.layout.segments {
        segments.push(match edit {
            SegmentEdit::Add {
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
            SegmentEdit::Remove { name } => ag_image::SegmentEdit::Remove { name: name.clone() },
            SegmentEdit::Rename { name, to } => ag_image::SegmentEdit::Rename {
                name: name.clone(),
                to: to.clone(),
            },
        });
    }
    Ok(ag_image::Layout { base, segments })
}

/// How raw bytes load, as the project file records it.
fn raw_target_of(spec: &ag_image::RawSpec) -> ag_corpus::project::RawTarget {
    let arch = ag_image::raw_arch(&spec.language)
        .expect("a raw language the prompt handed out has its word");
    ag_corpus::project::RawTarget {
        arch: arch.to_string(),
        base: format!("{:#x}", spec.base),
        entry: spec.entry.map(|entry| format!("{entry:#x}")),
        offset: (spec.offset != 0).then(|| format!("{:#x}", spec.offset)),
        length: spec.length.map(|length| format!("{length:#x}")),
    }
}

/// How raw bytes load, as the project file says, in the image's terms.
fn raw_of_target(raw: &ag_corpus::project::RawTarget) -> Result<ag_image::RawSpec, String> {
    let language = ag_image::raw_language(&raw.arch).ok_or_else(|| {
        format!(
            "the project's raw target names {:?}, not an architecture raw bytes are read as",
            raw.arch
        )
    })?;
    let number = |text: &str| parse_number(text).ok_or_else(|| format!("{text:?} is not a number"));
    Ok(ag_image::RawSpec {
        language: language.to_string(),
        base: number(&raw.base)?,
        entry: raw.entry.as_deref().map(number).transpose()?,
        offset: raw.offset.as_deref().map(number).transpose()?.unwrap_or(0),
        length: raw.length.as_deref().map(number).transpose()?,
    })
}

/// A number as the analyst types it: decimal, or hex with `0x`.
fn parse_number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::bottom_panel::BottomTab;
    use std::fs;

    /// A workbench booted with the bundled sample project.
    fn app() -> App {
        App::boot(Config::default()).0
    }

    /// A temporary kuna export holding one function.
    struct TempExport(PathBuf);

    impl TempExport {
        fn new(tag: &str) -> TempExport {
            let path = std::env::temp_dir().join(format!(
                "ag-ui-app-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&path).expect("a temporary directory");

            let c = "// Function: one @ 0x1000\nint one(void)\n{\n  return 1;\n}\n\n";
            fs::write(path.join("a.c"), c).expect("the c file");
            fs::write(
                path.join("index.jsonl"),
                format!(
                    "{{\"seq\":0,\"name\":\"one\",\"addr\":\"0x1000\",\"size\":16,\"c_offset\":0,\"c_len\":{},\"error\":null}}\n",
                    c.len()
                ),
            )
            .expect("the index");

            TempExport(path)
        }
    }

    impl Drop for TempExport {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn booting_without_a_corpus_shows_the_sample() {
        let app = app();

        assert_eq!(app.navigator.rows.len(), 5);
        assert!(app.show_navigator);
        assert!(app.show_inspector);
        assert!(app.show_bottom);
    }

    #[test]
    fn the_view_menu_toggles_panes() {
        let mut app = app();

        let _ = app.update(Message::ViewToggleNavigator);
        assert!(!app.show_navigator);

        let _ = app.update(Message::ViewToggleInspector);
        assert!(!app.show_inspector);

        let _ = app.update(Message::ViewToggleBottom);
        assert!(!app.show_bottom);

        let _ = app.update(Message::ViewResetLayout);
        assert!(app.show_navigator && app.show_inspector && app.show_bottom);
    }

    #[test]
    fn the_file_menu_opens_a_path_prompt() {
        let mut app = app();

        let _ = app.update(Message::FileOpenCorpus);
        let prompt = app.prompt.as_ref().expect("a prompt should be open");
        assert_eq!(prompt.kind, PromptKind::Corpus);

        let _ = app.update(Message::PromptChanged("/tmp/nowhere".into()));
        assert_eq!(app.prompt.as_ref().unwrap().value, "/tmp/nowhere");

        let _ = app.update(Message::PromptCancel);
        assert!(app.prompt.is_none());
    }

    #[test]
    fn opening_a_directory_without_an_index_is_refused() {
        let mut app = app();

        let _ = app.update(Message::FileOpenCorpus);
        let _ = app.update(Message::PromptChanged("/tmp".into()));
        let _ = app.update(Message::PromptSubmit);

        assert!(app.prompt.is_none());
        assert!(app
            .notice
            .is_some_and(|notice| notice.contains("decompile-index")));
        assert_eq!(app.navigator.rows.len(), 5);
    }

    #[test]
    fn booting_with_a_kuna_export_shows_its_functions() {
        let export = TempExport::new("boot");
        let config = Config {
            kuna: Some(export.0.clone()),
            ..Config::default()
        };

        let app = App::boot(config).0;

        assert_eq!(app.project.kind, crate::model::ProjectKind::Kuna);
        assert_eq!(app.navigator.rows.len(), 1);
        assert_eq!(app.navigator.rows[0].name, "one");
        assert!(app.capabilities.pseudocode);
        assert_eq!(
            app.work.pseudocode.as_deref(),
            Some("int one(void)\n{\n  return 1;\n}")
        );
    }

    #[test]
    fn the_file_menu_opens_a_kuna_prompt() {
        let mut app = app();

        let _ = app.update(Message::FileOpenKuna);
        let prompt = app.prompt.as_ref().expect("a prompt should be open");
        assert_eq!(prompt.kind, PromptKind::Kuna);
    }

    #[test]
    fn opening_a_directory_without_a_kuna_export_is_refused() {
        let mut app = app();

        let _ = app.update(Message::FileOpenKuna);
        let _ = app.update(Message::PromptChanged("/tmp".into()));
        let _ = app.update(Message::PromptSubmit);

        assert!(app.prompt.is_none());
        assert!(app.notice.is_some_and(|notice| notice.contains("kuna")));
        assert_eq!(app.navigator.rows.len(), 5);
    }

    #[test]
    fn closing_the_project_empties_the_workbench() {
        let mut app = app();

        let _ = app.update(Message::FileClose);

        assert!(app.navigator.rows.is_empty());
        assert!(app.corpus_root.is_none());
        assert_eq!(app.selection, Selection::None);
    }

    /// The sample ELF the engine's own tests read.
    fn sample_elf() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-engine/tests/fixtures/sample.elf")
    }

    #[test]
    fn picking_a_string_moves_the_selection_to_it() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        let _ = app.update(Message::StringSelected(0x2004));

        assert_eq!(app.selection, Selection::Address(0x2004));

        let detail = app.work.detail.expect("the string is described");
        assert_eq!(detail.name, "%ld\\n");
        assert_eq!(detail.provenance, "String scan");
        assert!(detail.summary.contains(".rodata"), "{detail:?}");
    }

    #[test]
    fn the_functions_that_use_a_string_are_shown_as_its_references() {
        let provider = BinaryProvider::load(&sample_elf()).expect("the image is read");

        // The users of a string are only known once the whole program has
        // been read, so the index is worked out first.
        provider.binary().string_users();

        let strings = provider.strings();
        let functions = provider.functions();

        let references = references_of_string(&strings, &functions, 0x2004);

        assert_eq!(references.len(), 1, "{references:?}");
        assert_eq!(references[0].label, "main");
        assert_eq!(references[0].kind, ReferenceKind::UsedBy);
    }

    #[test]
    fn a_string_that_nothing_uses_has_no_references() {
        let provider = BinaryProvider::load(&sample_elf()).expect("the image is read");
        provider.binary().string_users();

        let strings = provider.strings();
        let functions = provider.functions();

        let references = references_of_string(&strings, &functions, 0);

        assert!(references.is_empty());
    }

    #[test]
    fn the_filter_of_the_strings_list_is_kept() {
        let mut app = app();

        let _ = app.update(Message::StringFilterChanged("ld".into()));

        assert_eq!(app.work.string_filter, "ld");
    }

    #[test]
    fn picking_a_piece_of_data_moves_the_selection_to_it() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        let _ = app.update(Message::DataSelected(0x4010));

        assert_eq!(app.selection, Selection::Address(0x4010));
        assert_eq!(app.data_selection, Some(0x4010));

        let detail = app.work.detail.expect("the data is described");
        assert_eq!(detail.name, "completed.0");
        assert_eq!(detail.status, "Data");
        assert_eq!(detail.provenance, "Program image");
        assert!(detail.summary.contains(".bss"), "{detail:?}");
    }

    #[test]
    fn the_functions_that_use_a_piece_of_data_are_shown_as_its_references() {
        let provider = BinaryProvider::load(&sample_elf()).expect("the image is read");

        // The users of a piece of data are only known once the whole
        // program has been read, so the index is worked out first.
        provider.binary().data_users();

        let references = provider.references(0x4010);

        let users: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ReferenceKind::UsedBy)
            .map(|reference| reference.label.as_str())
            .collect();

        // Three: frame_dummy's read of the flag was register_tm_clones',
        // which it tail-calls, and the walk stops at the jump; _start ends
        // in hlt before deregister_tm_clones, and the walk stops there too.
        assert_eq!(users.len(), 3, "{users:?}");
        assert!(users.contains(&"deregister_tm_clones"), "{users:?}");
        assert!(!users.contains(&"_start"), "{users:?}");
        assert!(!users.contains(&"frame_dummy"), "{users:?}");
    }

    #[test]
    fn a_function_is_chosen_over_the_data_around_it() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        let _ = app.update(Message::DataSelected(0x4010));
        assert_eq!(app.data_selection, Some(0x4010));

        let _ = app.update(Message::FunctionSelected(0x1198));

        assert_eq!(app.data_selection, None, "the data is not open any more");
    }

    #[test]
    fn going_back_to_a_piece_of_data_opens_it_again() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        let _ = app.update(Message::DataSelected(0x4010));
        let _ = app.update(Message::FunctionSelected(0x1198));

        let _ = app.update(Message::Back);

        assert_eq!(app.data_selection, Some(0x4010));
        assert_eq!(app.selection, Selection::Address(0x4010));
    }

    /// The PE fixture the image tests read.
    fn pe_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-image/tests/fixtures/sample.exe")
    }

    /// The Mach-O fixture the image tests read.
    fn macho_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-image/tests/fixtures/sample.macho")
    }

    #[test]
    fn booting_with_a_pe_shows_its_functions() {
        let config = Config {
            binary: Some(pe_image()),
            ..Config::default()
        };

        let app = App::boot(config).0;

        assert_eq!(app.project.kind, crate::model::ProjectKind::Binary);
        assert!(!app.navigator.rows.is_empty(), "the symbols are listed");
        assert!(app.capabilities.listing, "the listing is on");

        // The first function is selected, and its listing is loaded.
        let selected = app.navigator.selected.expect("a function is selected");
        assert!(!app.work.listing.is_empty(), "the listing is shown");
        assert_eq!(app.work.listing[0].address, selected);
    }

    #[test]
    fn booting_with_a_macho_shows_its_functions() {
        let config = Config {
            binary: Some(macho_image()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        assert_eq!(app.project.kind, crate::model::ProjectKind::Binary);
        assert!(!app.navigator.rows.is_empty(), "the symbols are listed");
        assert!(app.capabilities.listing, "the listing is on");

        // The first function of a Mach-O is its header, which holds no code,
        // so the listing of a function is asked for by name.
        let _ = app.update(Message::FunctionSelected(0x100000440));

        assert!(!app.work.listing.is_empty(), "the listing is shown");
        assert_eq!(app.work.listing[0].address, 0x100000440);
    }

    /// The 32-bit ELF fixture the image tests read.
    fn elf32_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-image/tests/fixtures/sample32.elf")
    }

    #[test]
    fn booting_with_a_32_bit_elf_shows_its_functions_and_its_listing() {
        let config = Config {
            binary: Some(elf32_image()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        assert_eq!(app.project.kind, crate::model::ProjectKind::Binary);
        assert_eq!(
            app.project.architecture.as_deref(),
            Some("x86:LE:32:default:gcc")
        );
        assert!(!app.navigator.rows.is_empty(), "the symbols are listed");
        assert!(app.capabilities.listing, "the listing is on for 32-bit x86");
        assert!(app.capabilities.graph, "and so is the graph");

        // The first function is selected, and its listing is loaded: `add`,
        // which starts with `push ebp`.
        let selected = app.navigator.selected.expect("a function is selected");
        assert_eq!(selected, 0x8049000);
        assert!(!app.work.listing.is_empty(), "the listing is shown");
        assert_eq!(app.work.listing[0].address, 0x8049000);
        assert_eq!(app.work.listing[0].mnemonic, "push");
        assert_eq!(app.work.listing[0].operands, "ebp");

        // main has a graph to draw, and a string to pick.
        let _ = app.update(Message::FunctionSelected(0x804900d));
        assert_eq!(app.work.listing[0].address, 0x804900d);
        let _ = app.update(Message::StringSelected(0x804a000));
        assert_eq!(app.selection, Selection::Address(0x804a000));
    }

    #[test]
    fn booting_with_a_binary_shows_its_functions() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let app = App::boot(config).0;

        assert_eq!(app.project.kind, crate::model::ProjectKind::Binary);
        assert!(!app.navigator.rows.is_empty(), "the symbols are listed");
        assert!(app.capabilities.listing, "the listing is on");
        assert!(app.capabilities.pseudocode, "the lifter reads 64-bit x86");

        // The first function is selected, and its listing is loaded.
        let selected = app.navigator.selected.expect("a function is selected");
        assert!(!app.work.listing.is_empty(), "the listing is shown");
        assert_eq!(app.work.listing[0].address, selected);
    }

    #[test]
    fn booting_with_a_binary_fills_the_pseudocode_tab_for_add() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        let _ = app.update(Message::FunctionSelected(0x1149));

        // The function opens with the comment that says what decided its
        // return type: main reads eax after the call.
        assert_eq!(
            app.work.pseudocode.as_deref(),
            Some(
                "// returns int: main reads eax after the call\n\
                 int add(int a, int b)\n{\n  return b + a;\n}"
            )
        );

        // The lines are mapped, so a click on the return lands on the add;
        // the comment came from no instruction.
        let addresses = app
            .work
            .line_addresses
            .get(&3)
            .expect("the return line is mapped");
        assert!(addresses.contains(&0x115d), "{addresses:?}");
        assert_eq!(app.work.line_addresses.get(&0), None);
        assert_eq!(
            app.work.line_addresses.get(&1),
            Some(&vec![0x1149, 0x114d, 0x114e, 0x115f]),
            "the signature stands for the entry and the frame"
        );

        // A loop reads as a for, with the for line mapped to its compare.
        let _ = app.update(Message::FunctionSelected(0x1161));
        let body = app.work.pseudocode.as_deref().expect("sum_to lifts");
        assert!(
            body.contains("for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {"),
            "{body}"
        );
        assert!(
            app.work
                .line_addresses
                .get(&7)
                .is_some_and(|addresses| addresses.contains(&0x118d)),
            "{:?}",
            app.work.line_addresses
        );

        // A function the lifter refuses has no body, and the problem says
        // why: register_tm_clones shifts right, which the lifter does not
        // read.
        let _ = app.update(Message::FunctionSelected(0x10c0));
        assert_eq!(app.work.pseudocode, None);
        assert!(app.work.line_addresses.is_empty());
        assert!(
            app.bottom
                .problems
                .iter()
                .any(|problem| problem.message.contains("not lifted yet: shr")),
            "{:?}",
            app.bottom.problems
        );

        // A PLT stub is a thunk: one line, standing for its two
        // instructions, and no problem.
        let _ = app.update(Message::FunctionSelected(0x1050));
        assert_eq!(app.work.pseudocode.as_deref(), Some("// thunk for printf"));
        assert_eq!(app.work.line_addresses.get(&0), Some(&vec![0x1050, 0x1054]));
        assert!(
            !app.bottom
                .problems
                .iter()
                .any(|problem| problem.address == Some(0x1050)),
            "{:?}",
            app.bottom.problems
        );

        // The start-up glue __do_global_dtors_aux leaves a callee's result
        // in rax on one path and nothing on the other: nothing reads it, so
        // the function is void, with the comment saying so, and no problem.
        let _ = app.update(Message::FunctionSelected(0x1100));
        let body = app.work.pseudocode.as_deref().expect("the glue lifts");
        assert!(
            body.starts_with(
                "// void: no caller in the image, and rax at the ret holds only \
                 deregister_tm_clones's result, which nothing reads\n\
                 void __do_global_dtors_aux(void)\n"
            ),
            "{body}"
        );
        assert!(body.contains("  deregister_tm_clones();\n"), "{body}");
        assert_eq!(
            app.work.line_addresses.get(&0),
            None,
            "the comment is unmapped"
        );
        assert!(
            app.work
                .line_addresses
                .get(&1)
                .is_some_and(|addresses| addresses.contains(&0x1100)),
            "the signature stands for the entry: {:?}",
            app.work.line_addresses
        );
        assert!(
            !app.bottom
                .problems
                .iter()
                .any(|problem| problem.address == Some(0x1100)),
            "{:?}",
            app.bottom.problems
        );
    }

    #[test]
    fn booting_with_a_binary_fills_the_pseudocode_tab_for_main() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        // main is a chain of blocks cut at its three calls, and reads as C
        // with them; the format string is printed as its literal.
        let _ = app.update(Message::FunctionSelected(0x1198));

        assert_eq!(
            app.work.pseudocode.as_deref(),
            Some(
                "// returns long: no caller in the image, and the function writes rax itself \
                 before the ret\n\
                 long main(int a, long b)\n\
                 {\n\
                 \x20 long v2;\n\
                 \n\
                 \x20 v2 = sum_to(add(a, 3));\n\
                 \x20 printf(\"%ld\\n\", v2);\n\
                 \x20 return v2;\n\
                 }"
            )
        );

        // A click on the printf line lands on the call.
        let addresses = app
            .work
            .line_addresses
            .get(&6)
            .expect("the printf line is mapped");
        assert!(addresses.contains(&0x11e1), "{addresses:?}");
        assert!(
            !app.bottom
                .problems
                .iter()
                .any(|problem| problem.message.starts_with("No pseudocode")),
            "{:?}",
            app.bottom.problems
        );
    }

    #[test]
    fn the_index_fills_in_the_callers_of_the_selection() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        // The index has not landed yet, so the callers are not known.
        assert!(app.provider.references_pending());

        let _ = app.update(Message::BinaryIndexReady);

        assert!(!app.provider.references_pending(), "the index has landed");

        // The selection is the first function, and the callers of it are in
        // the pane now.
        let selected = app.navigator.selected.expect("a function is selected");
        let callers: Vec<&str> = app
            .work
            .references
            .iter()
            .filter(|reference| reference.kind == crate::data::ReferenceKind::CalledBy)
            .map(|reference| reference.label.as_str())
            .collect();
        let expected = app.provider.references(selected);
        let expected: Vec<&str> = expected
            .iter()
            .filter(|reference| reference.kind == crate::data::ReferenceKind::CalledBy)
            .map(|reference| reference.label.as_str())
            .collect();
        assert_eq!(callers, expected, "the pane holds the callers");
    }

    #[test]
    fn the_byte_pane_follows_the_selection() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };

        let mut app = App::boot(config).0;

        // The first function is selected, and the bytes around it are shown.
        assert!(!app.work.bytes.is_empty(), "the bytes are shown");

        // Picking an address in the listing moves the byte pane to it.
        let address = app.work.listing[2].address;
        let _ = app.update(Message::AddressSelected(address));

        assert_eq!(app.selection, Selection::Address(address));
        assert!(
            app.work
                .bytes
                .iter()
                .any(|row| row.address <= address && address < row.address + 16),
            "the byte pane moved to the address: {:?}",
            app.work.bytes
        );
    }

    #[test]
    fn the_file_menu_opens_a_binary_prompt() {
        let mut app = app();

        let _ = app.update(Message::FileOpenBinary);
        let prompt = app.prompt.as_ref().expect("a prompt should be open");
        assert_eq!(prompt.kind, PromptKind::Binary);
    }

    #[test]
    fn a_path_that_is_not_a_file_is_refused() {
        let mut app = app();

        let _ = app.update(Message::FileOpenBinary);
        let _ = app.update(Message::PromptChanged("/tmp".into()));
        let _ = app.update(Message::PromptSubmit);

        assert!(app.prompt.is_none());
        assert!(app
            .notice
            .is_some_and(|notice| notice.contains("not a file")));
        assert_eq!(app.navigator.rows.len(), 5, "the sample is still open");
    }

    #[test]
    fn the_analysis_menu_opens_the_log() {
        let mut app = app();

        let _ = app.update(Message::AnalysisShowLog);

        assert_eq!(app.bottom.tab, BottomTab::AnalysisLog);
        assert!(app.show_bottom);
    }

    #[test]
    fn the_help_menu_opens_the_about_dialog() {
        let mut app = app();

        let _ = app.update(Message::HelpAbout);
        assert!(app.show_about);

        let _ = app.update(Message::AboutClose);
        assert!(!app.show_about);
    }

    #[test]
    fn escape_dismisses_the_about_dialog_then_the_prompt() {
        let mut app = app();

        let _ = app.update(Message::HelpAbout);
        let _ = app.update(Message::Dismiss);
        assert!(!app.show_about);

        let _ = app.update(Message::FileOpenCorpus);
        let _ = app.update(Message::Dismiss);
        assert!(app.prompt.is_none());
    }

    #[test]
    fn shortcuts_map_onto_menu_commands() {
        // The platform's command key: Cmd on macOS, Ctrl elsewhere, as `shortcut` reads it.
        let ctrl = keyboard::Modifiers::COMMAND;

        let event = keyboard::Event::KeyPressed {
            key: Key::Character("o".into()),
            modified_key: Key::Character("o".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyO),
            location: keyboard::Location::Standard,
            modifiers: ctrl,
            text: None,
            repeat: false,
        };

        assert!(matches!(shortcut(event), Message::FileOpenCorpus));

        let named = |key: keyboard::key::Named, modifiers: keyboard::Modifiers| {
            keyboard::Event::KeyPressed {
                key: Key::Named(key),
                modified_key: Key::Named(key),
                physical_key: keyboard::key::Physical::Code(keyboard::key::Code::F2),
                location: keyboard::Location::Standard,
                modifiers,
                text: None,
                repeat: false,
            }
        };

        let none = keyboard::Modifiers::empty();
        // The graph's keys: text and a group for the block, and the
        // arrows bare.
        let character = |c: &str, modifiers: keyboard::Modifiers| keyboard::Event::KeyPressed {
            key: Key::Character(c.into()),
            modified_key: Key::Character(c.into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyL),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        };
        assert!(matches!(
            shortcut(character("l", ctrl | keyboard::Modifiers::SHIFT)),
            Message::EditBlockText
        ));
        assert!(matches!(shortcut(character("g", ctrl)), Message::EditGroup));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::ArrowUp, none)),
            Message::GraphMove(crate::views::graph::Direction::Up)
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::ArrowLeft, none)),
            Message::GraphMove(crate::views::graph::Direction::Left)
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F2, none)),
            Message::EditRename
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F2, ctrl)),
            Message::EditRenameVariable
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F3, none)),
            Message::EditRenameLabel
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F3, ctrl)),
            Message::EditRenameRegister
        ));

        let slash = |modifiers: keyboard::Modifiers| keyboard::Event::KeyPressed {
            key: Key::Character("/".into()),
            modified_key: Key::Character("/".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::Slash),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        };
        assert!(matches!(
            shortcut(slash(ctrl)),
            Message::EditComment
        ));
        assert!(matches!(
            shortcut(slash(ctrl | keyboard::Modifiers::SHIFT)),
            Message::EditCommentAbove
        ));

        let b = |modifiers: keyboard::Modifiers| keyboard::Event::KeyPressed {
            key: Key::Character("b".into()),
            modified_key: Key::Character("B".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyB),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        };
        assert!(matches!(
            shortcut(b(ctrl)),
            Message::ViewToggleNavigator
        ));
        assert!(matches!(
            shortcut(b(ctrl | keyboard::Modifiers::SHIFT)),
            Message::EditBookmark
        ));

        let t = keyboard::Event::KeyPressed {
            key: Key::Character("t".into()),
            modified_key: Key::Character("t".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyT),
            location: keyboard::Location::Standard,
            modifiers: ctrl,
            text: None,
            repeat: false,
        };
        assert!(matches!(shortcut(t), Message::EditTags));

        let h = |modifiers: keyboard::Modifiers| keyboard::Event::KeyPressed {
            key: Key::Character("h".into()),
            modified_key: Key::Character("H".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyH),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        };
        assert!(matches!(shortcut(h(ctrl)), Message::EditColor));
        assert!(matches!(
            shortcut(h(ctrl | keyboard::Modifiers::SHIFT)),
            Message::EditColorBlock
        ));

        let z = |modifiers: keyboard::Modifiers| keyboard::Event::KeyPressed {
            key: Key::Character("z".into()),
            modified_key: Key::Character("Z".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyZ),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        };
        let x = |modifiers: keyboard::Modifiers| keyboard::Event::KeyPressed {
            key: Key::Character("x".into()),
            modified_key: Key::Character("X".into()),
            physical_key: keyboard::key::Physical::Code(keyboard::key::Code::KeyX),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat: false,
        };
        let chord =
            |letter: &str, upper: &str, code: keyboard::key::Code| keyboard::Event::KeyPressed {
                key: Key::Character(letter.into()),
                modified_key: Key::Character(upper.into()),
                physical_key: keyboard::key::Physical::Code(code),
                location: keyboard::Location::Standard,
                modifiers: ctrl | keyboard::Modifiers::SHIFT,
                text: None,
                repeat: false,
            };
        assert!(matches!(
            shortcut(chord("c", "C", keyboard::key::Code::KeyC)),
            Message::EditMark(Mark::Code)
        ));
        assert!(matches!(
            shortcut(chord("d", "D", keyboard::key::Code::KeyD)),
            Message::EditMark(Mark::Data)
        ));
        assert!(matches!(
            shortcut(chord("u", "U", keyboard::key::Code::KeyU)),
            Message::EditMark(Mark::Undefined)
        ));
        assert!(matches!(
            shortcut(chord("n", "N", keyboard::key::Code::KeyN)),
            Message::EditOperandFormat
        ));
        assert!(matches!(
            shortcut(chord("j", "J", keyboard::key::Code::KeyJ)),
            Message::EditSwitch
        ));
        assert!(matches!(
            shortcut(chord("e", "E", keyboard::key::Code::KeyE)),
            Message::EditAssemble
        ));
        assert!(matches!(
            shortcut(chord("o", "O", keyboard::key::Code::KeyO)),
            Message::EditNop
        ));
        assert!(matches!(
            shortcut(chord("y", "Y", keyboard::key::Code::KeyY)),
            Message::EditBytes
        ));
        assert!(matches!(
            shortcut(chord("r", "R", keyboard::key::Code::KeyR)),
            Message::EditNopRange
        ));
        assert!(matches!(shortcut(x(ctrl)), Message::EditReference));
        assert!(matches!(
            shortcut(x(ctrl | keyboard::Modifiers::SHIFT)),
            Message::EditReferenceRemove
        ));
        assert!(matches!(shortcut(z(ctrl)), Message::EditUndo));
        assert!(matches!(
            shortcut(z(ctrl | keyboard::Modifiers::SHIFT)),
            Message::EditRedo
        ));
    }

    /// A workbench holding a kuna export, whose CLI has no binary to work on.
    fn kuna_app() -> (TempExport, App) {
        let export = TempExport::new("kuna-json");
        let config = Config {
            kuna: Some(export.0.clone()),
            ..Config::default()
        };

        let app = App::boot(config).0;
        (export, app)
    }

    #[test]
    fn the_line_mapping_reaches_the_pseudocode() {
        let (_export, mut app) = kuna_app();

        let function = FunctionJson {
            code: Some("int one(void)\n{\n  return 1;\n}".into()),
            error: None,
            unstructured_gotos: 0,
            line_mappings: vec![crate::data::kuna_json::LineMapping {
                line_number: 3,
                addresses: vec![0x1004],
            }],
        };

        let _ = app.update(Message::KunaFunctionReady(0x1000, Ok(function)));

        assert_eq!(
            app.work.line_addresses.get(&2),
            Some(&vec![0x1004]),
            "the third line of the body came from 0x1004"
        );
    }

    #[test]
    fn a_stale_line_mapping_is_not_applied() {
        let (_export, mut app) = kuna_app();

        let function = FunctionJson {
            code: Some("int one(void)\n{\n  return 2;\n}".into()),
            error: None,
            unstructured_gotos: 0,
            line_mappings: vec![crate::data::kuna_json::LineMapping {
                line_number: 3,
                addresses: vec![0x1004],
            }],
        };

        let _ = app.update(Message::KunaFunctionReady(0x1000, Ok(function)));

        assert!(
            app.work.line_addresses.is_empty(),
            "a body that no longer matches the export carries no mapping"
        );
    }

    #[test]
    fn the_cross_references_reach_the_work_surface() {
        let (_export, mut app) = kuna_app();

        let xrefs = vec![XrefJson {
            kind: "call".into(),
            from_address: 0x1000,
            to_address: 0x2000,
            from_function: None,
            to_function: Some(crate::data::kuna_json::FunctionRef {
                name: "two".into(),
                address: 0x2000,
            }),
            instruction: Some("CALL 0x2000".into()),
        }];

        let _ = app.update(Message::KunaXrefsReady(0x1000, Direction::From, Ok(xrefs)));

        assert_eq!(app.work.references.len(), 1);
        assert_eq!(app.work.references[0].label, "two");
        assert_eq!(app.work.references[0].address, 0x2000);
    }

    #[test]
    fn the_strings_reach_the_navigator_count() {
        let (_export, mut app) = kuna_app();

        let strings = vec![StringJson {
            address: 0x2006,
            text: "%ld\n".into(),
            section: Some(".rodata".into()),
            functions: vec![crate::data::kuna_json::FunctionRef {
                name: "one".into(),
                address: 0x1000,
            }],
        }];

        let _ = app.update(Message::KunaStringsReady(Ok(strings)));

        assert_eq!(app.navigator.counts.strings, 1);
    }

    #[test]
    fn a_functions_error_and_gotos_become_problems() {
        let (_export, mut app) = kuna_app();

        let function = FunctionJson {
            code: None,
            error: Some("boom".into()),
            unstructured_gotos: 1,
            line_mappings: Vec::new(),
        };

        let _ = app.update(Message::KunaFunctionReady(0x1000, Ok(function)));

        let problems = &app.bottom.problems;
        assert!(
            problems
                .iter()
                .any(|problem| problem.message.contains("boom")),
            "the error is reported"
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.message.contains("unstructured goto")),
            "the unstructured goto is reported"
        );
    }

    #[test]
    fn the_summary_reaches_the_inspector() {
        let (_export, mut app) = kuna_app();

        let summary = SummaryJson {
            total: 13,
            error: None,
            warnings: Vec::new(),
            summary: crate::data::kuna_json::SummaryBody {
                entry: Some(crate::data::kuna_json::FunctionRef {
                    name: "_start".into(),
                    address: 0x1060,
                }),
                main: Some(crate::data::kuna_json::FunctionRef {
                    name: "main".into(),
                    address: 0x1198,
                }),
                reachable_from_entry: 5,
                no_callers: 8,
                code_bytes: 500,
            },
        };

        let _ = app.update(Message::KunaSummaryReady(Ok(summary)));

        let reported = app.provider.summary().expect("a summary");
        assert_eq!(reported.functions, 13);
        assert_eq!(reported.reachable, Some(5));
        assert_eq!(reported.code_bytes, 500);
        assert_eq!(reported.main.map(|(_, address)| address), Some(0x1198));
    }

    /// The decompilation the CLI gives for the sample export's one function.
    fn one_function() -> FunctionJson {
        FunctionJson {
            code: Some("int one(void)\n{\n  return 1;\n}".into()),
            error: None,
            unstructured_gotos: 0,
            line_mappings: Vec::new(),
        }
    }

    #[test]
    fn a_cached_function_is_not_asked_about_again() {
        let (_export, mut app) = kuna_app();

        // Nothing has been answered yet, so everything is asked.
        assert_eq!(
            app.kuna_asks(0x1000),
            KunaAsks {
                decompile: true,
                xrefs_from: true,
                xrefs_to: true
            }
        );

        let _ = app.update(Message::KunaFunctionReady(0x1000, Ok(one_function())));
        let _ = app.update(Message::KunaXrefsReady(
            0x1000,
            Direction::From,
            Ok(Vec::new()),
        ));
        let _ = app.update(Message::KunaXrefsReady(
            0x1000,
            Direction::To,
            Ok(Vec::new()),
        ));

        let asks = app.kuna_asks(0x1000);
        assert!(!asks.decompile, "the decompilation is known");
        assert!(!asks.xrefs_from, "the references out are known");
        assert!(!asks.xrefs_to, "the references in are known");
    }

    #[test]
    fn each_direction_of_the_cross_references_is_asked_about_on_its_own() {
        let (_export, mut app) = kuna_app();

        // An answer of no references at all is an answer.
        let _ = app.update(Message::KunaXrefsReady(
            0x1000,
            Direction::From,
            Ok(Vec::new()),
        ));

        let asks = app.kuna_asks(0x1000);
        assert!(asks.decompile, "the decompilation is not known yet");
        assert!(!asks.xrefs_from, "the references out are known");
        assert!(asks.xrefs_to, "the references in are not known yet");
    }

    #[test]
    fn a_reload_throws_away_what_the_cli_answered() {
        let (_export, mut app) = kuna_app();

        let _ = app.update(Message::KunaFunctionReady(0x1000, Ok(one_function())));
        let _ = app.update(Message::KunaXrefsReady(
            0x1000,
            Direction::From,
            Ok(Vec::new()),
        ));

        let before = app.kuna.as_ref().expect("the kuna state").cache.clone();
        assert!(before.lock().expect("the cache").function(0x1000).is_some());

        // A reload asks the CLI again.
        let _ = app.update(Message::FileReload);

        let after = app.kuna.as_ref().expect("the kuna state").cache.clone();
        assert!(
            Arc::ptr_eq(&before, &after),
            "the reload kept the cache the answers live in"
        );
        assert!(after.lock().expect("the cache").function(0x1000).is_none());
        assert!(after
            .lock()
            .expect("the cache")
            .xrefs(0x1000, Direction::From)
            .is_none());
    }

    #[test]
    fn renaming_a_function_replaces_its_name_in_the_list() {
        let mut app = app();
        let address = 0x100084A20;
        let original = app.navigator.rows[0].name.clone();

        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditRename);
        assert_eq!(
            app.prompt.as_ref().expect("a rename prompt").kind,
            PromptKind::Rename
        );

        let _ = app.update(Message::PromptChanged("decode_frame".into()));
        let _ = app.update(Message::PromptSubmit);

        assert_eq!(app.navigator.rows[0].name, "decode_frame");
        // The provider still reports its own name; the rename is the workbench's.
        assert_eq!(app.provider.functions()[0].name, original);
    }

    #[test]
    fn renaming_back_to_the_analysis_name_clears_the_annotation() {
        let mut app = app();
        let address = 0x100084A20;
        let original = app.navigator.rows[0].name.clone();

        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode_frame".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.navigator.rows[0].name, "decode_frame");

        // Re-entering the displayed name keeps the rename…
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode_frame".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.navigator.rows[0].name, "decode_frame");

        // …and returning the analysis's own name clears it.
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged(original.clone()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.navigator.rows[0].name, original);
        assert!(app.annotations.annotations.is_empty());
    }

    #[test]
    fn a_bookmark_toggles_and_survives_a_save_and_reload() {
        let dir = std::env::temp_dir().join(format!(
            "ag-ui-project-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("bookmark.agproj");

        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));

        let _ = app.update(Message::EditBookmark);
        assert!(app
            .annotations
            .annotations
            .iter()
            .any(|a| a.bookmark && a.address == format!("{address:#x}")));

        app.save_project_to(&file);
        assert!(file.is_file());

        let read = ag_corpus::project::ProjectFile::load(&file).expect("the saved project");
        assert!(read
            .annotations
            .iter()
            .any(|a| a.bookmark && a.address == format!("{address:#x}")));

        // Toggling again clears it, and the cleared annotation is pruned.
        let _ = app.update(Message::EditBookmark);
        app.save_project_to(&file);
        let read = ag_corpus::project::ProjectFile::load(&file).expect("the saved project");
        assert!(read.annotations.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bookmarked_function_is_listed_by_its_name_and_jumps() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditBookmark);

        // The explore count is the analyst's own marks, not a provider claim.
        assert_eq!(app.annotations.bookmarks().len(), 1);

        // The place is named by the function that lives there.
        let name = app.place_name(address);
        let row = app
            .provider
            .functions()
            .into_iter()
            .find(|row| row.address == address)
            .expect("the sample has a function there");
        assert_eq!(name, row.name, "the function's own name");

        // Jumping to it opens the function.
        let _ = app.update(Message::FunctionSelected(0x100084A00));
        let _ = app.update(Message::BookmarkSelected(address));
        assert!(matches!(app.selection, Selection::Function(a) if a == address));
        assert_eq!(app.work.listing_of, Some(address));
    }

    #[test]
    fn a_bookmark_at_a_bare_address_moves_the_selection() {
        let mut app = app();
        // A place that is not a function entry: the bytes of the image, say.
        let address = 0x100084A28;
        let _ = app.update(Message::AddressSelected(address));
        let _ = app.update(Message::EditBookmark);
        assert!(app.annotations.bookmarks().iter().any(|a| a.address == format!("{address:#x}")));

        // Nothing names the place, so it is named by its address.
        assert_eq!(app.place_name(address), format!("{address:#x}"));

        // Jumping to it moves the selection rather than opening a function.
        let _ = app.update(Message::FunctionSelected(0x100084A00));
        let _ = app.update(Message::BookmarkSelected(address));
        assert!(matches!(app.selection, Selection::Address(a) if a == address));
    }

    #[test]
    fn a_named_bookmark_shows_the_analysts_name() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditBookmark);
        // Naming the place is naming its label; the bookmark shows that name.
        let _ = app.update(Message::EditRenameLabel);
        let _ = app.update(Message::PromptChanged("loop_head".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.place_name(address), "loop_head");
    }

    #[test]
    fn the_tags_prompt_records_tags_on_the_selection() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditTags);
        assert!(matches!(
            app.prompt.as_ref().map(|p| &p.kind),
            Some(PromptKind::Tags)
        ));
        let _ = app.update(Message::PromptChanged("crypto, parser  crypto".into()));
        let _ = app.update(Message::PromptSubmit);

        let key = app.annotation_key(address);
        let record = app.annotations.annotation_for(&key).expect("the record");
        assert_eq!(record.tags, ["crypto", "parser"], "sorted, unique");
        assert_eq!(record.kind, ag_corpus::project::TargetKind::Function);
        assert_eq!(
            app.notice.as_deref(),
            Some("Tagged 0x100084a20 crypto parser")
        );

        // The prompt prefills the analyst's own tags; an empty submit clears them.
        let _ = app.update(Message::EditTags);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some("crypto parser")
        );
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.annotations.annotation_for(&key).is_none(),
            "an empty record is dropped"
        );

        // A tag on a bare address is on the address, not a function.
        let bare = 0x100084A28;
        let _ = app.update(Message::AddressSelected(bare));
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("loop".into()));
        let _ = app.update(Message::PromptSubmit);
        let record = app
            .annotations
            .annotation_for(&app.annotation_key(bare))
            .expect("the record");
        assert_eq!(record.kind, ag_corpus::project::TargetKind::Address);
        assert_eq!(app.tags_at(bare), ["loop"]);
    }

    #[test]
    fn a_hash_filter_narrows_the_list_to_a_tag() {
        let mut app = app();
        let total = app.navigator.rows.len();
        let tagged = 0x100081D60;
        let _ = app.update(Message::FunctionSelected(tagged));
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("Crypto".into()));
        let _ = app.update(Message::PromptSubmit);

        // Typing the tag with a hash narrows the list. The tag is matched
        // as stored, so a different case is a different tag.
        let _ = app.update(Message::NavigatorFilterChanged("#Crypto".into()));
        assert_eq!(app.navigator.rows.len(), 1);
        assert_eq!(app.navigator.rows[0].address, tagged);
        let _ = app.update(Message::NavigatorFilterChanged("# Crypto ".into()));
        assert_eq!(app.navigator.rows.len(), 1, "the spaces around are noise");
        let _ = app.update(Message::NavigatorFilterChanged("#crypto".into()));
        assert!(app.navigator.rows.is_empty());

        // A bare hash matches nothing rather than everything.
        let _ = app.update(Message::NavigatorFilterChanged("#".into()));
        assert!(app.navigator.rows.is_empty());

        // Clearing the filter brings the list back.
        let _ = app.update(Message::NavigatorFilterChanged(String::new()));
        assert_eq!(app.navigator.rows.len(), total);

        // Picking a tag from the Tags section does the same as typing it,
        // and lands on the function list.
        let _ = app.update(Message::SectionSelected(Section::Bookmarks));
        let _ = app.update(Message::TagSelected("Crypto".into()));
        assert_eq!(app.navigator.filter, "#Crypto");
        assert_eq!(app.navigator.section, Section::Functions);
        assert_eq!(app.navigator.rows.len(), 1);
    }

    #[test]
    fn the_analysis_tags_its_entry_point_and_objective_c_classes() {
        let row = |name: &str, address: u64, objc: bool| FunctionRow {
            address,
            space: None,
            name: name.into(),
            status: String::new(),
            size: None,
            objc,
        };
        assert_eq!(
            automatic_tags(&row("_start", 0x1000, false), Some(0x1000)),
            ["entry"]
        );
        assert!(automatic_tags(&row("main", 0x1100, false), Some(0x1000)).is_empty());
        assert!(automatic_tags(&row("main", 0x1100, false), None).is_empty());
        assert_eq!(
            automatic_tags(&row("-[SignalService decryptMessage:]", 0x2000, true), None),
            ["objc:SignalService"]
        );
        assert_eq!(
            automatic_tags(&row("+[NSString(Hex) fromHex:]", 0x2000, true), None),
            ["objc:NSString"]
        );
        // A name the method map gave that is not a method has no class.
        assert!(automatic_tags(&row("sub_2000", 0x2000, true), None).is_empty());

        // The sample's Objective-C method shows up in the index, filters the
        // list, and is one tag on one place when the analyst gives it too.
        let mut app = app();
        let one_function = TagCount {
            functions: 1,
            places: 0,
        };
        assert_eq!(
            app.navigator.tags.get("objc:SignalService"),
            Some(&one_function),
            "{:?}",
            app.navigator.tags
        );
        assert_eq!(app.tags_at(0x100084A20), ["objc:SignalService"]);
        let _ = app.update(Message::NavigatorFilterChanged(
            "#objc:SignalService".into(),
        ));
        assert_eq!(app.navigator.rows.len(), 1);
        assert_eq!(app.navigator.rows[0].address, 0x100084A20);

        let _ = app.update(Message::FunctionSelected(0x100084A20));
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("objc:SignalService".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.navigator.tags.get("objc:SignalService"),
            Some(&one_function)
        );
        assert_eq!(app.tags_at(0x100084A20), ["objc:SignalService"]);
    }

    #[test]
    fn the_tag_index_tells_functions_from_other_places() {
        let mut app = app();
        // The same tag on a function and on a bare address: the section
        // says one function, and one place the list cannot show.
        let _ = app.update(Message::FunctionSelected(0x100081D60));
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("loop".into()));
        let _ = app.update(Message::PromptSubmit);
        let _ = app.update(Message::AddressSelected(0x100084A28));
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("loop".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.navigator.tags.get("loop"),
            Some(&TagCount {
                functions: 1,
                places: 1
            })
        );
        let _ = app.update(Message::TagSelected("loop".into()));
        assert_eq!(
            app.navigator.rows.len(),
            1,
            "the function; the address has no row"
        );

        // Two cases are two tags, each on its own place.
        let _ = app.update(Message::FunctionSelected(0x100084A20));
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("Loop".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.navigator.tags.get("Loop").map(|c| c.functions), Some(1));
        assert_eq!(app.navigator.tags.get("loop").map(|c| c.functions), Some(1));
        let _ = app.update(Message::TagSelected("Loop".into()));
        assert_eq!(app.navigator.rows.len(), 1);
        assert_eq!(app.navigator.rows[0].address, 0x100084A20);
    }

    #[test]
    fn a_highlight_is_recorded_as_a_normalized_color() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditColor);
        assert!(matches!(
            app.prompt.as_ref().map(|p| &p.kind),
            Some(PromptKind::Color { block: false })
        ));
        let _ = app.update(Message::PromptChanged("Red".into()));
        let _ = app.update(Message::PromptSubmit);

        let key = app.annotation_key(address);
        let record = app.annotations.annotation_for(&key).expect("the record");
        assert_eq!(record.color.as_deref(), Some("#e07a6a"), "the name's value");
        assert_eq!(record.kind, ag_corpus::project::TargetKind::Function);

        // A function's color reaches every line of it, its entry included.
        let renamed = app.renames();
        assert!(renamed.function_color().is_some());
        assert!(renamed.line_color(address + 8, None).is_some());
        assert_eq!(renamed.address_color(address), renamed.function_color());

        // A comment on the entry leaves the function's color reaching.
        let _ = app.update(Message::EditComment);
        let _ = app.update(Message::PromptChanged("the entry".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.renames().function_color().is_some(),
            "a comment is not a relabel"
        );
        assert_eq!(
            app.annotations.annotation_for(&key).map(|a| a.kind),
            Some(ag_corpus::project::TargetKind::Function)
        );
        let _ = app.update(Message::EditComment);
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);

        // The prompt prefills the color; a hex value is normalized; a typo
        // is refused and changes nothing.
        let _ = app.update(Message::EditColor);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some("#e07a6a")
        );
        let _ = app.update(Message::PromptChanged("#ABC".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.annotations
                .annotation_for(&key)
                .and_then(|a| a.color.clone())
                .as_deref(),
            Some("#aabbcc")
        );
        let _ = app.update(Message::EditColor);
        let _ = app.update(Message::PromptChanged("blurple".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Not a color")));
        assert_eq!(
            app.annotations
                .annotation_for(&key)
                .and_then(|a| a.color.clone())
                .as_deref(),
            Some("#aabbcc")
        );

        // An empty submit clears it, and the empty record goes with it.
        let _ = app.update(Message::EditColor);
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.annotation_for(&key).is_none());
        assert!(app.renames().function_color().is_none());
    }

    #[test]
    fn a_block_highlight_reaches_every_line_of_the_block() {
        let mut app = app();
        let function = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(function));
        let inside = 0x100084A28;
        let from = app
            .block_of(inside)
            .expect("the sample's graph holds the address");
        let _ = app.update(Message::AddressSelected(inside));
        let _ = app.update(Message::EditColorBlock);
        let _ = app.update(Message::PromptChanged("green".into()));
        let _ = app.update(Message::PromptSubmit);

        let record = app
            .annotations
            .block_for(&app.annotation_key(from))
            .expect("the block's record");
        assert_eq!(record.kind, ag_corpus::project::TargetKind::Region);
        assert_eq!(record.color.as_deref(), Some("#8bcf9c"));

        let renamed = app.renames();
        assert!(renamed.block_color(from).is_some());
        assert!(renamed.line_color(inside, Some(from)).is_some());
        assert!(
            renamed.line_color(inside, None).is_none(),
            "not the line's own"
        );

        // A line's own color wins over its block's.
        let _ = app.update(Message::EditColor);
        let _ = app.update(Message::PromptChanged("red".into()));
        let _ = app.update(Message::PromptSubmit);
        let renamed = app.renames();
        let own = renamed.address_color(inside).expect("the line's color");
        assert_eq!(renamed.line_color(inside, Some(from)), Some(own));
        assert_ne!(renamed.block_color(from), Some(own));
    }

    #[test]
    fn a_pane_cycles_through_the_levels_of_the_lift_and_back() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        // sum_to: a counted loop, four chains.
        let _ = app.update(Message::FunctionSelected(0x1161));
        let disassembly = app.work.listing.clone();
        assert!(disassembly.iter().any(|line| line.mnemonic == "cmp"));
        let _ = app.update(Message::ViewTabSelected(ViewTab::Listing));

        // F7: the lifted level, then low, medium, high, and back.
        let _ = app.update(Message::ViewCycleLevel);
        assert_eq!(
            app.work.listing_level,
            PaneLevel::Il {
                level: ag_image::Level::Lifted,
                ssa: false
            }
        );
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("lifted IL")));
        assert!(app
            .work
            .listing
            .iter()
            .any(|line| line.operands.contains("cmp eax,[rbp-14h]")));
        let _ = app.update(Message::ViewCycleLevel);
        let _ = app.update(Message::ViewCycleLevel);
        assert_eq!(
            app.work.listing_level,
            PaneLevel::Il {
                level: ag_image::Level::Medium,
                ssa: false
            }
        );
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands == "local_14 = 1"),
            "{:?}",
            app.work.listing
        );
        // The rows carry the addresses the statements came from, so the
        // selection and the block lookups still work.
        assert!(app
            .work
            .listing
            .iter()
            .all(|line| (0x1161..0x1198).contains(&line.address)));
        // The graph pane keeps the disassembly until its own level is set.
        assert!(app
            .work
            .graph
            .blocks
            .iter()
            .any(|b| b.instructions.iter().any(|l| l.mnemonic == "cmp")));
        // Shift+F7: SSA form.
        let _ = app.update(Message::ViewToggleSsa);
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.contains("local_14#1 = 1")),
            "{:?}",
            app.work.listing
        );
        assert!(app
            .work
            .listing
            .iter()
            .any(|line| line.operands.contains("φ(")));
        let _ = app.update(Message::ViewCycleLevel);
        assert!(matches!(
            app.work.listing_level,
            PaneLevel::Il {
                level: ag_image::Level::High,
                ssa: true
            }
        ));
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.starts_with("for (")),
            "{:?}",
            app.work.listing
        );
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.starts_with("    local_10")),
            "depth indents"
        );
        let _ = app.update(Message::ViewCycleLevel);
        assert_eq!(app.work.listing_level, PaneLevel::Disassembly);
        assert_eq!(app.work.listing.len(), disassembly.len());

        // The graph pane has its own level: four chains at the medium level.
        let _ = app.update(Message::ViewTabSelected(ViewTab::Graph));
        for _ in 0..3 {
            let _ = app.update(Message::ViewCycleLevel);
        }
        assert_eq!(
            app.work.graph_level,
            PaneLevel::Il {
                level: ag_image::Level::Medium,
                ssa: false
            }
        );
        assert_eq!(app.work.shown_graph().blocks.len(), 4);
        assert!(
            app.work.shown_graph().edges.len() >= 4,
            "{:?}",
            app.work.shown_graph().edges
        );
        assert!(app.work.shown_graph().blocks.iter().any(|b| b
            .instructions
            .iter()
            .any(|l| l.operands.starts_with("if ("))));
        // The disassembly's graph is kept for the arrows and the block
        // lookups, and the level's edges know a fall-through from a jump.
        assert!(app.work.il_graph.is_some());
        assert!(app
            .work
            .graph
            .blocks
            .iter()
            .any(|b| b.instructions.iter().any(|l| l.mnemonic == "cmp")));
        assert!(
            app.work
                .shown_graph()
                .edges
                .iter()
                .any(|e| matches!(e.kind, ag_image::EdgeKind::Fallthrough)),
            "{:?}",
            app.work.shown_graph().edges
        );
        assert!(app
            .work
            .shown_graph()
            .edges
            .iter()
            .any(|e| matches!(e.kind, ag_image::EdgeKind::Taken)));
        assert_eq!(
            app.block_of(0x118a),
            Some(0x118a),
            "the block lookup is the disassembly's"
        );
        // The level follows the function: another function at the same level.
        let _ = app.update(Message::FunctionSelected(0x1149));
        assert_eq!(app.work.shown_graph().blocks.len(), 1);
        assert!(app.work.shown_graph().blocks[0]
            .instructions
            .iter()
            .any(|l| l.operands.contains("return")));
        // A function the lifter does not read shows the disassembly and says
        // so; the pane keeps its level for the next function.
        let _ = app.update(Message::FunctionSelected(0x1060));
        assert_eq!(app.work.graph_shown, PaneLevel::Disassembly);
        assert!(matches!(app.work.graph_level, PaneLevel::Il { .. }));
        assert!(app.work.il_graph.is_none());
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("showing the disassembly")),
            "{:?}",
            app.notice
        );
        let _ = app.update(Message::FunctionSelected(0x1161));
        assert_eq!(app.work.graph_shown, app.work.graph_level);
        // Other panes have no level to cycle.
        let _ = app.update(Message::ViewTabSelected(ViewTab::Bytes));
        let _ = app.update(Message::ViewCycleLevel);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("Listing and Graph")));

        // The shortcuts.
        let named = |key: keyboard::key::Named, modifiers: keyboard::Modifiers| {
            keyboard::Event::KeyPressed {
                key: Key::Named(key),
                modified_key: Key::Named(key),
                physical_key: keyboard::key::Physical::Code(keyboard::key::Code::F7),
                location: keyboard::Location::Standard,
                modifiers,
                text: None,
                repeat: false,
            }
        };
        assert!(matches!(
            shortcut(named(
                keyboard::key::Named::F7,
                keyboard::Modifiers::empty()
            )),
            Message::ViewCycleLevel
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F7, keyboard::Modifiers::SHIFT)),
            Message::ViewToggleSsa
        ));
        assert_eq!(
            PaneLevel::Disassembly
                .cycled()
                .cycled()
                .cycled()
                .cycled()
                .cycled(),
            PaneLevel::Disassembly
        );
    }

    #[test]
    fn the_level_options_decorate_the_rows_and_the_casts_spell_the_constants() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1161));
        let _ = app.update(Message::ViewTabSelected(ViewTab::Listing));
        for _ in 0..3 {
            let _ = app.update(Message::ViewCycleLevel);
        }
        let plain = app.work.listing.clone();
        assert!(
            plain.iter().any(|line| line.operands == "local_14 = 1"),
            "{plain:?}"
        );
        let _ = app.update(Message::ViewToggleIlOption(IlOption::Opcodes));
        assert!(app.work.il_option(IlOption::Opcodes));
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Opcodes: on")));
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands == "[assign] local_14 = 1"),
            "{:?}",
            app.work.listing
        );
        let _ = app.update(Message::ViewToggleIlOption(IlOption::Types));
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.contains("; types: local_14: int")),
            "{:?}",
            app.work.listing
        );
        let _ = app.update(Message::ViewToggleIlOption(IlOption::StackPointer));
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.contains("; sp = entry-0x")),
            "{:?}",
            app.work.listing
        );
        let _ = app.update(Message::ViewToggleIlOption(IlOption::Casts));
        assert!(app.work.casts);
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.contains("local_14 = (int)1")),
            "{:?}",
            app.work.listing
        );
        // Off again: the rows are as they were.
        for option in [
            IlOption::Opcodes,
            IlOption::Types,
            IlOption::StackPointer,
            IlOption::Casts,
        ] {
            let _ = app.update(Message::ViewToggleIlOption(option));
        }
        assert_eq!(app.work.listing.len(), plain.len());
        assert!(app
            .work
            .listing
            .iter()
            .any(|line| line.operands == "local_14 = 1"));
        // The flags are the lifted level's: high, the disassembly, lifted.
        for _ in 0..3 {
            let _ = app.update(Message::ViewCycleLevel);
        }
        assert!(matches!(
            app.work.listing_level,
            PaneLevel::Il {
                level: ag_image::Level::Lifted,
                ..
            }
        ));
        let _ = app.update(Message::ViewToggleIlOption(IlOption::Flags));
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.starts_with("cmp ")
                    && line.operands.contains("flags: reads none, writes")
                    && line.operands.contains("ZF")),
            "{:?}",
            app.work.listing
        );
        let _ = app.update(Message::ViewToggleIlOption(IlOption::Opcodes));
        assert!(
            app.work
                .listing
                .iter()
                .any(|line| line.operands.starts_with("[Cmp_")),
            "{:?}",
            app.work.listing
        );
        assert_eq!(IlOption::ALL.len(), 5);
    }

    #[test]
    fn the_margins_arrows_follow_the_disassembly_and_stop_at_the_statement_levels() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1161));
        let _ = app.update(Message::ViewTabSelected(ViewTab::Listing));
        let renamed = app.renames();
        let rows = crate::views::work_surface::listing_rows(&app.work.listing, &renamed);
        let plain = crate::views::work_surface::arrows_for(&app, &rows);
        assert!(!plain.arrows.is_empty());
        // The lifted level is the instructions, one row each: the arrows stand.
        let _ = app.update(Message::ViewCycleLevel);
        let rows = crate::views::work_surface::listing_rows(&app.work.listing, &renamed);
        let lifted = crate::views::work_surface::arrows_for(&app, &rows);
        assert_eq!(lifted.arrows.len(), plain.arrows.len());
        // The statement levels share addresses between rows: no arrows, and
        // the rows are still counted one per line.
        let _ = app.update(Message::ViewCycleLevel);
        let rows = crate::views::work_surface::listing_rows(&app.work.listing, &renamed);
        assert_eq!(rows.len(), app.work.listing.len());
        assert!(crate::views::work_surface::arrows_for(&app, &rows)
            .arrows
            .is_empty());
        // A branch target with several rows lands on the first of them.
        let first = crate::views::arrows::Arrows::of(
            &[Some(0x10), Some(0x10), Some(0x20), Some(0x20)],
            &Graph {
                blocks: vec![
                    GraphBlock {
                        from: 0x10,
                        to: 0x20,
                        successors: vec![0x20],
                        instructions: vec![ListingLine {
                            address: 0x10,
                            ..Default::default()
                        }],
                    },
                    GraphBlock {
                        from: 0x20,
                        to: 0x30,
                        successors: vec![0x10],
                        instructions: vec![ListingLine {
                            address: 0x20,
                            ..Default::default()
                        }],
                    },
                ],
                edges: vec![ag_image::Edge {
                    from: 0x20,
                    to: 0x10,
                    kind: ag_image::EdgeKind::Taken,
                }],
            },
            &[],
        );
        assert_eq!(first.arrows.len(), 1);
        assert_eq!(first.arrows[0].to, Some(0));
    }

    #[test]
    fn a_function_the_lifter_refuses_keeps_the_disassembly_in_its_panes() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        // _start is not lifted (it ends in hlt): the level cannot be set.
        let _ = app.update(Message::FunctionSelected(0x1060));
        let before = app.work.listing.len();
        let _ = app.update(Message::ViewCycleLevel);
        assert_eq!(app.work.listing_level, PaneLevel::Disassembly);
        assert_eq!(app.work.listing.len(), before);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("no levels")),
            "{:?}",
            app.notice
        );
    }

    #[test]
    fn breakpoints_are_toggled_at_the_selection_and_kept_without_a_debugger() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1149));
        let _ = app.update(Message::AddressSelected(0x114d));
        let _ = app.update(Message::DebugToggleBreakpoint(None));
        assert!(app.debug.breakpoints.contains(&0x114d));
        assert_eq!(app.notice.as_deref(), Some("Breakpoint at 0x114d"));
        let _ = app.update(Message::DebugToggleBreakpoint(Some(0x1198)));
        assert_eq!(app.debug.breakpoints.len(), 2);
        let _ = app.update(Message::DebugToggleBreakpoint(None));
        assert!(!app.debug.breakpoints.contains(&0x114d));
        assert_eq!(app.debug.breakpoints.len(), 1);
        // The controls that need a program under the debugger say so.
        let _ = app.update(Message::DebugContinue);
        assert_eq!(
            app.notice.as_deref(),
            Some("The program is not stopped under the debugger")
        );
        let _ = app.update(Message::DebugStop);
        assert_eq!(app.notice.as_deref(), Some("No debugger is running"));
        // The shortcuts.
        let named = |key: keyboard::key::Named, modifiers: keyboard::Modifiers| {
            keyboard::Event::KeyPressed {
                key: Key::Named(key),
                modified_key: Key::Named(key),
                physical_key: keyboard::key::Physical::Code(keyboard::key::Code::F9),
                location: keyboard::Location::Standard,
                modifiers,
                text: None,
                repeat: false,
            }
        };
        let none = keyboard::Modifiers::empty();
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F9, none)),
            Message::DebugToggleBreakpoint(None)
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F10, none)),
            Message::DebugNext
        ));
        assert!(matches!(
            shortcut(named(keyboard::key::Named::F11, keyboard::Modifiers::SHIFT)),
            Message::DebugFinish
        ));
    }

    #[test]
    fn a_scripted_debugger_stops_at_a_breakpoint_and_the_listing_follows() {
        use ag_debug::fake::Scripted;
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1198));
        let _ = app.update(Message::DebugToggleBreakpoint(Some(0x1149)));

        let scripted = Scripted::new();
        let sent = scripted.sent();
        scripted.answer("-gdb-set mi-async on", &["^done"]);
        scripted.answer("-file-exec-and-symbols", &["^done"]);
        scripted.answer(
            "-interpreter-exec console \"starti\"",
            &[
                "^running",
                "*running,thread-id=\"all\"",
                "*stopped,reason=\"signal-received\",frame={addr=\"0x00007ffff7fe3340\",func=\"_start\"},thread-id=\"1\"",
            ],
        );
        scripted.answer(
            "-interpreter-exec console \"info proc mappings\"",
            &[
                "~\"0x0000555555554000 0x0000555555555000 0x1000             0x0                r--p  /x/sample.elf \\n\"",
                "^done",
            ],
        );
        scripted.answer(
            "-break-insert *0x555555555149",
            &["^done,bkpt={number=\"1\",addr=\"0x0000555555555149\"}"],
        );
        scripted.answer(
            "-exec-continue",
            &["^running", "*running,thread-id=\"all\""],
        );
        scripted.answer(
            "-data-list-register-names",
            &["^done,register-names=[\"rax\",\"rip\"]"],
        );
        scripted.answer(
            "-data-list-register-values x",
            &["^done,register-values=[{number=\"0\",value=\"0x2a\"},{number=\"1\",value=\"0x555555555149\"}]"],
        );
        scripted.answer(
            "-stack-list-frames",
            &["^done,stack=[frame={level=\"0\",addr=\"0x0000555555555149\",func=\"add\"},frame={level=\"1\",addr=\"0x00005555555551ba\",func=\"main\"}]"],
        );
        scripted.answer(
            "-data-read-memory-bytes",
            &["^done,memory=[{begin=\"0x0\",offset=\"0x0\",end=\"0x4\",contents=\"f30f1efa\"}]"],
        );
        scripted.answer("-exec-abort", &["^done"]);
        let mut session =
            ag_debug::Session::with_transport(Box::new(scripted.clone()), &sample_elf(), 0);
        session.hello().expect("the scripted debugger says hello");
        app.debug.session = Some(session);

        // Start: the pending breakpoint is set under the slide, the program
        // stands at its first instruction, outside the image.
        let _ = app.update(Message::DebugStart);
        assert_eq!(
            app.debug.status,
            crate::debug::Status::Stopped,
            "{:?}",
            app.notice
        );
        assert!(sent
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.ends_with("-break-insert *0x555555555149")));
        assert_eq!(app.work.lower, LowerTab::Debug);
        assert_eq!(app.debug.pc, None);

        // Continue: running, until the breakpoint is hit.
        let _ = app.update(Message::DebugContinue);
        assert_eq!(app.debug.status, crate::debug::Status::Running);
        scripted.push_line(
            "*stopped,reason=\"breakpoint-hit\",disp=\"keep\",bkptno=\"1\",frame={addr=\"0x0000555555555149\",func=\"add\"},thread-id=\"1\"",
        );
        let _ = app.update(Message::DebugPoll);
        assert_eq!(app.debug.status, crate::debug::Status::Stopped);
        assert_eq!(app.debug.pc, Some(0x1149));
        // The listing followed: the function, and the instruction.
        assert_eq!(app.work.listing_of, Some(0x1149));
        assert_eq!(app.selection, Selection::Address(0x1149));
        assert_eq!(
            app.debug.registers,
            [
                ("rax".to_string(), 0x2a),
                ("rip".to_string(), 0x555555555149)
            ]
        );
        assert_eq!(app.debug.frames.len(), 2);
        assert_eq!(app.debug.frames[1].pc, 0x11ba);
        assert_eq!(app.debug.memory, [0xf3, 0x0f, 0x1e, 0xfa]);
        assert_eq!(app.debug.memory_at, Some(0x1149));
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("breakpoint-hit")));

        // A breakpoint set while stopped reaches the debugger at once.
        scripted.answer(
            "-break-insert *0x5555555551a4",
            &["^done,bkpt={number=\"2\",addr=\"0x00005555555551a4\"}"],
        );
        let _ = app.update(Message::DebugToggleBreakpoint(Some(0x11a4)));
        assert!(sent
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.ends_with("-break-insert *0x5555555551a4")));

        // The program ends.
        let _ = app.update(Message::DebugContinue);
        scripted.push_line("*stopped,reason=\"exited\",exit-code=\"012\"");
        let _ = app.update(Message::DebugPoll);
        assert_eq!(app.debug.status, crate::debug::Status::Exited(Some(10)));
        assert_eq!(app.debug.pc, None);
        assert_eq!(
            app.notice.as_deref(),
            Some("The program exited with code 10")
        );
        // The breakpoints outlive the session.
        let _ = app.update(Message::DebugStop);
        assert_eq!(app.debug.status, crate::debug::Status::Off);
        assert_eq!(app.debug.breakpoints.len(), 2);
    }

    #[test]
    fn the_graph_is_exported_as_the_picture_the_extension_names() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        // The program opens on its entry, so there is a graph to export
        // from the first; the prompt is put away for the function chosen.
        let _ = app.update(Message::FileExportGraph);
        assert!(app.prompt.is_some(), "{:?}", app.notice);
        let _ = app.update(Message::PromptCancel);
        let main = app
            .provider
            .functions()
            .into_iter()
            .find(|row| row.name == "main")
            .map(|row| row.address)
            .expect("main");
        let _ = app.update(Message::FunctionSelected(main));
        let _ = app.update(Message::AddressSelected(main));
        let _ = app.update(Message::ViewTabSelected(ViewTab::Graph));
        let blocks = app.work.graph.blocks.len();
        assert!(blocks > 0);

        // The prompt offers a path beside the program, named for the
        // function.
        let _ = app.update(Message::FileExportGraph);
        let offered = app
            .prompt
            .as_ref()
            .map(|p| p.value.clone())
            .expect("a prompt");
        assert!(offered.ends_with("main.svg"), "{offered}");
        assert_eq!(
            Path::new(&offered).parent(),
            sample_elf().parent(),
            "{offered}"
        );

        let stem = std::env::temp_dir().join(format!(
            "ag-ui-export-graph-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let svg = stem.with_extension("svg");
        let pdf = stem.with_extension("pdf");
        let txt = stem.with_extension("txt");
        let _ = std::fs::remove_file(&svg);
        let _ = std::fs::remove_file(&pdf);

        // An extension that names no picture is refused.
        let _ = app.update(Message::PromptChanged(txt.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.ends_with("is neither a .svg nor a .pdf path")),
            "{:?}",
            app.notice
        );
        assert!(!txt.exists());

        // The SVG holds a box per block; the PDF is a PDF.
        let _ = app.update(Message::FileExportGraph);
        let _ = app.update(Message::PromptChanged(svg.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.starts_with("Wrote ")),
            "{:?}",
            app.notice
        );
        let text = std::fs::read_to_string(&svg).expect("the SVG");
        assert_eq!(text.matches("<rect x=").count(), blocks, "{text}");
        assert!(text.contains("<title>main at "), "{text}");

        let _ = app.update(Message::FileExportGraph);
        let _ = app.update(Message::PromptChanged(pdf.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        let bytes = std::fs::read(&pdf).expect("the PDF");
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));

        // A file already there takes a second submit of the same path,
        // and is then written over.
        std::fs::write(&svg, b"not a picture").expect("the sentinel");
        let _ = app.update(Message::FileExportGraph);
        let _ = app.update(Message::PromptChanged(svg.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.ends_with("submit again to write over it")),
            "{:?}",
            app.notice
        );
        assert!(app.prompt.is_some());
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Wrote ")));
        let again = std::fs::read_to_string(&svg).expect("the SVG");
        assert!(again.starts_with("<svg"), "{again}");
        assert_eq!(again, text);

        // The program itself is never the target.
        let _ = app.update(Message::FileExportGraph);
        let _ = app.update(Message::PromptChanged(
            sample_elf().with_extension("svg").display().to_string(),
        ));
        // A path beside the program with a picture's extension is fine;
        // the program's own path is refused before any extension check.
        let _ = app.update(Message::PromptCancel);
        let _ = app.update(Message::FileExportGraph);
        let _ = app.update(Message::PromptChanged(sample_elf().display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.ends_with("is the program itself")),
            "{:?}",
            app.notice
        );

        let _ = std::fs::remove_file(&svg);
        let _ = std::fs::remove_file(&pdf);
    }

    #[test]
    fn the_listings_branches_are_arrows_to_their_targets_rows() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        // register_tm_clones: two forward jumps to the return at 0x10f8,
        // from 0x10e2 and 0x10ee.
        let _ = app.update(Message::FunctionSelected(0x10c0));
        assert!(!app.work.listing.is_empty());
        let renamed = app.renames();
        let rows = crate::views::work_surface::listing_rows(&app.work.listing, &renamed);
        let arrows = crate::views::arrows::Arrows::of(&rows, &app.work.graph, &app.work.listing);
        let mut jumps: Vec<(u64, u64)> = arrows
            .arrows
            .iter()
            .map(|arrow| (arrow.source, arrow.target))
            .collect();
        jumps.sort_unstable();
        assert_eq!(jumps, [(0x10e2, 0x10f8), (0x10ee, 0x10f8)]);
        let target_row = rows.iter().position(|row| *row == Some(0x10f8));
        for arrow in &arrows.arrows {
            assert_eq!(arrow.to, target_row);
            assert_eq!(rows[arrow.from], Some(arrow.source));
            assert!(arrow.to > Some(arrow.from));
        }
        // The two overlap, so they take two lanes; the shorter one, from
        // 0x10ee, is nearest the text.
        assert_eq!(arrows.lanes, 2);
        let far_from = arrows
            .arrows
            .iter()
            .find(|arrow| arrow.source == 0x10e2)
            .expect("the far jump")
            .from;
        let near = arrows
            .arrows
            .iter()
            .find(|arrow| arrow.source == 0x10ee)
            .expect("the near jump");
        assert_eq!(near.lane, 0);
        let near_from = near.from;

        // A comment above an instruction between the far jump and the near
        // one adds a row: the far jump's row stays, the near jump's and the
        // target's move down by one.
        let _ = app.update(Message::AddressSelected(0x10e4));
        let _ = app.update(Message::EditCommentAbove);
        let _ = app.update(Message::PromptChanged("the second check".into()));
        let _ = app.update(Message::PromptSubmit);
        let renamed = app.renames();
        assert!(renamed
            .comment_for(0x10e4)
            .is_some_and(|comment| comment.above));
        let rows = crate::views::work_surface::listing_rows(&app.work.listing, &renamed);
        assert_eq!(rows.iter().filter(|row| row.is_none()).count(), 1);
        let again = crate::views::arrows::Arrows::of(&rows, &app.work.graph, &app.work.listing);
        let far = again
            .arrows
            .iter()
            .find(|arrow| arrow.source == 0x10e2)
            .expect("the far jump");
        let near = again
            .arrows
            .iter()
            .find(|arrow| arrow.source == 0x10ee)
            .expect("the near jump");
        assert_eq!(far.from, far_from);
        assert_eq!(near.from, near_from + 1);
        assert_eq!(far.to, target_row.map(|row| row + 1));
        assert_eq!(near.to, far.to);

        // frame_dummy ends in a tail jump to register_tm_clones: a jump out
        // of the function, with no row to arrive at.
        let _ = app.update(Message::FunctionSelected(0x1140));
        let renamed = app.renames();
        let rows = crate::views::work_surface::listing_rows(&app.work.listing, &renamed);
        let tail = crate::views::arrows::Arrows::of(&rows, &app.work.graph, &app.work.listing);
        assert!(app.work.listing.iter().any(|line| line.tail), "a tail call");
        assert_eq!(tail.arrows.len(), 1, "{:?}", tail.arrows);
        assert_eq!(tail.arrows[0].to, None);
        assert_eq!(tail.arrows[0].target, 0x10c0);
        assert_eq!(rows[tail.arrows[0].from], Some(tail.arrows[0].source));
    }

    #[test]
    fn block_text_and_a_group_are_recorded_on_the_block_and_drawn() {
        let mut app = app();
        let function = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(function));
        let inside = 0x100084A28;
        let from = app
            .block_of(inside)
            .expect("the sample's graph holds the address");
        let _ = app.update(Message::AddressSelected(inside));

        // The text goes on the block's record, and titles the node.
        let _ = app.update(Message::EditBlockText);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some(""));
        let _ = app.update(Message::PromptChanged("check the flag".into()));
        let _ = app.update(Message::PromptSubmit);
        let record = app
            .annotations
            .block_for(&app.annotation_key(from))
            .expect("the block's record");
        assert!(record.block);
        assert_eq!(record.label.as_deref(), Some("check the flag"));
        let layout = crate::views::graph::layout(&app.work.graph, &app.renames());
        let node = layout
            .nodes
            .iter()
            .find(|node| node.from == from)
            .expect("the block's node");
        assert_eq!(node.label.as_deref(), Some("check the flag"));
        // The prompt offers the text again; emptied, it is cleared.
        let _ = app.update(Message::EditBlockText);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some("check the flag")
        );
        let _ = app.update(Message::PromptChanged("".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .annotations
            .block_for(&app.annotation_key(from))
            .and_then(|a| a.label.clone())
            .is_none());

        // A group: the block and another are one node.
        let before = crate::views::graph::layout(&app.work.graph, &app.renames())
            .nodes
            .len();
        let other = app
            .work
            .graph
            .blocks
            .iter()
            .map(|block| block.from)
            .find(|start| *start != from)
            .expect("another block");
        for start in [from, other] {
            let _ = app.update(Message::AddressSelected(start));
            let _ = app.update(Message::EditGroup);
            let _ = app.update(Message::PromptChanged("setup".into()));
            let _ = app.update(Message::PromptSubmit);
        }
        let layout = crate::views::graph::layout(&app.work.graph, &app.renames());
        assert_eq!(layout.nodes.len(), before - 1);
        let group = layout
            .nodes
            .iter()
            .find(|node| node.group.is_some())
            .expect("the group node");
        assert_eq!(group.group, Some(("setup".to_string(), 2)));
        assert_eq!(group.from, from.min(other));
        // The project file carries both.
        let json = serde_json::to_string(&app.annotations).expect("serializes");
        assert!(json.contains("\"group\":\"setup\""), "{json}");
    }

    #[test]
    fn the_arrow_keys_walk_the_graph_while_it_is_open() {
        let mut app = app();
        let function = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(function));
        let entry = app.block_of(function).expect("the entry block");
        // The keys do nothing in another tab, or while a prompt is open.
        let _ = app.update(Message::GraphMove(crate::views::graph::Direction::Down));
        assert_eq!(app.selection.address(), Some(function));
        let _ = app.update(Message::ViewTabSelected(ViewTab::Graph));
        let _ = app.update(Message::EditBlockText);
        let _ = app.update(Message::GraphMove(crate::views::graph::Direction::Down));
        assert_eq!(app.selection.address(), Some(function));
        let _ = app.update(Message::PromptCancel);
        // Down leaves the entry for the block it goes on to.
        let _ = app.update(Message::GraphMove(crate::views::graph::Direction::Down));
        let moved = app.selection.address().expect("a selection");
        assert_ne!(moved, entry);
        assert!(app
            .work
            .graph
            .blocks
            .iter()
            .any(|block| block.from == moved));
        // Up comes back.
        let _ = app.update(Message::GraphMove(crate::views::graph::Direction::Up));
        assert_eq!(app.selection.address(), Some(entry));
    }

    #[test]
    fn the_entry_block_and_the_function_keep_their_own_colors() {
        let mut app = app();
        let function = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(function));
        assert_eq!(
            app.block_of(function),
            Some(function),
            "the entry starts a block"
        );

        let _ = app.update(Message::EditColor);
        let _ = app.update(Message::PromptChanged("red".into()));
        let _ = app.update(Message::PromptSubmit);

        // The block prompt does not prefill the function's color: the block
        // has none yet.
        let _ = app.update(Message::EditColorBlock);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some(""));
        let _ = app.update(Message::PromptChanged("green".into()));
        let _ = app.update(Message::PromptSubmit);

        let renamed = app.renames();
        let red = crate::theme::hex_color("#e07a6a");
        let green = crate::theme::hex_color("#8bcf9c");
        assert_eq!(renamed.function_color(), red);
        assert_eq!(renamed.block_color(function), green);
        // The nearest mark wins: the entry line is the function's color,
        // a later line of the entry block the block's.
        assert_eq!(renamed.line_color(function, Some(function)), red);
        assert_eq!(renamed.line_color(function + 8, Some(function)), green);

        // Clearing the block's color leaves the function's.
        let _ = app.update(Message::EditColorBlock);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some("#8bcf9c")
        );
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);
        let renamed = app.renames();
        assert_eq!(renamed.function_color(), red);
        assert_eq!(renamed.block_color(function), None);
    }

    #[test]
    fn every_analyst_change_is_undone_and_redone_in_order() {
        let mut app = app();
        let address = 0x100084A20;
        let key = app.annotation_key(address);
        let _ = app.update(Message::FunctionSelected(address));

        // Nothing yet.
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.notice.as_deref(), Some("Nothing to undo"));

        // Three changes: a rename, a bookmark, a comment.
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decrypt".into()));
        let _ = app.update(Message::PromptSubmit);
        let _ = app.update(Message::EditBookmark);
        let _ = app.update(Message::EditComment);
        let _ = app.update(Message::PromptChanged("careful".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.undo.len(), 3);
        assert_eq!(app.undo[0].label, format!("Renamed {key}"));
        let record = |app: &App| app.annotations.annotation_for(&key).cloned();
        assert_eq!(
            record(&app).and_then(|a| a.comment).as_deref(),
            Some("careful")
        );

        // Undo walks back one at a time, and the list follows.
        let _ = app.update(Message::EditUndo);
        assert_eq!(
            app.notice.as_deref(),
            Some(&*format!("Undid: Commented {key}"))
        );
        assert!(record(&app).and_then(|a| a.comment).is_none());
        assert!(record(&app).is_some_and(|a| a.bookmark));
        let _ = app.update(Message::EditUndo);
        assert!(record(&app).is_some_and(|a| !a.bookmark));
        assert_eq!(
            app.navigator
                .rows
                .iter()
                .find(|r| r.address == address)
                .map(|r| r.name.as_str()),
            Some("decrypt")
        );
        let _ = app.update(Message::EditUndo);
        assert!(record(&app).is_none(), "back to nothing");
        assert_ne!(
            app.navigator
                .rows
                .iter()
                .find(|r| r.address == address)
                .map(|r| r.name.as_str()),
            Some("decrypt"),
            "the list follows the undo"
        );
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.notice.as_deref(), Some("Nothing to undo"));

        // Redo walks forward again.
        let _ = app.update(Message::EditRedo);
        assert_eq!(
            record(&app).and_then(|a| a.name).as_deref(),
            Some("decrypt")
        );
        let _ = app.update(Message::EditRedo);
        assert!(record(&app).is_some_and(|a| a.bookmark));
        assert_eq!(app.redo.len(), 1);

        // A new change after an undo forgets what was taken back.
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptChanged("crypto".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.redo.is_empty());
        let _ = app.update(Message::EditRedo);
        assert_eq!(app.notice.as_deref(), Some("Nothing to redo"));
        assert_eq!(app.undo.len(), 3);

        // A submit that changes nothing is not a change.
        let _ = app.update(Message::EditTags);
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.undo.len(), 3);

        // Undo while a prompt is open leaves the marks alone: the chord is
        // about the typing.
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.undo.len(), 3, "nothing undone under a prompt");
        let _ = app.update(Message::Dismiss);

        // A path prompt is not an analyst change either.
        let _ = app.update(Message::FileOpenCorpus);
        let _ = app.update(Message::PromptChanged("/nowhere".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.undo.len(), 3);
    }

    #[test]
    fn opening_a_project_forgets_the_changes_made_before_it() {
        let dir = std::env::temp_dir().join(format!(
            "ag-ui-undo-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("empty.agproj");
        ag_corpus::project::ProjectFile::new(ag_corpus::project::Target::default())
            .save(&file)
            .expect("the file");

        let mut app = app();
        let _ = app.update(Message::FunctionSelected(0x100084A20));
        let _ = app.update(Message::EditBookmark);
        assert_eq!(app.undo.len(), 1);

        let _ = app.update(Message::FileOpenProject);
        let _ = app.update(Message::PromptChanged(file.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.undo.is_empty(), "the marks those changes were made to are gone");
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.notice.as_deref(), Some("Nothing to undo"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manual_cross_reference_shows_from_both_ends_and_is_undone() {
        let mut app = app();
        let source = 0x100084A28;
        let target = 0x100081D60;
        let _ = app.update(Message::FunctionSelected(0x100084A20));
        let _ = app.update(Message::AddressSelected(source));

        // Not an address: refused, nothing recorded.
        let _ = app.update(Message::EditReference);
        let _ = app.update(Message::PromptChanged("nowhere".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Not an address")));
        assert!(app.undo.is_empty());

        let _ = app.update(Message::EditReference);
        let _ = app.update(Message::PromptChanged(format!("{target:#X}")));
        let _ = app.update(Message::PromptSubmit);
        let key = app.annotation_key(source);
        let record = app.annotations.annotation_for(&key).expect("the record");
        assert_eq!(record.references, [format!("{target:#x}")], "canonical");
        assert_eq!(record.kind, ag_corpus::project::TargetKind::Address);
        assert_eq!(app.undo.len(), 1, "a change undo remembers");

        // From the source: the place it reaches, by the function's name.
        let manual = app.manual_references();
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].kind, ReferenceKind::Manual);
        assert_eq!(manual[0].address, target);
        let name = app.place_name(target);
        assert!(manual[0].label.starts_with(&name), "{}", manual[0].label);

        // From the target: the place that reaches it.
        let _ = app.update(Message::FunctionSelected(target));
        let manual = app.manual_references();
        assert_eq!(manual.len(), 1);
        assert_eq!(manual[0].kind, ReferenceKind::ManualFrom);
        assert_eq!(manual[0].address, source);

        // A renamed target reads by the analyst's name.
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode".into()));
        let _ = app.update(Message::PromptSubmit);
        let _ = app.update(Message::AddressSelected(source));
        assert!(app.manual_references()[0].label.starts_with("decode"));

        // Taking it back offers the one there is, and clears the record.
        let _ = app.update(Message::EditReferenceRemove);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some(&*format!("{target:#x}"))
        );
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.annotation_for(&key).is_none());
        assert!(app.manual_references().is_empty());
        let _ = app.update(Message::EditReferenceRemove);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("No manual reference")));

        // Undo brings the reference back.
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.manual_references().len(), 1);

        // Jumping from a manual reference opens the function it names.
        let _ = app.update(Message::JumpTo(target));
        assert!(matches!(app.selection, Selection::Function(a) if a == target));
    }

    #[test]
    fn a_reference_typed_bare_reaches_a_place_the_analysis_spaced() {
        let dir = temp_corpus("xref-space");
        let mut app = app();
        let _ = app.update(Message::FileOpenCorpus);
        let _ = app.update(Message::PromptChanged(dir.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.navigator.rows.len(), 2, "the corpus opened");
        let main = app
            .navigator
            .rows
            .iter()
            .find(|row| row.address != 0x1)
            .map(|row| row.address)
            .expect("the other function");

        // The analyst types the import's address as the listing prints it.
        let _ = app.update(Message::FunctionSelected(main));
        let _ = app.update(Message::EditReference);
        let _ = app.update(Message::PromptChanged("0x1".into()));
        let _ = app.update(Message::PromptSubmit);
        let record = app
            .annotations
            .annotation_for(&app.annotation_key(main))
            .expect("the record");
        assert_eq!(
            record.references,
            ["EXTERNAL:0x1"],
            "stored under the import's key"
        );

        // The import finds it from its own end.
        let _ = app.update(Message::FunctionSelected(0x1));
        let manual = app.manual_references();
        assert_eq!(manual.len(), 1, "{manual:?}");
        assert_eq!(manual[0].kind, ReferenceKind::ManualFrom);
        assert_eq!(manual[0].address, main);

        // Taking back one that was never there says so and changes nothing.
        let _ = app.update(Message::FunctionSelected(main));
        let _ = app.update(Message::EditReferenceRemove);
        let _ = app.update(Message::PromptChanged("0x9999".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("No manual reference")));
        assert_eq!(app.undo.len(), 1, "nothing recorded");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_data_mark_stands_in_for_the_instruction_and_widens_each_time() {
        let mut app = app();
        let start = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(start));
        let before = app.work.listing.clone();
        let at = before
            .iter()
            .position(|line| line.address == start + 4)
            .expect("the second instruction");
        assert_eq!(before[at].bytes, "FD 03 00 91");
        let _ = app.update(Message::AddressSelected(start + 4));

        // One byte, and the rest of the instruction as bytes.
        let _ = app.update(Message::EditMark(Mark::Data));
        let shown = &app.work.listing;
        assert_eq!(shown.len(), before.len() + 1);
        assert_eq!(
            (shown[at].mnemonic.as_str(), shown[at].operands.as_str()),
            ("db", "0xfd")
        );
        assert_eq!(shown[at + 1].address, start + 5);
        assert_eq!(shown[at + 1].operands, "0x03, 0x00, 0x91");
        assert_eq!(
            shown[at + 2].address,
            start + 8,
            "the next instruction follows"
        );
        assert_eq!(app.undo.len(), 1);

        // Again: a word, then a double word that takes the whole instruction.
        let _ = app.update(Message::EditMark(Mark::Data));
        assert_eq!(
            (
                app.work.listing[at].mnemonic.as_str(),
                app.work.listing[at].operands.as_str()
            ),
            ("dw", "0x03fd")
        );
        let _ = app.update(Message::EditMark(Mark::Data));
        let shown = &app.work.listing;
        assert_eq!(shown.len(), before.len());
        assert_eq!(
            (shown[at].mnemonic.as_str(), shown[at].operands.as_str()),
            ("dd", "0x910003fd")
        );
        assert_eq!(shown[at].bytes, "FD 03 00 91");

        // A quad word reaches into the next instruction's bytes.
        let _ = app.update(Message::EditMark(Mark::Data));
        let shown = &app.work.listing;
        assert_eq!(shown.len(), before.len() - 1);
        assert_eq!(shown[at].mnemonic, "dq");
        assert_eq!(shown[at + 1].address, start + 12);

        // Round to a byte again; the graph shows the same lines.
        let _ = app.update(Message::EditMark(Mark::Data));
        assert_eq!(app.work.listing[at].mnemonic, "db");
        let in_graph = app
            .work
            .graph
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|line| line.address == start + 4)
            .expect("the graph has the line");
        assert_eq!(in_graph.mnemonic, "db");

        // Code puts the instruction back and takes the mark off; undo
        // walks the marks back too.
        let _ = app.update(Message::EditMark(Mark::Code));
        assert_eq!(app.work.listing.len(), before.len());
        assert_eq!(app.work.listing[at].mnemonic, before[at].mnemonic);
        assert!(
            app.annotations
                .annotation_for(&app.annotation_key(start + 4))
                .is_none(),
            "code is no mark"
        );
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.work.listing[at].mnemonic, "db");
        let _ = app.update(Message::EditRedo);
        assert_eq!(app.work.listing[at].mnemonic, before[at].mnemonic);
    }

    #[test]
    fn a_mark_stops_at_a_gap_a_block_and_a_line_without_bytes() {
        use ag_corpus::project::ByteType;
        let line = |address: u64, bytes: &str| ListingLine {
            address,
            bytes: bytes.into(),
            mnemonic: "nop".into(),
            operands: String::new(),
            call_target: None,
            tail: false,
            registers: Vec::new(),
            comment: None,
        };
        let marks =
            |address: u64, mark: ByteType| std::collections::HashMap::from([(address, mark)]);
        let no_stops = std::collections::HashSet::new();
        let quad = ByteType::Data { width: 8, count: 1 };

        // A gap: the mark takes what is there and no more, and the line
        // past the gap stays.
        let lines = vec![line(0x5000, "AA BB CC DD"), line(0x6000, "11 22 33 44")];
        let shown = marked(lines, &marks(0x5000, quad), &no_stops);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].mnemonic, "db");
        assert_eq!(shown[0].operands, "0xaa, 0xbb, 0xcc, 0xdd");
        assert_eq!(shown[1].address, 0x6000);

        // Contiguous lines are taken until the mark is full.
        let lines = vec![
            line(0x5000, "AA BB CC DD"),
            line(0x5004, "11 22 33 44"),
            line(0x5008, "99"),
        ];
        let shown = marked(lines, &marks(0x5000, quad), &no_stops);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].mnemonic, "dq");
        assert_eq!(shown[0].operands, "0x44332211ddccbbaa");
        assert_eq!(shown[1].address, 0x5008);

        // A block's start ends the mark, the way the graph cuts there.
        let lines = vec![line(0x5000, "AA BB CC DD"), line(0x5004, "11 22 33 44")];
        let stops = std::collections::HashSet::from([0x5004]);
        let shown = marked(lines, &marks(0x5000, quad), &stops);
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].mnemonic, "db");

        // A string stops at a line without bytes, and never runs past its
        // reach without a zero.
        let lines = vec![
            line(0x5000, "41 42"),
            line(0x5002, ""),
            line(0x5010, "43 44"),
        ];
        let shown = marked(lines, &marks(0x5000, ByteType::String), &no_stops);
        assert_eq!(shown.len(), 3);
        assert_eq!(shown[0].operands, "\"AB\"");
        assert_eq!(shown[1].address, 0x5002);
        let long: Vec<ListingLine> = (0..40u64)
            .map(|i| line(0x5000 + i * 8, "41 41 41 41 41 41 41 41"))
            .collect();
        let shown = marked(long, &marks(0x5000, ByteType::String), &no_stops);
        assert_eq!(hex_bytes(&shown[0].bytes).len(), STRING_REACH);
        assert_eq!(shown[1].address, 0x5000 + STRING_REACH as u64);

        // The first line that stands in keeps the header of the one it
        // replaced; a line with no bytes to re-read is left alone.
        let mut headed = line(0x5000, "AA BB");
        headed.comment = Some("block 0x5000".into());
        let shown = marked(vec![headed], &marks(0x5000, ByteType::Undefined), &no_stops);
        assert_eq!(shown[0].comment.as_deref(), Some("block 0x5000"));
        let shown = marked(
            vec![line(0x5000, "")],
            &marks(0x5000, ByteType::Undefined),
            &no_stops,
        );
        assert_eq!(shown[0].mnemonic, "nop");
    }

    #[test]
    fn a_mark_off_an_instruction_is_refused() {
        let mut app = app();
        let start = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(start));
        let before = app.work.listing.clone();
        let _ = app.update(Message::AddressSelected(start + 4));
        let _ = app.update(Message::EditMark(Mark::Data));
        assert_eq!(app.work.listing.len(), before.len() + 1);

        // The leftover line a mark produced is not an instruction start.
        let _ = app.update(Message::AddressSelected(start + 5));
        let _ = app.update(Message::EditMark(Mark::Data));
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Marks start at an instruction")));
        assert_eq!(app.undo.len(), 1, "nothing recorded");
        assert!(app
            .annotations
            .annotation_for(&app.annotation_key(start + 5))
            .is_none());

        // A function may start anywhere.
        let _ = app.update(Message::EditMark(Mark::Function));
        assert!(app
            .annotations
            .annotation_for(&app.annotation_key(start + 5))
            .is_some_and(|a| a.byte_type.as_deref() == Some("function")));
    }

    #[test]
    fn undefined_and_string_marks_show_the_bytes_their_own_way() {
        let mut app = app();
        let start = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(start));
        let before = app.work.listing.clone();
        let at = before
            .iter()
            .position(|line| line.address == start + 4)
            .expect("the second instruction");
        let _ = app.update(Message::AddressSelected(start + 4));

        let _ = app.update(Message::EditMark(Mark::Undefined));
        let shown = &app.work.listing;
        assert_eq!(
            shown.len(),
            before.len(),
            "one instruction, one line of bytes"
        );
        assert_eq!(shown[at].mnemonic, "db");
        assert_eq!(shown[at].operands, "0xfd, 0x03, 0x00, 0x91");

        // A string runs to its zero; what is left of the instruction follows.
        let _ = app.update(Message::EditMark(Mark::String));
        let shown = &app.work.listing;
        assert_eq!(shown.len(), before.len() + 1);
        assert_eq!(shown[at].operands, "0xfd, 0x03, 0");
        assert_eq!(shown[at + 1].address, start + 7);
        assert_eq!(shown[at + 1].operands, "0x91");

        let record = app
            .annotations
            .annotation_for(&app.annotation_key(start + 4))
            .expect("the record");
        assert_eq!(record.byte_type.as_deref(), Some("string"));
    }

    #[test]
    fn a_function_mark_lists_a_function_the_analysis_did_not() {
        let mut app = app();
        let total = app.navigator.rows.len();
        let inside = 0x100084A44;
        let _ = app.update(Message::FunctionSelected(0x100084A20));
        let _ = app.update(Message::AddressSelected(inside));
        let _ = app.update(Message::EditMark(Mark::Function));

        let record = app
            .annotations
            .annotation_for(&app.annotation_key(inside))
            .expect("the record");
        assert_eq!(record.kind, ag_corpus::project::TargetKind::Function);
        assert_eq!(record.byte_type.as_deref(), Some("function"));

        let rows = &app.navigator.rows;
        assert_eq!(rows.len(), total + 1);
        let row = rows
            .iter()
            .find(|row| row.address == inside)
            .expect("the new row");
        assert_eq!(row.name, "sub_100084a44");
        assert_eq!(row.status, "Marked");
        let after = rows.iter().position(|row| row.address == inside).unwrap();
        assert!(
            rows[..after].iter().all(|row| row.address < inside),
            "in address order"
        );

        // Opening it describes the mark, since the analysis found nothing.
        let _ = app.update(Message::FunctionSelected(inside));
        assert!(matches!(app.selection, Selection::Function(a) if a == inside));
        let detail = app.work.detail.as_ref().expect("a detail");
        assert_eq!(detail.name, "sub_100084a44");
        assert_eq!(detail.provenance, "Analyst");
        assert_eq!(detail.start, Some(inside));

        // Undo takes the function off the list again.
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.navigator.rows.len(), total);
    }

    #[test]
    fn a_constant_is_shown_in_the_base_the_analyst_chose() {
        use ag_corpus::project::OperandFormat::*;
        let none = |_: u64| None;
        let named = |value: u64| (value == 0x1149).then(|| "decode".to_string());
        assert_eq!(
            reformat_operands("x29, sp, #0x30", Hex, &none),
            "x29, sp, #0x30"
        );
        assert_eq!(
            reformat_operands("x29, sp, #0x30", Decimal, &none),
            "x29, sp, #48"
        );
        assert_eq!(
            reformat_operands("x29, sp, #0x30", Octal, &none),
            "x29, sp, #0o60"
        );
        assert_eq!(
            reformat_operands("x29, sp, #0x30", Signed, &none),
            "x29, sp, #0x30"
        );
        // Signed reads the width the constant is printed in.
        assert_eq!(reformat_operands("eax, 0xff", Signed, &none), "eax, -0x1");
        assert_eq!(
            reformat_operands("eax, 0xffffffff", Signed, &none),
            "eax, -0x1"
        );
        assert_eq!(reformat_operands("eax, 0x7f", Signed, &none), "eax, 0x7f");
        assert_eq!(
            reformat_operands("rax, 0x8000000000000000", Signed, &none),
            "rax, -0x8000000000000000"
        );
        assert_eq!(reformat_operands("al, 0x80", Signed, &none), "al, -0x80");
        // A sign the analysis printed makes the constant signed already:
        // it is what it says, under every format that keeps the base.
        assert_eq!(reformat_operands("[rbp-0x88]", Signed, &none), "[rbp-0x88]");
        assert_eq!(reformat_operands("[rbp+0x88]", Signed, &none), "[rbp+0x88]");
        assert_eq!(
            reformat_operands("[RBP + -0x88]", Signed, &none),
            "[RBP + -0x88]"
        );
        assert_eq!(reformat_operands("[rbp-0x8]", Decimal, &none), "[rbp-8]");
        assert_eq!(reformat_operands("[rbp+0x10]", Octal, &none), "[rbp+0o20]");
        // Every constant in the line is shown the same way; labels are not
        // constants, and neither is a literal a word runs into.
        assert_eq!(reformat_operands("0x10, 0x20", Decimal, &none), "16, 32");
        assert_eq!(
            reformat_operands("x0, loc_0x10", Decimal, &none),
            "x0, loc_0x10"
        );
        assert_eq!(reformat_operands("0x1Fh", Decimal, &none), "0x1Fh");
        assert_eq!(reformat_operands("0x", Decimal, &none), "0x");
        // An address shows the place's name when there is one.
        assert_eq!(
            reformat_operands("rdi, 0x1149", Address, &named),
            "rdi, decode"
        );
        assert_eq!(
            reformat_operands("rdi, 0x1150", Address, &named),
            "rdi, 0x1150"
        );
        assert_eq!(
            reformat_operands("[rbp-0x1149]", Address, &named),
            "[rbp-0x1149]"
        );

        // iced's Intel syntax, which a program image's listing is printed
        // in, spells hex with an `h`: the same constants, read the same way
        // and shown in the same spelling.
        assert_eq!(
            reformat_operands("eax,[ebp+0Ch]", Decimal, &none),
            "eax,[ebp+12]"
        );
        assert_eq!(reformat_operands("eax,30h", Octal, &none), "eax,0o60");
        assert_eq!(reformat_operands("eax,0FFh", Signed, &none), "eax,-1h");
        assert_eq!(
            reformat_operands("eax,0FFFFFFFFh", Signed, &none),
            "eax,-1h"
        );
        assert_eq!(
            reformat_operands("rax,[rbp-88h]", Signed, &none),
            "rax,[rbp-88h]"
        );
        assert_eq!(
            reformat_operands("qword ptr [1149h]", Address, &named),
            "qword ptr [decode]"
        );
        assert_eq!(
            reformat_operands("qword ptr [3FD0h]", Address, &named),
            "qword ptr [3FD0h]"
        );
        assert_eq!(reformat_operands("sub_1149h", Decimal, &none), "sub_1149h");
        assert_eq!(reformat_operands("1149hx", Decimal, &none), "1149hx");
        assert_eq!(reformat_operands("eax,ebx", Decimal, &none), "eax,ebx");
    }

    #[test]
    fn the_operand_format_cycles_per_instruction_and_shows_in_the_listing() {
        let mut app = app();
        let start = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(start));
        let at = app
            .work
            .listing
            .iter()
            .position(|line| line.address == start + 20)
            .expect("the add");
        assert_eq!(app.work.listing[at].operands, "x29, sp, #0x30");
        let _ = app.update(Message::AddressSelected(start + 20));

        // Hex → signed (the same for a small value) → decimal → octal →
        // address (no place) → hex again, which clears the record.
        let _ = app.update(Message::EditOperandFormat);
        assert_eq!(app.work.listing[at].operands, "x29, sp, #0x30");
        assert!(app.notice.as_deref().unwrap().ends_with("signed"));
        let _ = app.update(Message::EditOperandFormat);
        assert_eq!(app.work.listing[at].operands, "x29, sp, #48");
        let in_graph = app
            .work
            .graph
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|line| line.address == start + 20)
            .expect("the graph has the line");
        assert_eq!(in_graph.operands, "x29, sp, #48");
        let _ = app.update(Message::EditOperandFormat);
        assert_eq!(app.work.listing[at].operands, "x29, sp, #0o60");
        let _ = app.update(Message::EditOperandFormat);
        assert_eq!(app.work.listing[at].operands, "x29, sp, #0x30");
        let _ = app.update(Message::EditOperandFormat);
        assert_eq!(app.work.listing[at].operands, "x29, sp, #0x30");
        assert!(
            app.annotations
                .annotation_for(&app.annotation_key(start + 20))
                .is_none(),
            "hex is the default, so the record is gone"
        );
        assert_eq!(app.undo.len(), 5, "every step is a change");

        // Only the one instruction changes; undo brings the base back.
        let _ = app.update(Message::EditUndo);
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.work.listing[at].operands, "x29, sp, #0o60");
        assert_eq!(app.work.listing[at + 1].operands, "x19, x0");
    }

    fn switch_elf() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/ag-engine/tests/fixtures/switch.elf")
    }

    #[test]
    fn the_bytes_at_the_selection_are_edited_as_hex_and_the_listing_follows() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let add = 0x1149;
        let _ = app.update(Message::FunctionSelected(add));
        let before = app.work.listing.clone();

        // The prompt starts from the bytes of the instruction here.
        let _ = app.update(Message::AddressSelected(add));
        let _ = app.update(Message::EditBytes);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some(before[0].bytes.as_str())
        );

        // Two bytes typed over the one-byte `push rbp`: `xor eax, eax`.
        let _ = app.update(Message::PromptChanged("31 c0".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.notice.as_deref(), Some("Wrote 31 C0 at 0x1149"));
        assert_eq!(app.work.listing[0].mnemonic, "xor");
        assert_eq!(app.work.listing[0].bytes, "31 C0");
        let record = app
            .annotations
            .annotation_for("0x1149")
            .expect("the record");
        assert_eq!(record.patch.as_deref(), Some("31 C0"));
        assert!(
            record.patch_text.is_none(),
            "typed bytes, not an instruction"
        );
        let row = app
            .work
            .bytes
            .iter()
            .find(|row| row.address <= add && add < row.address + row.bytes.len() as u64)
            .expect("the bytes pane shows the address");
        assert_eq!(row.bytes[(add - row.address) as usize], 0x31);
        assert_eq!(app.undo.len(), 1);

        // Bytes past the section's end are refused; bytes over an older
        // patch take it off.
        let _ = app.update(Message::EditBytes);
        let _ = app.update(Message::PromptChanged("90 ".repeat(100_000)));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("past the end of the section")));
        assert_eq!(app.undo.len(), 1);
        let _ = app.update(Message::AddressSelected(add + 1));
        let _ = app.update(Message::EditBytes);
        let _ = app.update(Message::PromptChanged("cc".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.annotation_for("0x114a").is_some());
        let _ = app.update(Message::AddressSelected(add));
        let _ = app.update(Message::EditBytes);
        let _ = app.update(Message::PromptChanged("31 c0".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.annotations.annotation_for("0x114a").is_none(),
            "the overlapped patch is gone"
        );
        assert_eq!(app.undo.len(), 3);
        let _ = app.update(Message::EditUndo);
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.undo.len(), 1);

        // Editing again starts from the patch; submitted as it came up it
        // changes nothing, and half a byte is refused.
        let _ = app.update(Message::EditBytes);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some("31 C0"));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.notice.as_deref(), Some("No change at 0x1149"));
        assert_eq!(app.undo.len(), 1);
        let _ = app.update(Message::EditBytes);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some("31 C0"));
        let _ = app.update(Message::PromptChanged("9".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Not bytes")));
        assert_eq!(app.undo.len(), 1);

        // Undo and an empty submit both put the file's bytes back; a second
        // empty submit has nothing to take off.
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.work.listing[0].mnemonic, before[0].mnemonic);
        let _ = app.update(Message::EditRedo);
        let _ = app.update(Message::EditBytes);
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.notice.as_deref(), Some("Patch taken off 0x1149"));
        assert!(app.annotations.annotation_for("0x1149").is_none());
        assert_eq!(app.work.listing[0].mnemonic, before[0].mnemonic);
        let _ = app.update(Message::EditBytes);
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.notice.as_deref(), Some("No patch at 0x1149"));

        // The instruction's bytes come up as the image reads them now, so
        // the prompt over an assembled instruction holds its bytes, and
        // submitting them keeps the instruction's text; a byte inside an
        // instruction comes up alone.
        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged("mov eax, 1".into()));
        let _ = app.update(Message::PromptSubmit);
        let _ = app.update(Message::EditBytes);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some("B8 01 00 00 00")
        );
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.notice.as_deref(), Some("No change at 0x1149"));
        let record = app
            .annotations
            .annotation_for("0x1149")
            .expect("the record");
        assert_eq!(record.patch_text.as_deref(), Some("mov eax, 1"));
        let _ = app.update(Message::AddressSelected(add + 2));
        let _ = app.update(Message::EditBytes);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some("00"));
    }

    #[test]
    fn the_patched_program_is_written_as_a_copy_and_the_patch_history_lists_the_patches() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let add = 0x1149;
        let _ = app.update(Message::FunctionSelected(add));
        let _ = app.update(Message::AddressSelected(add));

        // Nothing to write before a patch.
        let _ = app.update(Message::FileWritePatched);
        assert_eq!(app.notice.as_deref(), Some("No patches to write"));
        assert!(app.prompt.is_none());
        assert!(app.annotations.patch_records().is_empty());

        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged("mov eax, 1".into()));
        let _ = app.update(Message::PromptSubmit);
        let records = app.annotations.patch_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, add);
        assert_eq!(records[0].1.patch_text.as_deref(), Some("mov eax, 1"));

        // The prompt offers a path beside the program; the copy differs
        // from it in the five bytes, and the program is untouched.
        let out = std::env::temp_dir().join(format!(
            "ag-ui-write-patched-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&out);
        let _ = app.update(Message::FileWritePatched);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some(format!("{}.patched", sample_elf().display()).as_str())
        );
        let _ = app.update(Message::PromptChanged(out.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.starts_with("Wrote ") && n.ends_with("1 patch)")),
            "{:?}",
            app.notice
        );
        let original = std::fs::read(sample_elf()).expect("the program");
        let written = std::fs::read(&out).expect("the copy");
        let _ = std::fs::remove_file(&out);
        assert_eq!(written.len(), original.len());
        let differing = (0..original.len())
            .filter(|&i| original[i] != written[i])
            .count();
        assert_eq!(differing, 5);

        // Writing over the program itself is refused, and so is the project
        // file; a file already there takes a second submit, and the copy
        // written over it is whole.
        let _ = app.update(Message::FileWritePatched);
        let _ = app.update(Message::PromptChanged(sample_elf().display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.ends_with("is the program itself")));
        assert_eq!(std::fs::read(sample_elf()).expect("the program"), original);
        let project = out.with_extension("agproj");
        std::fs::write(&project, "{}").expect("a file standing for the project");
        app.project_path = Some(project.clone());
        let _ = app.update(Message::FileWritePatched);
        let _ = app.update(Message::PromptChanged(project.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.ends_with("is the project file")));
        assert_eq!(std::fs::read(&project).expect("the project"), b"{}");
        let _ = std::fs::remove_file(&project);
        std::fs::write(&out, b"stale").expect("a file in the way");
        let _ = app.update(Message::FileWritePatched);
        let _ = app.update(Message::PromptChanged(out.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("submit again")));
        assert_eq!(std::fs::read(&out).expect("the file in the way"), b"stale");
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some(out.display().to_string().as_str())
        );
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Wrote ")));
        assert_eq!(std::fs::read(&out).expect("the copy").len(), original.len());
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn an_arm_image_lists_its_functions_and_a_mode_mark_reads_them_again() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/arm_thumb.elf");
        let config = Config {
            binary: Some(fixture),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let names: Vec<(u64, String)> = app
            .provider
            .functions()
            .into_iter()
            .map(|row| (row.address, row.name))
            .collect();
        assert!(names.contains(&(0x2_0000, "add".to_string())), "{names:?}");

        // `other_mode` is ARM by its symbol: four bytes an instruction.
        let _ = app.update(Message::FunctionSelected(0x2_0038));
        assert!(!app.work.listing.is_empty());
        assert!(app
            .work
            .listing
            .iter()
            .all(|line| line.bytes.split_whitespace().count() == 4));
        let _ = app.update(Message::AddressSelected(0x2_0038));
        let _ = app.update(Message::EditMode);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some("arm"));

        // Marked Thumb, the same bytes read as Thumb words, and the project
        // remembers; undo reads them as ARM again.
        let _ = app.update(Message::PromptChanged("thumb".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("decodes as thumb")),
            "{:?}",
            app.notice
        );
        assert!(app
            .work
            .listing
            .iter()
            .any(|line| line.bytes.split_whitespace().count() == 2));
        assert_eq!(
            app.annotations
                .annotation_for("0x20038")
                .and_then(|a| a.mode.clone()),
            Some("thumb".to_string())
        );
        let _ = app.update(Message::EditUndo);
        assert!(app
            .work
            .listing
            .iter()
            .all(|line| line.bytes.split_whitespace().count() == 4));
        let _ = app.update(Message::EditRedo);
        assert!(app
            .work
            .listing
            .iter()
            .any(|line| line.bytes.split_whitespace().count() == 2));

        // A word that is not an instruction set is refused; an x86 image has
        // no instruction set to choose.
        let _ = app.update(Message::EditMode);
        let _ = app.update(Message::PromptChanged("x86".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Not an instruction set")));
        let mut x86 = App::boot(Config {
            binary: Some(sample_elf()),
            ..Config::default()
        })
        .0;
        let _ = x86.update(Message::AddressSelected(0x1149));
        let _ = x86.update(Message::EditMode);
        assert_eq!(
            x86.notice.as_deref(),
            Some("Choosing the instruction set needs a 32-bit ARM image")
        );
    }

    #[test]
    fn the_image_is_moved_and_its_segments_edited_and_the_project_remembers() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let main_at = |app: &App| {
            app.provider
                .functions()
                .into_iter()
                .find(|row| row.name == "main")
                .map(|row| row.address)
        };
        assert_eq!(main_at(&app), Some(0x1198));

        // Moved to 0x400000: every function and section moves with it, and
        // the project remembers.
        let _ = app.update(Message::EditRebase);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some("0x0"));
        let _ = app.update(Message::PromptChanged("0x400000".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(main_at(&app), Some(0x401198), "{:?}", app.notice);
        assert_eq!(app.annotations.layout.base.as_deref(), Some("0x400000"));
        let text = app
            .provider
            .segments()
            .into_iter()
            .find(|segment| segment.name == ".text")
            .expect(".text");
        assert_eq!(text.vma, 0x401060);
        let _ = app.update(Message::FunctionSelected(0x401198));
        assert!(
            !app.work.listing.is_empty(),
            "main is listed at its new address"
        );

        // Segments renamed, removed and added, in the moved image's addresses.
        let _ = app.update(Message::AddressSelected(0x401198));
        let _ = app.update(Message::EditSegmentRename);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some(".text ")
        );
        let _ = app.update(Message::PromptChanged(".text code".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.provider
                .segments()
                .iter()
                .any(|segment| segment.name == "code" && segment.vma == 0x401060),
            "{:?}",
            app.notice
        );
        let _ = app.update(Message::EditSegmentRemove);
        let _ = app.update(Message::PromptChanged(".comment".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(!app
            .provider
            .segments()
            .iter()
            .any(|segment| segment.name == ".comment"));
        let _ = app.update(Message::EditSegmentAdd);
        let _ = app.update(Message::PromptChanged(
            "extra 0x405000 16 file:0x3000".into(),
        ));
        let _ = app.update(Message::PromptSubmit);
        let extra = app
            .provider
            .segments()
            .into_iter()
            .find(|segment| segment.name == "extra")
            .expect("the segment added");
        assert_eq!((extra.vma, extra.size), (0x405000, 16));
        assert_eq!(app.annotations.layout.segments.len(), 3);

        // One the image cannot take is refused, and nothing changes.
        let _ = app.update(Message::EditSegmentAdd);
        let _ = app.update(Message::PromptChanged("clash 0x401070 4".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("overlaps")),
            "{:?}",
            app.notice
        );
        assert_eq!(app.annotations.layout.segments.len(), 3);
        assert!(app
            .provider
            .segments()
            .iter()
            .any(|segment| segment.name == "extra"));
        let _ = app.update(Message::EditSegmentAdd);
        let _ = app.update(Message::PromptChanged("half 0x409000".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("A segment is")));

        // Saved and opened again, the project reads the image under its layout.
        let file = std::env::temp_dir().join(format!(
            "ag-ui-layout-{}-{:?}.agproj",
            std::process::id(),
            std::thread::current().id()
        ));
        app.save_project_to(&file);
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut again = App::boot(config).0;
        assert_eq!(main_at(&again), Some(0x1198));
        let _ = again.update(Message::FileOpenProject);
        let _ = again.update(Message::PromptChanged(file.display().to_string()));
        let _ = again.update(Message::PromptSubmit);
        let _ = std::fs::remove_file(&file);
        assert_eq!(main_at(&again), Some(0x401198), "{:?}", again.notice);
        assert!(again
            .provider
            .segments()
            .iter()
            .any(|segment| segment.name == "code"));

        // A project whose layout the image cannot take opens all the same:
        // the program is read as the loader reads it, and the notice says
        // why.
        std::fs::write(
            &file,
            r#"{"format": 5, "target": {}, "layout": {"segments": [{"action": "add", "name": "clash", "address": "0x1070", "size": 4}]}}"#,
        )
        .expect("a project with a bad layout");
        let mut bad = App::boot(Config {
            binary: Some(sample_elf()),
            ..Config::default()
        })
        .0;
        let _ = bad.update(Message::FileOpenProject);
        let _ = bad.update(Message::PromptChanged(file.display().to_string()));
        let _ = bad.update(Message::PromptSubmit);
        let _ = std::fs::remove_file(&file);
        assert!(
            bad.notice
                .as_deref()
                .is_some_and(|n| n.contains("could not be applied")),
            "{:?}",
            bad.notice
        );
        assert_eq!(main_at(&bad), Some(0x1198));
        assert!(!bad
            .provider
            .segments()
            .iter()
            .any(|segment| segment.name == "clash"));
        assert!(bad.layout_failed.is_some());

        // Put back, the image reads where the loader puts it.
        let _ = again.update(Message::EditRebase);
        assert_eq!(
            again.prompt.as_ref().map(|p| p.value.as_str()),
            Some("0x400000")
        );
        let _ = again.update(Message::PromptChanged("none".into()));
        let _ = again.update(Message::PromptSubmit);
        assert_eq!(main_at(&again), Some(0x1198), "{:?}", again.notice);
        assert!(again.annotations.layout.base.is_none());
    }

    #[test]
    fn raw_bytes_open_where_the_analyst_says_and_the_project_remembers() {
        let mut app = App::boot(Config::default()).0;
        let sample = sample_elf().display().to_string();

        // The sample's `.text` as raw bytes: the entry is the one function.
        let _ = app.update(Message::FileOpenRaw);
        let _ = app.update(Message::PromptChanged(format!(
            "{sample} x86-64 0x1060 entry=0x1149 offset=0x1060 length=0x18c"
        )));
        let _ = app.update(Message::PromptSubmit);
        let names: Vec<(u64, String)> = app
            .provider
            .functions()
            .into_iter()
            .map(|row| (row.address, row.name))
            .collect();
        assert_eq!(
            names,
            [(0x1149, "entry_0x1149".to_string())],
            "{:?}",
            app.notice
        );
        let _ = app.update(Message::FunctionSelected(0x1149));
        assert_eq!(app.work.listing[0].mnemonic, "endbr64");
        assert!(app.raw.is_some());

        // Saved, the project says how the bytes load; opened in a fresh
        // workbench on the same file, it reads them that way.
        let file = std::env::temp_dir().join(format!(
            "ag-ui-raw-{}-{:?}.agproj",
            std::process::id(),
            std::thread::current().id()
        ));
        app.save_project_to(&file);
        assert_eq!(
            app.annotations
                .target
                .raw
                .as_ref()
                .map(|raw| raw.arch.as_str()),
            Some("x86-64")
        );
        let mut again = App::boot(Config {
            binary: Some(sample_elf()),
            ..Config::default()
        })
        .0;
        assert!(
            again.provider.functions().len() > 1,
            "the ELF, as the loader reads it"
        );
        let _ = again.update(Message::FileOpenProject);
        let _ = again.update(Message::PromptChanged(file.display().to_string()));
        let _ = again.update(Message::PromptSubmit);
        assert_eq!(again.provider.functions().len(), 1, "{:?}", again.notice);
        assert!(again.raw.is_some());

        // A raw project opened with no program open opens its own.
        let mut alone = App::boot(Config::default()).0;
        let _ = alone.update(Message::FileOpenProject);
        let _ = alone.update(Message::PromptChanged(file.display().to_string()));
        let _ = alone.update(Message::PromptSubmit);
        let _ = std::fs::remove_file(&file);
        assert_eq!(
            alone.binary_path.as_deref(),
            Some(sample_elf().as_path()),
            "{:?}",
            alone.notice
        );
        assert_eq!(alone.provider.functions().len(), 1, "{:?}", alone.notice);

        // What is not raw bytes is refused by name.
        let _ = app.update(Message::FileOpenRaw);
        let _ = app.update(Message::PromptChanged(format!("{sample} sparc 0x1000")));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Not an architecture")));
        let _ = app.update(Message::FileOpenRaw);
        let _ = app.update(Message::PromptChanged(format!("{sample} x86-64")));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Raw bytes are")));
    }

    #[test]
    fn a_universal_macho_opens_as_the_slice_named_and_the_project_remembers() {
        let fat = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/sample_fat.macho");
        let mut app = App::boot(Config::default()).0;

        // Without a slice the notice names them; with one, that image opens.
        let _ = app.update(Message::FileOpenBinary);
        let _ = app.update(Message::PromptChanged(fat.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("x86_64, arm64")),
            "{:?}",
            app.notice
        );
        let _ = app.update(Message::FileOpenBinary);
        let _ = app.update(Message::PromptChanged(format!(
            "{} slice=arm64",
            fat.display()
        )));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.project
                .architecture
                .as_deref()
                .is_some_and(|language| language.starts_with("AARCH64")),
            "{:?} {:?}",
            app.project.architecture,
            app.notice
        );
        assert_eq!(app.slice.as_deref(), Some("arm64"));
        let _ = app.update(Message::FileOpenBinary);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some(format!("{} slice=arm64", fat.display()).as_str())
        );
        let _ = app.update(Message::PromptCancel);

        // Raw bytes opened after it have no slice; a path with a space in
        // it opens as the path it is.
        let spaced = std::env::temp_dir().join(format!(
            "ag ui spaced {}-{:?}.elf",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::copy(sample_elf(), &spaced).expect("a copy with a space in its name");
        let _ = app.update(Message::FileOpenRaw);
        let _ = app.update(Message::PromptChanged(format!(
            "{} x86-64 0x1060 offset=0x1060 length=0x18c",
            sample_elf().display()
        )));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.slice.is_none());
        assert!(app.raw.is_some());
        let _ = app.update(Message::FileOpenBinary);
        let _ = app.update(Message::PromptChanged(spaced.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.binary_path.as_deref(),
            Some(spaced.as_path()),
            "{:?}",
            app.notice
        );
        assert!(app.raw.is_none() && app.slice.is_none());
        assert!(app.provider.functions().len() > 1);
        let _ = std::fs::remove_file(&spaced);
        let _ = app.update(Message::FileOpenBinary);
        let _ = app.update(Message::PromptChanged(format!(
            "{} slice=arm64",
            fat.display()
        )));
        let _ = app.update(Message::PromptSubmit);

        // Saved, the project says which slice; opened on the same file in a
        // fresh workbench, it reads that slice.
        let file = std::env::temp_dir().join(format!(
            "ag-ui-slice-{}-{:?}.agproj",
            std::process::id(),
            std::thread::current().id()
        ));
        app.save_project_to(&file);
        assert_eq!(app.annotations.target.slice.as_deref(), Some("arm64"));
        let mut again = App::boot(Config::default()).0;
        again.binary_path = Some(fat.clone());
        let _ = again.update(Message::FileOpenProject);
        let _ = again.update(Message::PromptChanged(file.display().to_string()));
        let _ = again.update(Message::PromptSubmit);
        let _ = std::fs::remove_file(&file);
        assert!(
            again
                .project
                .architecture
                .as_deref()
                .is_some_and(|language| language.starts_with("AARCH64")),
            "{:?}",
            again.notice
        );
    }

    #[test]
    fn the_dead_code_toggle_flips_the_option_and_relifts_the_function() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-engine/tests/fixtures/sample.elf");
        let mut app = App::boot(Config {
            binary: Some(fixture),
            ..Config::default()
        })
        .0;
        // deregister_tm_clones: a store nothing reads, and a branch that can
        // only go one way.
        let _ = app.update(Message::FunctionSelected(0x1090));
        let shown = app.work.pseudocode.clone().expect("lifts");
        assert!(shown.contains("rax = &completed.0;"), "{shown}");
        assert_eq!(app.options.get("dead-code").as_deref(), Some("keep"));

        // A click inside the function moves the selection; the toggle keeps
        // the function on screen, not the line.
        let _ = app.update(Message::AddressSelected(0x1094));
        let _ = app.update(Message::ToggleDeadCode);
        assert_eq!(app.options.get("dead-code").as_deref(), Some("drop"));
        assert_eq!(app.work.listing_of, Some(0x1090));
        let hidden = app.work.pseudocode.clone().expect("lifts");
        assert!(!hidden.contains("rax"), "{hidden}");
        assert!(hidden.contains("return;"), "{hidden}");

        let _ = app.update(Message::ToggleDeadCode);
        assert_eq!(app.options.get("dead-code").as_deref(), Some("keep"));
        assert_eq!(app.work.pseudocode.as_deref(), Some(shown.as_str()));
    }

    #[test]
    fn the_inspector_sizes_a_function_by_its_unwind_data() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-engine/tests/fixtures/sample.elf");
        let app = App::boot(Config {
            binary: Some(fixture),
            ..Config::default()
        })
        .0;
        let detail = app.provider.function_detail(0x1149).expect("add");
        assert_eq!(detail.start, Some(0x1149));
        assert_eq!(detail.end, Some(0x1161));
        // A stripped image lists what the unwind data names.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/unwind_stripped.elf");
        let app = App::boot(Config {
            binary: Some(fixture),
            ..Config::default()
        })
        .0;
        let names: Vec<String> = app
            .provider
            .functions()
            .into_iter()
            .map(|row| row.name)
            .collect();
        assert_eq!(names, ["sub_401000", "sub_401014", "sub_401047"]);
    }

    #[test]
    fn a_mangled_symbol_is_listed_demangled_and_the_inspector_keeps_the_mangled_name() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/sample_cpp.elf");
        let app = App::boot(Config {
            binary: Some(fixture),
            ..Config::default()
        })
        .0;
        let area = app
            .provider
            .functions()
            .into_iter()
            .find(|row| row.name == "geometry::area(int, int)")
            .expect("the overload is listed by its signature");
        let detail = app.provider.function_detail(area.address).expect("detail");
        assert_eq!(detail.name, "geometry::area(int, int)");
        assert_eq!(detail.mangled.as_deref(), Some("_ZN8geometry4areaEii"));
        let main = app
            .provider
            .functions()
            .into_iter()
            .find(|row| row.name == "main")
            .expect("main");
        assert_eq!(
            app.provider
                .function_detail(main.address)
                .expect("detail")
                .mangled,
            None
        );
    }

    #[test]
    fn an_objective_c_image_offers_its_header_and_another_image_does_not() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/sample_objc_stripped");
        let app = App::boot(Config {
            binary: Some(fixture),
            ..Config::default()
        })
        .0;
        let header = app.work.objc_header.as_deref().expect("a header");
        assert!(
            header.contains("@interface Derived : Base <Greeting>"),
            "{header}"
        );
        assert!(
            header.contains("@property (nonatomic) int count;"),
            "{header}"
        );
        assert!(header.contains("- (int)greet:(int)arg1;"), "{header}");
        assert!(header.contains("@interface Base (Extra)"), "{header}");

        let plain = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/sample.macho");
        let app = App::boot(Config {
            binary: Some(plain),
            ..Config::default()
        })
        .0;
        assert!(app.work.objc_header.is_none());
    }

    #[test]
    fn an_objective_c_images_methods_are_listed_under_their_runtime_names() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/ag-image/tests/fixtures/sample_objc_stripped");
        let app = App::boot(Config {
            binary: Some(fixture),
            ..Config::default()
        })
        .0;
        let names: Vec<String> = app
            .provider
            .functions()
            .into_iter()
            .map(|row| row.name)
            .collect();
        assert!(
            names.iter().any(|name| name == "-[Derived greet:]"),
            "{names:?}"
        );
        assert!(
            names.iter().any(|name| name == "+[Base answer]"),
            "{names:?}"
        );
        assert!(
            names.iter().any(|name| name == "-[Base(Extra) thrice:]"),
            "{names:?}"
        );
    }

    #[test]
    fn editing_bytes_needs_a_program_image() {
        let mut app = App::boot(Config::default()).0;
        app.selection = Selection::Address(0x1149);
        let _ = app.update(Message::EditBytes);
        assert_eq!(
            app.notice.as_deref(),
            Some("Editing bytes needs a program image")
        );
        assert!(app.prompt.is_none());
    }

    #[test]
    fn an_instruction_or_a_run_of_bytes_is_filled_with_nops() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let add = 0x1149;
        let _ = app.update(Message::FunctionSelected(add));
        let before = app.work.listing.len();

        // The one instruction: add's `endbr64` is four bytes, which become
        // four one-byte nops.
        let _ = app.update(Message::AddressSelected(add));
        let _ = app.update(Message::EditNop);
        assert_eq!(
            app.notice.as_deref(),
            Some("Filled 4 bytes at 0x1149 with nop")
        );
        assert!(app.work.listing[..4]
            .iter()
            .all(|line| line.mnemonic == "nop"));
        assert_eq!(app.work.listing.len(), before + 3);
        let record = app
            .annotations
            .annotation_for("0x1149")
            .expect("the record");
        assert_eq!(record.patch.as_deref(), Some("90 90 90 90"));
        assert_eq!(record.patch_text.as_deref(), Some("nop x4"));
        assert_eq!(app.undo.len(), 1);

        // A run from the next instruction, said as +N.
        let second = app.work.listing[4].address;
        let _ = app.update(Message::AddressSelected(second));
        let _ = app.update(Message::EditNopRange);
        let _ = app.update(Message::PromptChanged("+4".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.annotations
                .annotation_for(&format!("{second:#x}"))
                .and_then(|a| a.patch.clone())
                .as_deref(),
            Some("90 90 90 90")
        );
        assert!(app.work.listing[4..8]
            .iter()
            .all(|line| line.mnemonic == "nop"));

        // Said as an address to stop before, and refused when it reaches
        // nowhere.
        let _ = app.update(Message::EditNopRange);
        let _ = app.update(Message::PromptChanged(format!("{:#x}", second + 2)));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.annotations
                .annotation_for(&format!("{second:#x}"))
                .and_then(|a| a.patch.clone())
                .as_deref(),
            Some("90 90")
        );
        let _ = app.update(Message::EditNopRange);
        let _ = app.update(Message::PromptChanged(format!("{:#x}", second - 2)));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("Not a reach")));

        // A run past the section's end is refused before anything is
        // written, and a nop run over an older patch takes it off.
        let _ = app.update(Message::EditNopRange);
        let _ = app.update(Message::PromptChanged("+100000000000".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("past the end of the section")));
        let _ = app.update(Message::AddressSelected(second + 1));
        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged("int3".into()));
        let _ = app.update(Message::PromptSubmit);
        let _ = app.update(Message::AddressSelected(second));
        let _ = app.update(Message::EditNopRange);
        let _ = app.update(Message::PromptChanged("+4".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .annotations
            .annotation_for(&format!("{:#x}", second + 1))
            .is_none());
        assert!(app.work.listing[4..8]
            .iter()
            .all(|line| line.mnemonic == "nop"));

        // Undo puts the instructions back.
        while !app.undo.is_empty() {
            let _ = app.update(Message::EditUndo);
        }
        assert_ne!(app.work.listing[0].mnemonic, "nop");
        assert_eq!(app.work.listing.len(), before);
    }

    #[test]
    fn an_instruction_assembled_over_the_bytes_changes_what_every_view_reads() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let add = 0x1149;
        let _ = app.update(Message::FunctionSelected(add));
        let first = app.work.listing[0].clone();
        assert_eq!(first.address, add);
        assert_ne!(first.mnemonic, "mov");
        let before = app.work.listing.len();

        // The sample has no bytes to patch: nothing offered.
        let mut sample = App::boot(Config::default()).0;
        let _ = sample.update(Message::FunctionSelected(0x100084A20));
        let _ = sample.update(Message::EditAssemble);
        assert_eq!(
            sample.notice.as_deref(),
            Some("Assembling needs a program image")
        );

        // `push rbp` (1 byte) becomes `mov eax, 7` (5 bytes): the listing,
        // the bytes and the pseudocode follow, and the notice says what
        // was overwritten.
        let _ = app.update(Message::AddressSelected(add));
        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged("mov eax, 7".into()));
        let _ = app.update(Message::PromptSubmit);
        let notice = app.notice.clone().unwrap_or_default();
        assert!(
            notice.starts_with("Wrote B8 07 00 00 00 at 0x1149"),
            "{notice}"
        );
        assert!(notice.contains("overwritten"), "{notice}");
        let record = app
            .annotations
            .annotation_for("0x1149")
            .expect("the record");
        assert_eq!(record.patch.as_deref(), Some("B8 07 00 00 00"));
        assert_eq!(record.patch_text.as_deref(), Some("mov eax, 7"));
        assert_eq!(app.work.listing[0].mnemonic, "mov");
        assert_eq!(app.work.listing[0].bytes, "B8 07 00 00 00");
        assert!(
            app.work.listing.len() < before,
            "the next instruction went under the patch"
        );
        let row = app
            .work
            .bytes
            .iter()
            .find(|row| row.address <= add && add < row.address + row.bytes.len() as u64)
            .expect("the bytes pane shows the address");
        assert_eq!(row.bytes[(add - row.address) as usize], 0xb8);
        assert_eq!(app.undo.len(), 1);

        // A typo is refused by the assembler's reason and records nothing.
        let _ = app.update(Message::EditAssemble);
        assert_eq!(
            app.prompt.as_ref().map(|p| p.value.as_str()),
            Some("mov eax, 7")
        );
        let _ = app.update(Message::PromptChanged("frob eax".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app
            .notice
            .as_deref()
            .is_some_and(|n| n.starts_with("not assembled")));
        assert_eq!(app.undo.len(), 1);

        // Undo puts the file's bytes back in every view.
        let _ = app.update(Message::EditUndo);
        assert_eq!(app.work.listing[0].mnemonic, first.mnemonic);
        assert_eq!(app.work.listing.len(), before);
        let _ = app.update(Message::EditRedo);
        assert_eq!(app.work.listing[0].mnemonic, "mov");

        // A reload of the same binary keeps the patch and shows it.
        let _ = app.update(Message::FileReload);
        let _ = app.update(Message::FunctionSelected(add));
        assert_eq!(
            app.work.listing[0].mnemonic, "mov",
            "the new image was told the patch"
        );

        // A patch written over another takes it off.
        let _ = app.update(Message::AddressSelected(add + 1));
        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged("int3".into()));
        let _ = app.update(Message::PromptSubmit);
        let _ = app.update(Message::AddressSelected(add));
        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged("mov eax, 9".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.annotation_for("0x114a").is_none());
        assert_eq!(app.work.listing[0].bytes, "B8 09 00 00 00");

        // An empty submit takes the patch off.
        let _ = app.update(Message::EditAssemble);
        let _ = app.update(Message::PromptChanged(String::new()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.annotation_for("0x1149").is_none());
        assert_eq!(app.work.listing[0].mnemonic, first.mnemonic);
    }

    #[test]
    fn a_jump_table_note_tells_the_analysis_where_the_cases_are() {
        let config = Config {
            binary: Some(switch_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let classify = 0x401000;
        let _ = app.update(Message::FunctionSelected(classify));
        let jump_block = |app: &App| {
            app.work
                .graph
                .blocks
                .iter()
                .find(|block| block.from == 0x401005)
                .map(|block| block.successors.clone())
                .expect("the block that jumps through the table")
        };
        assert_eq!(jump_block(&app).len(), 6, "the walk reads the table itself");
        assert!(
            app.work
                .pseudocode
                .as_deref()
                .is_some_and(|code| code.contains("switch (")),
            "{:?}",
            app.work.pseudocode
        );

        // The analyst says three entries: the graph and the pseudocode
        // follow the note.
        let _ = app.update(Message::AddressSelected(0x401007));
        let _ = app.update(Message::EditSwitch);
        let _ = app.update(Message::PromptChanged("0x402000 3".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.annotations
                .annotation_for("0x401007")
                .and_then(|a| a.jump_table.clone())
                .as_deref(),
            Some("0x402000 8 3")
        );
        assert_eq!(jump_block(&app).len(), 3);
        assert!(app
            .work
            .pseudocode
            .as_deref()
            .is_some_and(|code| code.contains("case 2:") && !code.contains("case 3:")));

        // A note that does not read is refused; undo brings the six back.
        let _ = app.update(Message::EditSwitch);
        assert_eq!(app.prompt.as_ref().map(|p| p.value.as_str()), Some("0x402000 8 3"));
        let _ = app.update(Message::PromptChanged("0x402000 3 9".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.notice.as_deref().is_some_and(|n| n.starts_with("Not a jump table")));
        let _ = app.update(Message::EditUndo);
        assert_eq!(jump_block(&app).len(), 6);
    }

    #[test]
    fn opening_a_project_file_loads_its_annotations() {
        let dir = std::env::temp_dir().join(format!(
            "ag-ui-open-project-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("open.agproj");
        fs::write(
            &file,
            r#"{"format":1,"target":{},"annotations":[{"kind":"function","address":"0x100084a20","name":"decode_frame"}]}"#,
        )
        .expect("write");

        let mut app = app();
        let _ = app.update(Message::FileOpenProject);
        let _ = app.update(Message::PromptChanged(file.display().to_string()));
        let _ = app.update(Message::PromptSubmit);

        assert_eq!(app.navigator.rows[0].name, "decode_frame");
        assert_eq!(app.project_path.as_deref(), Some(file.as_path()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_project_format_is_refused_with_a_notice() {
        let dir = std::env::temp_dir().join(format!(
            "ag-ui-new-format-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("future.agproj");
        fs::write(&file, r#"{"format": 99, "target": {}}"#).expect("write");

        let mut app = app();
        let _ = app.update(Message::FileOpenProject);
        let _ = app.update(Message::PromptChanged(file.display().to_string()));
        let _ = app.update(Message::PromptSubmit);

        assert!(app
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("newer")));
        assert!(app.project_path.is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_comment_and_a_rename_at_one_address_share_one_record() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));

        // The comment is made as an address annotation and the rename as a
        // function one; neither may mask the other.
        let _ = app.update(Message::EditComment);
        let _ = app.update(Message::PromptChanged("the entry".into()));
        let _ = app.update(Message::PromptSubmit);

        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode_frame".into()));
        let _ = app.update(Message::PromptSubmit);

        assert_eq!(
            app.annotations.annotations.len(),
            1,
            "one record for one address"
        );
        let kept = app
            .annotations
            .annotation_for(&format!("{address:#x}"))
            .expect("the record is there");
        assert_eq!(kept.name.as_deref(), Some("decode_frame"));
        assert_eq!(kept.comment.as_deref(), Some("the entry"));
    }

    #[test]
    fn an_inline_comment_and_an_above_comment_are_told_apart() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));

        // The plain chord comments inline…
        let _ = app.update(Message::EditComment);
        let _ = app.update(Message::PromptChanged("the entry".into()));
        let _ = app.update(Message::PromptSubmit);
        let kept = app
            .annotations
            .annotation_for(&format!("{address:#x}"))
            .expect("the comment is there");
        assert_eq!(kept.comment.as_deref(), Some("the entry"));
        assert!(!kept.comment_above, "Ctrl+/ comments inline");

        // …and the shifted chord stands the note above, on the same record.
        let _ = app.update(Message::EditCommentAbove);
        let _ = app.update(Message::PromptChanged("the loop head".into()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(
            app.annotations.annotations.len(),
            1,
            "placement changes the record, it does not add one"
        );
        let kept = app
            .annotations
            .annotation_for(&format!("{address:#x}"))
            .expect("the comment is there");
        assert_eq!(kept.comment.as_deref(), Some("the loop head"));
        assert!(kept.comment_above, "Ctrl+Shift+/ stands the note above");
    }

    #[test]
    fn a_comment_reaches_the_listing_by_address() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditCommentAbove);
        let _ = app.update(Message::PromptChanged("the loop head".into()));
        let _ = app.update(Message::PromptSubmit);

        let renamed = app.renames();
        let note = renamed
            .comment_for(address)
            .expect("the comment reaches the view by address");
        assert_eq!(note.text, "the loop head");
        assert!(note.above, "the placement travels with the note");
        assert!(
            renamed.comment_for(0xdeadbeef).is_none(),
            "an address with no note has none to draw"
        );
    }

    /// A corpus whose index holds one plain function and one import, so a
    /// row exists that only the provider's own list shows with its space.
    fn temp_corpus(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ag-ui-corpus-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a temporary directory");
        fs::write(
            dir.join("decompile-index.json"),
            r#"{
                "version": 1,
                "target_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "provider": {"id": "test", "name": "test", "version": "0"},
                "functions": [
                    {"address": "0x1000", "name": "main", "status": "failed",
                     "body": {"available": false, "ranges": [], "non_contiguous": false}},
                    {"address": "EXTERNAL:0x1", "name": "qsort", "status": "failed",
                     "body": {"available": false, "ranges": [], "non_contiguous": false}}
                ]
            }"#,
        )
        .expect("the index");
        dir
    }

    #[test]
    fn a_comment_on_a_filtered_out_row_keys_on_its_space() {
        let dir = temp_corpus("filter-key");
        let mut app = app();
        let _ = app.update(Message::FileOpenCorpus);
        let _ = app.update(Message::PromptChanged(dir.display().to_string()));
        let _ = app.update(Message::PromptSubmit);
        assert_eq!(app.navigator.rows.len(), 2, "the corpus opened");

        // The filter hides qsort; the analyst still selects it by address.
        let _ = app.update(Message::NavigatorFilterChanged("main".into()));
        assert_eq!(app.navigator.rows.len(), 1, "qsort is hidden");
        let _ = app.update(Message::FunctionSelected(0x1));

        let _ = app.update(Message::EditComment);
        let _ = app.update(Message::PromptChanged("imported".into()));
        let _ = app.update(Message::PromptSubmit);

        // The key comes from the provider's row, not the filtered navigator,
        // so the comment lands on the import rather than a bare 0x1.
        let _ = app.update(Message::NavigatorFilterChanged(String::new()));
        let kept = app
            .annotations
            .annotation_for("EXTERNAL:0x1")
            .expect("the comment is keyed on the space");
        assert_eq!(kept.comment.as_deref(), Some("imported"));

        // A view asks by the address it prints, so the spaced record must
        // answer to the bare value — the way a rename of the same import
        // already does.
        let renamed = app.renames();
        let comment = renamed
            .comment_for(0x1)
            .expect("the spaced comment resolves for a view");
        assert_eq!(comment.text, "imported");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rename_replaces_the_callee_name_in_the_listing() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // main calls add at 0x1149; the listing shows the callee by name.
        let _ = app.update(Message::FunctionSelected(0x1198));
        let calls_add: Vec<&ListingLine> = app
            .work
            .listing
            .iter()
            .filter(|line| line.call_target == Some(0x1149))
            .collect();
        assert!(!calls_add.is_empty(), "main calls add");
        assert_eq!(calls_add[0].operands, "add");

        // Rename add; the listing of its CALLER follows without a reload.
        let _ = app.update(Message::FunctionSelected(0x1149));
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode".into()));
        let _ = app.update(Message::PromptSubmit);

        // The listing resolves the callee's name as it draws, from the
        // same map the graph reads.
        let _ = app.update(Message::FunctionSelected(0x1198));
        let renamed = app.renames();
        let calls: Vec<String> = app
            .work
            .listing
            .iter()
            .filter(|line| line.call_target == Some(0x1149))
            .map(|line| App::shown_operands(line, &renamed))
            .collect();
        assert_eq!(calls, vec!["decode".to_string()], "the rename reaches the listing");
    }

    #[test]
    fn a_rename_replaces_the_reference_label() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1198));

        let before = app.shown_reference_labels(&app.work.references);
        assert!(before.iter().any(|label| label == "add"), "{before:?}");

        let _ = app.update(Message::FunctionSelected(0x1149));
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode".into()));
        let _ = app.update(Message::PromptSubmit);

        // Back at main: its references still point at the renamed function.
        let _ = app.update(Message::FunctionSelected(0x1198));
        let after = app.shown_reference_labels(&app.work.references);
        assert!(after.iter().any(|label| label == "decode"), "{after:?}");
        assert!(!after.iter().any(|label| label == "add"), "{after:?}");
    }

    #[test]
    fn the_locals_are_found_in_rust_and_python_pseudocode_too() {
        for (language, declaration) in [
            ("rust", "let mut local_14: i32;"),
            ("python", "# locals: long local_10, int local_14"),
        ] {
            let config = Config {
                binary: Some(sample_elf()),
                options: ag_image::Options::from_pairs([("language", language)])
                    .expect("a language"),
                ..Config::default()
            };
            let mut app = App::boot(config).0;
            let _ = app.update(Message::FunctionSelected(0x1161));
            let body = app.work.pseudocode.clone().unwrap_or_default();
            assert!(body.contains(declaration), "{language}: {body}");
            let declared = app.declared_variables();
            assert!(
                declared.contains(&"local_14".to_string()),
                "{language}: {declared:?}"
            );
            assert!(
                declared.contains(&"local_10".to_string()),
                "{language}: {declared:?}"
            );
        }
    }

    #[test]
    fn renaming_a_local_variable_renames_its_uses_in_the_pseudocode() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // sum_to declares local_10 and local_14.
        let _ = app.update(Message::FunctionSelected(0x1161));
        let declared = app.declared_variables();
        assert!(declared.contains(&"local_14".to_string()), "{declared:?}");

        let _ = app.update(Message::EditRenameVariable);
        assert_eq!(
            app.prompt.as_ref().expect("a variable prompt").kind,
            PromptKind::Variable
        );
        let _ = app.update(Message::PromptChanged("local_14=count".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.prompt.is_none());

        // The pseudocode view shows the new name wherever the old one stood.
        let pairs = app.rename_pairs();
        assert!(pairs.contains(&("local_14".to_string(), "count".to_string())), "{pairs:?}");
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(original, renamed)| (original.as_str(), renamed.as_str()))
            .collect();
        let line = "  for (local_14 = 1; local_14 <= a; local_14 = local_14 + 1) {";
        assert_eq!(
            replace_words(line, &pairs),
            "  for (count = 1; count <= a; count = count + 1) {"
        );
    }

    #[test]
    fn clearing_a_variable_rename_returns_the_declared_name() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1161));

        let _ = app.update(Message::EditRenameVariable);
        let _ = app.update(Message::PromptChanged("local_14=count".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.variable_for("0x1161", "local_14").is_some());

        // An empty right side is the analyst taking the name back.
        let _ = app.update(Message::EditRenameVariable);
        let _ = app.update(Message::PromptChanged("local_14=".into()));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.annotations.variable_for("0x1161", "local_14").is_none(),
            "an empty rename leaves no record behind"
        );
    }

    #[test]
    fn a_callee_rename_shows_in_the_callers_pseudocode() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // Rename add while standing on add.
        let _ = app.update(Message::FunctionSelected(0x1149));
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode".into()));
        let _ = app.update(Message::PromptSubmit);

        // main's body calls add; its pairs carry the callee's rename too,
        // so the call line reads with the analyst's name.
        let _ = app.update(Message::FunctionSelected(0x1198));
        let pairs = app.rename_pairs();
        assert!(
            pairs.contains(&("add".to_string(), "decode".to_string())),
            "the callee's rename reaches the caller's body: {pairs:?}"
        );
    }

    #[test]
    fn a_label_at_an_unnamed_address_reaches_the_listing() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // An address the analysis named no function for; the analyst still
        // names its label, and a call to it must read with that name.
        let _ = app.update(Message::FunctionSelected(0x1180));
        let _ = app.update(Message::EditRenameLabel);
        let _ = app.update(Message::PromptChanged("add_one".into()));
        let _ = app.update(Message::PromptSubmit);

        let renamed = app.renames();
        let line = ListingLine {
            address: 0x11a0,
            bytes: "e8 a4 ff ff ff".into(),
            mnemonic: "call".into(),
            operands: "funct_1180".into(),
            call_target: Some(0x1180),
            tail: false,
            registers: Vec::new(),
            comment: None,
        };
        assert_eq!(
            App::shown_operands(&line, &renamed),
            "add_one",
            "a label at an address with no provider row still keys the listing"
        );
    }

    #[test]
    fn a_register_rename_reaches_the_listing_and_the_pseudocode() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // sum_to names its registers in the listing; the analyst can see
        // what the function prints before naming any of it.
        let _ = app.update(Message::FunctionSelected(0x1161));
        let named = app.listing_registers();
        assert!(!named.is_empty(), "the listing names registers: {named:?}");

        let _ = app.update(Message::EditRenameRegister);
        assert_eq!(
            app.prompt.as_ref().expect("a register prompt").kind,
            PromptKind::Register
        );
        let first = named[0].clone();
        let _ = app.update(Message::PromptChanged(format!("{first}=counter")));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.prompt.is_none());

        // The listing draws the new name wherever the register stood.
        let renamed = app.renames();
        let shown: Vec<String> = app
            .work
            .listing
            .iter()
            .filter(|line| line.registers.contains(&first))
            .map(|line| App::shown_operands(line, &renamed))
            .collect();
        assert!(!shown.is_empty(), "the register is printed in the listing");
        assert!(
            shown.iter().all(|text| !text.contains(&first)),
            "the old spelling is gone from every line that named it: {shown:?}"
        );
        assert!(
            shown.iter().all(|text| text.contains("counter")),
            "the new name stands in: {shown:?}"
        );

        // The pseudocode pairs carry it too, so the body reads the same.
        let pairs = app.rename_pairs();
        assert!(
            pairs.contains(&(first.clone(), "counter".to_string())),
            "the register rename reaches the pseudocode: {pairs:?}"
        );
    }

    #[test]
    fn a_register_rename_belongs_to_one_function_only() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // Name a register of sum_to…
        let _ = app.update(Message::FunctionSelected(0x1161));
        let named = app.listing_registers();
        let first = named[0].clone();
        let _ = app.update(Message::EditRenameRegister);
        let _ = app.update(Message::PromptChanged(format!("{first}=counter")));
        let _ = app.update(Message::PromptSubmit);

        // …and the same register in main, another function, is its own.
        let _ = app.update(Message::FunctionSelected(0x1198));
        assert!(
            !app.renames().registers.contains_key(&first)
                || app.renames().registers[&first] != "counter",
            "sum_to's rename does not follow into main"
        );
        let pairs = app.rename_pairs();
        assert!(
            !pairs.contains(&(first, "counter".to_string())),
            "main's body does not borrow sum_to's name: {pairs:?}"
        );
    }

    #[test]
    fn a_register_rename_stays_with_its_function_when_the_selection_moves() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;

        // Name a register of sum_to…
        let _ = app.update(Message::FunctionSelected(0x1161));
        let first = app.listing_registers()[0].clone();
        let _ = app.update(Message::EditRenameRegister);
        let _ = app.update(Message::PromptChanged(format!("{first}=counter")));
        let _ = app.update(Message::PromptSubmit);

        // …then click a string. The selection moves and the detail becomes
        // the string's; the listing keeps standing, so the rename must keep
        // drawing for the function the listing was read for, and the record
        // must not key on the string's address.
        let string = app
            .provider
            .strings()
            .first()
            .expect("the sample holds a string")
            .address;
        assert_ne!(string, 0x1161, "the string is elsewhere");
        let _ = app.update(Message::StringSelected(string));

        assert!(
            app.renames().registers.contains_key(&first),
            "the rename still reaches the listing on screen"
        );
        assert!(
            app.annotations.register_for("0x1161", &first).is_some(),
            "the record belongs to sum_to, not to the string at {string:#x}"
        );
        assert!(
            app.annotations
                .register_for(&format!("{string:#x}"), &first)
                .is_none(),
            "no record was keyed on the string's address"
        );
    }

    #[test]
    fn clearing_a_register_rename_returns_the_register_name() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1161));
        let first = app.listing_registers()[0].clone();

        let _ = app.update(Message::EditRenameRegister);
        let _ = app.update(Message::PromptChanged(format!("{first}=counter")));
        let _ = app.update(Message::PromptSubmit);
        assert!(app.annotations.register_for("0x1161", &first).is_some());

        let _ = app.update(Message::EditRenameRegister);
        let _ = app.update(Message::PromptChanged(format!("{first}=")));
        let _ = app.update(Message::PromptSubmit);
        assert!(
            app.annotations.register_for("0x1161", &first).is_none(),
            "an empty rename leaves no record behind"
        );
    }

    #[test]
    fn a_reference_label_must_end_its_stem_at_a_word_end() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1149));
        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode".into()));
        let _ = app.update(Message::PromptSubmit);

        let references = vec![
            Reference {
                address: 0x1149,
                label: "add (tail call)".into(),
                kind: ReferenceKind::Calls,
            },
            Reference {
                address: 0x1149,
                label: "address".into(),
                kind: ReferenceKind::Data,
            },
        ];
        assert_eq!(
            app.shown_reference_labels(&references),
            vec!["decode (tail call)".to_string(), "address".to_string()],
            "the tail the provider added is kept; a longer word is not a stem"
        );
    }

    #[test]
    fn renaming_a_function_renames_its_own_pseudocode_header() {
        let config = Config {
            binary: Some(sample_elf()),
            ..Config::default()
        };
        let mut app = App::boot(config).0;
        let _ = app.update(Message::FunctionSelected(0x1149));

        let _ = app.update(Message::EditRename);
        let _ = app.update(Message::PromptChanged("decode".into()));
        let _ = app.update(Message::PromptSubmit);

        let pairs = app.rename_pairs();
        assert!(pairs.contains(&("add".to_string(), "decode".to_string())), "{pairs:?}");
        let shown = replace_words("int add(int a, int b)", &[("add", "decode")]);
        assert_eq!(shown, "int decode(int a, int b)");
    }

    #[test]
    fn replace_words_only_reaches_whole_words() {
        let one = &[("add", "X")][..];
        assert_eq!(replace_words("call add", &[("add", "decode")]), "call decode");
        assert_eq!(replace_words("address", one), "address");
        assert_eq!(replace_words("dadd + add_", one), "dadd + add_");
        assert_eq!(replace_words("add(add(1))", &[("add", "f")]), "f(f(1))");
        assert_eq!(replace_words("local_14", &[("local_1", "X")]), "local_14");
        assert_eq!(replace_words("a.b", &[("a", "X")]), "X.b");
        // A name that contains the word is not reached into twice.
        assert_eq!(replace_words("add + add;", &[("add", "addX")]), "addX + addX;");
    }

    #[test]
    fn replace_words_applies_two_renames_in_one_pass() {
        // local_14 becomes local_10 while local_10 becomes count: each
        // renders as its own new name, never as the other's.
        let pairs = &[("local_10", "count"), ("local_14", "local_10")][..];
        assert_eq!(
            replace_words("local_10 = local_14 + local_10;", pairs),
            "count = local_10 + count;"
        );
        // A declared name that starts with another keys on the whole word.
        let named = &[("v1", "one"), ("v10", "ten")][..];
        assert_eq!(replace_words("v1 = v10 + v1;", named), "one = ten + one;");
    }

    #[test]
    fn a_label_rename_shares_the_address_record_with_the_function() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));

        let _ = app.update(Message::EditRenameLabel);
        let _ = app.update(Message::PromptChanged("entry_point".into()));
        let _ = app.update(Message::PromptSubmit);

        assert_eq!(app.navigator.rows[0].name, "entry_point");
        assert_eq!(app.annotations.annotations.len(), 1, "one record for one address");
    }

    #[test]
    fn opening_a_different_analysis_drops_the_annotations() {
        let mut app = app();
        let address = 0x100084A20;
        let _ = app.update(Message::FunctionSelected(address));
        let _ = app.update(Message::EditBookmark);
        assert!(!app.annotations.annotations.is_empty(), "sample has a note");

        // A rename of the sample's address means nothing to the ELF.
        let _ = app.update(Message::FileOpenBinary);
        let _ = app.update(Message::PromptChanged(sample_elf().display().to_string()));
        let _ = app.update(Message::PromptSubmit);

        assert!(
            app.annotations.annotations.is_empty(),
            "the sample's annotations do not follow the ELF"
        );
        assert!(app.project_path.is_none(), "the old file is not the target");

        // A note made against the ELF survives a reload of the same file.
        let elf_address = app.navigator.rows[0].address;
        let _ = app.update(Message::FunctionSelected(elf_address));
        let _ = app.update(Message::EditBookmark);
        let _ = app.update(Message::FileReload);
        assert_eq!(
            app.annotations.annotations.len(),
            1,
            "a reload of the same analysis keeps its notes"
        );
    }
}
