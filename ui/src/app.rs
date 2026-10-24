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
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, Graph, ListingLine, Problem, Provider,
    Reference, ReferenceKind, SearchHit, SectionCounts, StringEntry,
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
    /// Reload the open project.
    FileReload,
    /// Close the open project.
    FileClose,
    /// Quit the application.
    FileQuit,
    /// Rename the selected function.
    EditRename,
    /// Comment the selected function.
    EditComment,
    /// Toggle a bookmark on the selection.
    EditBookmark,
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
    /// Listing lines of the selected function.
    pub listing: Vec<ListingLine>,
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
    /// The program image currently open.
    pub binary_path: Option<PathBuf>,
    /// The engine's options, for the pseudocode of a program image.
    pub options: ag_image::Options,
    /// The Objective-C method map currently open.
    pub methods_path: Option<PathBuf>,
    /// Image-base shift applied to Objective-C IMP addresses.
    pub shift: u64,
    /// The kuna CLI of an open kuna project, and the answers it has given.
    pub kuna: Option<KunaState>,
}

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
            binary_path: config.binary.clone(),
            options: config.options,
            methods_path: config.methods.clone(),
            shift: config.shift,
            kuna: None,
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
        match BinaryProvider::load_with_options(path, self.options) {
            Ok(provider) => {
                let binary = provider.binary();
                self.provider = Box::new(provider);
                self.notice = Some(format!("Opened {}", path.display()));

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
        self.methods_path = None;
        self.kuna = None;
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
        self.refresh_functions();
        self.select_first_function()
    }

    /// The window title.
    pub fn window_title(&self) -> String {
        format!("AdmiralGrace — {}", self.project.name)
    }

    /// The current analysis state.
    pub fn analysis_state(&self) -> AnalysisState {
        self.provider.analysis_state()
    }

    /// Reload the function list and apply the current filter.
    fn refresh_functions(&mut self) {
        let filter = self.navigator.filter.trim().to_lowercase();
        let rows = self
            .provider
            .functions()
            .into_iter()
            .filter(|row| filter.is_empty() || row.name.to_lowercase().contains(&filter))
            .collect();

        self.navigator.rows = rows;
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

        self.work.detail = self.provider.function_detail(address);
        self.work.listing = self.provider.listing(address).unwrap_or_default();
        self.work.graph = self.provider.graph(address).unwrap_or_default();
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
        match message {
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

            Message::FileOpenBinary => {
                self.prompt = Some(Prompt {
                    kind: PromptKind::Binary,
                    title: "Open a program image",
                    value: self
                        .binary_path
                        .as_ref()
                        .map(|path| path.display().to_string())
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
                            return self.load_project();
                        }
                    }
                    PromptKind::Methods => {
                        self.methods_path = Some(path);
                        return self.load_project();
                    }
                    PromptKind::Binary => {
                        if !path.is_file() {
                            self.notice = Some(format!("{} is not a file", path.display()));
                        } else {
                            self.binary_path = Some(path);
                            self.corpus_root = None;
                            self.kuna_root = None;
                            return self.load_project();
                        }
                    }
                }
            }

            Message::PromptCancel => {
                self.prompt = None;
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
                self.notice = Some("Renaming lands with project persistence (milestone 3)".into());
            }

            Message::EditComment => {
                self.notice = Some("Comments land with project persistence (milestone 3)".into());
            }

            Message::EditBookmark => {
                self.notice = Some("Bookmarks land with project persistence (milestone 3)".into());
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
                    "Ctrl+O open corpus · Ctrl+B navigator · Ctrl+I inspector · Ctrl+J bottom panel · F2 rename · F5 reload"
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

/// Map a key press onto a workbench command.
fn shortcut(event: keyboard::Event) -> Message {
    let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
        return Message::Ignore;
    };

    match (key.as_ref(), modifiers.command()) {
        (Key::Character("o"), true) => Message::FileOpenCorpus,
        (Key::Character("q"), true) => Message::FileQuit,
        (Key::Character("b"), true) => Message::ViewToggleNavigator,
        (Key::Character("i"), true) => Message::ViewToggleInspector,
        (Key::Character("j"), true) => Message::ViewToggleBottom,
        (Key::Character("/"), true) => Message::EditComment,
        (Key::Character("r"), true) => Message::FileReload,
        (Key::Named(keyboard::key::Named::F2), _) => Message::EditRename,
        (Key::Named(keyboard::key::Named::F5), _) => Message::FileReload,
        (Key::Named(keyboard::key::Named::Escape), _) => Message::Dismiss,
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

        assert_eq!(users.len(), 5, "{users:?}");
        assert!(users.contains(&"_start"), "{users:?}");
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
        // why: _init calls through a register.
        let _ = app.update(Message::FunctionSelected(0x1000));
        assert_eq!(app.work.pseudocode, None);
        assert!(app.work.line_addresses.is_empty());
        assert!(
            app.bottom
                .problems
                .iter()
                .any(|problem| problem.message.contains("not lifted yet: an indirect call")),
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
        let ctrl = keyboard::Modifiers::CTRL;

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
}
