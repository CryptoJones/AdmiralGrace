//! Application state, messages, and the update loop.

use std::path::PathBuf;

use iced::keyboard::{self, Key};
use iced::{Element, Subscription, Task};

use crate::data::corpus::CorpusProvider;
use crate::data::empty::EmptyProvider;
use crate::data::sample::SampleProvider;
use crate::data::{
    AnalysisState, ByteLine, FunctionDetail, FunctionRow, ListingLine, Problem, Provider,
    Reference, SearchHit, SectionCounts,
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
}

/// What the path prompt is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// A corpus directory.
    Corpus,
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
    /// Objective-C method map to overlay.
    pub methods: Option<PathBuf>,
    /// Image-base shift applied to Objective-C IMP addresses.
    pub shift: u64,
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
    /// Pseudocode of the selected function.
    pub pseudocode: Option<String>,
    /// Byte rows around the selection.
    pub bytes: Vec<ByteLine>,
    /// References to and from the selection.
    pub references: Vec<Reference>,
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
    /// The Objective-C method map currently open.
    pub methods_path: Option<PathBuf>,
    /// Image-base shift applied to Objective-C IMP addresses.
    pub shift: u64,
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
            global_query: String::new(),
            notice: None,
            show_navigator: true,
            show_inspector: true,
            show_bottom: true,
            show_about: false,
            prompt: None,
            corpus_root: config.corpus.clone(),
            methods_path: config.methods.clone(),
            shift: config.shift,
        };

        if config.corpus.is_some() {
            app.load_project();
        } else {
            app.use_sample();
        }

        (app, Task::none())
    }

    /// Load the corpus (and optional method map) into the workbench.
    fn load_project(&mut self) {
        let Some(root) = self.corpus_root.clone() else {
            self.use_sample();
            return;
        };

        match CorpusProvider::load(&root, self.methods_path.as_deref(), self.shift) {
            Ok(provider) => {
                self.provider = Box::new(provider);
                self.notice = Some(format!("Opened {}", root.display()));
                self.adopt_provider();
            }
            Err(error) => {
                self.notice = Some(format!("Could not open {}: {error:#}", root.display()));
                self.use_sample();
            }
        }
    }

    /// Fall back to the bundled sample project.
    fn use_sample(&mut self) {
        self.provider = Box::new(SampleProvider::new());
        self.notice = Some("No corpus supplied — showing sample data".into());
        self.adopt_provider();
    }

    /// Close the open project.
    fn close_project(&mut self) {
        self.provider = Box::new(EmptyProvider::new());
        self.corpus_root = None;
        self.methods_path = None;
        self.notice = Some("Project closed".into());
        self.adopt_provider();
    }

    /// Re-read the project identity and lists after the provider changed.
    fn adopt_provider(&mut self) {
        self.project = self.provider.project();
        self.capabilities = self.provider.capabilities();
        self.navigator.counts = self.provider.counts();
        self.bottom.problems = self.provider.problems();
        self.selection = Selection::None;
        self.work = WorkSurface::default();
        self.refresh_functions();
        self.select_first_function();
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
    fn select_first_function(&mut self) {
        if let Some(first) = self.navigator.rows.first() {
            let address = first.address;
            self.select_function(address, false);
        }
    }

    /// Move the shared selection to a function.
    pub fn select_function(&mut self, address: u64, record_history: bool) {
        self.selection = Selection::Function(address);
        self.navigator.selected = Some(address);

        self.work.detail = self.provider.function_detail(address);
        self.work.listing = self.provider.listing(address).unwrap_or_default();
        self.work.pseudocode = self.provider.pseudocode(address);
        self.work.bytes = self.provider.bytes(address).unwrap_or_default();
        self.work.references = self.provider.references(address);

        if record_history {
            self.history.push(self.selection);
        }
    }

    /// Apply a selection without recording it in the history.
    fn apply_history_selection(&mut self, selection: Selection) {
        match selection {
            Selection::Function(address) => self.select_function(address, false),
            Selection::Address(address) => {
                if let Some(function) = self.containing_function(address) {
                    self.select_function(function, false);
                }
                self.selection = Selection::Address(address);
            }
            Selection::ByteRange { start, .. } => {
                if let Some(function) = self.containing_function(start) {
                    self.select_function(function, false);
                }
                self.selection = Selection::ByteRange { start, len: 0 };
            }
            Selection::None => self.selection = Selection::None,
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
                    self.select_function(address, true);
                } else {
                    self.navigator.selected = Some(address);
                }
            }

            Message::AddressSelected(address) => {
                self.selection = Selection::Address(address);
                self.history.push(self.selection);
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
                    self.apply_history_selection(selection);
                }
            }

            Message::Forward => {
                if let Some(selection) = self.history.forward().copied() {
                    self.apply_history_selection(selection);
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
                            self.load_project();
                        }
                    }
                    PromptKind::Methods => {
                        self.methods_path = Some(path);
                        self.load_project();
                    }
                }
            }

            Message::PromptCancel => {
                self.prompt = None;
            }

            Message::FileReload => {
                if self.corpus_root.is_some() {
                    self.load_project();
                } else {
                    self.notice = Some("Nothing to reload".into());
                }
            }

            Message::FileClose => {
                self.close_project();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::bottom_panel::BottomTab;

    /// A workbench booted with the bundled sample project.
    fn app() -> App {
        App::boot(Config::default()).0
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
    fn closing_the_project_empties_the_workbench() {
        let mut app = app();

        let _ = app.update(Message::FileClose);

        assert!(app.navigator.rows.is_empty());
        assert!(app.corpus_root.is_none());
        assert_eq!(app.selection, Selection::None);
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
}
