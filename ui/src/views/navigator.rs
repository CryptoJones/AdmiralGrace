//! The left navigator: project identity, filter, function list, explore sections.

use iced::widget::{
    container, mouse_area, scrollable, text_input, Column, Container, Row, Space, Text,
};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message, TagCount};
use crate::data::{DataSymbolEntry, FunctionRow, SegmentEntry};
use crate::theme::{color, MONO};
use crate::views::{count, count_or_indexing, section_header, subtle};

/// The explorable sections of a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Section {
    /// Functions.
    #[default]
    Functions,
    /// Imported symbols.
    Imports,
    /// Exported symbols.
    Exports,
    /// Strings.
    Strings,
    /// File segments.
    Segments,
    /// Recovered types.
    Types,
    /// Analyst bookmarks.
    Bookmarks,
    /// Tags, the analyst's and the analysis's.
    Tags,
}

impl Section {
    /// The label shown in the navigator.
    pub fn label(self) -> &'static str {
        match self {
            Section::Functions => "Functions",
            Section::Imports => "Imports",
            Section::Exports => "Exports",
            Section::Strings => "Strings",
            Section::Segments => "Segments",
            Section::Types => "Types",
            Section::Bookmarks => "Bookmarks",
            Section::Tags => "Tags",
        }
    }

    /// The order the sections appear in the explore list.
    pub const ALL: [Section; 7] = [
        Section::Imports,
        Section::Exports,
        Section::Strings,
        Section::Segments,
        Section::Types,
        Section::Bookmarks,
        Section::Tags,
    ];
}

/// Build the navigator.
pub fn view(app: &App) -> Element<'_, Message> {
    Container::new(
        Column::new()
            .padding(12)
            .spacing(6)
            .push(section_header("Project"))
            .push(subtle(app.project.subtitle()))
            .push(program_summary(app))
            .push(filter_input(app))
            .push(
                Row::new()
                    .align_y(Alignment::Center)
                    .push(section_header(list_heading(app)))
                    .push(Space::new().width(Length::Fill))
                    .push(subtle(count(list_count(app)))),
            )
            .push(
                scrollable(list_contents(app))
                    .height(Length::Fill)
                    .width(Length::Fill),
            )
            .push(section_header("Explore"))
            .push(explore_list(app)),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(color::PANEL)),
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..container::Style::default()
    })
    .into()
}

/// The shape of the program, as the analysis reported it.
///
/// A kuna export knows the binary it was made from, so the CLI can say how
/// the program is put together: where it starts, how much of it is reachable
/// and how much of it nothing calls.
fn program_summary(app: &App) -> Element<'_, Message> {
    let Some(summary) = app.provider.summary() else {
        return Space::new().width(Length::Fill).into();
    };

    let mut column = Column::new().spacing(2).width(Length::Fill);

    if let Some((name, address)) = &summary.entry {
        column = column.push(summary_row(
            format!("entry {name}"),
            format!("{address:#x}"),
        ));
    }

    if let Some((name, address)) = &summary.main {
        column = column.push(summary_row(format!("main {name}"), format!("{address:#x}")));
    }

    column = column.push(summary_row(
        "reachable".into(),
        count_or_indexing(summary.reachable),
    ));
    column = column.push(summary_row(
        "no callers".into(),
        count_or_indexing(summary.no_callers),
    ));
    column = column.push(summary_row(
        "code bytes".into(),
        summary.code_bytes.to_string(),
    ));

    column.into()
}

/// One row of the program summary.
fn summary_row(key: String, value: String) -> Element<'static, Message> {
    Row::new()
        .align_y(Alignment::Center)
        .push(Text::new(key).size(11).color(color::MUTED).font(MONO))
        .push(Space::new().width(Length::Fill))
        .push(Text::new(value).size(11).color(color::DIM).font(MONO))
        .into()
}

/// The navigator filter.
fn filter_input(app: &App) -> Element<'_, Message> {
    text_input::TextInput::new("Filter functions, or #tag…", &app.navigator.filter)
        .on_input(Message::NavigatorFilterChanged)
        .width(Length::Fill)
        .size(13)
        .padding([6, 8])
        .style(|_, _| text_input::Style {
            background: Background::Color(color::INPUT),
            border: Border {
                color: color::LINE,
                width: 1.0,
                radius: 5.0.into(),
            },
            icon: color::MUTED,
            placeholder: color::MUTED,
            value: color::TEXT,
            selection: color::CYAN.scale_alpha(0.35),
        })
        .into()
}

/// The heading above the navigator's list.
///
/// The Segments section lists the sections of the program image, the
/// Bookmarks section the analyst's marked places and the Tags section the
/// tags; every other section lists the functions.
fn list_heading(app: &App) -> &'static str {
    match app.navigator.section {
        Section::Segments => "Segments",
        Section::Bookmarks => "Bookmarks",
        Section::Tags => "Tags",
        _ => "Functions",
    }
}

/// How many rows the navigator's list holds.
fn list_count(app: &App) -> usize {
    match app.navigator.section {
        Section::Segments => app.provider.segments().len() + app.provider.data_symbols().len(),
        Section::Bookmarks => app.annotations.bookmarks().len(),
        Section::Tags => app.navigator.tags.len(),
        _ => app.navigator.rows.len(),
    }
}

/// The list the navigator shows.
///
/// The Segments section holds the sections of the program image, the
/// Bookmarks section the analyst's marked places and the Tags section the
/// tags; every other section holds the functions.
fn list_contents(app: &App) -> Column<'_, Message> {
    match app.navigator.section {
        Section::Segments => segment_list(app),
        Section::Bookmarks => bookmark_list(app),
        Section::Tags => tag_list(app),
        _ => function_list(app),
    }
}

/// The sections of the program image, and the named data in it.
///
/// A section or a symbol can be picked, which moves the byte pane to it.
fn segment_list(app: &App) -> Column<'_, Message> {
    let segments = app.provider.segments();
    let symbols = app.provider.data_symbols();

    if segments.is_empty() && symbols.is_empty() {
        return Column::new()
            .spacing(3)
            .push(Text::new("No sections").size(12).color(color::MUTED))
            .push(
                Text::new("This project has no program image behind it.")
                    .size(11)
                    .color(color::DIM),
            );
    }

    let mut list = Column::new().spacing(1).width(Length::Fill);

    if !segments.is_empty() {
        list = list.push(subtle("Sections"));

        for segment in &segments {
            list = list.push(segment_row(segment));
        }
    }

    if !symbols.is_empty() {
        list = list.push(subtle("Data"));

        for symbol in &symbols {
            list = list.push(symbol_row(symbol));
        }
    }

    list
}

/// One section of the program image.
fn segment_row(segment: &SegmentEntry) -> Element<'static, Message> {
    let content = Row::new()
        .align_y(Alignment::Center)
        .spacing(6)
        .push(
            Text::new(segment.name.clone())
                .size(12)
                .color(color::TEXT)
                .width(Length::Fill),
        )
        .push(
            Text::new(if segment.executable { "x" } else { " " })
                .size(11)
                .color(color::GREEN)
                .font(MONO),
        )
        .push(
            Text::new(format!("{:#x}", segment.vma))
                .size(11)
                .color(color::MUTED)
                .font(MONO)
                .width(Length::Fixed(72.0)),
        );

    // A section that is not mapped has no address to jump to.
    if !segment.mapped {
        return content.into();
    }

    mouse_area(content)
        .on_press(Message::AddressSelected(segment.vma))
        .into()
}

/// One named piece of data.
fn symbol_row(symbol: &DataSymbolEntry) -> Element<'static, Message> {
    let content = Row::new()
        .align_y(Alignment::Center)
        .spacing(6)
        .push(
            Text::new(symbol.name.clone())
                .size(12)
                .color(color::TEXT)
                .width(Length::Fill),
        )
        .push(
            Text::new(format!("{:#x}", symbol.address))
                .size(11)
                .color(color::MUTED)
                .font(MONO)
                .width(Length::Fixed(72.0)),
        );

    mouse_area(content)
        .on_press(Message::DataSelected(symbol.address))
        .into()
}

/// The scrollable function list.
fn function_list(app: &App) -> Column<'_, Message> {
    let mut list = Column::new().spacing(1).width(Length::Fill);

    if app.navigator.rows.is_empty() {
        list = list.push(
            Column::new()
                .spacing(3)
                .push(Text::new("No functions match").size(12).color(color::MUTED))
                .push(
                    Text::new("Clear the filter to see every function.")
                        .size(11)
                        .color(color::DIM),
                ),
        );
    }

    for row in &app.navigator.rows {
        list = list.push(function_row(app, row));
    }

    list
}

/// A single function row.
fn function_row<'a>(app: &'a App, row: &'a FunctionRow) -> Element<'a, Message> {
    let selected = app.navigator.selected == Some(row.address);
    let name_color = if row.objc { color::CYAN } else { color::TEXT };

    let content = Row::new()
        .align_y(Alignment::Center)
        .spacing(6)
        .push(
            Text::new(row.name.clone())
                .size(12)
                .color(name_color)
                .width(Length::Fill),
        )
        .push(
            Text::new(row.display_address())
                .size(11)
                .color(color::MUTED)
                .font(MONO),
        );

    let surface = Container::new(content)
        .padding([5, 7])
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(if selected {
                color::SELECT_BG
            } else {
                color::PANEL
            })),
            border: Border {
                color: color::PANEL,
                width: 1.0,
                radius: 4.0.into(),
            },
            ..container::Style::default()
        });

    let element: Element<'a, Message> = mouse_area(surface)
        .on_press(Message::FunctionSelected(row.address))
        .into();

    element
}

/// The places the analyst marked, in address order.
///
/// A bookmark row shows the place's name and its address, and clicking it
/// jumps there. A place the analyst named (a label) shows that name; a
/// function entry shows the function's name; a bare address shows the
/// address.
fn bookmark_list(app: &App) -> Column<'_, Message> {
    let marked = app.annotations.bookmarks();

    if marked.is_empty() {
        return Column::new()
            .spacing(3)
            .push(Text::new("No bookmarks").size(12).color(color::MUTED))
            .push(
                Text::new("Select a place and press Ctrl+Shift+B to mark it.")
                    .size(11)
                    .color(color::DIM),
            );
    }

    let mut list = Column::new().spacing(1).width(Length::Fill);

    for annotation in marked {
        // The stored address is canonical; a place in a named space keys on
        // its value, the way every other view asks for it. A record whose
        // address parses to no value — a hand-edited file, say — is still
        // listed, so the count and the list agree, but there is nowhere to
        // jump, so its row does not press.
        let address = ag_corpus::parse_addr_space(&annotation.address)
            .map(|(value, _)| value)
            .ok();

        let selected = address.is_some_and(|address| {
            matches!(app.selection, crate::model::Selection::Address(a) if a == address)
                || app.navigator.selected == Some(address)
        });

        // A place named only by its address shows the address once.
        let name = address.map(|address| app.place_name(address));
        let shows_address = name.as_deref() != Some(annotation.address.as_str());

        let mut content = Row::new()
            .align_y(Alignment::Center)
            .spacing(6)
            .push(Text::new("★").size(11).color(color::AMBER))
            .push(
                Text::new(name.unwrap_or_else(|| annotation.address.clone()))
                    .size(12)
                    .color(color::TEXT)
                    .width(Length::Fill),
            );
        if shows_address {
            content = content.push(
                Text::new(annotation.address.clone())
                    .size(11)
                    .color(color::MUTED)
                    .font(MONO),
            );
        }

        let surface = Container::new(content)
            .padding([5, 7])
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(if selected {
                    color::SELECT_BG
                } else {
                    color::PANEL
                })),
                border: Border {
                    color: color::PANEL,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..container::Style::default()
            });

        let element: Element<'_, Message> = match address {
            Some(address) => mouse_area(surface)
                .on_press(Message::BookmarkSelected(address))
                .into(),
            None => surface.into(),
        };

        list = list.push(element);
    }

    list
}

/// The tags, each with how many functions carry it, in tag order.
///
/// Clicking a tag filters the function list to the functions carrying it,
/// the way typing `#tag` into the filter does. A tag on a place that is
/// not a function — a bare address, a block — is counted beside the row
/// in its own words, since the list cannot show it.
fn tag_list(app: &App) -> Column<'_, Message> {
    let index = &app.navigator.tags;

    if index.is_empty() {
        return Column::new()
            .spacing(3)
            .push(Text::new("No tags").size(12).color(color::MUTED))
            .push(
                Text::new("Select a place and press Ctrl+T to tag it.")
                    .size(11)
                    .color(color::DIM),
            );
    }

    let mut list = Column::new().spacing(1).width(Length::Fill);
    let active = app
        .navigator
        .filter
        .trim()
        .strip_prefix('#')
        .map(|tag| tag.trim().to_string());

    for (tag, TagCount { functions, places }) in index {
        let selected = active.as_deref() == Some(tag.as_str());

        let mut content = Row::new()
            .align_y(Alignment::Center)
            .spacing(6)
            .push(Text::new("#").size(11).color(color::PURPLE).font(MONO))
            .push(
                Text::new(tag.clone())
                    .size(12)
                    .color(color::TEXT)
                    .width(Length::Fill),
            );
        if *places > 0 {
            content = content.push(
                Text::new(format!(
                    "+{places} place{}",
                    if *places == 1 { "" } else { "s" }
                ))
                .size(11)
                .color(color::DIM),
            );
        }
        content = content.push(
            Text::new(count(*functions))
                .size(11)
                .color(color::MUTED)
                .font(MONO),
        );

        let surface = Container::new(content)
            .padding([5, 7])
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(if selected {
                    color::SELECT_BG
                } else {
                    color::PANEL
                })),
                border: Border {
                    color: color::PANEL,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..container::Style::default()
            });

        let element: Element<'_, Message> = mouse_area(surface)
            .on_press(Message::TagSelected(tag.clone()))
            .into();

        list = list.push(element);
    }

    list
}

/// The explore sections with their counts.
fn explore_list(app: &App) -> Column<'_, Message> {
    let counts = &app.navigator.counts;
    let mut list = Column::new().spacing(1).width(Length::Fill);

    for section in Section::ALL {
        // A bookmark is the analyst's own mark, not something the analysis
        // reported, so its count comes from the annotation set rather than
        // the provider's section counts.
        let total = match section {
            Section::Imports => counts.imports,
            Section::Exports => counts.exports,
            Section::Strings => counts.strings,
            Section::Segments => counts.segments,
            Section::Types => counts.types,
            Section::Bookmarks => app.annotations.bookmarks().len(),
            Section::Tags => app.navigator.tags.len(),
            Section::Functions => counts.functions,
        };

        let selected = app.navigator.section == section;

        let content: Row<'_, Message> = Row::new()
            .align_y(Alignment::Center)
            .push(
                Text::new(format!("▸ {}", section.label()))
                    .size(12)
                    .color(if selected { color::CYAN } else { color::TEXT }),
            )
            .push(Space::new().width(Length::Fill))
            .push(
                Text::new(count(total))
                    .size(11)
                    .color(color::MUTED)
                    .font(MONO),
            );

        let surface = Container::new(content)
            .padding([5, 7])
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(if selected {
                    color::SELECT_BG
                } else {
                    color::PANEL
                })),
                border: Border {
                    color: color::PANEL,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..container::Style::default()
            });

        let element: Element<'_, Message> = mouse_area(surface)
            .on_press(Message::SectionSelected(section))
            .into();

        list = list.push(element);
    }

    list
}
