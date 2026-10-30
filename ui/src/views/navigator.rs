//! The left navigator: project identity, filter, function list, explore sections.

use iced::widget::{
    container, mouse_area, scrollable, text_input, Column, Container, Row, Space, Text,
};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
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
        }
    }

    /// The order the sections appear in the explore list.
    pub const ALL: [Section; 6] = [
        Section::Imports,
        Section::Exports,
        Section::Strings,
        Section::Segments,
        Section::Types,
        Section::Bookmarks,
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
    text_input::TextInput::new("Filter functions…", &app.navigator.filter)
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
/// The Segments section lists the sections of the program image; every other
/// section lists the functions.
fn list_heading(app: &App) -> &'static str {
    if app.navigator.section == Section::Segments {
        "Segments"
    } else {
        "Functions"
    }
}

/// How many rows the navigator's list holds.
fn list_count(app: &App) -> usize {
    if app.navigator.section == Section::Segments {
        app.provider.segments().len() + app.provider.data_symbols().len()
    } else {
        app.navigator.rows.len()
    }
}

/// The list the navigator shows.
///
/// The Segments section holds the sections of the program image; every other
/// section holds the functions.
fn list_contents(app: &App) -> Column<'_, Message> {
    if app.navigator.section == Section::Segments {
        return segment_list(app);
    }

    function_list(app)
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

/// The explore sections with their counts.
fn explore_list(app: &App) -> Column<'_, Message> {
    let counts = &app.navigator.counts;
    let mut list = Column::new().spacing(1).width(Length::Fill);

    for section in Section::ALL {
        let total = match section {
            Section::Imports => counts.imports,
            Section::Exports => counts.exports,
            Section::Strings => counts.strings,
            Section::Segments => counts.segments,
            Section::Types => counts.types,
            Section::Bookmarks => counts.bookmarks,
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
