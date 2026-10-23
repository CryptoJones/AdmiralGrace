//! The center work surface: listing, pseudocode, graph, bytes, references.

use iced::widget::{
    button, container, mouse_area, scrollable, Column, Container, Row, Space, Text,
};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
use crate::data::{ByteLine, ListingLine, Reference};
use crate::model::Selection;
use crate::theme::{color, MONO};
use crate::views::{empty_state, pill, subtle};

/// The top tabs of the work surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewTab {
    /// Linear disassembly.
    #[default]
    Listing,
    /// Decompiled pseudocode.
    Pseudocode,
    /// Control-flow graph.
    Graph,
    /// Raw bytes.
    Bytes,
    /// Cross references.
    References,
}

impl ViewTab {
    /// Every tab, in display order.
    pub const ALL: [ViewTab; 5] = [
        ViewTab::Listing,
        ViewTab::Pseudocode,
        ViewTab::Graph,
        ViewTab::Bytes,
        ViewTab::References,
    ];

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            ViewTab::Listing => "Listing",
            ViewTab::Pseudocode => "Pseudocode",
            ViewTab::Graph => "Graph",
            ViewTab::Bytes => "Bytes",
            ViewTab::References => "References",
        }
    }
}

/// The lower tabs of the work surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LowerTab {
    /// Nearby bytes.
    #[default]
    Bytes,
    /// Strings in view.
    Strings,
    /// References in view.
    References,
    /// Diagnostics.
    Problems,
}

impl LowerTab {
    /// Every tab, in display order.
    pub const ALL: [LowerTab; 4] = [
        LowerTab::Bytes,
        LowerTab::Strings,
        LowerTab::References,
        LowerTab::Problems,
    ];

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            LowerTab::Bytes => "Bytes",
            LowerTab::Strings => "Strings",
            LowerTab::References => "References",
            LowerTab::Problems => "Problems",
        }
    }
}

/// Build the work surface.
pub fn view(app: &App) -> Element<'_, Message> {
    Container::new(
        Column::new()
            .push(file_bar(app))
            .push(view_tabs(app))
            .push(
                container(main_content(app))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .padding([10, 0]),
            )
            .push(lower_tabs(app))
            .push(
                container(lower_content(app))
                    .width(Length::Fill)
                    .height(Length::Fixed(150.0))
                    .padding([0, 12]),
            ),
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

/// The header showing the current location.
fn file_bar(app: &App) -> Element<'_, Message> {
    let detail = app.work.detail.as_ref();

    let name = detail
        .map(|d| d.name.clone())
        .unwrap_or_else(|| "No selection".to_string());
    let address = detail.and_then(|d| d.start);
    let size = detail
        .and_then(|d| d.end.zip(d.start))
        .map(|(end, start)| format!("size {:#x}", end - start));
    let status = detail.map(|d| d.status.clone()).unwrap_or_default();

    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(14)
            .push(Text::new(name).size(13).color(color::TEXT))
            .push(
                address
                    .map(|a| {
                        Text::new(format!("{a:#x}"))
                            .size(12)
                            .color(color::MUTED)
                            .font(MONO)
                    })
                    .unwrap_or(Text::new("")),
            )
            .push(
                size.map(|s| Text::new(s).size(12).color(color::MUTED).font(MONO))
                    .unwrap_or(Text::new("")),
            )
            .push(pill(status.clone(), color::GREEN))
            .push(Space::new().width(Length::Fill))
            .push(history_button(
                "← Back",
                app.history.can_go_back(),
                Message::Back,
            ))
            .push(history_button(
                "Forward →",
                app.history.can_go_forward(),
                Message::Forward,
            ))
            .push(pin_button(app)),
    )
    .padding([9, 13])
    .width(Length::Fill)
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

/// The top tab strip.
fn view_tabs(app: &App) -> Element<'_, Message> {
    let mut row = Row::new().spacing(4);

    for tab in ViewTab::ALL {
        row = row.push(tab_button(
            tab.label(),
            app.work.tab == tab,
            Message::ViewTabSelected(tab),
        ));
    }

    row = row.push(Space::new().width(Length::Fill));

    Container::new(row)
        .padding([0, 12])
        .width(Length::Fill)
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

/// The content of the active top tab.
fn main_content(app: &App) -> Element<'_, Message> {
    match app.work.tab {
        ViewTab::Listing => listing_content(app),
        ViewTab::Pseudocode => pseudocode_content(app),
        ViewTab::Graph => graph_content(app),
        ViewTab::Bytes => bytes_content(app),
        ViewTab::References => references_content(app),
    }
}

/// The linear listing.
fn listing_content(app: &App) -> Element<'_, Message> {
    if !app.capabilities.listing {
        return empty_state(
            "Listing is not available for this project",
            "The active provider produces decompiled output, not a linear disassembly.",
        )
        .into();
    }

    if app.work.listing.is_empty() {
        return empty_state(
            "No listing for this selection",
            "Select a function with a decoded body to see its instructions.",
        )
        .into();
    }

    let mut list = Column::new().spacing(0).width(Length::Fill);

    for line in &app.work.listing {
        list = list.push(listing_row(app, line));
    }

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// One instruction row.
fn listing_row<'a>(app: &'a App, line: &'a ListingLine) -> Element<'a, Message> {
    let focused = matches!(app.selection, Selection::Address(a) if a == line.address);

    let row = Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(10)
            .push(
                Text::new(format!("{:08X}", line.address))
                    .size(12)
                    .color(color::ADDR)
                    .font(MONO)
                    .width(Length::Fixed(88.0)),
            )
            .push(
                Text::new(line.bytes.clone())
                    .size(12)
                    .color(color::BYTES)
                    .font(MONO)
                    .width(Length::Fixed(120.0)),
            )
            .push(
                Text::new(line.mnemonic.clone())
                    .size(12)
                    .color(color::PURPLE)
                    .font(MONO)
                    .width(Length::Fixed(58.0)),
            )
            .push(
                Text::new(line.operands.clone())
                    .size(12)
                    .color(color::TEXT)
                    .font(MONO),
            )
            .push(
                line.comment
                    .clone()
                    .map(|c| {
                        Text::new(format!("; {c}"))
                            .size(12)
                            .color(color::DIM)
                            .font(MONO)
                    })
                    .unwrap_or(Text::new("")),
            ),
    )
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(if focused {
            color::FOCUS_BG
        } else {
            color::PANEL
        })),
        border: Border {
            color: if focused { color::CYAN } else { color::PANEL },
            width: 1.0,
            radius: 0.0.into(),
        },
        ..container::Style::default()
    });

    let element: Element<'a, Message> = mouse_area(row)
        .on_press(Message::AddressSelected(line.address))
        .into();

    element
}

/// The pseudocode view.
fn pseudocode_content(app: &App) -> Element<'_, Message> {
    if !app.capabilities.pseudocode {
        return empty_state(
            "Pseudocode is not available for this project",
            "This provider does not produce decompiled output.",
        )
        .into();
    }

    let body = app.work.pseudocode.clone().unwrap_or_default();

    if body.trim().is_empty() {
        return empty_state(
            "No pseudocode for this function",
            "The provider recorded no body for this address.",
        )
        .into();
    }

    let selection = app.selection.address();
    let mut list = Column::new().spacing(0).width(Length::Fill);

    for (index, line) in body.lines().enumerate() {
        let addresses = app.work.line_addresses.get(&index).cloned();
        list = list.push(pseudocode_row(
            index,
            line.to_string(),
            addresses,
            selection,
        ));
    }

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// One line of pseudocode.
///
/// A line that kuna mapped to addresses can be clicked, which moves the
/// selection to the first of them; a line that holds the selection is
/// highlighted, so the listing and the pseudocode stay in step.
fn pseudocode_row(
    index: usize,
    line: String,
    addresses: Option<Vec<u64>>,
    selection: Option<u64>,
) -> Element<'static, Message> {
    let focused = addresses
        .as_ref()
        .is_some_and(|addresses| selection.is_some_and(|address| addresses.contains(&address)));

    let row = Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(10)
            .push(
                Text::new(format!("{:4}", index + 1))
                    .size(11)
                    .color(color::DIM)
                    .font(MONO)
                    .width(Length::Fixed(38.0)),
            )
            .push(
                Text::new(line)
                    .size(12)
                    .color(color::TEXT)
                    .font(MONO)
                    .width(Length::Fill),
            ),
    )
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(if focused {
            color::FOCUS_BG
        } else {
            color::PANEL
        })),
        border: Border {
            color: if focused { color::CYAN } else { color::PANEL },
            width: 1.0,
            radius: 0.0.into(),
        },
        ..container::Style::default()
    });

    let address = addresses.and_then(|addresses| addresses.first().copied());

    match address {
        Some(address) => mouse_area(row)
            .on_press(Message::AddressSelected(address))
            .into(),
        None => row.into(),
    }
}

/// The control-flow graph view.
fn graph_content(app: &App) -> Element<'_, Message> {
    if !app.capabilities.graph {
        return empty_state(
            "Control flow is not available for this project",
            "This provider does not produce a control-flow graph.",
        )
        .into();
    }

    empty_state(
        "The graph view is not implemented yet",
        "Use the listing to move through this function until the graph lands.",
    )
    .into()
}

/// The byte view.
fn bytes_content(app: &App) -> Element<'_, Message> {
    if !app.capabilities.bytes {
        return empty_state(
            "Raw bytes are not available for this project",
            "Byte access needs the binary pipeline; a corpus only holds decompiled output.",
        )
        .into();
    }

    if app.work.bytes.is_empty() {
        return empty_state(
            "No bytes for this selection",
            "Select a function inside the binary to inspect its bytes.",
        )
        .into();
    }

    hex_dump(&app.work.bytes)
}

/// The reference view.
fn references_content(app: &App) -> Element<'_, Message> {
    if !app.capabilities.references {
        return empty_state(
            "Cross references are not available for this project",
            "Reference data is produced by the binary pipeline.",
        )
        .into();
    }

    if app.provider.references_pending() {
        return empty_state(
            "Indexing the cross references",
            "The whole program is being read to find who calls what.",
        )
        .into();
    }

    if app.work.references.is_empty() {
        return empty_state(
            "No cross references",
            "Nothing in this project refers to the current selection.",
        )
        .into();
    }

    reference_table(&app.work.references)
}

/// The lower tab strip.
fn lower_tabs(app: &App) -> Element<'_, Message> {
    let mut row = Row::new().spacing(16);

    for tab in LowerTab::ALL {
        row = row.push(tab_button(
            tab.label(),
            app.work.lower == tab,
            Message::LowerTabSelected(tab),
        ));
    }

    row = row.push(Space::new().width(Length::Fill));

    Container::new(row)
        .padding([0, 12])
        .width(Length::Fill)
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

/// The content of the active lower tab.
fn lower_content(app: &App) -> Element<'_, Message> {
    match app.work.lower {
        LowerTab::Bytes => {
            if app.work.bytes.is_empty() {
                empty_state(
                    "No bytes in view",
                    "Select a location to load nearby bytes.",
                )
                .into()
            } else {
                hex_dump(&app.work.bytes)
            }
        }
        LowerTab::Strings => {
            if !app.capabilities.strings {
                empty_state(
                    "Strings are not available for this project",
                    "The active provider does not extract strings.",
                )
                .into()
            } else {
                string_table(app)
            }
        }
        LowerTab::References => {
            if app.provider.references_pending() {
                empty_state(
                    "Indexing the cross references",
                    "The whole program is being read to find who calls what.",
                )
                .into()
            } else if app.work.references.is_empty() {
                empty_state("No references in view", "Nothing refers to this selection.").into()
            } else {
                reference_table(&app.work.references)
            }
        }
        LowerTab::Problems => {
            let problems = app.bottom.problems.clone();
            if problems.is_empty() {
                empty_state(
                    "No problems reported",
                    "The analysis did not report any diagnostics.",
                )
                .into()
            } else {
                problem_list(problems)
            }
        }
    }
}

/// A hex dump of the given rows.
fn hex_dump(rows: &[ByteLine]) -> Element<'_, Message> {
    let mut list = Column::new().spacing(0).width(Length::Fill);

    for row in rows {
        let hex = row
            .bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii: String = row
            .bytes
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();

        list = list.push(
            Container::new(
                Row::new()
                    .align_y(Alignment::Center)
                    .spacing(14)
                    .push(
                        Text::new(format!("{:08X}", row.address))
                            .size(12)
                            .color(color::ADDR)
                            .font(MONO)
                            .width(Length::Fixed(88.0)),
                    )
                    .push(
                        Text::new(hex)
                            .size(12)
                            .color(color::BYTES)
                            .font(MONO)
                            .width(Length::Fixed(360.0)),
                    )
                    .push(Text::new(ascii).size(12).color(color::DIM).font(MONO)),
            )
            .width(Length::Fill),
        );
    }

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// A table of the strings the binary holds.
///
/// The strings the selected function refers to come first: those are the ones
/// in view. When the function refers to none, every string is listed.
fn string_table(app: &App) -> Element<'_, Message> {
    let strings = app.provider.strings();

    if strings.is_empty() {
        return empty_state(
            "No strings in view",
            "The binary holds no strings the analysis could name.",
        )
        .into();
    }

    let selected = app.navigator.selected;
    let referenced: Vec<_> = strings
        .iter()
        .filter(|string| selected.is_some_and(|address| string.functions.contains(&address)))
        .collect();

    let (rows, note): (Vec<_>, &str) = if referenced.is_empty() {
        (strings.iter().collect(), "Every string the binary holds")
    } else {
        (referenced, "The strings this function refers to")
    };

    let mut list = Column::new().spacing(4).width(Length::Fill);
    list = list.push(subtle(note));

    for string in rows {
        list = list.push(
            Row::new()
                .align_y(Alignment::Center)
                .spacing(12)
                .push(
                    Text::new(format!("{:#x}", string.address))
                        .size(11)
                        .color(color::MUTED)
                        .font(MONO)
                        .width(Length::Fixed(96.0)),
                )
                .push(
                    Text::new(string.text.clone())
                        .size(12)
                        .color(color::TEXT)
                        .font(MONO),
                )
                .push(Space::new().width(Length::Fill))
                .push(subtle(string.section.clone().unwrap_or_default())),
        );
    }

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// A table of cross references.
fn reference_table(references: &[Reference]) -> Element<'_, Message> {
    let mut list = Column::new().spacing(2).width(Length::Fill);

    for reference in references {
        list = list.push(
            Row::new()
                .align_y(Alignment::Center)
                .spacing(12)
                .push(
                    Text::new(format!("{:#x}", reference.address))
                        .size(11)
                        .color(color::MUTED)
                        .font(MONO)
                        .width(Length::Fixed(96.0)),
                )
                .push(
                    Text::new(reference.label.clone())
                        .size(12)
                        .color(color::BLUE),
                )
                .push(Space::new().width(Length::Fill))
                .push(subtle(reference.kind.label())),
        );
    }

    list.into()
}

/// A list of diagnostics.
fn problem_list(problems: Vec<crate::data::Problem>) -> Element<'static, Message> {
    let mut list = Column::new().spacing(6).width(Length::Fill);

    for problem in problems {
        let mut column = Column::new().spacing(2);
        column = column.push(
            Text::new(problem.message.clone())
                .size(12)
                .color(color::TEXT),
        );

        if let Some(address) = problem.address {
            column = column.push(
                Text::new(format!("{address:#x}"))
                    .size(11)
                    .color(color::MUTED)
                    .font(MONO),
            );
        }

        if let Some(action) = &problem.action {
            column = column.push(subtle(action.clone()));
        }

        list = list.push(column);
    }

    list.into()
}

/// A tab-styled button.
fn tab_button(label: &str, active: bool, message: Message) -> Element<'_, Message> {
    button::Button::new(Text::new(label.to_string()).size(12).color(if active {
        color::CYAN
    } else {
        color::MUTED
    }))
    .on_press(message)
    .padding([8, 10])
    .style(move |_, status| button::Style {
        background: match status {
            button::Status::Hovered | button::Status::Pressed => {
                Some(Background::Color(color::PANEL_ALT))
            }
            button::Status::Active => Some(Background::Color(color::PANEL_ALT)),
            button::Status::Disabled => None,
        },
        text_color: if active { color::CYAN } else { color::MUTED },
        border: Border {
            color: if active { color::CYAN } else { color::PANEL },
            width: 1.0,
            radius: 4.0.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// A history navigation button.
fn history_button(label: &str, enabled: bool, message: Message) -> Element<'_, Message> {
    let mut button = button::Button::new(Text::new(label.to_string()).size(12)).padding([6, 10]);

    if enabled {
        button = button.on_press(message);
    }

    button
        .style(|_, status| button::Style {
            background: match status {
                button::Status::Hovered | button::Status::Pressed => {
                    Some(Background::Color(color::PANEL_ALT))
                }
                _ => None,
            },
            text_color: match status {
                button::Status::Disabled => color::DIM,
                _ => color::MUTED,
            },
            border: Border {
                color: color::LINE,
                width: 1.0,
                radius: 5.0.into(),
            },
            ..button::Style::default()
        })
        .into()
}

/// The pin toggle.
fn pin_button(app: &App) -> Element<'_, Message> {
    let label = if app.work.pinned {
        "◉ Pinned"
    } else {
        "○ Pin"
    };

    button::Button::new(
        Text::new(label.to_string())
            .size(12)
            .color(if app.work.pinned {
                color::CYAN
            } else {
                color::MUTED
            }),
    )
    .on_press(Message::TogglePin)
    .padding([6, 10])
    .style(|_, status| button::Style {
        background: match status {
            button::Status::Hovered | button::Status::Pressed => {
                Some(Background::Color(color::PANEL_ALT))
            }
            _ => None,
        },
        text_color: color::MUTED,
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 5.0.into(),
        },
        ..button::Style::default()
    })
    .into()
}
