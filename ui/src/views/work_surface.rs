//! The center work surface: listing, pseudocode, graph, bytes, references,
//! and the Objective-C header of an image that has one.

use std::collections::BTreeMap;

use iced::widget::{
    button, container, mouse_area, scrollable, text_input, Column, Container, Row, Space, Text,
};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{replace_words, App, Message};
use crate::data::{ByteLine, ListingLine, StringEntry};
use crate::model::Selection;
use crate::theme::{color, tinted, MONO};
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
    /// The Objective-C header recovered from the image's metadata; offered
    /// only when the image has any.
    Header,
}

impl ViewTab {
    /// Every tab, in display order.
    pub const ALL: [ViewTab; 6] = [
        ViewTab::Listing,
        ViewTab::Pseudocode,
        ViewTab::Graph,
        ViewTab::Bytes,
        ViewTab::References,
        ViewTab::Header,
    ];

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            ViewTab::Listing => "Listing",
            ViewTab::Pseudocode => "Pseudocode",
            ViewTab::Graph => "Graph",
            ViewTab::Bytes => "Bytes",
            ViewTab::References => "References",
            ViewTab::Header => "Header",
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
        .map(|d| match d.start {
            Some(start) => app.shown_name(start, &d.name),
            None => d.name.clone(),
        })
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
        // The header is offered where there is one to show.
        if tab == ViewTab::Header && app.work.objc_header.is_none() {
            continue;
        }
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
        ViewTab::Header => header_content(app),
    }
}

/// The Objective-C header view: the declarations recovered from the
/// image, one line per row, read-only.
fn header_content(app: &App) -> Element<'_, Message> {
    let Some(header) = app.work.objc_header.as_deref() else {
        return empty_state(
            "No Objective-C in this image",
            "The header is written from a Mach-O's Objective-C metadata; this image has none.",
        )
        .into();
    };
    let mut list = Column::new().spacing(0).width(Length::Fill);
    for line in header.lines() {
        list = list.push(
            Container::new(
                Text::new(line.to_string())
                    .size(12)
                    .font(MONO)
                    .color(if line.starts_with("//") {
                        color::MUTED
                    } else {
                        color::TEXT
                    }),
            )
            .padding([1, 12])
            .width(Length::Fill),
        );
    }
    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
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

    // The analyst's names, resolved once for the whole listing.
    let renamed = app.renames();
    let mut list = Column::new().spacing(0).width(Length::Fill);

    // The rows as they will stand, a comment's own row counted, so the
    // margin's arrows know which row a branch and its target are on.
    let rows = listing_rows(&app.work.listing, &renamed);
    let arrows = crate::views::arrows::Arrows::of(&rows, &app.work.graph, &app.work.listing);
    // The arrows of the focused instruction are brightened: a selected
    // function or range focuses no row, so it brightens none.
    let selected = match app.selection {
        Selection::Address(address) => Some(address),
        _ => None,
    };
    let mut row = 0;

    for line in &app.work.listing {
        // A comment the analyst chose to stand above the instruction gets
        // its own line, indented to where the operands start; an inline
        // comment rides at the end of the instruction row itself.
        if let Some(comment) = renamed
            .comment_for(line.address)
            .filter(|comment| comment.above)
        {
            list = list.push(with_margin(
                arrows.margin(row, selected),
                comment_row(&comment.text),
            ));
            row += 1;
        }
        list = list.push(with_margin(
            arrows.margin(row, selected),
            listing_row(app, line, &renamed),
        ));
        row += 1;
    }
    debug_assert_eq!(row, rows.len(), "the rows drawn are the rows counted");

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// The rows of the listing as they stand on screen: the address of the
/// instruction on each, or none for the row an analyst's comment above an
/// instruction takes. The margin's arrows and the view count rows by this
/// one rule.
pub(crate) fn listing_rows(
    listing: &[ListingLine],
    renamed: &crate::app::Renames,
) -> Vec<Option<u64>> {
    listing
        .iter()
        .flat_map(|line| {
            let above = renamed
                .comment_for(line.address)
                .is_some_and(|comment| comment.above);
            above
                .then_some(None)
                .into_iter()
                .chain(std::iter::once(Some(line.address)))
        })
        .collect()
}

/// A row of the listing with the margin's arrows beside it. The margin
/// fills the row's height, so the arrows run on from row to row.
fn with_margin<'a>(
    margin: Element<'static, Message>,
    element: Element<'a, Message>,
) -> Element<'a, Message> {
    Row::new()
        .push(margin)
        .push(Container::new(element).width(Length::Fill))
        .width(Length::Fill)
        .into()
}

/// One instruction row.
///
/// A call shows the callee by the analyst's name when it has one, so a
/// rename made once reaches the listing as it reaches every other view.
fn listing_row<'a>(
    app: &'a App,
    line: &'a ListingLine,
    renamed: &crate::app::Renames,
) -> Element<'a, Message> {
    let focused = matches!(app.selection, Selection::Address(a) if a == line.address);
    let operands = App::shown_operands(line, renamed);
    // The disassembler's own comment (what the bytes point at) and the
    // analyst's note are different things and both keep their place: the
    // disassembler's shows in its usual slot, and an inline analyst note
    // rides after it in its own color. An above-comment already has its
    // own row, so it does not repeat here.
    let analyst_inline = renamed
        .comment_for(line.address)
        .filter(|comment| !comment.above)
        .map(|comment| comment.text.clone());
    // The analyst's highlight: the line's own, its block's, or its
    // function's, mixed into the row's surface so the text stays legible.
    let tint = renamed.line_color(line.address, app.block_of(line.address));

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
                Text::new(operands)
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
            )
            .push(
                analyst_inline
                    .map(|c| {
                        Text::new(format!("; {c}"))
                            .size(12)
                            .color(color::AMBER)
                            .font(MONO)
                    })
                    .unwrap_or(Text::new("")),
            ),
    )
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(Background::Color(match (focused, tint) {
            (true, _) => color::FOCUS_BG,
            (false, Some(tint)) => tinted(color::PANEL, tint, 0.28),
            (false, None) => color::PANEL,
        })),
        border: Border {
            color: match (focused, tint) {
                (true, _) => color::CYAN,
                (false, Some(tint)) => tinted(color::PANEL, tint, 0.28),
                (false, None) => color::PANEL,
            },
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

/// A comment standing on its own line above an instruction.
///
/// The note is indented to where the operands start, so it reads as
/// belonging to the instruction below it rather than floating at the left
/// edge with the addresses.
fn comment_row(text: &str) -> Element<'static, Message> {
    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(10)
            // The operands of a listing row start at 1 (the row's border)
            // + 88 + 10 + 120 + 10 + 58 + 10 = 297. This row's own spacing
            // adds 10 before the note, so the spacer is 287 to land it on
            // that column.
            .push(Space::new().width(Length::Fixed(287.0)))
            .push(
                Text::new(format!("; {text}"))
                    .size(12)
                    .color(color::AMBER)
                    .font(MONO),
            ),
    )
    .width(Length::Fill)
    .into()
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

    // The dead-code toggle, for a program image: the engine's `dead-code`
    // option, which the toolbar line names and flips.
    let toolbar = (app.project.kind == crate::model::ProjectKind::Binary).then(|| {
        let dropping = app.options.get("dead-code").as_deref() == Some("drop");
        Container::new(
            Row::new().spacing(4).push(tab_button(
                if dropping {
                    "Dead code: hidden"
                } else {
                    "Dead code: shown"
                },
                dropping,
                Message::ToggleDeadCode,
            )),
        )
        .padding([2, 12])
        .width(Length::Fill)
    });

    if body.trim().is_empty() {
        let empty = empty_state(
            "No pseudocode for this function",
            "The provider recorded no body for this address; the Problems panel says why when it knows.",
        );
        return match toolbar {
            Some(toolbar) => Column::new().push(toolbar).push(empty).into(),
            None => empty.into(),
        };
    }

    let selection = app.selection.address();
    // The analyst's names, resolved once for the whole body rather than
    // row by row.
    let pairs = app.rename_pairs();
    // Applied in one pass, so two renames in flight at once never reach
    // into each other's output.
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(original, renamed)| (original.as_str(), renamed.as_str()))
        .collect();
    // The analyst's comments, so a note made at an address shows on the
    // pseudocode line that maps to it. A line maps to several addresses;
    // the first that carries a note wins, in the order the addresses come.
    let renamed = app.renames();
    let mut list = Column::new().spacing(0).width(Length::Fill);

    for (index, line) in body.lines().enumerate() {
        let addresses = app.work.line_addresses.get(&index).cloned();
        let comment = addresses
            .as_ref()
            .and_then(|addresses| addresses.iter().find_map(|a| renamed.comment_for(*a)));
        let text = replace_words(line, &pairs);
        // An above-comment stands on its own line over the one it maps to;
        // an inline note rides at the end of it.
        if let Some(note) = comment.filter(|note| note.above) {
            list = list.push(pseudocode_comment_row(&note.text));
        }
        let shown = match comment.filter(|note| !note.above) {
            Some(note) => format!("{text}  ; {}", note.text),
            None => text,
        };
        list = list.push(pseudocode_row(index, shown, addresses, selection));
    }

    let body = scrollable(list).height(Length::Fill).width(Length::Fill);
    match toolbar {
        Some(toolbar) => Column::new().push(toolbar).push(body).into(),
        None => body.into(),
    }
}

/// A comment standing on its own line above a pseudocode line.
///
/// The line number is left blank: the note belongs to the numbered line
/// below it, and repeating the number would read as two lines of code.
fn pseudocode_comment_row(text: &str) -> Element<'static, Message> {
    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(10)
            .push(
                Text::new(" ".repeat(4))
                    .size(11)
                    .color(color::DIM)
                    .font(MONO)
                    .width(Length::Fixed(38.0)),
            )
            .push(
                Text::new(format!("; {text}"))
                    .size(12)
                    .color(color::AMBER)
                    .font(MONO)
                    .width(Length::Fill),
            ),
    )
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

    if app.work.graph.blocks.is_empty() {
        return empty_state(
            "This function has no control flow to draw",
            "Select a function that the analysis has walked to see its blocks.",
        )
        .into();
    }

    crate::views::graph::view(app)
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

    hex_dump(app, &app.work.bytes)
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

    reference_table(app)
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
                hex_dump(app, &app.work.bytes)
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
                reference_table(app)
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
///
/// The bytes of the selected instruction are marked, so the reader can see
/// which bytes of the row the selection covers.
fn hex_dump<'a>(app: &'a App, rows: &'a [ByteLine]) -> Element<'a, Message> {
    let selected = selected_instruction(app);
    // The bytes the analyst wrote: shown in the analyst's color, so a
    // patch is told from the file's own bytes at a glance.
    let patched: Vec<(u64, usize)> = app
        .annotations
        .patches()
        .into_iter()
        .map(|(at, bytes)| (at, bytes.len()))
        .collect();
    let mut list = Column::new().spacing(0).width(Length::Fill);

    for row in rows {
        list = list.push(hex_row(row, selected, &patched));
    }

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// The bytes of the selected instruction, as an address and a length.
///
/// The listing knows how long each instruction is, so the byte pane can
/// mark the bytes of the instruction the selection sits on.
fn selected_instruction(app: &App) -> Option<(u64, usize)> {
    let address = app.selection.address()?;
    let line = app
        .work
        .listing
        .iter()
        .find(|line| line.address == address)?;
    let length = line.bytes.split_whitespace().count();

    (length > 0).then_some((address, length))
}

/// One row of the hex dump.
fn hex_row<'a>(
    row: &'a ByteLine,
    selected: Option<(u64, usize)>,
    patched: &[(u64, usize)],
) -> Element<'a, Message> {
    let mut hex = Row::new().spacing(0);

    for (index, byte) in row.bytes.iter().enumerate() {
        let address = row.address + index as u64;
        let marked = selected
            .is_some_and(|(start, length)| address >= start && address < start + length as u64);
        let written = patched
            .iter()
            .any(|&(start, length)| address >= start && address < start + length as u64);

        // A byte is picked by clicking it, so Edit bytes… starts there.
        hex = hex.push(
            mouse_area(
                Container::new(
                    Text::new(format!("{byte:02X}"))
                        .size(12)
                        .color(if marked {
                            color::CYAN
                        } else if written {
                            color::AMBER
                        } else {
                            color::BYTES
                        })
                        .font(MONO),
                )
                .width(Length::Fixed(21.0))
                .style(move |_| container::Style {
                    background: if marked {
                        Some(Background::Color(color::FOCUS_BG))
                    } else {
                        None
                    },
                    ..container::Style::default()
                }),
            )
            .on_press(Message::AddressSelected(address)),
        );
    }

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
            .push(hex)
            .push(Text::new(ascii).size(12).color(color::DIM).font(MONO)),
    )
    .width(Length::Fill)
    .into()
}

/// A table of the strings the binary holds.
///
/// The strings the selected function refers to come first: those are the ones
/// in view. When the function refers to none, every string is listed. The
/// filter narrows the list as it is typed.
fn string_table(app: &App) -> Element<'_, Message> {
    let strings = app.provider.strings();

    if strings.is_empty() {
        return empty_state(
            "No strings in view",
            "The binary holds no strings the analysis could name.",
        )
        .into();
    }

    let filter = app.work.string_filter.trim().to_lowercase();
    let matching: Vec<&StringEntry> = strings
        .iter()
        .filter(|string| filter.is_empty() || string.text.to_lowercase().contains(&filter))
        .collect();

    let selected = app.navigator.selected;
    let referenced: Vec<&StringEntry> = matching
        .iter()
        .copied()
        .filter(|string| selected.is_some_and(|address| string.functions.contains(&address)))
        .collect();

    let (rows, note): (Vec<&StringEntry>, &str) = if referenced.is_empty() {
        (matching, "Every string the binary holds")
    } else {
        (referenced, "The strings this function refers to")
    };

    // The names of the functions, so a string can say who uses it.
    let names: BTreeMap<u64, String> = app
        .provider
        .functions()
        .into_iter()
        .map(|row| (row.address, row.name))
        .collect();

    let mut list = Column::new().spacing(4).width(Length::Fill);
    list = list.push(string_filter(app));
    list = list.push(subtle(note));

    if rows.is_empty() {
        list = list.push(subtle("No string matches the filter."));
    }

    for string in rows {
        let users: Vec<String> = string
            .functions
            .iter()
            .filter_map(|address| names.get(address).cloned())
            .collect();

        let selected = app.selection.address() == Some(string.address);
        list = list.push(string_row(selected, string, users));
    }

    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// The filter of the strings list.
fn string_filter(app: &App) -> Element<'_, Message> {
    text_input::TextInput::new("Filter strings…", &app.work.string_filter)
        .on_input(Message::StringFilterChanged)
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

/// One string in the strings list.
fn string_row(
    selected: bool,
    string: &StringEntry,
    users: Vec<String>,
) -> Element<'static, Message> {
    let content = Row::new()
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
        .push(subtle(users.join(", ")))
        .push(subtle(string.section.clone().unwrap_or_default()))
        // The scrollbar of the list lies over the right edge, so the last
        // column is kept clear of it.
        .push(Space::new().width(Length::Fixed(16.0)));

    let surface = Container::new(content)
        .padding([2, 0])
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

    mouse_area(surface)
        .on_press(Message::StringSelected(string.address))
        .into()
}

/// A table of cross references.
fn reference_table(app: &App) -> Element<'_, Message> {
    let labels = app.shown_reference_labels(&app.work.references);
    let mut list = Column::new().spacing(2).width(Length::Fill);

    for (reference, label) in app.work.references.iter().zip(labels) {
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
                .push(Text::new(label).size(12).color(color::BLUE))
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
