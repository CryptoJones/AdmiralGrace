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
    /// The debugger: the program under it, its registers, stack and memory.
    Debug,
}

impl LowerTab {
    /// Every tab, in display order.
    pub const ALL: [LowerTab; 5] = [
        LowerTab::Bytes,
        LowerTab::Strings,
        LowerTab::References,
        LowerTab::Problems,
        LowerTab::Debug,
    ];

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            LowerTab::Bytes => "Bytes",
            LowerTab::Strings => "Strings",
            LowerTab::References => "References",
            LowerTab::Problems => "Problems",
            LowerTab::Debug => "Debug",
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

    // The level the pane shows, when it is not the disassembly.
    let level = match app.work.tab {
        ViewTab::Listing => Some(app.work.listing_shown),
        ViewTab::Graph => Some(app.work.graph_shown),
        _ => None,
    };
    if let Some(level) = level.filter(|level| *level != crate::app::PaneLevel::Disassembly) {
        row = row.push(
            Container::new(Text::new(level.label()).size(11).color(color::AMBER))
                .padding([4, 8])
                .center_y(Length::Fill),
        );
    }

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
    let arrows = arrows_for(app, &rows);
    // The arrows of the focused instruction are brightened: a selected
    // function or range focuses no row, so it brightens none.
    let selected = match app.selection {
        Selection::Address(address) => Some(address),
        _ => None,
    };
    let mut row = 0;
    let mut previous = None;

    for line in &app.work.listing {
        // Several rows of a level can come from one instruction: what
        // belongs to the instruction — its comment, its marks — is drawn on
        // the first of them.
        let first = previous != Some(line.address);
        previous = Some(line.address);
        // A comment the analyst chose to stand above the instruction gets
        // its own line, indented to where the operands start; an inline
        // comment rides at the end of the instruction row itself.
        if let Some(comment) = renamed
            .comment_for(line.address)
            .filter(|comment| first && comment.above)
        {
            list = list.push(with_margin(
                arrows.margin(row, selected, crate::views::arrows::Marks::default()),
                comment_row(&comment.text),
            ));
            row += 1;
        }
        // The debugger's marks on the instruction's row.
        let marks = crate::views::arrows::Marks {
            address: first.then_some(line.address),
            breakpoint: first && app.debug.breakpoints.contains(&line.address),
            at_pc: first && app.debug.pc == Some(line.address),
        };
        list = list.push(with_margin(
            arrows.margin(row, selected, marks),
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
    let mut previous = None;
    listing
        .iter()
        .flat_map(|line| {
            let first = previous != Some(line.address);
            previous = Some(line.address);
            let above = first
                && renamed
                    .comment_for(line.address)
                    .is_some_and(|comment| comment.above);
            above
                .then_some(None)
                .into_iter()
                .chain(std::iter::once(Some(line.address)))
        })
        .collect()
}

/// The margin's arrows for the listing as it stands: from the disassembly's
/// graph, for the disassembly and the lifted level, whose rows are the
/// instructions; none for a level whose rows are statements, several to an
/// instruction.
pub(crate) fn arrows_for(app: &App, rows: &[Option<u64>]) -> crate::views::arrows::Arrows {
    match app.work.listing_shown {
        crate::app::PaneLevel::Disassembly
        | crate::app::PaneLevel::Il {
            level: ag_image::Level::Lifted,
            ..
        } => crate::views::arrows::Arrows::of(rows, &app.work.graph, &app.work.listing),
        crate::app::PaneLevel::Il { .. } => {
            crate::views::arrows::Arrows::of(rows, &crate::data::Graph::default(), &[])
        }
    }
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
    // How the text is decorated: braces colored by depth, guides down the
    // indented blocks, by the engine's indent.
    let decor = Decor {
        rainbow: app.rainbow_braces,
        guides: app.indent_guides,
        indent: app
            .options
            .get("indent")
            .and_then(|indent| indent.parse().ok())
            .unwrap_or(2),
    };
    let mut depth = 0usize;

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
        // A line outside the slice on screen is dimmed as dead code is.
        let dead = app.work.dead_lines.contains(&index)
            || app
                .work
                .slice
                .as_ref()
                .is_some_and(|slice| slice.dims(index));
        let spans = spans(&shown, dead, &decor, &mut depth);
        list = list.push(pseudocode_row(index, spans, addresses, selection));
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
    spans: Vec<(String, iced::Color)>,
    addresses: Option<Vec<u64>>,
    selection: Option<u64>,
) -> Element<'static, Message> {
    let mut text = Row::new().width(Length::Fill);
    for (piece, color) in spans {
        text = text.push(Text::new(piece).size(12).color(color).font(MONO));
    }
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
            .push(text),
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
            .on_press(Message::PseudocodeLineSelected(index, address))
            .into(),
        None => row.into(),
    }
}

/// How a line of pseudocode is decorated beyond its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decor {
    /// Braces colored by their depth.
    pub rainbow: bool,
    /// A guide down each indented block.
    pub guides: bool,
    /// The spaces one level is indented by.
    pub indent: usize,
}

/// The colors the braces cycle through, by depth.
const BRACE_COLORS: [iced::Color; 6] = [
    color::CYAN,
    color::AMBER,
    color::PURPLE,
    color::GREEN,
    color::BLUE,
    color::RED,
];

/// The pieces of one line of pseudocode with their colors: the text in
/// `base` — dimmed when the line is dead code — the leading indentation
/// as guides when asked, and each brace in its depth's color when asked.
/// `depth` is the brace depth at the line's start, and is left at its end,
/// so the lines are decorated in order.
pub fn spans(line: &str, dead: bool, decor: &Decor, depth: &mut usize) -> Vec<(String, iced::Color)> {
    let base = if dead { color::DIM } else { color::TEXT };
    let mut spans: Vec<(String, iced::Color)> = Vec::new();
    let push = |text: String, color: iced::Color, spans: &mut Vec<(String, iced::Color)>| {
        if text.is_empty() {
            return;
        }
        match spans.last_mut() {
            Some((last, last_color)) if *last_color == color => last.push_str(&text),
            _ => spans.push((text, color)),
        }
    };
    let leading = line.len() - line.trim_start_matches(' ').len();
    let rest = &line[leading..];
    // A closing brace at the line's start closes the depth it was opened at.
    let closes_first = rest.starts_with('}');
    if closes_first {
        *depth = depth.saturating_sub(1);
    }
    if decor.guides && decor.indent > 0 && leading >= decor.indent {
        let levels = leading / decor.indent;
        let mut guides = String::new();
        for _ in 0..levels {
            guides.push('│');
            guides.push_str(&" ".repeat(decor.indent - 1));
        }
        push(guides, color::LINE, &mut spans);
        push(" ".repeat(leading - levels * decor.indent), base, &mut spans);
    } else {
        push(" ".repeat(leading), base, &mut spans);
    }
    if !decor.rainbow {
        push(rest.to_string(), base, &mut spans);
        if !closes_first {
            // Keep the depth in step for the lines after.
            for c in rest.chars() {
                match c {
                    '{' => *depth += 1,
                    '}' => *depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
        } else {
            for c in rest.chars().skip(1) {
                match c {
                    '{' => *depth += 1,
                    '}' => *depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        return spans;
    }
    let mut plain = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut first = true;
    for (i, c) in rest.char_indices() {
        // A comment is text to its end, braces and all.
        if !quoted && rest[i..].starts_with("//") {
            plain.push_str(&rest[i..]);
            break;
        }
        let brace = !quoted && (c == '{' || c == '}');
        if quoted && escaped {
            escaped = false;
        } else if quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        }
        if brace {
            push(std::mem::take(&mut plain), base, &mut spans);
            let level = if c == '{' {
                let level = *depth;
                *depth += 1;
                level
            } else if first && closes_first {
                *depth
            } else {
                *depth = depth.saturating_sub(1);
                *depth
            };
            let color = if dead {
                color::DIM
            } else {
                BRACE_COLORS[level % BRACE_COLORS.len()]
            };
            push(c.to_string(), color, &mut spans);
        } else {
            plain.push(c);
        }
        first = false;
    }
    push(plain, base, &mut spans);
    spans
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

    if app.work.shown_graph().blocks.is_empty() {
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
        LowerTab::Debug => debug_panel(app),
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

/// The Debug panel: the program under the debugger, the controls, and
/// what it showed when it last stopped.
fn debug_panel(app: &App) -> Element<'_, Message> {
    use crate::debug::Status;
    let debug = &app.debug;
    let stopped = debug.is_stopped();
    let running = debug.is_running();
    let off = debug.session.is_none();
    let control =
        |label: &'static str, message: Message, enabled: bool| -> Element<'static, Message> {
            let mut button = button(Text::new(label).size(12)).padding([4, 10]);
            if enabled {
                button = button.on_press(message);
            }
            button.into()
        };
    let controls = Row::new()
        .spacing(6)
        .align_y(Alignment::Center)
        .push(control(
            "Start",
            Message::DebugStart,
            off || matches!(debug.status, Status::Exited(_)),
        ))
        .push(control(
            "Attach…",
            Message::DebugAttach,
            off || matches!(debug.status, Status::Exited(_)),
        ))
        .push(control("Continue", Message::DebugContinue, stopped))
        .push(control("Step into", Message::DebugStep, stopped))
        .push(control("Step over", Message::DebugNext, stopped))
        .push(control("Finish", Message::DebugFinish, stopped))
        .push(control("Interrupt", Message::DebugInterrupt, running))
        .push(control("Stop", Message::DebugStop, !off))
        .push(control(
            "Breakpoint",
            Message::DebugToggleBreakpoint(None),
            app.selection.address().is_some() || app.work.listing_of.is_some(),
        ));
    let status = match debug.status {
        Status::Off => "No debugger is running. Start runs the program under the debugger, stopped at its first instruction; a click in the listing's margin sets a breakpoint.".to_string(),
        Status::Running => "Running…".to_string(),
        Status::Stopped => match debug.pc {
            Some(pc) => format!(
                "Stopped at {pc:#x}{}",
                app.provider
                    .functions()
                    .iter()
                    .filter(|row| row.address <= pc)
                    .max_by_key(|row| row.address)
                    .filter(|row| {
                        row.size
                            .is_none_or(|size| pc < row.address.saturating_add(size))
                    })
                    .map(|row| format!(" ({}+{:#x})", row.name, pc - row.address))
                    .unwrap_or_default()
            ),
            None => "Stopped outside the image".to_string(),
        },
        Status::Exited(Some(code)) => format!("The program exited with code {code}."),
        Status::Exited(None) => "The program ended.".to_string(),
    };
    let mut column = Column::new()
        .spacing(8)
        .padding(8)
        .push(controls)
        .push(Text::new(status).size(12).color(color::TEXT));
    if !debug.breakpoints.is_empty() {
        let list: Vec<String> = debug
            .breakpoints
            .iter()
            .map(|a| format!("{a:#x}"))
            .collect();
        column = column.push(
            Text::new(format!("Breakpoints: {}", list.join(", ")))
                .size(12)
                .color(color::MUTED)
                .font(MONO),
        );
    }
    if !debug.registers.is_empty() {
        let mut grid = Column::new().spacing(2);
        for chunk in debug.registers.chunks(4) {
            let mut row = Row::new().spacing(14);
            for (name, value) in chunk {
                row = row.push(
                    Text::new(format!("{name:>6} {value:#018x}"))
                        .size(12)
                        .font(MONO)
                        .color(color::TEXT),
                );
            }
            grid = grid.push(row);
        }
        column = column.push(subtle("REGISTERS")).push(grid);
    }
    if !debug.frames.is_empty() {
        let mut stack = Column::new().spacing(2);
        for frame in &debug.frames {
            let label = format!(
                "#{} {:#x}{}",
                frame.level,
                frame.pc,
                frame
                    .function
                    .as_deref()
                    .map(|name| format!(" {name}"))
                    .unwrap_or_default()
            );
            // A frame in a library is outside the image: nowhere to go.
            let mut row = button(Text::new(label).size(12).font(MONO)).padding([2, 6]);
            if app.provider.contains_address(frame.pc) {
                row = row.on_press(Message::AddressSelected(frame.pc));
            }
            stack = stack.push(row);
        }
        column = column.push(subtle("STACK")).push(stack);
    }
    if debug.memory_at.is_some() && !debug.memory_rows.is_empty() {
        column = column
            .push(subtle("MEMORY AT THE PROGRAM COUNTER"))
            .push(hex_dump(app, &debug.memory_rows));
    }
    if !debug.log.is_empty() {
        let mut log = Column::new().spacing(1);
        for line in debug.log.iter().rev().take(8).rev() {
            log = log.push(
                Text::new(line.clone())
                    .size(11)
                    .font(MONO)
                    .color(color::DIM),
            );
        }
        column = column.push(subtle("LOG")).push(log);
    }
    scrollable(column)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_braces_take_their_depths_colors_and_the_guides_stand_in_the_indent() {
        let decor = Decor {
            rainbow: true,
            guides: true,
            indent: 2,
        };
        let mut depth = 0;
        let head = spans("long f(int a)", false, &decor, &mut depth);
        assert_eq!(head, vec![("long f(int a)".to_string(), color::TEXT)]);
        let open = spans("{", false, &decor, &mut depth);
        assert_eq!(open, vec![("{".to_string(), BRACE_COLORS[0])]);
        assert_eq!(depth, 1);
        let inner = spans("  if (a == 0) {", false, &decor, &mut depth);
        assert_eq!(
            inner,
            vec![
                ("│ ".to_string(), color::LINE),
                ("if (a == 0) ".to_string(), color::TEXT),
                ("{".to_string(), BRACE_COLORS[1]),
            ]
        );
        assert_eq!(depth, 2);
        let body = spans("    return \"{\";", true, &decor, &mut depth);
        assert_eq!(
            body,
            vec![
                ("│ │ ".to_string(), color::LINE),
                ("return \"{\";".to_string(), color::DIM),
            ],
            "a brace in a string is text, and a dead line is dim"
        );
        assert_eq!(depth, 2);
        // `} else {` closes the block at its level and opens another there.
        let else_line = spans("  } else {", false, &decor, &mut depth);
        assert_eq!(else_line.len(), 4, "{else_line:?}");
        assert_eq!(else_line[1].1, BRACE_COLORS[1]);
        assert_eq!(else_line[3].1, BRACE_COLORS[1]);
        assert_eq!(depth, 2);
        let close = spans("  }", false, &decor, &mut depth);
        assert_eq!(
            close,
            vec![
                ("│ ".to_string(), color::LINE),
                ("}".to_string(), BRACE_COLORS[1]),
            ]
        );
        assert_eq!(depth, 1);
        assert_eq!(
            spans("}", false, &decor, &mut depth),
            vec![("}".to_string(), BRACE_COLORS[0])]
        );
        assert_eq!(depth, 0);
        // A brace in a comment, or after an escaped quote, is text.
        let mut depth = 1;
        assert_eq!(
            spans("  if (0) { // constant: {", false, &decor, &mut depth),
            vec![
                ("│ ".to_string(), color::LINE),
                ("if (0) ".to_string(), color::TEXT),
                ("{".to_string(), BRACE_COLORS[1]),
                (" // constant: {".to_string(), color::TEXT),
            ]
        );
        assert_eq!(depth, 2);
        assert_eq!(
            spans("    s = \"\\\"{\";", false, &decor, &mut depth),
            vec![
                ("│ │ ".to_string(), color::LINE),
                ("s = \"\\\"{\";".to_string(), color::TEXT),
            ]
        );
        assert_eq!(depth, 2);
        // Nothing asked: the text in one piece, the depth still counted.
        let plain = Decor {
            rainbow: false,
            guides: false,
            indent: 2,
        };
        let mut depth = 0;
        assert_eq!(
            spans("  while (1) {", false, &plain, &mut depth),
            vec![("  while (1) {".to_string(), color::TEXT)]
        );
        assert_eq!(depth, 1);
        assert_eq!(
            spans("  }", true, &plain, &mut depth),
            vec![("  }".to_string(), color::DIM)]
        );
        assert_eq!(depth, 0);
    }
}
