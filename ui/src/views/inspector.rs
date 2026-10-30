//! The right inspector: contextual details for the shared selection.

use iced::widget::{button, mouse_area, scrollable, Column, Row, Text};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
use crate::data::{Reference, ReferenceKind};
use crate::theme::{color, MONO};
use crate::views::{count_or_indexing, kv, pill, recessed, section_header, subtle};

/// Build the inspector.
pub fn view(app: &App) -> Element<'_, Message> {
    let selection = app.selection;

    let mut column = Column::new()
        .padding(12)
        .spacing(8)
        .push(Text::new("Current selection").size(14).color(color::TEXT))
        .push(subtle(selection.describe()));

    column = column.push(selection_card(app));

    // The analysis's references, and the ones the analyst recorded that
    // the analysis could not see.
    let manual = app.manual_references();
    if !app.work.references.is_empty() || !manual.is_empty() {
        column = column.push(section_header("References"));
        column = column.push(reference_cards(app, &manual));
    }

    column = column.push(section_header("Analysis provenance"));
    column = column.push(provenance_card(app));

    column = column.push(section_header("Project"));
    column = column.push(project_card(app));

    // The program image, when the project is one: what it is, where it
    // starts, and how it is laid out.
    if !app.provider.segments().is_empty() {
        column = column.push(section_header("Image"));
        column = column.push(image_card(app));
    }

    column = column.push(section_header("Analyst notes"));
    let mut notes = Column::new().spacing(5);
    if let Some(address) = selection.address() {
        let key = app.annotation_key(address);
        if let Some(annotation) = app.annotations.annotation_for(&key) {
            if let Some(name) = &annotation.name {
                notes = notes.push(kv("Renamed to", name.clone()));
            }
            if let Some(comment) = &annotation.comment {
                notes = notes.push(kv("Comment", comment.clone()));
            }
            if annotation.bookmark {
                notes = notes.push(subtle("★ bookmarked"));
            }
            if let Some(mark) = &annotation.byte_type {
                notes = notes.push(kv("Marked as", mark.clone()));
            }
            if let Some(hex) = &annotation.color {
                // The swatch is the color itself; the value beside it is
                // what the file holds.
                let mut row = Row::new().spacing(6).align_y(Alignment::Center);
                if let Some(tint) = crate::theme::hex_color(hex) {
                    row = row.push(pill("■", tint));
                }
                row = row.push(kv("Highlight", hex.clone()));
                notes = notes.push(row);
            }
        }
        // The tags on the place: the analyst's own and the ones the
        // analysis implies, the entry point and an Objective-C class.
        let tags = app.tags_at(address);
        if !tags.is_empty() {
            notes = notes.push(kv("Tags", tags.join(", ")));
        }
        // The locals of the function on screen that the analyst has named.
        let function = app
            .work
            .detail
            .as_ref()
            .and_then(|detail| detail.start)
            .unwrap_or(address);
        let function_key = app.annotation_key(function);
        for variable in app.declared_variables() {
            if let Some(renamed) = app.annotations.variable_name(&function_key, &variable) {
                let label = format!("Local {variable}");
                notes = notes.push(kv(label, renamed));
            }
        }
        // The registers the function on screen prints that the analyst has
        // named: the function the listing was read for, which is where a
        // register rename draws, not the current selection.
        if let Some(listing_of) = app.work.listing_of {
            let register_key = app.canonical_key(listing_of);
            for register in app.listing_registers() {
                if let Some(renamed) = app.annotations.register_name(&register_key, &register) {
                    let label = format!("Register {register}");
                    notes = notes.push(kv(label, renamed));
                }
            }
        }
    }
    column = column.push(notes);
    column = column.push(
        Row::new()
            .spacing(8)
            .push(note_button("＋ Add comment", Message::EditComment))
            .push(note_button("☆ Bookmark", Message::EditBookmark))
            .push(note_button("# Tags", Message::EditTags))
            .push(note_button("◆ Highlight", Message::EditColor)),
    );

    scrollable(column)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}

/// The card describing the current selection.
fn selection_card(app: &App) -> Element<'_, Message> {
    let detail = app.work.detail.clone();
    let mut rows = Column::new().spacing(5);

    if let Some(detail) = &detail {
        let name = match detail.start {
            Some(start) => app.shown_name(start, &detail.name),
            None => detail.name.clone(),
        };
        rows = rows.push(kv("Name", name));
        rows = rows.push(kv(
            "Selected",
            app.selection
                .address()
                .map(|a| format!("{a:#x}"))
                .unwrap_or_else(|| "unknown".into()),
        ));
        rows = rows.push(kv(
            "Size",
            detail
                .start
                .zip(detail.end)
                .map(|(s, e)| format!("{:#x}", e - s))
                .unwrap_or_else(|| "unknown".into()),
        ));
        rows = rows.push(kv("Status", detail.status.clone()));
    } else {
        rows = rows.push(subtle("Nothing is selected."));
    }

    recessed(rows.padding(10)).into()
}

/// Cards of cross references, grouped by kind.
fn reference_cards(app: &App, manual: &[Reference]) -> Element<'static, Message> {
    let mut column = Column::new().spacing(8).width(Length::Fill);

    for kind in [
        ReferenceKind::Calls,
        ReferenceKind::CalledBy,
        ReferenceKind::Data,
        ReferenceKind::String,
        ReferenceKind::UsedBy,
        ReferenceKind::Manual,
        ReferenceKind::ManualFrom,
    ] {
        let matching: Vec<_> = app
            .work
            .references
            .iter()
            .chain(manual.iter())
            .filter(|r| r.kind == kind)
            .collect();

        if matching.is_empty() {
            continue;
        }

        let mut card = Column::new().spacing(4).width(Length::Fill);
        card = card.push(subtle(kind.label()));

        for reference in matching {
            // A manual reference is the analyst's, drawn in the analyst's
            // color, and jumps to the place it names.
            let manual_kind = matches!(kind, ReferenceKind::Manual | ReferenceKind::ManualFrom);
            let text = Text::new(reference.label.clone())
                .size(12)
                .color(if manual_kind {
                    color::PURPLE
                } else {
                    color::BLUE
                });
            if manual_kind {
                card = card.push(mouse_area(text).on_press(Message::JumpTo(reference.address)));
            } else {
                card = card.push(text);
            }
        }

        column = column.push(recessed(card.padding(10)));
    }

    column.into()
}

/// The project card: identity and provenance of the open target.
fn project_card(app: &App) -> Element<'_, Message> {
    let project = &app.project;

    let mut card = Column::new().spacing(6).width(Length::Fill);
    card = card.push(kv("Kind", project.kind.label().to_string()));
    card = card.push(kv("Provider", project.provider.clone()));

    if let Some(sha) = &project.target_sha256 {
        let short = sha.chars().take(16).collect::<String>();
        card = card.push(kv("Target", format!("{short}…")));
    }

    if let Some(root) = &project.root {
        card = card.push(kv("Root", root.display().to_string()));
    }

    // The binary the export was made from, when the CLI can still reach it.
    if let Some(binary) = app.kuna.as_ref().and_then(|kuna| kuna.cli.as_ref()) {
        card = card.push(kv("Binary", binary.binary().display().to_string()));
    }

    // The shape of the program, when the analysis could say it.
    if let Some(summary) = app.provider.summary() {
        if let Some((name, address)) = &summary.entry {
            card = card.push(kv("Entry", format!("{name} ({address:#x})")));
        }
        if let Some((name, address)) = &summary.main {
            card = card.push(kv("Main", format!("{name} ({address:#x})")));
        }
        card = card.push(kv("Functions", summary.functions.to_string()));
        card = card.push(kv("Reachable", count_or_indexing(summary.reachable)));
        card = card.push(kv("No callers", count_or_indexing(summary.no_callers)));
        card = card.push(kv("Code bytes", summary.code_bytes.to_string()));
    }

    recessed(card.padding(10)).into()
}

/// The image card: the language, the entry point, and the sections.
///
/// The sections are listed with the flag that says whether they hold code,
/// because that is what decides whether the decoder reads them.
fn image_card(app: &App) -> Element<'_, Message> {
    let project = &app.project;
    let mut card = Column::new().spacing(5).width(Length::Fill);

    if let Some(language) = &project.architecture {
        card = card.push(kv("Language", language.clone()));
    }

    if let Some(summary) = app.provider.summary() {
        if let Some((name, address)) = summary.entry {
            card = card.push(kv("Entry", format!("{name} ({address:#x})")));
        }
    }

    for section in app.provider.segments() {
        card = card.push(
            Row::new()
                .align_y(Alignment::Center)
                .spacing(6)
                .push(
                    Text::new(section.name.clone())
                        .size(11)
                        .color(color::TEXT)
                        .font(MONO)
                        .width(Length::Fill),
                )
                .push(pill(
                    if section.executable { "exec" } else { "data" },
                    if section.executable {
                        color::GREEN
                    } else {
                        color::MUTED
                    },
                ))
                .push(
                    Text::new(format!("{:#x}", section.vma))
                        .size(10)
                        .color(color::MUTED)
                        .font(MONO),
                ),
        );
    }

    recessed(card.padding(10)).into()
}

/// The provenance card.
fn provenance_card(app: &App) -> Element<'_, Message> {
    let detail = app.work.detail.clone();

    let mut card = Column::new().spacing(6).width(Length::Fill);

    match detail {
        Some(detail) => {
            card = card.push(
                Row::new()
                    .align_y(Alignment::Center)
                    .spacing(8)
                    .push(pill("Decoder", color::CYAN))
                    .push(subtle(detail.provenance.clone())),
            );
            card = card.push(subtle(detail.summary.clone()));
        }
        None => {
            card = card.push(subtle("No provenance for the current selection."));
        }
    }

    recessed(card.padding(10)).into()
}

/// An action button in the notes section.
fn note_button(label: &str, message: Message) -> Element<'_, Message> {
    button::Button::new(Text::new(label.to_string()).size(12).color(color::MUTED))
        .on_press(message)
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
