//! The bottom workspace: search results, problems, analysis log, patch
//! history, and the variables of the function on screen.

use iced::widget::{
    button, container, mouse_area, scrollable, Column, Container, Row, Space, Text,
};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
use crate::data::HitKind;
use crate::theme::{color, MONO};
use crate::views::{section_header, subtle};

/// The tabs of the bottom workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BottomTab {
    /// Search results.
    #[default]
    SearchResults,
    /// Diagnostics.
    Problems,
    /// Analysis log.
    AnalysisLog,
    /// Patch history.
    PatchHistory,
    /// The variables of the function on screen, with where each lives.
    Variables,
}

impl BottomTab {
    /// Every tab, in display order.
    pub const ALL: [BottomTab; 5] = [
        BottomTab::SearchResults,
        BottomTab::Problems,
        BottomTab::AnalysisLog,
        BottomTab::PatchHistory,
        BottomTab::Variables,
    ];

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            BottomTab::SearchResults => "Search Results",
            BottomTab::Problems => "Problems",
            BottomTab::AnalysisLog => "Analysis Log",
            BottomTab::PatchHistory => "Patch History",
            BottomTab::Variables => "Variables",
        }
    }
}

/// Build the bottom workspace.
pub fn view(app: &App) -> Element<'_, Message> {
    Container::new(
        Column::new().push(tab_strip(app)).push(
            container(content(app))
                .width(Length::Fill)
                .height(Length::Fill)
                .padding([6, 14]),
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

/// The tab strip.
fn tab_strip(app: &App) -> Element<'_, Message> {
    let mut row = Row::new().spacing(16).padding([0, 12]);

    for tab in BottomTab::ALL {
        let count = match tab {
            BottomTab::SearchResults => app.bottom.hits.len(),
            BottomTab::Problems => app.bottom.problems.len(),
            BottomTab::AnalysisLog => app.bottom.log.len(),
            BottomTab::PatchHistory => app.annotations.patch_records().len(),
            BottomTab::Variables => app.shown_variables().len(),
        };

        let active = app.bottom.tab == tab;
        let label = if count > 0 {
            format!("{} · {count}", tab.label())
        } else {
            tab.label().to_string()
        };

        let element: Element<'_, Message> =
            mouse_area(Text::new(label).size(12).color(if active {
                color::AMBER
            } else {
                color::MUTED
            }))
            .on_press(Message::BottomTabSelected(tab))
            .into();

        row = row.push(element);
    }

    row = row.push(Space::new().width(Length::Fill));

    row = row.push(
        button::Button::new(Text::new("Search bodies").size(11).color(color::MUTED))
            .on_press(Message::DeepSearchSubmitted)
            .padding([4, 8])
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
            }),
    );

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

/// The content of the active tab.
fn content(app: &App) -> Element<'_, Message> {
    match app.bottom.tab {
        BottomTab::SearchResults => {
            if app.bottom.hits.is_empty() {
                return section_header("No results").into();
            }

            let mut list = Column::new().spacing(0).width(Length::Fill);

            for hit in &app.bottom.hits {
                // A result can be picked: a function opens its listing, and
                // anything else moves the selection to its address.
                let message = match hit.kind {
                    HitKind::Function => Message::FunctionSelected(hit.address),
                    _ => Message::AddressSelected(hit.address),
                };

                list = list.push(
                    mouse_area(
                        Row::new()
                            .align_y(Alignment::Center)
                            .spacing(12)
                            .push(
                                Text::new(format!("{:#x}", hit.address))
                                    .size(11)
                                    .color(color::MUTED)
                                    .font(MONO)
                                    .width(Length::Fixed(96.0)),
                            )
                            .push(
                                Text::new(hit.title.clone())
                                    .size(12)
                                    .color(color::TEXT)
                                    .width(Length::Fill),
                            )
                            .push(subtle(hit.kind.label()))
                            .push(subtle(hit.detail.clone()).width(Length::Fixed(120.0))),
                    )
                    .on_press(message),
                );
            }

            scrollable(list)
                .height(Length::Fill)
                .width(Length::Fill)
                .into()
        }
        BottomTab::Problems => {
            if app.bottom.problems.is_empty() {
                return subtle("No problems reported.").into();
            }

            let mut list = Column::new().spacing(4).width(Length::Fill);

            for problem in &app.bottom.problems {
                list = list.push(
                    Row::new()
                        .align_y(Alignment::Center)
                        .spacing(12)
                        .push(Text::new("●").size(10).color(color::AMBER))
                        .push(Text::new(problem.message.clone()).size(12))
                        .push(Space::new().width(Length::Fill))
                        .push(subtle(
                            problem
                                .address
                                .map(|a| format!("{a:#x}"))
                                .unwrap_or_default(),
                        )),
                );
            }

            list.into()
        }
        BottomTab::AnalysisLog => {
            let mut list = Column::new().spacing(2).width(Length::Fill);

            for line in &app.bottom.log {
                list = list.push(
                    Text::new(line.clone())
                        .size(11)
                        .color(color::MUTED)
                        .font(MONO),
                );
            }

            list.into()
        }
        BottomTab::PatchHistory => {
            let patches = app.annotations.patch_records();
            if patches.is_empty() {
                return subtle("No patches have been applied.").into();
            }

            // Each patch: where, the bytes, and the instruction they were
            // assembled from when they were. Clicking one goes there.
            let mut list = Column::new().spacing(2).width(Length::Fill);
            for (address, record) in patches {
                let selected = app.selection.address() == Some(address);
                let row = Row::new()
                    .align_y(Alignment::Center)
                    .spacing(12)
                    .push(
                        Text::new(record.address.clone())
                            .size(12)
                            .color(color::ADDR)
                            .font(MONO)
                            .width(Length::Fixed(140.0)),
                    )
                    .push(
                        Text::new(record.patch.clone().unwrap_or_default())
                            .size(12)
                            .color(color::AMBER)
                            .font(MONO)
                            .width(Length::Fill),
                    )
                    .push(subtle(record.patch_text.clone().unwrap_or_default()));
                list = list.push(
                    mouse_area(
                        Container::new(row)
                            .padding([2, 8])
                            .width(Length::Fill)
                            .style(move |_| container::Style {
                                background: selected.then_some(Background::Color(color::FOCUS_BG)),
                                ..container::Style::default()
                            }),
                    )
                    .on_press(Message::AddressSelected(address)),
                );
            }

            scrollable(list)
                .height(Length::Fill)
                .width(Length::Fill)
                .into()
        }
        BottomTab::Variables => variables(app),
    }
}

/// The Variables tab: a row a variable of the function on screen — its
/// name, the analyst's when renamed with the lift's beside it, its type,
/// where it lives, and how many statements assign and read it. Clicking a
/// row selects the first line of the pseudocode that names it; its button
/// renames it.
fn variables(app: &App) -> Element<'_, Message> {
    let rows = app.shown_variables();
    if rows.is_empty() {
        return subtle(if app.work.listing_of.is_some() {
            "This function declares no variables, or was not lifted."
        } else {
            "Open a function to list its variables."
        })
        .into();
    }
    let cell = |text: String, width: f32, tint: iced::Color| {
        Text::new(text)
            .size(12)
            .color(tint)
            .font(MONO)
            .width(Length::Fixed(width))
    };
    let header = Row::new()
        .spacing(12)
        .padding([2, 8])
        .push(cell("name".into(), 200.0, color::MUTED))
        .push(cell("type".into(), 110.0, color::MUTED))
        .push(cell("kind".into(), 50.0, color::MUTED))
        .push(
            Text::new("placement")
                .size(12)
                .color(color::MUTED)
                .font(MONO)
                .width(Length::Fill),
        )
        .push(cell("defs".into(), 40.0, color::MUTED))
        .push(cell("uses".into(), 40.0, color::MUTED))
        .push(Space::new().width(Length::Fixed(64.0)));
    let mut list = Column::new().spacing(0).width(Length::Fill).push(header);
    for (index, row) in rows.into_iter().enumerate() {
        let selected = app.bottom.selected_variable.as_deref() == Some(row.lift_name.as_str());
        let name = if row.name == row.lift_name {
            row.name.clone()
        } else {
            format!("{} ({})", row.name, row.lift_name)
        };
        let line = Row::new()
            .align_y(Alignment::Center)
            .spacing(12)
            .push(cell(name, 200.0, color::TEXT))
            .push(cell(row.ty.clone(), 110.0, color::TEXT))
            .push(cell(row.kind.name().to_string(), 50.0, color::MUTED))
            .push(
                Text::new(row.placement_text())
                    .size(12)
                    .color(color::ADDR)
                    .font(MONO)
                    .width(Length::Fill),
            )
            .push(cell(row.defined_at.len().to_string(), 40.0, color::TEXT))
            .push(cell(row.used_at.len().to_string(), 40.0, color::TEXT))
            .push(
                button::Button::new(Text::new("Rename").size(11).color(color::MUTED))
                    .on_press(Message::VariableRename(row.lift_name.clone()))
                    .padding([2, 8])
                    .width(Length::Fixed(64.0))
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
                    }),
            );
        list = list.push(
            mouse_area(
                Container::new(line)
                    .padding([2, 8])
                    .width(Length::Fill)
                    .style(move |_| container::Style {
                        background: selected.then_some(Background::Color(color::FOCUS_BG)),
                        ..container::Style::default()
                    }),
            )
            .on_press(Message::VariableSelected(index)),
        );
    }
    scrollable(list)
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
}
