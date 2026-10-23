//! The bottom workspace: search results, problems, analysis log, patch history.

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
}

impl BottomTab {
    /// Every tab, in display order.
    pub const ALL: [BottomTab; 4] = [
        BottomTab::SearchResults,
        BottomTab::Problems,
        BottomTab::AnalysisLog,
        BottomTab::PatchHistory,
    ];

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            BottomTab::SearchResults => "Search Results",
            BottomTab::Problems => "Problems",
            BottomTab::AnalysisLog => "Analysis Log",
            BottomTab::PatchHistory => "Patch History",
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
            BottomTab::PatchHistory => 0,
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
        BottomTab::PatchHistory => subtle("No patches have been applied.").into(),
    }
}
