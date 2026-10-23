//! The application header: brand, project tabs, command search, analysis state.

use iced::widget::{container, text_input, Container, Row, Space, Text};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
use crate::data::AnalysisState;
use crate::theme::color;

/// Build the header.
pub fn view(app: &App) -> Element<'_, Message> {
    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(14)
            .push(Text::new("◈").size(15).color(color::CYAN))
            .push(Text::new("ADMIRALGRACE").size(13).color(color::TEXT))
            .push(project_tab(app))
            .push(Space::new().width(Length::Fill))
            .push(search_field(app))
            .push(analysis_indicator(app))
            .padding([0, 16])
            .height(Length::Fixed(48.0)),
    )
    .width(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(color::TOPBAR)),
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..container::Style::default()
    })
    .into()
}

/// The open project tab.
fn project_tab(app: &App) -> Container<'_, Message> {
    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(8)
            .push(
                Text::new(app.project.name.clone())
                    .size(12)
                    .color(color::TEXT),
            )
            .push(Text::new("×").size(12).color(color::MUTED)),
    )
    .padding([6, 10])
    .style(|_| container::Style {
        background: Some(Background::Color(color::PANEL_ALT)),
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 5.0.into(),
        },
        ..container::Style::default()
    })
}

/// The global command / search field.
fn search_field(app: &App) -> Container<'_, Message> {
    Container::new(
        text_input::TextInput::new("⌕  Search symbols, strings, addresses…", &app.global_query)
            .on_input(Message::GlobalQueryChanged)
            .on_submit(Message::SearchSubmitted)
            .width(Length::Fixed(390.0))
            .size(13)
            .padding([6, 10])
            .style(|_, _| text_input::Style {
                background: Background::Color(color::INPUT),
                border: Border {
                    color: color::LINE,
                    width: 1.0,
                    radius: 6.0.into(),
                },
                icon: color::MUTED,
                placeholder: color::MUTED,
                value: color::TEXT,
                selection: color::CYAN.scale_alpha(0.35),
            }),
    )
}

/// The analysis state indicator.
fn analysis_indicator(app: &App) -> Element<'_, Message> {
    let state = app.analysis_state();
    let (tint, label) = match &state {
        AnalysisState::Idle => (color::MUTED, state.label()),
        AnalysisState::Running { .. } => (color::AMBER, state.label()),
        AnalysisState::Complete => (color::GREEN, state.label()),
        AnalysisState::Failed(_) => (color::RED, state.label()),
    };

    Row::new()
        .align_y(Alignment::Center)
        .spacing(6)
        .push(Text::new("●").size(11).color(tint))
        .push(Text::new(label).size(11).color(tint))
        .into()
}
