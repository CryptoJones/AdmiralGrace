//! The status bar: analysis state, target, selection, and save state.

use iced::widget::{container, Container, Row, Space, Text};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
use crate::data::AnalysisState;
use crate::theme::color;

/// Build the status bar.
pub fn view(app: &App) -> Element<'_, Message> {
    let state = app.analysis_state();
    let tint = match &state {
        AnalysisState::Idle => color::MUTED,
        AnalysisState::Running { .. } => color::AMBER,
        AnalysisState::Complete => color::GREEN,
        AnalysisState::Failed(_) => color::RED,
    };

    let target = match (&app.project.architecture, &app.project.format) {
        (Some(arch), Some(format)) => format!("{arch} · {format}"),
        (Some(arch), None) => arch.clone(),
        (None, Some(format)) => format.clone(),
        (None, None) => app.project.provider.clone(),
    };

    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(18)
            .push(
                Row::new()
                    .align_y(Alignment::Center)
                    .spacing(6)
                    .push(Text::new("●").size(10).color(tint))
                    .push(Text::new(state.label()).size(11).color(tint)),
            )
            .push(Text::new(target).size(11).color(color::MUTED))
            .push(
                Text::new(format!(
                    "{} functions",
                    crate::views::count(app.navigator.counts.functions)
                ))
                .size(11)
                .color(color::MUTED),
            )
            .push(
                Text::new(format!("Selection: {}", app.selection.describe()))
                    .size(11)
                    .color(color::MUTED),
            )
            .push(match &app.work.register_web {
                Some(web) => Text::new(web.summary.clone()).size(11).color(color::AMBER),
                None => Text::new(""),
            })
            .push(match &app.work.line_values {
                Some(values) => Text::new(format!("Values: {values}"))
                    .size(11)
                    .color(color::MUTED),
                None => Text::new(""),
            })
            .push(Space::new().width(Length::Fill))
            .push(match &app.notice {
                Some(notice) => Text::new(notice.clone()).size(11).color(color::AMBER),
                None => Text::new("Project saved").size(11).color(color::MUTED),
            }),
    )
    .padding([0, 14])
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
