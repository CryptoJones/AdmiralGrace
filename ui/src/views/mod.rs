//! The workbench views.

pub mod about;
pub mod bottom_panel;
pub mod graph;
pub mod inspector;
pub mod menu_bar;
pub mod navigator;
pub mod prompt_bar;
pub mod status_bar;
pub mod top_bar;
pub mod work_surface;

use iced::widget::{container, Column, Container, Row, Stack, Text};
use iced::{Background, Border, Color, Element, Length};

use crate::app::{App, Message};
use crate::theme::color;

/// Assemble the full workbench layout.
pub fn layout(app: &App) -> Element<'_, Message> {
    let mut layout = Column::new()
        .push(menu_bar::view(app))
        .push(top_bar::view(app));

    if let Some(prompt) = prompt_bar::view(app) {
        layout = layout.push(prompt);
    }

    let mut panes = Row::new();

    if app.show_navigator {
        panes = panes.push(Container::new(navigator::view(app)).width(Length::Fixed(238.0)));
    }

    panes = panes.push(Container::new(work_surface::view(app)).width(Length::Fill));

    if app.show_inspector {
        panes = panes.push(Container::new(inspector::view(app)).width(Length::Fixed(272.0)));
    }

    layout = layout.push(panes.height(Length::Fill));

    if app.show_bottom {
        layout = layout.push(Container::new(bottom_panel::view(app)).height(Length::Fixed(155.0)));
    }

    let base = layout
        .push(Container::new(status_bar::view(app)).height(Length::Fixed(43.0)))
        .width(Length::Fill)
        .height(Length::Fill)
        .into();

    if app.show_about {
        Stack::new()
            .push(base)
            .push(about::view())
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    } else {
        base
    }
}

/// An uppercase section heading.
pub fn section_header<'a>(label: &str) -> Text<'a> {
    Text::new(label.to_uppercase())
        .size(11)
        .color(color::MUTED)
        .font(iced::Font::DEFAULT)
}

/// A small rounded label used for status and provenance.
pub fn pill(label: impl Into<String>, tint: Color) -> Container<'static, Message> {
    Container::new(
        Text::new(label.into())
            .size(10)
            .color(tint)
            .font(iced::Font::DEFAULT),
    )
    .padding([2, 7])
    .style(move |_| container::Style {
        background: Some(Background::Color(tint.scale_alpha(0.14))),
        border: Border {
            color: tint.scale_alpha(0.35),
            width: 1.0,
            radius: 10.0.into(),
        },
        ..container::Style::default()
    })
}

/// A muted, single-line caption.
pub fn subtle<'a>(text: impl Into<String>) -> Text<'a> {
    Text::new(text.into()).size(11).color(color::MUTED)
}

/// A count that is not known yet.
///
/// The numbers that need the whole program read are not known until the
/// cross-reference index has been worked out, and the workbench says so
/// rather than showing a zero that is not true.
pub fn count_or_indexing(count: Option<usize>) -> String {
    match count {
        Some(count) => count.to_string(),
        None => "indexing…".to_string(),
    }
}

/// A key/value row for inspector cards.
pub fn kv(key: impl Into<String>, value: impl Into<String>) -> Row<'static, Message> {
    Row::new()
        .align_y(iced::Alignment::Center)
        .push(
            Text::new(key.into())
                .size(11)
                .color(color::MUTED)
                .width(Length::Fixed(84.0)),
        )
        .push(Text::new(value.into()).size(12).color(color::TEXT))
}

/// A recessed surface used for inputs and cards.
pub fn recessed<'a>(content: impl Into<Element<'a, Message>>) -> Container<'a, Message> {
    Container::new(content).style(|_| container::Style {
        background: Some(Background::Color(color::CARD)),
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 5.0.into(),
        },
        ..container::Style::default()
    })
}

/// Explanation shown when a view has nothing to render for this project.
pub fn empty_state<'a>(headline: &'a str, detail: &'a str) -> Column<'a, Message> {
    Column::new()
        .spacing(4)
        .push(Text::new(headline).size(13).color(color::MUTED))
        .push(Text::new(detail).size(11).color(color::DIM))
}

/// Format a count with thousands separators.
pub fn count(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }

    out
}
