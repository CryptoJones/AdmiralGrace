//! The inline path prompt shown under the menu bar.

use iced::widget::{button, container, text_input, Container, Row, Space, Text};
use iced::{Alignment, Background, Border, Element, Length};

use crate::app::{App, Message};
use crate::theme::color;

/// Build the path prompt row, if a prompt is open.
pub fn view(app: &App) -> Option<Element<'_, Message>> {
    let prompt = app.prompt.as_ref()?;

    let field = text_input::TextInput::new("path…", &prompt.value)
        .on_input(Message::PromptChanged)
        .on_submit(Message::PromptSubmit)
        .width(Length::Fill)
        .size(13)
        .padding([6, 8])
        .style(|_, _| text_input::Style {
            background: Background::Color(color::INPUT),
            border: Border {
                color: color::CYAN.scale_alpha(0.4),
                width: 1.0,
                radius: 5.0.into(),
            },
            icon: color::MUTED,
            placeholder: color::MUTED,
            value: color::TEXT,
            selection: color::CYAN.scale_alpha(0.35),
        });

    let element: Element<'_, Message> = Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(8)
            .push(Text::new(prompt.title).size(12).color(color::TEXT))
            .push(field)
            .push(
                button::Button::new(Text::new("Open").size(12).color(color::TEXT))
                    .padding([5, 12])
                    .on_press(Message::PromptSubmit)
                    .style(|_, status| button::Style {
                        background: Some(Background::Color(match status {
                            button::Status::Hovered | button::Status::Pressed => {
                                color::CYAN.scale_alpha(0.25)
                            }
                            _ => color::PANEL_ALT,
                        })),
                        text_color: color::TEXT,
                        border: Border {
                            color: color::LINE,
                            width: 1.0,
                            radius: 5.0.into(),
                        },
                        ..button::Style::default()
                    }),
            )
            .push(
                button::Button::new(Text::new("Cancel").size(12).color(color::MUTED))
                    .padding([5, 12])
                    .on_press(Message::PromptCancel)
                    .style(|_, status| button::Style {
                        background: Some(Background::Color(match status {
                            button::Status::Hovered | button::Status::Pressed => color::PANEL_ALT,
                            _ => color::PANEL,
                        })),
                        text_color: color::MUTED,
                        border: Border {
                            color: color::LINE,
                            width: 1.0,
                            radius: 5.0.into(),
                        },
                        ..button::Style::default()
                    }),
            )
            .push(Space::new().width(Length::Fill)),
    )
    .padding([8, 16])
    .width(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(color::PANEL_ALT)),
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..container::Style::default()
    })
    .into();

    Some(element)
}
