//! The about dialog: artwork, version, and repository.

use std::sync::OnceLock;

use iced::widget::{button, container, image, Column, Container, Row, Space, Text};
use iced::{Alignment, Background, Border, Color, ContentFit, Element, Length};

use crate::app::Message;
use crate::theme::color;

/// Where the workbench lives.
pub const REPOSITORY: &str = "https://github.com/CryptoJones/AdmiralGrace";

/// The version of the workbench.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The artwork shown in the dialog.
const ARTWORK: &[u8] = include_bytes!("../../../images/about.png");

/// The decoded artwork, kept around so the renderer caches it.
static ARTWORK_HANDLE: OnceLock<image::Handle> = OnceLock::new();

/// The artwork handle.
fn artwork() -> image::Handle {
    ARTWORK_HANDLE
        .get_or_init(|| image::Handle::from_bytes(ARTWORK))
        .clone()
}

/// Build the about dialog.
pub fn view() -> Element<'static, Message> {
    let picture = image::Image::new(artwork())
        .width(Length::Fixed(112.0))
        .content_fit(ContentFit::Contain);

    let card = Container::new(
        Column::new()
            .spacing(10)
            .align_x(Alignment::Center)
            .push(picture)
            .push(Text::new("ADMIRALGRACE").size(15).color(color::TEXT))
            .push(
                Text::new(format!("version {VERSION}"))
                    .size(11)
                    .color(color::CYAN),
            )
            .push(
                Text::new("An open-source disassembler and decompiler for binary analysis.")
                    .size(12)
                    .color(color::MUTED),
            )
            .push(Space::new().height(Length::Fixed(4.0)))
            .push(repository_link())
            .push(close_button()),
    )
    .padding([20, 28])
    .width(Length::Fixed(360.0))
    .style(|_| container::Style {
        background: Some(Background::Color(color::PANEL)),
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 10.0.into(),
        },
        ..container::Style::default()
    });

    Container::new(card)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(Color::BLACK.scale_alpha(0.62))),
            ..container::Style::default()
        })
        .into()
}

/// The repository link.
fn repository_link() -> Element<'static, Message> {
    button::Button::new(
        Row::new()
            .align_y(Alignment::Center)
            .spacing(6)
            .push(Text::new("▸").size(11).color(color::CYAN))
            .push(
                Text::new("github.com/CryptoJones/AdmiralGrace")
                    .size(11)
                    .color(color::CYAN),
            ),
    )
    .padding([5, 10])
    .on_press(Message::AboutOpenRepository)
    .style(|_, status| button::Style {
        background: Some(Background::Color(match status {
            button::Status::Hovered | button::Status::Pressed => color::PANEL_ALT,
            _ => color::CARD,
        })),
        text_color: color::CYAN,
        border: Border {
            color: color::LINE,
            width: 1.0,
            radius: 6.0.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// The close button.
fn close_button() -> Element<'static, Message> {
    button::Button::new(Text::new("Close").size(12).color(color::TEXT))
        .padding([6, 18])
        .on_press(Message::AboutClose)
        .style(|_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => color::PANEL_ALT,
                _ => color::CARD,
            })),
            text_color: color::TEXT,
            border: Border {
                color: color::LINE,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..button::Style::default()
        })
        .into()
}

/// Open the repository in the system browser.
pub fn open_repository() {
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open")
        .arg(REPOSITORY)
        .spawn();

    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(REPOSITORY).spawn();

    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", REPOSITORY])
        .spawn();
}
