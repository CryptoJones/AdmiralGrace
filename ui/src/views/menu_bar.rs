//! The application menu bar.
//!
//! Menus are built from ordinary buttons so they carry the workbench's own
//! styling instead of a second visual language.

use iced::widget::{button, container, Container, Row, Space, Text};
use iced::{Alignment, Background, Border, Element, Length};
use iced_aw::menu::{Item, Menu, MenuBar};

use crate::app::{App, Mark, Message};
use crate::theme::color;

/// Build the menu bar.
pub fn view(app: &App) -> Element<'_, Message> {
    // The Undo and Redo items say what they would take back or put back,
    // the way the notice said it when the change was made.
    let undo_label = match app.undo.last() {
        Some(change) => format!("Undo: {}", change.label),
        None => "Undo".to_string(),
    };
    let redo_label = match app.redo.last() {
        Some(change) => format!("Redo: {}", change.label),
        None => "Redo".to_string(),
    };
    let file = Item::with_menu(
        root_button("File"),
        Menu::new(vec![
            Item::new(item_button(
                "Open corpus…",
                "Ctrl+O",
                Message::FileOpenCorpus,
            )),
            Item::new(item_button("Open kuna export…", "", Message::FileOpenKuna)),
            Item::new(item_button("Open binary…", "", Message::FileOpenBinary)),
            Item::new(item_button("Open raw bytes…", "", Message::FileOpenRaw)),
            Item::new(item_button(
                "Open Objective-C method map…",
                "",
                Message::FileOpenMethods,
            )),
            Item::new(item_button(
                "Open project file…",
                "",
                Message::FileOpenProject,
            )),
            Item::new(item_button(
                "Save project",
                "Ctrl+S",
                Message::FileSaveProject,
            )),
            Item::new(item_button(
                "Save project as…",
                "",
                Message::FileSaveProjectAs,
            )),
            Item::new(item_button(
                "Write patched program…",
                "",
                Message::FileWritePatched,
            )),
            Item::new(separator()),
            Item::new(item_button("Reload project", "F5", Message::FileReload)),
            Item::new(item_button("Close project", "", Message::FileClose)),
            Item::new(separator()),
            Item::new(item_button("Quit", "Ctrl+Q", Message::FileQuit)),
        ])
        .width(260.0),
    );

    let edit = Item::with_menu(
        root_button("Edit"),
        Menu::new(vec![
            Item::new(item_button("Rename function…", "F2", Message::EditRename)),
            Item::new(item_button("Rename label…", "F3", Message::EditRenameLabel)),
            Item::new(item_button(
                "Rename register…",
                "Ctrl+F3",
                Message::EditRenameRegister,
            )),
            Item::new(item_button(
                "Rename local variable…",
                "Ctrl+F2",
                Message::EditRenameVariable,
            )),
            Item::new(item_button(
                "Add comment inline",
                "Ctrl+/",
                Message::EditComment,
            )),
            Item::new(item_button(
                "Add comment above",
                "Ctrl+Shift+/",
                Message::EditCommentAbove,
            )),
            Item::new(item_button(
                "Toggle bookmark",
                "Ctrl+Shift+B",
                Message::EditBookmark,
            )),
            Item::new(item_button("Tags…", "Ctrl+T", Message::EditTags)),
            Item::new(item_button("Highlight…", "Ctrl+H", Message::EditColor)),
            Item::new(item_button(
                "Highlight block…",
                "Ctrl+Shift+H",
                Message::EditColorBlock,
            )),
            Item::new(item_button(
                "Block text…",
                "Ctrl+Shift+L",
                Message::EditBlockText,
            )),
            Item::new(item_button("Group…", "Ctrl+G", Message::EditGroup)),
            Item::new(item_button(
                "Add cross reference…",
                "Ctrl+X",
                Message::EditReference,
            )),
            Item::new(item_button(
                "Remove cross reference…",
                "Ctrl+Shift+X",
                Message::EditReferenceRemove,
            )),
            Item::new(separator()),
            Item::new(item_button(
                "Mark as code",
                "Ctrl+Shift+C",
                Message::EditMark(Mark::Code),
            )),
            Item::new(item_button(
                "Mark as function",
                "Ctrl+Shift+F",
                Message::EditMark(Mark::Function),
            )),
            Item::new(item_button(
                "Mark as data (wider each time)",
                "Ctrl+Shift+D",
                Message::EditMark(Mark::Data),
            )),
            Item::new(item_button(
                "Mark as string",
                "Ctrl+Shift+A",
                Message::EditMark(Mark::String),
            )),
            Item::new(item_button(
                "Mark undefined",
                "Ctrl+Shift+U",
                Message::EditMark(Mark::Undefined),
            )),
            Item::new(item_button(
                "Operand format (next: hex, signed, decimal, octal, address)",
                "Ctrl+Shift+N",
                Message::EditOperandFormat,
            )),
            Item::new(item_button(
                "Decode from here as ARM or Thumb…",
                "",
                Message::EditMode,
            )),
            Item::new(item_button(
                "Jump table…",
                "Ctrl+Shift+J",
                Message::EditSwitch,
            )),
            Item::new(separator()),
            Item::new(item_button(
                "Assemble over bytes…",
                "Ctrl+Shift+E",
                Message::EditAssemble,
            )),
            Item::new(item_button(
                "NOP instruction",
                "Ctrl+Shift+O",
                Message::EditNop,
            )),
            Item::new(item_button(
                "Edit bytes…",
                "Ctrl+Shift+Y",
                Message::EditBytes,
            )),
            Item::new(item_button(
                "NOP range…",
                "Ctrl+Shift+R",
                Message::EditNopRange,
            )),
            Item::new(separator()),
            Item::new(item_button("Rebase image…", "", Message::EditRebase)),
            Item::new(item_button("Add segment…", "", Message::EditSegmentAdd)),
            Item::new(item_button(
                "Remove segment…",
                "",
                Message::EditSegmentRemove,
            )),
            Item::new(item_button(
                "Rename segment…",
                "",
                Message::EditSegmentRename,
            )),
            Item::new(separator()),
            Item::new(item_button(&undo_label, "Ctrl+Z", Message::EditUndo)),
            Item::new(item_button(&redo_label, "Ctrl+Shift+Z", Message::EditRedo)),
        ])
        .width(240.0),
    );

    let view_menu = Item::with_menu(
        root_button("View"),
        Menu::new(vec![
            Item::new(item_button(
                "Show navigator",
                "Ctrl+B",
                Message::ViewToggleNavigator,
            )),
            Item::new(item_button(
                "Show inspector",
                "Ctrl+I",
                Message::ViewToggleInspector,
            )),
            Item::new(item_button(
                "Show bottom panel",
                "Ctrl+J",
                Message::ViewToggleBottom,
            )),
            Item::new(separator()),
            Item::new(item_button("Reset layout", "", Message::ViewResetLayout)),
        ])
        .width(240.0),
    );

    let analysis = Item::with_menu(
        root_button("Analysis"),
        Menu::new(vec![
            Item::new(item_button(
                "Restart analysis",
                "",
                Message::AnalysisRestart,
            )),
            Item::new(item_button(
                "Show analysis log",
                "",
                Message::AnalysisShowLog,
            )),
        ])
        .width(240.0),
    );

    let help = Item::with_menu(
        root_button("Help"),
        Menu::new(vec![
            Item::new(item_button(
                "Keyboard shortcuts",
                "",
                Message::HelpShortcuts,
            )),
            Item::new(item_button("About AdmiralGrace", "", Message::HelpAbout)),
        ])
        .width(240.0),
    );

    Container::new(
        Row::new()
            .align_y(Alignment::Center)
            .push(MenuBar::new(vec![file, edit, view_menu, analysis, help]))
            .push(Space::new().width(Length::Fill)),
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

/// A top-level menu header.
fn root_button(label: &str) -> Element<'static, Message> {
    button::Button::new(Text::new(label.to_string()).size(12).color(color::TEXT))
        .padding([6, 10])
        .style(|_, status| button::Style {
            background: match status {
                button::Status::Hovered | button::Status::Pressed => {
                    Some(Background::Color(color::PANEL_ALT))
                }
                _ => None,
            },
            text_color: color::TEXT,
            border: Border {
                color: color::TOPBAR,
                width: 1.0,
                radius: 4.0.into(),
            },
            ..button::Style::default()
        })
        .into()
}

/// A menu entry with an optional shortcut hint.
fn item_button(label: &str, shortcut: &str, message: Message) -> Element<'static, Message> {
    button::Button::new(
        Row::new()
            .align_y(Alignment::Center)
            .push(
                Text::new(label.to_string())
                    .size(12)
                    .color(color::TEXT)
                    .width(Length::Fill),
            )
            .push(Text::new(shortcut.to_string()).size(11).color(color::DIM)),
    )
    .width(Length::Fill)
    .padding([6, 8])
    .on_press(message)
    .style(|_, status| button::Style {
        background: match status {
            button::Status::Hovered | button::Status::Pressed => {
                Some(Background::Color(color::PANEL_ALT))
            }
            _ => None,
        },
        text_color: color::TEXT,
        border: Border {
            color: color::PANEL,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..button::Style::default()
    })
    .into()
}

/// A divider between groups of entries.
fn separator() -> Element<'static, Message> {
    Container::new(
        iced::widget::rule::horizontal(1).style(|_| iced::widget::rule::Style {
            color: color::LINE,
            radius: 0.0.into(),
            fill_mode: iced::widget::rule::FillMode::Full,
            snap: true,
        }),
    )
    .padding([4, 0])
    .width(Length::Fill)
    .into()
}
