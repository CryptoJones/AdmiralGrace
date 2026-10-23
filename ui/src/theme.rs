//! Semantic palette and iced theme for the AdmiralGrace workbench.
//!
//! The colours mirror the layout reference in `ui/wireframe.html`: a dark,
//! low-glare surface with restrained semantic accents.

use iced::theme::Palette;
use iced::{Color, Font};

/// Monospace face used for addresses, bytes, and code.
pub const MONO: Font = Font::MONOSPACE;

/// The workbench palette.
pub mod color {
    use super::Color;

    /// Window background.
    pub const BG: Color = Color::from_rgb8(0x10, 0x14, 0x19);
    /// Title bar / project tab strip.
    pub const TOPBAR: Color = Color::from_rgb8(0x13, 0x19, 0x20);
    /// Panel surface.
    pub const PANEL: Color = Color::from_rgb8(0x17, 0x1d, 0x24);
    /// Raised panel surface (tabs, buttons).
    pub const PANEL_ALT: Color = Color::from_rgb8(0x1c, 0x24, 0x2d);
    /// Recessed surface (inputs, cards).
    pub const INPUT: Color = Color::from_rgb8(0x0e, 0x13, 0x18);
    /// Card surface inside the inspector.
    pub const CARD: Color = Color::from_rgb8(0x11, 0x17, 0x1d);
    /// Hairline separators.
    pub const LINE: Color = Color::from_rgb8(0x2b, 0x35, 0x40);
    /// Primary text.
    pub const TEXT: Color = Color::from_rgb8(0xdc, 0xe5, 0xed);
    /// Secondary text.
    pub const MUTED: Color = Color::from_rgb8(0x8c, 0x9a, 0xa8);
    /// Tertiary text (comments, notes).
    pub const DIM: Color = Color::from_rgb8(0x78, 0x88, 0x94);
    /// Address column.
    pub const ADDR: Color = Color::from_rgb8(0x75, 0x85, 0x94);
    /// Byte column.
    pub const BYTES: Color = Color::from_rgb8(0x7b, 0x8c, 0x9a);
    /// Labels, active tabs, focus.
    pub const CYAN: Color = Color::from_rgb8(0x68, 0xc5, 0xd2);
    /// Links and cross references.
    pub const BLUE: Color = Color::from_rgb8(0x86, 0xae, 0xf3);
    /// Analysis complete / success.
    pub const GREEN: Color = Color::from_rgb8(0x8b, 0xcf, 0x9c);
    /// Warnings and inactive tab accents.
    pub const AMBER: Color = Color::from_rgb8(0xe4, 0xba, 0x6a);
    /// Operands and operators.
    pub const PURPLE: Color = Color::from_rgb8(0xc1, 0xa4, 0xed);
    /// Errors.
    pub const RED: Color = Color::from_rgb8(0xe0, 0x7a, 0x6a);
    /// Selected row background.
    pub const SELECT_BG: Color = Color::from_rgb8(0x26, 0x37, 0x44);
    /// Focus row background.
    pub const FOCUS_BG: Color = Color::from_rgb8(0x22, 0x2c, 0x35);
}

/// The iced palette backing the workbench theme.
pub fn palette() -> Palette {
    Palette {
        background: color::BG,
        text: color::TEXT,
        primary: color::CYAN,
        success: color::GREEN,
        warning: color::AMBER,
        danger: color::RED,
    }
}

/// The application theme.
pub fn theme() -> iced::Theme {
    iced::Theme::custom("AdmiralGrace", palette())
}
