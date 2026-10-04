//! HUD / cockpit theme: dark or light, monospace, amber + cyan telemetry.
//!
//! The active mode is a process-global so the small drawing helpers can pick
//! colors without threading a palette through every function.

use std::sync::atomic::{AtomicBool, Ordering};

use eframe::egui::{self, Color32, CornerRadius, FontId, Margin, Stroke, TextStyle, Vec2, Visuals};

static DARK: AtomicBool = AtomicBool::new(true);

fn dark() -> bool {
    DARK.load(Ordering::Relaxed)
}

pub fn bg() -> Color32 {
    if dark() {
        Color32::from_rgb(5, 9, 11)
    } else {
        Color32::from_rgb(230, 236, 238)
    }
}
pub fn panel() -> Color32 {
    if dark() {
        Color32::from_rgb(9, 15, 19)
    } else {
        Color32::from_rgb(247, 250, 250)
    }
}
pub fn panel2() -> Color32 {
    if dark() {
        Color32::from_rgb(12, 21, 26)
    } else {
        Color32::from_rgb(228, 235, 237)
    }
}
pub fn line() -> Color32 {
    if dark() {
        Color32::from_rgb(26, 58, 66)
    } else {
        Color32::from_rgb(168, 192, 196)
    }
}
pub fn text() -> Color32 {
    if dark() {
        Color32::from_rgb(196, 236, 236)
    } else {
        Color32::from_rgb(18, 36, 40)
    }
}
pub fn dim() -> Color32 {
    if dark() {
        Color32::from_rgb(108, 150, 156)
    } else {
        Color32::from_rgb(96, 124, 130)
    }
}
pub fn cyan() -> Color32 {
    if dark() {
        Color32::from_rgb(0, 224, 220)
    } else {
        Color32::from_rgb(0, 122, 126)
    }
}
pub fn amber() -> Color32 {
    if dark() {
        Color32::from_rgb(255, 176, 0)
    } else {
        Color32::from_rgb(172, 100, 0)
    }
}
pub fn green() -> Color32 {
    if dark() {
        Color32::from_rgb(0, 230, 140)
    } else {
        Color32::from_rgb(0, 132, 80)
    }
}
pub fn red() -> Color32 {
    if dark() {
        Color32::from_rgb(255, 84, 84)
    } else {
        Color32::from_rgb(184, 40, 40)
    }
}
pub fn grid() -> Color32 {
    if dark() {
        Color32::from_rgba_unmultiplied(90, 160, 170, 18)
    } else {
        Color32::from_rgba_unmultiplied(60, 90, 95, 22)
    }
}

/// A stable per-app badge color.
pub fn badge(name: &str) -> Color32 {
    const PALETTE: [Color32; 6] = [
        Color32::from_rgb(0, 176, 176),
        Color32::from_rgb(200, 148, 0),
        Color32::from_rgb(0, 168, 110),
        Color32::from_rgb(168, 92, 200),
        Color32::from_rgb(64, 132, 220),
        Color32::from_rgb(208, 92, 92),
    ];
    let mut h: u32 = 2_166_136_261;
    for b in name.bytes() {
        h = (h ^ b as u32).wrapping_mul(16_777_619);
    }
    PALETTE[(h as usize) % PALETTE.len()]
}

fn widget(fg: Color32, bg: Color32, border: Color32) -> egui::style::WidgetVisuals {
    egui::style::WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: Stroke::new(1.0, border),
        corner_radius: CornerRadius::same(3),
        fg_stroke: Stroke::new(1.0, fg),
        expansion: 0.0,
    }
}

/// Apply the HUD theme with a base font size and light/dark mode.
pub fn apply(ctx: &egui::Context, font_size: f32, dark_mode: bool) {
    DARK.store(dark_mode, Ordering::SeqCst);
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::monospace(font_size + 6.0)),
            (TextStyle::Body, FontId::monospace(font_size)),
            (TextStyle::Button, FontId::monospace(font_size)),
            (TextStyle::Small, FontId::monospace(font_size - 1.0)),
            (TextStyle::Monospace, FontId::monospace(font_size)),
        ]
        .into();
        style.spacing.item_spacing = Vec2::new(9.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.window_margin = Margin::same(10);
        style.spacing.interact_size.y = (font_size + 12.0).max(22.0);

        let mut v = if dark_mode {
            Visuals::dark()
        } else {
            Visuals::light()
        };
        v.dark_mode = dark_mode;
        v.panel_fill = panel();
        v.window_fill = panel();
        v.extreme_bg_color = bg();
        v.faint_bg_color = panel2();
        v.code_bg_color = bg();
        v.hyperlink_color = cyan();
        v.warn_fg_color = amber();
        v.error_fg_color = red();
        v.window_corner_radius = CornerRadius::same(4);
        v.menu_corner_radius = CornerRadius::same(4);
        v.selection.bg_fill = cyan();
        v.selection.stroke = Stroke::new(1.0, bg());
        v.widgets.noninteractive = widget(text(), panel(), line());
        v.widgets.inactive = widget(text(), panel2(), line());
        v.widgets.hovered = widget(
            if dark_mode {
                Color32::WHITE
            } else {
                Color32::BLACK
            },
            if dark_mode {
                Color32::from_rgb(0, 54, 60)
            } else {
                Color32::from_rgb(208, 230, 232)
            },
            cyan(),
        );
        v.widgets.active = widget(bg(), cyan(), cyan());
        v.widgets.open = widget(cyan(), panel2(), cyan());
        style.visuals = v;
    });
}
