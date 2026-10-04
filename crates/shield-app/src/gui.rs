//! egui HUD: a cockpit-style Feed and Settings.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use shield_core::{now_unix, Alert, AlertKind, Config, Connection, CpuSampler};

use crate::state::{Shared, Tick};
use crate::theme;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Feed,
    Settings,
}

/// Horizontal lines per CPU core: the count of lit lines shows current load.
const CORE_LEVELS: usize = 12;

pub struct ShieldApp {
    shared: Arc<Shared>,
    rx: Receiver<Tick>,
    tab: Tab,
    conns: Vec<Connection>,
    alerts: Vec<Alert>,
    config: Config,
    config_path: PathBuf,
    store_path: PathBuf,
    really_quit: bool,
    status: String,
    known: usize,
    last_scan: u64,
    cpu: CpuSampler,
    core_usage: Vec<f32>,
    last_cpu: u64,
}

impl ShieldApp {
    pub fn new(
        shared: Arc<Shared>,
        rx: Receiver<Tick>,
        config: Config,
        config_path: PathBuf,
        store_path: PathBuf,
    ) -> Self {
        Self {
            shared,
            rx,
            tab: Tab::Feed,
            conns: Vec::new(),
            alerts: Vec::new(),
            config,
            config_path,
            store_path,
            really_quit: false,
            status: String::from("STARTING"),
            known: 0,
            last_scan: 0,
            cpu: CpuSampler::new(),
            core_usage: Vec::new(),
            last_cpu: 0,
        }
    }

    fn drain(&mut self) {
        while let Ok(tick) = self.rx.try_recv() {
            self.conns = tick.conns;
            self.last_scan = now_unix();
            self.known = self.shared.store.lock().unwrap().len();
            if tick.baselined {
                self.status = "BASELINE SET".to_string();
            } else if tick.alerts.is_empty() {
                self.status = "CALM".to_string();
            } else {
                let n = tick.alerts.len();
                self.alerts.splice(0..0, tick.alerts.into_iter().rev());
                self.alerts.truncate(200);
                self.status = format!("{n} NEW");
            }
        }
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        theme::apply(ctx, self.config.font_size as f32, self.config.dark_theme);
    }

    fn save_config(&self) {
        *self.shared.config.lock().unwrap() = self.config.clone();
        let _ = self.config.save(&self.config_path);
    }

    fn status_color(&self) -> egui::Color32 {
        if self.status.ends_with("NEW") {
            theme::amber()
        } else if self.status == "CALM" {
            theme::green()
        } else {
            theme::cyan()
        }
    }

    fn feed(&mut self, ui: &mut egui::Ui) {
        grid_backdrop(ui);
        let show_local = self.config.show_local_connections;
        let mut rows: Vec<&Connection> = self
            .conns
            .iter()
            .filter(|c| {
                c.exe.is_some() && (show_local || c.remote.is_none_or(|r| !r.ip().is_loopback()))
            })
            .collect();
        rows.sort_by(|a, b| a.exe.cmp(&b.exe));

        ui.horizontal(|ui| {
            core_strip(ui, &self.core_usage);
            ui.label(
                egui::RichText::new(format!("{} CORES", self.core_usage.len()))
                    .color(theme::dim())
                    .size(small(ui)),
            );
        });
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            gauge(ui, "LINKS", &rows.len().to_string());
            gauge(ui, "KNOWN", &self.known.to_string());
            let age = now_unix().saturating_sub(self.last_scan);
            gauge(ui, "SCAN", &format!("{age}s"));
        });
        ui.add_space(4.0);
        hr(ui);
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            section(ui, "ALERTS");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("TEST ALERT").clicked() {
                    self.shared.test_alert.store(true, Ordering::SeqCst);
                }
            });
        });
        if self.alerts.is_empty() {
            ui.label(
                egui::RichText::new("// no anomalies")
                    .color(theme::dim())
                    .size(small(ui)),
            );
        } else {
            let mut remove: Option<usize> = None;
            egui::ScrollArea::vertical()
                .id_salt("alerts")
                .max_height(150.0)
                .show(ui, |ui| {
                    for (idx, alert) in self.alerts.iter().enumerate() {
                        if alert_card(ui, alert) {
                            remove = Some(idx);
                        }
                    }
                });
            if let Some(i) = remove {
                self.alerts.remove(i);
            }
        }
        ui.add_space(8.0);

        section(ui, &format!("LINKS // {}", rows.len()));
        egui::ScrollArea::vertical()
            .id_salt("conns")
            .show(ui, |ui| {
                egui::Grid::new("links")
                    .num_columns(4)
                    .spacing([14.0, 5.0])
                    .show(ui, |ui| {
                        let mut i = 0;
                        while i < rows.len() {
                            let app = short_exe(rows[i].exe.as_deref());
                            let mut j = i;
                            while j < rows.len() && short_exe(rows[j].exe.as_deref()) == app {
                                j += 1;
                            }
                            for (k, c) in rows[i..j].iter().enumerate() {
                                if k == 0 {
                                    ui.horizontal(|ui| {
                                        app_badge(ui, &app);
                                        ui.label(
                                            egui::RichText::new(app.to_uppercase())
                                                .color(theme::cyan())
                                                .strong(),
                                        );
                                        ui.label(
                                            egui::RichText::new(format!("x{}", j - i))
                                                .color(theme::dim())
                                                .size(small(ui)),
                                        );
                                    });
                                } else {
                                    ui.label("");
                                }
                                let dest = c
                                    .remote
                                    .map(|r| r.to_string())
                                    .unwrap_or_else(|| "-".into());
                                ui.label(egui::RichText::new(dest).color(theme::text()));
                                let pid =
                                    c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
                                ui.label(
                                    egui::RichText::new(pid).color(theme::dim()).size(small(ui)),
                                );
                                ui.label(
                                    egui::RichText::new(state_name(&c.state))
                                        .color(state_color(&c.state)),
                                );
                                ui.end_row();
                            }
                            i = j;
                        }
                    });
            });
    }

    fn settings(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        grid_backdrop(ui);
        let mut changed = false;

        section(ui, "POLICY");
        changed |= ui
            .checkbox(
                &mut self.config.alert_on_new_endpoints,
                "Alert on new destinations for known apps",
            )
            .changed();
        ui.label(
            egui::RichText::new(
                "// off by default: a new destination for a trusted app is usually a CDN",
            )
            .color(theme::dim())
            .size(small(ui)),
        );
        ui.add_space(6.0);
        changed |= ui
            .checkbox(&mut self.config.quiet_browsers, "Keep browsers quiet")
            .changed();
        ui.add_space(6.0);
        changed |= ui
            .checkbox(
                &mut self.config.show_local_connections,
                "Show local (loopback) connections",
            )
            .changed();

        ui.add_space(12.0);
        section(ui, "DISPLAY");
        ui.horizontal(|ui| {
            if ui.button("-").clicked() && self.config.font_size > 9 {
                self.config.font_size -= 1;
                changed = true;
            }
            ui.label(
                egui::RichText::new(format!("{} px", self.config.font_size))
                    .color(theme::cyan())
                    .strong(),
            );
            if ui.button("+").clicked() && self.config.font_size < 20 {
                self.config.font_size += 1;
                changed = true;
            }
            ui.label(
                egui::RichText::new("ctrl +/- ; ctrl 0 resets")
                    .color(theme::dim())
                    .size(small(ui)),
            );
        });
        changed |= ui
            .checkbox(&mut self.config.dark_theme, "Dark HUD")
            .changed();

        if changed {
            self.save_config();
            self.apply_theme(ctx);
        }

        ui.add_space(12.0);
        section(ui, "PATHS");
        ui.label(
            egui::RichText::new(format!("config   {}", self.config_path.display()))
                .color(theme::dim())
                .size(small(ui)),
        );
        ui.label(
            egui::RichText::new(format!("baseline {}", self.store_path.display()))
                .color(theme::dim())
                .size(small(ui)),
        );
    }
}

fn small(ui: &egui::Ui) -> f32 {
    ui.style().text_styles[&egui::TextStyle::Small].size
}

fn fade(c: egui::Color32, a: u8) -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

/// One level meter per core: a stack of `CORE_LEVELS` lines, lit from the
/// bottom up to the current load. Redrawn every cycle; nothing accumulates.
fn core_strip(ui: &mut egui::Ui, usage: &[f32]) {
    if usage.is_empty() {
        return;
    }
    const COL_W: f32 = 16.0;
    const GAP: f32 = 6.0;
    const ROW_H: f32 = 3.0;
    let rows = CORE_LEVELS;
    let width = usage.len() as f32 * (COL_W + GAP);
    let height = rows as f32 * ROW_H;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter();
    for (ci, u) in usage.iter().enumerate() {
        let x = rect.left() + ci as f32 * (COL_W + GAP);
        let lit = (u * rows as f32).round() as usize;
        for row in 0..rows {
            // row 0 is the bottom line.
            let y = rect.top() + (rows - 1 - row) as f32 * ROW_H;
            let h = ROW_H - 1.0;
            let seg = egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(COL_W, h));
            let color = if row * 2 < rows {
                theme::cyan()
            } else if row * 5 < rows * 4 {
                theme::amber()
            } else {
                theme::red()
            };
            painter.rect_filled(seg, egui::CornerRadius::same(0), fade(theme::line(), 70));
            if row < lit {
                painter.rect_filled(seg, egui::CornerRadius::same(0), color);
            }
        }
    }
}

fn grid_backdrop(ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    let painter = ui.painter();
    let step = 24.0;
    let mut y = rect.top() + step;
    while y < rect.bottom() {
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            egui::Stroke::new(1.0, theme::grid()),
        );
        y += step;
    }
}

fn hr(ui: &mut egui::Ui) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 1.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(0), theme::line());
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 14.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(1), theme::amber());
        ui.label(egui::RichText::new(title).color(theme::text()).strong());
    });
}

fn gauge(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::NONE
        .fill(theme::panel2())
        .stroke(egui::Stroke::new(1.0, theme::line()))
        .corner_radius(egui::CornerRadius::same(2))
        .inner_margin(egui::Margin::symmetric(14, 6))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(label)
                        .color(theme::dim())
                        .size(small(ui)),
                );
                ui.label(egui::RichText::new(value).color(theme::cyan()).strong());
            });
        });
}

fn alert_card(ui: &mut egui::Ui, alert: &Alert) -> bool {
    let (accent, title) = match alert.kind {
        AlertKind::NewExecutable => (theme::red(), "NEW EXECUTABLE"),
        AlertKind::FirstSeenEndpoint => (theme::amber(), "NEW DESTINATION"),
    };
    let pid = alert
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".into());
    let detail = format!(
        "{}  pid {}  ->  {}",
        short_exe(Some(&alert.exe)),
        pid,
        alert.remote
    );
    let age = now_unix().saturating_sub(alert.first_seen_unix);
    let mut closed = false;
    egui::Frame::NONE
        .fill(theme::panel2())
        .stroke(egui::Stroke::new(1.0, theme::line()))
        .corner_radius(egui::CornerRadius::same(2))
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 22.0), egui::Sense::hover());
                ui.painter()
                    .rect_filled(rect, egui::CornerRadius::same(1), accent);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(title).color(accent).strong());
                    ui.label(
                        egui::RichText::new(detail)
                            .color(theme::text())
                            .size(small(ui)),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("X").on_hover_text("dismiss").clicked() {
                        closed = true;
                    }
                    ui.label(
                        egui::RichText::new(format!("{age}s"))
                            .color(theme::dim())
                            .size(small(ui)),
                    );
                });
            });
        });
    ui.add_space(4.0);
    closed
}

fn app_badge(ui: &mut egui::Ui, name: &str) {
    let body = ui.style().text_styles[&egui::TextStyle::Body].size;
    let size = body * 1.15;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let color = theme::badge(name);
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(3), color);
    let initial = name.chars().next().unwrap_or('?').to_ascii_uppercase();
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initial.to_string(),
        egui::FontId::monospace(body * 0.75),
        theme::bg(),
    );
}

fn state_color(code: &str) -> egui::Color32 {
    match code {
        "01" => theme::green(),
        "02" | "03" | "08" => theme::amber(),
        "0A" => theme::cyan(),
        "04" | "05" | "06" | "07" | "09" | "0B" => theme::dim(),
        _ => theme::text(),
    }
}

fn state_name(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "OTHER",
    }
}

fn short_exe(exe: Option<&str>) -> String {
    match exe {
        None => "-".into(),
        Some(path) => path.rsplit('/').next().unwrap_or(path).to_string(),
    }
}

impl eframe::App for ShieldApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        let ctx = ui.ctx().clone();

        let now = now_unix();
        if now > self.last_cpu {
            // Read the system once per second and replace the displayed load.
            self.core_usage = self.cpu.sample();
            self.last_cpu = now;
        }

        if self.shared.show.swap(false, Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if self.shared.quit.load(Ordering::SeqCst) {
            self.really_quit = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.really_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // Keyboard: ctrl +/- font, ctrl 0 reset, ctrl T test alert.
        let (delta, reset, test) = ctx.input(|i| {
            let m = i.modifiers.command;
            let plus = m && (i.key_pressed(egui::Key::Plus) || i.key_pressed(egui::Key::Equals));
            let minus = m && i.key_pressed(egui::Key::Minus);
            let reset = m && i.key_pressed(egui::Key::Num0);
            let test = m && i.key_pressed(egui::Key::T);
            (plus as i32 - minus as i32, reset, test)
        });
        if test {
            self.shared.test_alert.store(true, Ordering::SeqCst);
        }
        if delta != 0 || reset {
            let next = if reset {
                12
            } else {
                (self.config.font_size as i32 + delta).clamp(9, 20) as u32
            };
            if next != self.config.font_size {
                self.config.font_size = next;
                self.save_config();
                self.apply_theme(&ctx);
            }
        }

        egui::Panel::top("header")
            .frame(
                egui::Frame::NONE
                    .fill(theme::bg())
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 18.0), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(1), theme::cyan());
                    ui.label(
                        egui::RichText::new("SHIELD")
                            .color(theme::text())
                            .strong()
                            .size(18.0),
                    );
                    ui.add_space(10.0);
                    if ui.selectable_label(self.tab == Tab::Feed, "FEED").clicked() {
                        self.tab = Tab::Feed;
                    }
                    if ui
                        .selectable_label(self.tab == Tab::Settings, "SETTINGS")
                        .clicked()
                    {
                        self.tab = Tab::Settings;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let color = self.status_color();
                        egui::Frame::NONE
                            .fill(color)
                            .corner_radius(egui::CornerRadius::same(2))
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(&self.status)
                                        .color(theme::bg())
                                        .strong()
                                        .size(small(ui)),
                                );
                            });
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::panel())
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ui, |ui| match self.tab {
                Tab::Feed => self.feed(ui),
                Tab::Settings => self.settings(&ctx, ui),
            });

        ctx.request_repaint_after(Duration::from_millis(500));
    }
}
