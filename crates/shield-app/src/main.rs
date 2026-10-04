//! Shield entrypoint.
//!
//! `shield` with no arguments opens the GUI (tray + window). Headless modes:
//!   --list      print current connections and exit
//!   --baseline  record current connections without alerting and exit
//!   --hidden    start with the window hidden (for autostart)

mod gui;
mod monitor;
mod state;
mod theme;
mod tray;

use std::env;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::sync::Arc;

use eframe::egui;
use ksni::blocking::TrayMethods;
use shield_core::{now_unix, scan, Config, FirstSeen};

use crate::gui::ShieldApp;
use crate::state::{Shared, Tick};
use crate::tray::ShieldTray;

fn default_store_path() -> PathBuf {
    let base = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("shield").join("first-seen.tsv")
}

fn default_config_path() -> PathBuf {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("shield").join("config.toml")
}

fn print_connections() {
    let conns = shield_core::list_connections();
    if conns.is_empty() {
        println!("shield: no established connections visible to this user");
        return;
    }
    println!(
        "{:>7}  {:<40}  {:<24}  {:<5}  INODE",
        "PID", "EXE", "REMOTE", "STATE"
    );
    for c in conns {
        println!(
            "{:>7}  {:<40}  {:<24}  {:<5}  {}",
            c.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
            c.exe.unwrap_or_else(|| "?".into()),
            c.remote
                .map(|r| r.to_string())
                .unwrap_or_else(|| "-".into()),
            c.state,
            c.inode,
        );
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--list") {
        print_connections();
        return;
    }
    let baseline_only = args.iter().any(|a| a == "--baseline");
    let hidden = args.iter().any(|a| a == "--hidden");
    let test_alert = args.iter().any(|a| a == "--test-alert");

    let config_path = default_config_path();
    let config = Config::open(&config_path).unwrap_or_default();
    // Normalize the file so newly added keys (e.g. show_local_connections) are
    // present even for an existing config.
    let _ = config.save(&config_path);
    let store_path = default_store_path();

    if baseline_only {
        let mut store = FirstSeen::open(&store_path).unwrap_or_else(|_| FirstSeen::in_memory());
        let _ = scan(&mut store, now_unix(), &config);
        println!(
            "shield: baseline recorded ({} known endpoints) at {}",
            store.len(),
            store_path.display()
        );
        return;
    }

    let store = FirstSeen::open(&store_path).unwrap_or_else(|_| FirstSeen::in_memory());
    let shared = Arc::new(Shared::new(store, config.clone()));
    if test_alert {
        shared.test_alert.store(true, Ordering::SeqCst);
    }
    let (tx, rx) = channel::<Tick>();

    let tray = ShieldTray {
        shared: shared.clone(),
    };
    let _tray_handle = match tray.spawn() {
        Ok(handle) => Some(handle),
        Err(err) => {
            eprintln!("shield: tray unavailable: {err}");
            None
        }
    };

    monitor::spawn(shared.clone(), tx);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([820.0, 520.0])
            .with_title("Shield")
            .with_visible(!hidden),
        ..Default::default()
    };
    let app_creator = Box::new(move |cc: &eframe::CreationContext<'_>| {
        theme::apply(&cc.egui_ctx, config.font_size as f32, config.dark_theme);
        Ok(
            Box::new(ShieldApp::new(shared, rx, config, config_path, store_path))
                as Box<dyn eframe::App>,
        )
    });
    if let Err(err) = eframe::run_native("Shield", options, app_creator) {
        eprintln!("shield: GUI failed: {err}");
    }
}
