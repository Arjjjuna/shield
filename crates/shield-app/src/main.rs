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
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::channel;
use std::sync::Arc;

use eframe::egui;
use ksni::blocking::TrayMethods;
use shield_core::{
    migrate_store, now_unix, scan, strip_deleted, Config, Destinations, TrustedApps,
};

use crate::gui::ShieldApp;
use crate::state::{Shared, Tick};
use crate::tray::ShieldTray;

fn data_dir() -> PathBuf {
    env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_store_path() -> PathBuf {
    data_dir().join("shield").join("destinations.tsv")
}

/// The pre-trust store name, read once and converted by `migrate_store`.
fn default_legacy_store_path() -> PathBuf {
    data_dir().join("shield").join("first-seen.tsv")
}

fn default_trusted_path() -> PathBuf {
    data_dir().join("shield").join("trusted-apps.tsv")
}

fn default_reset_path() -> PathBuf {
    data_dir().join("shield").join("reset-requested")
}

/// If Settings asked for a reset, clear the baseline and silently re-record
/// current connections before monitoring starts. Runs once, on the main thread,
/// while the store has no other owner. The alerts from this scan are dropped on
/// purpose: the first scan of an emptied store must stay quiet (review A1, A4).
fn apply_pending_reset(store: &mut Destinations, trusted: &TrustedApps, config: &Config) {
    let reset_path = default_reset_path();
    if !reset_path.exists() {
        return;
    }
    match store.clear() {
        Ok(()) => {
            let _ = scan(store, trusted, now_unix(), config);
            let _ = fs::remove_file(&reset_path);
            eprintln!("shield: destination history reset and re-baselined");
        }
        Err(err) => eprintln!("shield: reset failed: {err}"),
    }
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
    // Normalize the file so newly added keys (e.g. timezone) are
    // present even for an existing config.
    let _ = config.save(&config_path);
    let store_path = default_store_path();
    let trusted_path = default_trusted_path();

    // One-time conversion of the legacy IP-keyed store. `open` below reads only
    // the current format, so nothing is sniffed in place.
    match migrate_store(default_legacy_store_path(), &store_path) {
        Ok(true) => eprintln!("shield: migrated first-seen.tsv to destinations.tsv"),
        Ok(false) => {}
        Err(err) => eprintln!("shield: store migration failed: {err}"),
    }

    // A store that cannot be opened must not silently become an in-memory one:
    // the app still runs, but the failure is carried to the UI and shown (P1-1).
    let mut startup_error: Option<String> = None;
    let (mut store, store_persisted) = match Destinations::open(&store_path) {
        Ok(store) => (store, true),
        Err(err) => {
            eprintln!("shield: cannot open store {}: {err}", store_path.display());
            startup_error = Some(format!("cannot open {}: {err}", store_path.display()));
            (Destinations::in_memory(), false)
        }
    };
    let trusted = match TrustedApps::open(&trusted_path) {
        Ok(trusted) => trusted,
        Err(err) => {
            eprintln!(
                "shield: cannot open trust list {}: {err}",
                trusted_path.display()
            );
            if startup_error.is_none() {
                startup_error = Some(format!("cannot open {}: {err}", trusted_path.display()));
            }
            TrustedApps::in_memory()
        }
    };

    if baseline_only {
        let _ = scan(&mut store, &trusted, now_unix(), &config);
        if store_persisted {
            println!(
                "shield: baseline recorded ({} known destinations) at {}",
                store.len(),
                store_path.display()
            );
        } else {
            println!(
                "shield: baseline NOT persisted ({} destinations held in memory only; \
                 the store could not be opened)",
                store.len()
            );
        }
        return;
    }

    // One monitor owns the store. A second instance splits alerts (each sees the
    // other's pairs as already known) and can linger on a stale binary after an
    // update, so a duplicate start exits instead.
    if let Some(pid) = running_instance() {
        eprintln!("shield: already running (pid {pid}); use the tray icon to show it");
        return;
    }

    apply_pending_reset(&mut store, &trusted, &config);
    let shared = Arc::new(Shared::new(store, trusted, config.clone()));
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
        Ok(Box::new(ShieldApp::new(
            shared,
            rx,
            config,
            config_path,
            store_path,
            startup_error,
        )) as Box<dyn eframe::App>)
    });
    if let Err(err) = eframe::run_native("Shield", options, app_creator) {
        eprintln!("shield: GUI failed: {err}");
    }
}

/// The pid of another running `shield` process, if any. Best effort: any other
/// process whose executable resolves to the same program. This also catches a
/// copy left running an older binary — its `/proc/<pid>/exe` reads
/// `…/shield (deleted)` after an update replaced the file — so the guard holds
/// across an upgrade.
fn running_instance() -> Option<i32> {
    let me = std::process::id() as i32;
    let self_exe = exe_of(me)?;
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if pid != me && exe_of(pid).is_some_and(|exe| same_program(&exe, &self_exe)) {
            return Some(pid);
        }
    }
    None
}

/// `/proc/<pid>/exe`, with the kernel's `" (deleted)"` suffix stripped.
fn exe_of(pid: i32) -> Option<String> {
    let path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(strip_deleted(&path.to_string_lossy()))
}

/// Whether two executable paths name the same program, ignoring the kernel's
/// `" (deleted)"` suffix.
fn same_program(path: &str, self_exe: &str) -> bool {
    strip_deleted(path) == strip_deleted(self_exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_program_ignores_the_deleted_suffix() {
        assert!(same_program(
            "/usr/local/bin/shield (deleted)",
            "/usr/local/bin/shield"
        ));
        assert!(!same_program("/usr/local/bin/shield", "/usr/bin/shield"));
    }

    #[test]
    fn exe_of_a_missing_pid_is_none() {
        assert!(exe_of(-1).is_none());
    }
}
