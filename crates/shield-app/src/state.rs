//! Shared state between the monitor thread, the egui UI, and the tray.

use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use shield_core::{Alert, Config, Connection, Destinations};

/// State shared across threads. Everything is small and lock held briefly.
pub struct Shared {
    pub store: Mutex<Destinations>,
    pub config: Mutex<Config>,
    pub quit: AtomicBool,
    pub show: AtomicBool,
    pub baseline_requested: AtomicBool,
    pub has_alert: AtomicBool,
    /// Set by the UI to force a synthetic alert through the real pipeline.
    pub test_alert: AtomicBool,
}

impl Shared {
    pub fn new(store: Destinations, config: Config) -> Self {
        Self {
            store: Mutex::new(store),
            config: Mutex::new(config),
            quit: AtomicBool::new(false),
            show: AtomicBool::new(false),
            baseline_requested: AtomicBool::new(false),
            has_alert: AtomicBool::new(false),
            test_alert: AtomicBool::new(false),
        }
    }
}

/// One scan's result, sent from the monitor to the UI.
pub struct Tick {
    pub conns: Vec<Connection>,
    pub alerts: Vec<Alert>,
    pub baselined: bool,
}
