//! Background monitor: scan `/proc`, classify, notify, and feed the UI.

use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use shield_core::{classify, list_connections, now_unix, Alert};

use crate::state::{Shared, Tick};

/// How often to snapshot connections. Five seconds is responsive without being
/// a busy loop.
pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the monitor thread. Runs until `shared.quit` is set.
pub fn spawn(shared: Arc<Shared>, tx: Sender<Tick>) {
    thread::spawn(move || loop {
        if shared.quit.load(Ordering::SeqCst) {
            break;
        }
        let config = shared.config.lock().unwrap().clone();
        let conns = list_connections();
        let mut alerts = {
            let mut store = shared.store.lock().unwrap();
            classify(&mut store, &conns, now_unix(), &config).unwrap_or_default()
        };
        if shared.test_alert.swap(false, Ordering::SeqCst) {
            alerts.push(Alert {
                pid: Some(std::process::id() as i32),
                exe: "shield-self-test".to_string(),
                remote: "203.0.113.9:443".parse().unwrap(),
                first_seen_unix: now_unix(),
            });
        }
        let baselined = shared.baseline_requested.swap(false, Ordering::SeqCst);

        if !baselined {
            for alert in &alerts {
                notify(alert);
            }
        }
        if !alerts.is_empty() {
            shared.has_alert.store(true, Ordering::SeqCst);
        }

        let _ = tx.send(Tick {
            conns,
            alerts: if baselined { Vec::new() } else { alerts },
            baselined,
        });

        thread::sleep(SCAN_INTERVAL);
    });
}

fn notify(alert: &Alert) {
    let _ = notify_rust::Notification::new()
        .summary("Shield")
        .body(&alert.describe())
        .show();
}
