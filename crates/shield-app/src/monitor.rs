//! Background monitor: scan `/proc`, classify, notify, and feed the UI.

use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use shield_core::{classify, now_unix, snapshot, Alert, Config, Connection, Destinations};

use crate::state::{Shared, Tick};

/// How often to snapshot connections. Five seconds is responsive without being
/// a busy loop.
pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// Classify one snapshot, reporting a store failure as a message instead of
/// silently dropping the alerts. `unwrap_or_default()` here used to turn an
/// unwritable store into an empty (calm) tick — a false negative (review A2/Q1).
fn classify_reporting(
    store: &mut Destinations,
    conns: &[Connection],
    now: u64,
    config: &Config,
) -> (Vec<Alert>, Option<String>) {
    match classify(store, conns, now, config) {
        Ok(alerts) => (alerts, None),
        Err(err) => (Vec::new(), Some(format!("store write failed: {err}"))),
    }
}

/// Spawn the monitor thread. Runs until `shared.quit` is set.
pub fn spawn(shared: Arc<Shared>, tx: Sender<Tick>) {
    thread::spawn(move || loop {
        if shared.quit.load(Ordering::SeqCst) {
            break;
        }
        // Poison-safe: a panic elsewhere must not take the monitor down with it
        // (that is exactly the silent-death failure this guards against).
        let config = shared
            .config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let snap = snapshot();
        let conns = snap.connections;
        let (mut alerts, error) = {
            let mut store = shared.store.lock().unwrap_or_else(|e| e.into_inner());
            classify_reporting(&mut store, &conns, now_unix(), &config)
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
            procs: snap.processes,
            error,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_conn() -> Connection {
        Connection {
            pid: Some(1),
            exe: Some("/usr/bin/curl".to_string()),
            local: "0.0.0.0:0".parse().unwrap(),
            remote: Some("1.2.3.4:443".parse().unwrap()),
            state: "01".to_string(),
            inode: 10,
        }
    }

    #[test]
    fn classify_reporting_is_quiet_when_the_store_is_writable() {
        let mut store = Destinations::in_memory();
        let (alerts, error) =
            classify_reporting(&mut store, &[sample_conn()], 1, &Config::default());
        assert_eq!(alerts.len(), 1);
        assert!(error.is_none());
    }

    #[test]
    fn classify_reporting_surfaces_an_unwritable_store() {
        // Open a store, then make its parent unwritable by replacing the
        // directory with a file. The next write fails; that failure must be
        // reported, not swallowed into an empty alert list.
        let dir = std::env::temp_dir().join(format!("shield-mon-err-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("destinations.tsv");
        let mut store = Destinations::open(&path).unwrap(); // file missing -> empty
        fs::remove_dir_all(&dir).unwrap();
        fs::write(&dir, b"x").unwrap();

        let (alerts, error) =
            classify_reporting(&mut store, &[sample_conn()], 1, &Config::default());
        assert!(alerts.is_empty());
        assert!(
            error.is_some(),
            "a failed store write must be reported, not dropped"
        );

        let _ = fs::remove_file(&dir);
    }
}
