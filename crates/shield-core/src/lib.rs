//! Shield core: per-process connection attribution from `/proc`, plus the
//! first-seen baseline that decides what is worth an alert.
//!
//! Userspace only, no privileges beyond reading `/proc` and a local data file.
//! The store is a dependency-free append-only TSV. This is a deliberate
//! deviation from the design doc's SQLite: the wedge does not need queries or
//! retention yet, and the reuse ladder says not to add a dependency for what a
//! few lines cover. Migrate to SQLite when history/search is actually needed.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One observed TCP socket, attributed to a process when possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub pid: Option<i32>,
    pub exe: Option<String>,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: String,
    pub inode: u64,
}

/// Raw row parsed from `/proc/net/tcp[6]` before process attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawConn {
    local: SocketAddr,
    remote: Option<SocketAddr>,
    state: String,
    inode: u64,
}

fn hex_u16(s: &str) -> Option<u16> {
    u16::from_str_radix(s, 16).ok()
}

/// Parse a `HEXADDR:HEXPORT` token from `/proc/net/tcp[6]`.
///
/// IPv4 is 8 hex chars in little-endian byte order; IPv6 is 32 hex chars as
/// four little-endian 32-bit words.
fn parse_addr(token: &str) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = token.split_once(':')?;
    let port = hex_u16(port_hex)?;
    let ip = match addr_hex.len() {
        8 => {
            let v = u32::from_str_radix(addr_hex, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(v.to_le_bytes()))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in addr_hex.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parse the body of a `/proc/net/tcp[6]` file into raw connections.
fn parse_proc_net(content: &str) -> Vec<RawConn> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // 0 sl, 1 local, 2 rem, 3 st, 4 tx:rx, ... 9 inode
        if cols.len() < 10 {
            continue;
        }
        let Some(local) = parse_addr(cols[1]) else {
            continue;
        };
        let Some(remote) = parse_addr(cols[2]) else {
            continue;
        };
        let Ok(inode) = cols[9].parse::<u64>() else {
            continue;
        };
        let remote = if remote.port() == 0 {
            None
        } else {
            Some(remote)
        };
        out.push(RawConn {
            local,
            remote,
            state: cols[3].to_string(),
            inode,
        });
    }
    out
}

/// Build inode -> (pid, exe) by scanning `/proc/<pid>/fd` symlinks.
fn inode_owner_map() -> std::collections::HashMap<u64, (i32, Option<String>)> {
    let mut map = std::collections::HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(s) = target.to_str() else { continue };
            let Some(rest) = s.strip_prefix("socket:[") else {
                continue;
            };
            let Some(inode_str) = rest.strip_suffix(']') else {
                continue;
            };
            let Ok(inode) = inode_str.parse::<u64>() else {
                continue;
            };
            let exe = fs::read_link(entry.path().join("exe"))
                .ok()
                .map(|p| p.display().to_string());
            map.insert(inode, (pid, exe));
        }
    }
    map
}

/// Snapshot every TCP connection currently visible to this user, attributed to
/// its owning process where the socket is reachable via `/proc`.
pub fn list_connections() -> Vec<Connection> {
    let owners = inode_owner_map();
    let mut out = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for raw in parse_proc_net(&content) {
            if raw.remote.is_none() {
                continue;
            }
            let (pid, exe) = match owners.get(&raw.inode) {
                Some((pid, exe)) => (Some(*pid), exe.clone()),
                None => (None, None),
            };
            out.push(Connection {
                pid,
                exe,
                local: raw.local,
                remote: raw.remote,
                state: raw.state,
                inode: raw.inode,
            });
        }
    }
    out
}

/// A distinct `(executable, remote ip, remote port)` triple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointKey {
    pub exe: String,
    pub ip: IpAddr,
    pub port: u16,
}

/// Why an alert fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    NewExecutable,
    FirstSeenEndpoint,
}

/// One thing worth telling the user about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    pub pid: Option<i32>,
    pub exe: String,
    pub remote: SocketAddr,
    pub first_seen_unix: u64,
}

impl Alert {
    /// A single readable line explaining the alert.
    pub fn describe(&self) -> String {
        let pid = self
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        let exe = &self.exe;
        let remote = self.remote;
        match self.kind {
            AlertKind::NewExecutable => {
                format!("new executable {exe} (pid {pid}) connected to {remote}")
            }
            AlertKind::FirstSeenEndpoint => {
                format!("{exe} (pid {pid}) first contacted {remote}")
            }
        }
    }
}

/// First-seen baseline: which executables and endpoints have been observed.
///
/// Persists as an append-only `exe\tip\tport\tts` file when given a path, or
/// stays in memory for tests.
#[derive(Debug, Default)]
pub struct FirstSeen {
    path: Option<PathBuf>,
    exes: HashSet<String>,
    endpoints: HashSet<EndpointKey>,
}

impl FirstSeen {
    /// An empty, non-persistent store (for tests and dry runs).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Load an existing store from `path` (missing file means an empty store).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            path: Some(path.clone()),
            ..Self::default()
        };
        let Ok(content) = fs::read_to_string(&path) else {
            return Ok(store);
        };
        for line in content.lines() {
            let mut parts = line.split('\t');
            let (Some(exe), Some(ip), Some(port)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else {
                continue;
            };
            store.exes.insert(exe.to_string());
            store.endpoints.insert(EndpointKey {
                exe: exe.to_string(),
                ip,
                port,
            });
        }
        Ok(store)
    }

    pub fn is_exe_known(&self, exe: &str) -> bool {
        self.exes.contains(exe)
    }

    pub fn has_endpoint(&self, key: &EndpointKey) -> bool {
        self.endpoints.contains(key)
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Record an endpoint. Appends to disk only when it is new.
    pub fn record(&mut self, exe: &str, ip: IpAddr, port: u16, ts: u64) -> io::Result<()> {
        self.exes.insert(exe.to_string());
        let key = EndpointKey {
            exe: exe.to_string(),
            ip,
            port,
        };
        if !self.endpoints.insert(key) {
            return Ok(());
        }
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(file, "{exe}\t{ip}\t{port}\t{ts}")?;
        }
        Ok(())
    }
}

/// Whether an executable looks like a web browser. Browsers churn through CDN
/// endpoints constantly, so they are quiet by default.
pub fn is_browser_exe(exe: &str) -> bool {
    let name = exe.rsplit('/').next().unwrap_or(exe).to_ascii_lowercase();
    const BROWSERS: &[&str] = &[
        "firefox",
        "firefox-bin",
        "firefox-esr",
        "chrome",
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "brave",
        "brave-browser",
        "opera",
        "opera-gx",
        "microsoft-edge",
        "msedge",
        "vivaldi",
        "vivaldi-bin",
        "epiphany",
        "tor-browser",
    ];
    BROWSERS
        .iter()
        .any(|b| name == *b || name.starts_with(&format!("{b}.")))
}

/// Alert policy, persisted as a small `key = value` file so the UI can toggle
/// it. Defaults are chosen to stay calm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Notify on a known executable contacting a first-seen endpoint.
    pub alert_on_new_endpoints: bool,
    /// Record but never alert on browsers' endpoint churn.
    pub quiet_browsers: bool,
    /// Show loopback (127.0.0.1/::1) connections in the UI feed. Loopback never
    /// leaves this machine, so it never alerts; this only affects the feed.
    pub show_local_connections: bool,
    /// Base UI font size in px. Clamped to 9..=20. Ctrl +/- in the app.
    pub font_size: u32,
    /// true = dark HUD, false = light.
    pub dark_theme: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            alert_on_new_endpoints: false,
            quiet_browsers: true,
            show_local_connections: false,
            font_size: 12,
            dark_theme: true,
        }
    }
}

impl Config {
    /// Load from `path`; a missing file yields defaults.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut config = Self::default();
        let Ok(content) = fs::read_to_string(path.as_ref()) else {
            return Ok(config);
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_ascii_lowercase();
            let on = matches!(value.as_str(), "true" | "1" | "yes" | "on");
            match key.trim() {
                "alert_on_new_endpoints" => config.alert_on_new_endpoints = on,
                "quiet_browsers" => config.quiet_browsers = on,
                "show_local_connections" => config.show_local_connections = on,
                "font_size" => {
                    if let Ok(n) = value.parse::<u32>() {
                        config.font_size = n.clamp(9, 20);
                    }
                }
                "dark_theme" => config.dark_theme = on,
                _ => {}
            }
        }
        Ok(config)
    }

    /// Persist to `path`, creating parent directories.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = format!(
            "# shield configuration\nalert_on_new_endpoints = {}\nquiet_browsers = {}\nshow_local_connections = {}\nfont_size = {}\ndark_theme = {}\n",
            self.alert_on_new_endpoints,
            self.quiet_browsers,
            self.show_local_connections,
            self.font_size,
            self.dark_theme
        );
        fs::write(path, body)
    }
}

/// Classify a snapshot against the baseline.
///
/// Every non-loopback, owned connection is recorded, so the baseline and the
/// future feed stay complete. An alert fires when an executable is seen for the
/// first time (always), or when a known executable contacts a first-seen
/// endpoint *and* policy allows it (`alert_on_new_endpoints`, except quiet
/// browsers). A brand-new executable gets one alert; its other endpoints are
/// recorded silently.
pub fn classify(
    store: &mut FirstSeen,
    conns: &[Connection],
    now: u64,
    config: &Config,
) -> io::Result<Vec<Alert>> {
    let mut alerts = Vec::new();
    let mut new_this_scan: HashSet<String> = HashSet::new();
    for c in conns {
        if c.inode == 0 {
            continue;
        }
        let Some(exe) = c.exe.as_deref() else {
            continue;
        };
        let Some(remote) = c.remote else { continue };
        if remote.ip().is_loopback() {
            continue;
        }
        let (ip, port) = (remote.ip(), remote.port());
        let key = EndpointKey {
            exe: exe.to_string(),
            ip,
            port,
        };
        let exe_known = store.is_exe_known(exe);
        let endpoint_known = store.has_endpoint(&key);
        store.record(exe, ip, port, now)?;

        if !exe_known {
            alerts.push(Alert {
                kind: AlertKind::NewExecutable,
                pid: c.pid,
                exe: exe.to_string(),
                remote,
                first_seen_unix: now,
            });
            new_this_scan.insert(exe.to_string());
            continue;
        }
        if new_this_scan.contains(exe) || endpoint_known {
            continue;
        }
        if !config.alert_on_new_endpoints {
            continue;
        }
        if config.quiet_browsers && is_browser_exe(exe) {
            continue;
        }
        alerts.push(Alert {
            kind: AlertKind::FirstSeenEndpoint,
            pid: c.pid,
            exe: exe.to_string(),
            remote,
            first_seen_unix: now,
        });
    }
    Ok(alerts)
}

/// Snapshot the machine and classify it against the baseline.
pub fn scan(store: &mut FirstSeen, now: u64, config: &Config) -> io::Result<Vec<Alert>> {
    let conns = list_connections();
    classify(store, &conns, now, config)
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse the `cpuN` lines of `/proc/stat` into `(busy, total)` tick counters.
/// The aggregate `cpu ` line is skipped.
fn parse_cpu_times(content: &str) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let Some(label) = it.next() else { continue };
        let Some(rest) = label.strip_prefix("cpu") else {
            continue;
        };
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let nums: Vec<u64> = it.filter_map(|s| s.parse().ok()).collect();
        if nums.len() < 4 {
            continue;
        }
        let total: u64 = nums.iter().sum();
        let idle = nums.get(3).copied().unwrap_or(0) + nums.get(4).copied().unwrap_or(0);
        out.push((total.saturating_sub(idle), total));
    }
    out
}

fn read_cpu_times() -> Vec<(u64, u64)> {
    std::fs::read_to_string("/proc/stat")
        .map(|c| parse_cpu_times(&c))
        .unwrap_or_default()
}

/// Samples per-core CPU usage from `/proc/stat`.
#[derive(Debug, Default)]
pub struct CpuSampler {
    prev: Vec<(u64, u64)>,
}

impl CpuSampler {
    pub fn new() -> Self {
        Self {
            prev: read_cpu_times(),
        }
    }

    /// Per-core busy fraction since the previous call, each in `0.0..=1.0`.
    pub fn sample(&mut self) -> Vec<f32> {
        let now = read_cpu_times();
        let mut out = Vec::with_capacity(now.len());
        for (i, (busy, total)) in now.iter().enumerate() {
            let (db, dt) = match self.prev.get(i) {
                Some((pb, pt)) => (busy.saturating_sub(*pb), total.saturating_sub(*pt)),
                None => (0, 0),
            };
            out.push(if dt > 0 {
                (db as f32 / dt as f32).clamp(0.0, 1.0)
            } else {
                0.0
            });
        }
        self.prev = now;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(pid: i32, exe: &str, ip: &str, port: u16, inode: u64) -> Connection {
        Connection {
            pid: Some(pid),
            exe: Some(exe.to_string()),
            local: "0.0.0.0:0".parse().unwrap(),
            remote: Some(format!("{ip}:{port}").parse().unwrap()),
            state: "01".to_string(),
            inode,
        }
    }

    #[test]
    fn parses_ipv4_little_endian() {
        let addr = parse_addr("0100007F:01BB").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn parses_ipv6_loopback() {
        let addr = parse_addr("00000000000000000000000001000000:0035").unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn parses_cpu_times_skips_aggregate() {
        let s = "cpu  10 20 30 40 5 6 7 0 0 0\n\
                 cpu0 1 2 3 4 5 6 7 0 0 0\n\
                 cpu1 2 3 4 5 6 7 8 0 0 0\n\
                 intr 123\n";
        let t = parse_cpu_times(s);
        assert_eq!(t.len(), 2);
        // cpu0: total 28, idle 4+5=9, busy 19
        assert_eq!(t[0], (19, 28));
        // cpu1: total 35, idle 5+6=11, busy 24
        assert_eq!(t[1], (24, 35));
    }

    #[test]
    fn skips_header_and_malformed_rows() {
        let sample = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                       0: 0100007F:1F90 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0\n\
                       garbage row\n";
        let rows = parse_proc_net(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inode, 4242);
        assert_eq!(rows[0].state, "01");
        assert_eq!(rows[0].remote.unwrap().port(), 443);
    }

    #[test]
    fn listen_has_no_remote() {
        let sample = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                       0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 99 1 0000000000000000 100 0 0 10 0\n";
        let rows = parse_proc_net(sample);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].remote.is_none());
    }

    #[test]
    fn new_executable_alerts_once_then_is_calm() {
        let mut store = FirstSeen::in_memory();
        let conns = vec![
            conn(100, "/usr/bin/curl", "93.184.216.34", 443, 10),
            conn(100, "/usr/bin/curl", "93.184.216.35", 443, 11),
        ];
        let alerts = classify(&mut store, &conns, 1, &Config::default()).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::NewExecutable);
        // Second endpoint of the same new exe is recorded silently.
        assert_eq!(store.len(), 2);

        let again = classify(&mut store, &conns, 2, &Config::default()).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn known_exe_new_endpoint_alerts() {
        let mut store = FirstSeen::in_memory();
        store
            .record("/usr/bin/curl", "93.184.216.34".parse().unwrap(), 443, 1)
            .unwrap();
        let conns = vec![conn(100, "/usr/bin/curl", "93.184.216.35", 443, 10)];
        let config = Config {
            alert_on_new_endpoints: true,
            ..Config::default()
        };
        let alerts = classify(&mut store, &conns, 2, &config).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::FirstSeenEndpoint);
        assert!(alerts[0].describe().contains("93.184.216.35"));
    }

    #[test]
    fn ignores_loopback_unowned_and_kernel_rows() {
        let mut store = FirstSeen::in_memory();
        let mut no_pid = conn(0, "/usr/bin/x", "8.8.8.8", 443, 10);
        no_pid.pid = None;
        no_pid.exe = None;
        let conns = vec![
            conn(100, "/usr/bin/curl", "127.0.0.1", 8080, 10),
            no_pid,
            conn(100, "/usr/bin/curl", "8.8.8.8", 443, 0),
        ];
        let alerts = classify(&mut store, &conns, 1, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn endpoint_alerts_off_by_default_but_still_recorded() {
        let mut store = FirstSeen::in_memory();
        store
            .record("/usr/bin/curl", "1.1.1.1".parse().unwrap(), 443, 1)
            .unwrap();
        let conns = vec![conn(1, "/usr/bin/curl", "2.2.2.2", 443, 10)];
        let alerts = classify(&mut store, &conns, 2, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        assert!(store.has_endpoint(&EndpointKey {
            exe: "/usr/bin/curl".to_string(),
            ip: "2.2.2.2".parse().unwrap(),
            port: 443,
        }));
    }

    #[test]
    fn browsers_stay_quiet_even_when_endpoint_alerts_are_on() {
        let mut store = FirstSeen::in_memory();
        store
            .record(
                "/usr/lib/firefox/firefox-bin",
                "1.1.1.1".parse().unwrap(),
                443,
                1,
            )
            .unwrap();
        let config = Config {
            alert_on_new_endpoints: true,
            ..Config::default()
        };
        let conns = vec![conn(1, "/usr/lib/firefox/firefox-bin", "2.2.2.2", 443, 10)];
        let alerts = classify(&mut store, &conns, 2, &config).unwrap();
        assert!(alerts.is_empty());
        assert!(store.has_endpoint(&EndpointKey {
            exe: "/usr/lib/firefox/firefox-bin".to_string(),
            ip: "2.2.2.2".parse().unwrap(),
            port: 443,
        }));
    }

    #[test]
    fn config_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("shield-cfg-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::remove_file(&path);
        let config = Config {
            alert_on_new_endpoints: true,
            quiet_browsers: false,
            show_local_connections: true,
            font_size: 15,
            dark_theme: false,
        };
        config.save(&path).unwrap();
        assert_eq!(Config::open(&path).unwrap(), config);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn config_defaults_show_local_off_and_parses_it() {
        let dir = std::env::temp_dir().join(format!("shield-cfg2-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::remove_file(&path);
        let _ = fs::create_dir_all(&dir);
        fs::write(&path, "show_local_connections = true\n").unwrap();
        assert!(Config::open(&path).unwrap().show_local_connections);
        fs::write(&path, "quiet_browsers = true\n").unwrap();
        assert!(!Config::open(&path).unwrap().show_local_connections);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn config_clamps_font_size() {
        let dir = std::env::temp_dir().join(format!("shield-cfg3-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::create_dir_all(&dir);
        fs::write(&path, "font_size = 99\n").unwrap();
        assert_eq!(Config::open(&path).unwrap().font_size, 20);
        fs::write(&path, "font_size = 1\n").unwrap();
        assert_eq!(Config::open(&path).unwrap().font_size, 9);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn store_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("shield-test-{}", std::process::id()));
        let path = dir.join("first-seen.tsv");
        let _ = fs::remove_file(&path);

        let mut store = FirstSeen::open(&path).unwrap();
        assert!(store.is_empty());
        store
            .record("/usr/bin/curl", "93.184.216.34".parse().unwrap(), 443, 1)
            .unwrap();

        let reloaded = FirstSeen::open(&path).unwrap();
        assert!(reloaded.is_exe_known("/usr/bin/curl"));
        assert!(reloaded.has_endpoint(&EndpointKey {
            exe: "/usr/bin/curl".to_string(),
            ip: "93.184.216.34".parse().unwrap(),
            port: 443,
        }));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
