//! Shield core: per-process connection attribution from `/proc`, plus the
//! destination directory that decides what is worth an alert.
//!
//! Userspace only, no privileges beyond reading `/proc` and a local data file.
//! The store is a dependency-free append-only TSV. This is a deliberate
//! deviation from the design doc's SQLite: the wedge does not need queries or
//! retention yet, and the reuse ladder says not to add a dependency for what a
//! few lines cover. Migrate to SQLite when search over a large directory is
//! actually needed.

use std::collections::HashMap;
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

/// A known destination: one remote IP we have seen, with its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// First-seen UTC epoch seconds.
    pub first_seen: u64,
    /// The first executable seen contacting it.
    pub first_exe: String,
    /// Whether a human has looked at it. (Utopia: false on insert.)
    pub reviewed: bool,
    /// Whether it is considered safe. (Utopia: unknown until reviewed.)
    pub safe: bool,
}

/// One thing worth telling the user about: a destination seen for the first time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
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
        format!(
            "new destination {} - first contacted by {} (pid {pid})",
            self.remote.ip(),
            self.exe
        )
    }
}

/// Directory of remote IP destinations Shield has seen.
///
/// Persists as an append-only `ip\tts\treviewed\tsafe\tfirst_exe` file when
/// given a path, or stays in memory for tests. The legacy
/// `exe\tip\tport\tts` format is migrated on load.
#[derive(Debug, Default)]
pub struct Destinations {
    path: Option<PathBuf>,
    destinations: HashMap<IpAddr, Destination>,
}

impl Destinations {
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
            let fields: Vec<&str> = line.split('\t').collect();
            if let Some((ip, dest)) = parse_line(&fields) {
                store.destinations.entry(ip).or_insert(dest);
            }
        }
        Ok(store)
    }

    pub fn is_known(&self, ip: IpAddr) -> bool {
        self.destinations.contains_key(&ip)
    }

    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Every destination with its metadata, for display.
    pub fn entries(&self) -> Vec<(IpAddr, Destination)> {
        self.destinations
            .iter()
            .map(|(ip, dest)| (*ip, dest.clone()))
            .collect()
    }

    /// Forget everything and truncate the backing file, if any.
    ///
    /// Callers must treat an `Err` as real. Do not swallow it and continue as if
    /// the history were reset (see the review's A3).
    pub fn clear(&mut self) -> io::Result<()> {
        self.destinations.clear();
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(path, "")?;
        }
        Ok(())
    }

    /// Record a destination. Returns `true` when it was new (and appends to
    /// disk). A known destination is left untouched, so it is never re-flagged.
    pub fn record(&mut self, ip: IpAddr, exe: &str, ts: u64) -> io::Result<bool> {
        if self.destinations.contains_key(&ip) {
            return Ok(false);
        }
        // For now every destination counts as reviewed and safe. The utopia
        // inserts reviewed = false, safe = false instead, pending a real review.
        let dest = Destination {
            first_seen: ts,
            first_exe: exe.to_string(),
            reviewed: true,
            safe: true,
        };
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(file, "{ip}\t{ts}\t{}\t{}\t{exe}", dest.reviewed, dest.safe)?;
        }
        self.destinations.insert(ip, dest);
        Ok(true)
    }
}

/// Parse one store line in either the new `ip\tts\treviewed\tsafe\tfirst_exe`
/// format or the legacy `exe\tip\tport\tts` format.
fn parse_line(fields: &[&str]) -> Option<(IpAddr, Destination)> {
    let truthy = |v: &str| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    };
    if let Some(ip) = fields.first().and_then(|f| f.parse::<IpAddr>().ok()) {
        // New format.
        return Some((
            ip,
            Destination {
                first_seen: fields
                    .get(1)
                    .and_then(|t| t.parse::<u64>().ok())
                    .unwrap_or(0),
                first_exe: fields.get(4).map(|s| s.to_string()).unwrap_or_default(),
                reviewed: fields.get(2).map(|v| truthy(v)).unwrap_or(true),
                safe: fields.get(3).map(|v| truthy(v)).unwrap_or(true),
            },
        ));
    }
    // Legacy format: exe \t ip \t port \t ts.
    let first_exe = fields.first().map(|s| s.to_string()).unwrap_or_default();
    // Browsers are bypassed under the new rule, so an old browser row must not
    // whitelist the IP it visited.
    if is_browser_exe(&first_exe) {
        return None;
    }
    let ip = fields.get(1)?.parse::<IpAddr>().ok()?;
    Some((
        ip,
        Destination {
            first_seen: fields
                .get(3)
                .and_then(|t| t.parse::<u64>().ok())
                .unwrap_or(0),
            first_exe,
            reviewed: true,
            safe: true,
        },
    ))
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
    /// Bypass browsers entirely: no alert, no store.
    pub quiet_browsers: bool,
    /// Hide loopback (127.0.0.1/::1) rows from the UI feed. Loopback never leaves
    /// this machine, so it never alerts; this only affects the feed. Default true.
    pub quiet_local: bool,
    /// Base UI font size in px. Clamped to 9..=20. Ctrl +/- in the app.
    pub font_size: u32,
    /// true = dark HUD, false = light.
    pub dark_theme: bool,
    /// IANA timezone for display, e.g. `Europe/Paris`. Empty means system local.
    pub timezone: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            quiet_browsers: true,
            quiet_local: true,
            font_size: 12,
            dark_theme: true,
            timezone: String::new(),
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
        let mut saw_quiet_local = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let raw = value.trim();
            let on = matches!(
                raw.to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            );
            match key.trim() {
                "quiet_browsers" => config.quiet_browsers = on,
                "quiet_local" => {
                    config.quiet_local = on;
                    saw_quiet_local = true;
                }
                // Legacy key: `true` used to mean "show". Migrate to the inverse,
                // unless an explicit `quiet_local` was already seen.
                "show_local_connections" => {
                    if !saw_quiet_local {
                        config.quiet_local = !on;
                    }
                }
                "font_size" => {
                    if let Ok(n) = raw.parse::<u32>() {
                        config.font_size = n.clamp(9, 20);
                    }
                }
                "dark_theme" => config.dark_theme = on,
                // Timezone names are case-sensitive; keep the raw value.
                "timezone" => config.timezone = raw.trim_matches('"').to_string(),
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
            "# shield configuration\nquiet_browsers = {}\nquiet_local = {}\nfont_size = {}\ndark_theme = {}\ntimezone = {}\n",
            self.quiet_browsers,
            self.quiet_local,
            self.font_size,
            self.dark_theme,
            self.timezone
        );
        fs::write(path, body)
    }
}

/// Classify a snapshot against the destination directory.
///
/// One rule: the first time we see a remote IP, alert and record it. Browsers
/// (when `quiet_browsers`) and loopback (when `quiet_local`) are bypassed
/// entirely - neither alerted nor stored - so they cannot whitelist an IP for
/// anything else.
pub fn classify(
    store: &mut Destinations,
    conns: &[Connection],
    now: u64,
    config: &Config,
) -> io::Result<Vec<Alert>> {
    let mut alerts = Vec::new();
    for c in conns {
        if c.inode == 0 {
            continue;
        }
        let Some(exe) = c.exe.as_deref() else {
            continue;
        };
        let Some(remote) = c.remote else { continue };
        if config.quiet_local && remote.ip().is_loopback() {
            continue;
        }
        if config.quiet_browsers && is_browser_exe(exe) {
            continue;
        }
        if store.record(remote.ip(), exe, now)? {
            alerts.push(Alert {
                pid: c.pid,
                exe: exe.to_string(),
                remote,
                first_seen_unix: now,
            });
        }
    }
    Ok(alerts)
}

/// Snapshot the machine and classify it against the destination directory.
pub fn scan(store: &mut Destinations, now: u64, config: &Config) -> io::Result<Vec<Alert>> {
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
    fn new_destination_alerts_once_then_is_calm() {
        let mut store = Destinations::in_memory();
        let conns = vec![
            conn(100, "/usr/bin/curl", "93.184.216.34", 443, 10),
            conn(100, "/usr/bin/curl", "93.184.216.35", 443, 11),
        ];
        let alerts = classify(&mut store, &conns, 1, &Config::default()).unwrap();
        // One alert per new IP.
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].describe().contains("93.184.216.34"));
        assert_eq!(store.len(), 2);

        let again = classify(&mut store, &conns, 2, &Config::default()).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn same_ip_from_two_apps_alerts_once() {
        let mut store = Destinations::in_memory();
        let first = vec![conn(1, "/usr/bin/curl", "1.2.3.4", 443, 10)];
        let second = vec![conn(2, "/usr/bin/wget", "1.2.3.4", 80, 11)];
        assert_eq!(
            classify(&mut store, &first, 1, &Config::default())
                .unwrap()
                .len(),
            1
        );
        // The IP is known now, so another app reaching it is silent.
        assert!(classify(&mut store, &second, 2, &Config::default())
            .unwrap()
            .is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn ignores_loopback_unowned_and_kernel_rows() {
        let mut store = Destinations::in_memory();
        let mut no_pid = conn(0, "/usr/bin/x", "8.8.8.8", 443, 10);
        no_pid.pid = None;
        no_pid.exe = None;
        let conns = vec![
            conn(100, "/usr/bin/curl", "127.0.0.1", 8080, 10),
            no_pid,
            conn(100, "/usr/bin/curl", "8.8.8.8", 443, 0),
        ];
        let alerts = classify(&mut store, &conns, 1, &Config::default()).unwrap();
        // loopback (quiet_local on), a missing exe, and a kernel row are skipped.
        assert!(alerts.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn browsers_are_bypassed_entirely() {
        let mut store = Destinations::in_memory();
        let conns = vec![conn(1, "/usr/lib/firefox/firefox-bin", "2.2.2.2", 443, 10)];
        let alerts = classify(&mut store, &conns, 1, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        // Not stored, so it cannot whitelist the IP for another app.
        assert!(store.is_empty());
    }

    #[test]
    fn loopback_is_alerted_when_quiet_local_is_off() {
        let mut store = Destinations::in_memory();
        let conns = vec![conn(1, "/usr/bin/curl", "127.0.0.1", 8080, 10)];
        let config = Config {
            quiet_local: false,
            ..Config::default()
        };
        let alerts = classify(&mut store, &conns, 1, &config).unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(store.is_known("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn config_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("shield-cfg-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::remove_file(&path);
        let config = Config {
            quiet_browsers: false,
            quiet_local: false,
            font_size: 15,
            dark_theme: false,
            timezone: "Europe/Paris".to_string(),
        };
        config.save(&path).unwrap();
        assert_eq!(Config::open(&path).unwrap(), config);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn quiet_local_defaults_true_and_parses() {
        let dir = std::env::temp_dir().join(format!("shield-cfg2-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::create_dir_all(&dir);
        assert!(Config::default().quiet_local);
        fs::write(&path, "quiet_local = false\n").unwrap();
        assert!(!Config::open(&path).unwrap().quiet_local);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn legacy_show_local_migrates_inverted() {
        let dir = std::env::temp_dir().join(format!("shield-cfg-legacy-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::create_dir_all(&dir);
        fs::write(&path, "show_local_connections = true\n").unwrap();
        assert!(!Config::open(&path).unwrap().quiet_local);
        fs::write(&path, "show_local_connections = false\n").unwrap();
        assert!(Config::open(&path).unwrap().quiet_local);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn explicit_quiet_local_wins_over_legacy() {
        let dir = std::env::temp_dir().join(format!("shield-cfg-both-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::create_dir_all(&dir);
        // legacy first, explicit after
        fs::write(
            &path,
            "show_local_connections = false\nquiet_local = false\n",
        )
        .unwrap();
        assert!(!Config::open(&path).unwrap().quiet_local);
        // explicit first, legacy after
        fs::write(
            &path,
            "quiet_local = false\nshow_local_connections = true\n",
        )
        .unwrap();
        assert!(!Config::open(&path).unwrap().quiet_local);
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
        let path = dir.join("destinations.tsv");
        let _ = fs::remove_file(&path);

        let mut store = Destinations::open(&path).unwrap();
        assert!(store.is_empty());
        assert!(store
            .record("93.184.216.34".parse().unwrap(), "/usr/bin/curl", 1)
            .unwrap());

        let reloaded = Destinations::open(&path).unwrap();
        let entries = reloaded.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].1.first_seen, 1);
        assert_eq!(entries[0].1.first_exe, "/usr/bin/curl");
        assert!(entries[0].1.reviewed && entries[0].1.safe);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn open_reads_new_and_legacy_formats() {
        let dir = std::env::temp_dir().join(format!("shield-ts-{}", std::process::id()));
        let path = dir.join("destinations.tsv");
        let _ = fs::create_dir_all(&dir);
        fs::write(
            &path,
            // new: ip \t ts \t reviewed \t safe \t first_exe
            "1.1.1.1\t1700000000\ttrue\ttrue\t/usr/bin/a\n\
             /usr/bin/b\t2.2.2.2\t80\t1700000001\n\
             /usr/lib/firefox/firefox-bin\t3.3.3.3\t443\t1700000002\n",
        )
        .unwrap();
        let store = Destinations::open(&path).unwrap();
        assert_eq!(store.len(), 2);
        // A legacy browser row is dropped, not allowed to whitelist its IP.
        assert!(!store.is_known("3.3.3.3".parse().unwrap()));
        let entries = store.entries();
        let by_ip = |ip: &str| {
            entries
                .iter()
                .find(|(k, _)| *k == ip.parse::<IpAddr>().unwrap())
                .unwrap()
                .1
                .clone()
        };
        let d1 = by_ip("1.1.1.1");
        assert_eq!(d1.first_seen, 1_700_000_000);
        assert_eq!(d1.first_exe, "/usr/bin/a");
        // Legacy line migrates to the IP, reviewed and safe.
        let d2 = by_ip("2.2.2.2");
        assert_eq!(d2.first_seen, 1_700_000_001);
        assert_eq!(d2.first_exe, "/usr/bin/b");
        assert!(d2.reviewed && d2.safe);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn clear_empties_memory_and_truncates_file() {
        let dir = std::env::temp_dir().join(format!("shield-clear-{}", std::process::id()));
        let path = dir.join("destinations.tsv");
        let _ = fs::create_dir_all(&dir);
        let mut store = Destinations::open(&path).unwrap();
        assert!(store
            .record("1.1.1.1".parse().unwrap(), "/usr/bin/a", 5)
            .unwrap());
        assert_eq!(store.len(), 1);
        store.clear().unwrap();
        assert!(store.is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn duplicate_record_does_not_append_or_change_time() {
        let dir = std::env::temp_dir().join(format!("shield-dup-{}", std::process::id()));
        let path = dir.join("destinations.tsv");
        let _ = fs::create_dir_all(&dir);
        let mut store = Destinations::open(&path).unwrap();
        assert!(store
            .record("1.1.1.1".parse().unwrap(), "/usr/bin/a", 5)
            .unwrap());
        assert!(!store
            .record("1.1.1.1".parse().unwrap(), "/usr/bin/b", 99)
            .unwrap());
        assert_eq!(store.len(), 1);
        let entries = store.entries();
        assert_eq!(entries[0].1.first_seen, 5);
        assert_eq!(entries[0].1.first_exe, "/usr/bin/a");
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn config_parses_timezone_without_lowercasing() {
        let dir = std::env::temp_dir().join(format!("shield-tz-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _ = fs::create_dir_all(&dir);
        fs::write(&path, "timezone = Europe/Paris\n").unwrap();
        assert_eq!(Config::open(&path).unwrap().timezone, "Europe/Paris");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
