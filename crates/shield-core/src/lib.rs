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

/// The identity of a running app: `key` is what we store and trust (a verified
/// script path for interpreter-hosted apps, otherwise the executable path);
/// `label` is the short name to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppId {
    pub key: String,
    pub label: String,
}

/// One observed TCP socket, attributed to a process when possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub pid: Option<i32>,
    pub exe: Option<String>,
    /// The resolved app identity (`None` when the exe is unknown).
    pub app: Option<AppId>,
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

/// One running process visible to this user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub pid: i32,
    /// The resolved app identity. Only processes whose executable we can read
    /// appear at all; kernel threads have no exe and are never listed.
    pub app: AppId,
    /// Number of external (remote) TCP connections it currently holds.
    pub connections: usize,
}

/// One app's processes collapsed to a single row (for the processes tab and the
/// feed's trust pane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    /// The app key: a verified script path or an executable path.
    pub key: String,
    /// The short name to show.
    pub label: String,
    pub pids: Vec<i32>,
    pub connections: usize,
}

/// Collapse a per-pid process list into one row per app, sorted by key, with pids
/// sorted ascending.
pub fn group_processes(procs: &[Process]) -> Vec<AppRow> {
    let mut by_key: HashMap<String, AppRow> = HashMap::new();
    for p in procs {
        let row = by_key.entry(p.app.key.clone()).or_insert_with(|| AppRow {
            key: p.app.key.clone(),
            label: p.app.label.clone(),
            pids: Vec::new(),
            connections: 0,
        });
        row.pids.push(p.pid);
        row.connections += p.connections;
    }
    finish_rows(by_key)
}

/// Collapse live connections into one row per app: unique pids and the number of
/// external (non-loopback) links, sorted by key. Used by the feed's trust pane.
pub fn group_connections(conns: &[Connection]) -> Vec<AppRow> {
    let mut by_key: HashMap<String, AppRow> = HashMap::new();
    for c in conns {
        let Some(app) = c.app.as_ref() else { continue };
        if c.remote.is_some_and(|r| r.ip().is_loopback()) {
            continue;
        }
        let row = by_key.entry(app.key.clone()).or_insert_with(|| AppRow {
            key: app.key.clone(),
            label: app.label.clone(),
            pids: Vec::new(),
            connections: 0,
        });
        row.connections += 1;
        if let Some(pid) = c.pid {
            if !row.pids.contains(&pid) {
                row.pids.push(pid);
            }
        }
    }
    finish_rows(by_key)
}

/// Sort pids within each row and the rows by key.
fn finish_rows(by_key: HashMap<String, AppRow>) -> Vec<AppRow> {
    let mut rows: Vec<AppRow> = by_key.into_values().collect();
    for row in &mut rows {
        row.pids.sort_unstable();
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    rows
}

/// Attach per-pid connection counts to resolved apps, sorted by `(key, pid)`.
fn build_processes(
    apps: Vec<(i32, AppId)>,
    connections_by_pid: &HashMap<i32, usize>,
) -> Vec<Process> {
    let mut procs: Vec<Process> = apps
        .into_iter()
        .map(|(pid, app)| Process {
            pid,
            app,
            connections: connections_by_pid.get(&pid).copied().unwrap_or(0),
        })
        .collect();
    procs.sort_by(|a, b| a.app.key.cmp(&b.app.key).then(a.pid.cmp(&b.pid)));
    procs
}

/// inode -> (pid, exe) attribution for the socket fds we could reach.
type OwnedInode = HashMap<u64, (i32, Option<String>)>;

/// Walk `/proc` once: map socket inodes to their owning pid and resolve every
/// process whose executable we can read to an `AppId`. Returns `(owners, apps)`.
fn scan_proc() -> (OwnedInode, HashMap<i32, AppId>) {
    let mut owners: OwnedInode = HashMap::new();
    let mut apps: HashMap<i32, AppId> = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return (owners, apps);
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        // Read the executable once per process, not once per socket fd.
        let exe = fs::read_link(entry.path().join("exe"))
            .ok()
            .map(|p| p.display().to_string())
            .map(|path| strip_deleted(&path));
        if let Some(exe) = &exe {
            apps.insert(pid, resolve_app(pid, exe));
        }
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
            owners.insert(inode, (pid, exe.clone()));
        }
    }
    (owners, apps)
}

/// Resolve a pid's app identity from its executable and command line.
fn resolve_app(pid: i32, exe: &str) -> AppId {
    if !is_interpreter(exe) {
        return AppId {
            key: exe.to_string(),
            label: app_name(exe),
        };
    }
    let argv = read_cmdline(pid);
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).ok();
    let path_env = read_path_env(pid);
    app_identity(exe, &argv, cwd.as_deref(), path_env.as_deref())
}

/// Attribute the `/proc/net/tcp[6]` rows using a prepared inode -> owner map.
fn list_connections_with(owners: &OwnedInode, apps: &HashMap<i32, AppId>) -> Vec<Connection> {
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
            let app = pid.and_then(|p| apps.get(&p).cloned());
            out.push(Connection {
                pid,
                exe,
                app,
                local: raw.local,
                remote: raw.remote,
                state: raw.state,
                inode: raw.inode,
            });
        }
    }
    out
}

/// Everything one `/proc` traversal yields, so the monitor walks `/proc` once
/// per cycle instead of once for connections and again for processes.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub connections: Vec<Connection>,
    pub processes: Vec<Process>,
}

/// Count external (non-loopback) connections per pid.
fn count_connections_by_pid(conns: &[Connection]) -> HashMap<i32, usize> {
    let mut counts: HashMap<i32, usize> = HashMap::new();
    for c in conns {
        if let Some(pid) = c.pid {
            // Loopback never leaves the machine; it is not an external link.
            if c.remote.is_some_and(|r| r.ip().is_loopback()) {
                continue;
            }
            *counts.entry(pid).or_default() += 1;
        }
    }
    counts
}

/// Snapshot every TCP connection and every readable process of this user.
pub fn snapshot() -> Snapshot {
    let (owners, apps) = scan_proc();
    let connections = list_connections_with(&owners, &apps);
    let connections_by_pid = count_connections_by_pid(&connections);
    let processes = build_processes(apps.into_iter().collect(), &connections_by_pid);
    Snapshot {
        connections,
        processes,
    }
}

/// Snapshot every TCP connection currently visible to this user, attributed to
/// its owning process where the socket is reachable via `/proc`.
pub fn list_connections() -> Vec<Connection> {
    let (owners, apps) = scan_proc();
    list_connections_with(&owners, &apps)
}

/// A known destination: a remote IP a given app has contacted, with its
/// verdict. Kept per `(app, ip)` so trust is per-app (trusted-apps design A2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// First-seen UTC epoch seconds.
    pub first_seen: u64,
    /// Whether it has a verdict. A trusted app inserts `true`; an unknown app
    /// inserts `false` until that app is trusted.
    pub reviewed: bool,
    /// Whether it is considered safe. A trusted app inserts `true`; an unknown
    /// app inserts `false`.
    pub safe: bool,
}

/// One thing worth telling the user about: a destination seen for the first time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub pid: Option<i32>,
    /// The raw executable. For an interpreter-hosted app this is the
    /// interpreter, so prefer `app` for display.
    pub exe: String,
    /// The resolved app identity, when known.
    pub app: Option<AppId>,
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
        let who = self
            .app
            .as_ref()
            .map(|app| app.label.clone())
            .unwrap_or_else(|| app_name(&self.exe));
        format!(
            "new destination {} - first contacted by {who} (pid {pid})",
            self.remote.ip(),
        )
    }
}

/// Directory of remote destinations Shield has seen, keyed by `(exe, ip)`.
///
/// Persists as an append-only `exe \t ip \t ts \t reviewed \t safe` file when
/// given a path, or stays in memory for tests. A legacy `first-seen.tsv` is
/// converted once by `migrate_store`, never read here.
#[derive(Debug, Default)]
pub struct Destinations {
    path: Option<PathBuf>,
    destinations: HashMap<(String, IpAddr), Destination>,
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
        match fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    if let Some((key, dest)) = parse_destination_line(line) {
                        store.destinations.entry(key).or_insert(dest);
                    }
                }
            }
            // A missing file is a genuinely empty store. Any other read error is
            // real and must surface: silently treating an unreadable store as
            // empty makes a broken store look like "nothing has ever happened".
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        Ok(store)
    }

    pub fn is_known(&self, exe: &str, ip: IpAddr) -> bool {
        self.destinations.contains_key(&(exe.to_string(), ip))
    }

    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }

    /// Every destination with its key, for display.
    pub fn entries(&self) -> Vec<(String, IpAddr, Destination)> {
        self.destinations
            .iter()
            .map(|((exe, ip), dest)| (exe.clone(), *ip, dest.clone()))
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
    /// disk). A known pair is left untouched. `reviewed`/`safe` are the caller's
    /// verdict: a trusted app passes `true`/`true`, an unknown app
    /// `false`/`false`.
    pub fn record(
        &mut self,
        exe: &str,
        ip: IpAddr,
        ts: u64,
        reviewed: bool,
        safe: bool,
    ) -> io::Result<bool> {
        let key = (exe.to_string(), ip);
        if self.destinations.contains_key(&key) {
            return Ok(false);
        }
        let dest = Destination {
            first_seen: ts,
            reviewed,
            safe,
        };
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            writeln!(file, "{exe}\t{ip}\t{ts}\t{}\t{}", dest.reviewed, dest.safe)?;
        }
        self.destinations.insert(key, dest);
        Ok(true)
    }

    /// Mark every recorded destination of `exe` reviewed and safe, rewriting the
    /// file. Used when the user trusts an app (retroactive).
    pub fn mark_app_safe(&mut self, exe: &str) -> io::Result<()> {
        let mut changed = false;
        for ((e, _), dest) in self.destinations.iter_mut() {
            if e == exe && !(dest.reviewed && dest.safe) {
                dest.reviewed = true;
                dest.safe = true;
                changed = true;
            }
        }
        if changed {
            self.rewrite()?;
        }
        Ok(())
    }

    /// Mark one `(app, IP)` pair reviewed and safe, rewriting the file. Used when
    /// the user validates a single destination. Returns whether it changed.
    pub fn mark_pair_safe(&mut self, exe: &str, ip: IpAddr) -> io::Result<bool> {
        let changed = match self.destinations.get_mut(&(exe.to_string(), ip)) {
            Some(dest) if !(dest.reviewed && dest.safe) => {
                dest.reviewed = true;
                dest.safe = true;
                true
            }
            _ => false,
        };
        if changed {
            self.rewrite()?;
        }
        Ok(changed)
    }

    /// Rewrite the whole file from memory (after a bulk update).
    fn rewrite(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut lines: Vec<String> = self
            .destinations
            .iter()
            .map(|((exe, ip), d)| {
                format!(
                    "{exe}\t{ip}\t{}\t{}\t{}\n",
                    d.first_seen, d.reviewed, d.safe
                )
            })
            .collect();
        lines.sort();
        fs::write(path, lines.concat())
    }
}

/// Truthy parsing for stored flag values.
fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

/// Parse one line of the current store: `exe \t ip \t ts \t reviewed \t safe`.
fn parse_destination_line(line: &str) -> Option<((String, IpAddr), Destination)> {
    let f: Vec<&str> = line.split('\t').collect();
    let exe = f.first().filter(|s| !s.is_empty())?.to_string();
    let ip = f.get(1)?.parse::<IpAddr>().ok()?;
    Some((
        (exe, ip),
        Destination {
            first_seen: f.get(2).and_then(|t| t.parse().ok()).unwrap_or(0),
            reviewed: f.get(3).map(|v| truthy(v)).unwrap_or(false),
            safe: f.get(4).map(|v| truthy(v)).unwrap_or(false),
        },
    ))
}

/// Parse one line of a legacy `first-seen.tsv`, in either historical shape:
/// `ip \t ts \t reviewed \t safe \t first_exe`, or `exe \t ip \t port \t ts`.
fn parse_legacy_line(line: &str) -> Option<(String, IpAddr, Destination)> {
    let f: Vec<&str> = line.split('\t').collect();
    // Current legacy format: the first field is the IP.
    if let Some(ip) = f.first().and_then(|s| s.parse::<IpAddr>().ok()) {
        let exe = f.get(4).filter(|s| !s.is_empty())?.to_string();
        return Some((
            exe,
            ip,
            Destination {
                first_seen: f.get(1).and_then(|t| t.parse().ok()).unwrap_or(0),
                reviewed: f.get(2).map(|v| truthy(v)).unwrap_or(true),
                safe: f.get(3).map(|v| truthy(v)).unwrap_or(true),
            },
        ));
    }
    // Original format: `exe \t ip \t port \t ts`. Browser rows are dropped so
    // they cannot whitelist the IP they visited.
    let exe = f.first()?.to_string();
    if exe.is_empty() || is_browser_exe(&exe) {
        return None;
    }
    let ip = f.get(1)?.parse::<IpAddr>().ok()?;
    Some((
        exe,
        ip,
        Destination {
            first_seen: f.get(3).and_then(|t| t.parse().ok()).unwrap_or(0),
            reviewed: true,
            safe: true,
        },
    ))
}

/// One-time migration from a legacy `first-seen.tsv` to the `(exe, ip)`
/// `destinations.tsv`. Does nothing (`Ok(false)`) if `destinations` already
/// exists or the legacy file is absent. Returns `true` when it wrote the new
/// file. Existing verdicts are preserved, so nothing re-alerts.
pub fn migrate_store(legacy: impl AsRef<Path>, destinations: impl AsRef<Path>) -> io::Result<bool> {
    let destinations = destinations.as_ref();
    if destinations.exists() {
        return Ok(false);
    }
    let content = match fs::read_to_string(legacy.as_ref()) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let mut merged: HashMap<(String, IpAddr), Destination> = HashMap::new();
    for line in content.lines() {
        let Some((exe, ip, dest)) = parse_legacy_line(line) else {
            continue;
        };
        match merged.get_mut(&(exe.clone(), ip)) {
            // Earliest first-seen wins; a safe verdict from any row sticks.
            Some(existing) => {
                if dest.first_seen != 0
                    && (existing.first_seen == 0 || dest.first_seen < existing.first_seen)
                {
                    existing.first_seen = dest.first_seen;
                }
                existing.reviewed |= dest.reviewed;
                existing.safe |= dest.safe;
            }
            None => {
                merged.insert((exe, ip), dest);
            }
        }
    }
    if merged.is_empty() {
        return Ok(false);
    }
    if let Some(parent) = destinations.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut lines: Vec<String> = merged
        .iter()
        .map(|((exe, ip), d)| {
            format!(
                "{exe}\t{ip}\t{}\t{}\t{}\n",
                d.first_seen, d.reviewed, d.safe
            )
        })
        .collect();
    lines.sort();
    fs::write(destinations, lines.concat())?;
    Ok(true)
}

/// One app the user has explicitly trusted, pinned by executable path (v1;
/// content hashing is deferred, TODOS P2-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedApp {
    pub name: String,
    pub first_trusted: u64,
}

/// Apps the user has explicitly entrusted. Persists as
/// `exe \t name \t first_trusted`; absent means nothing is trusted.
#[derive(Debug, Default)]
pub struct TrustedApps {
    path: Option<PathBuf>,
    apps: HashMap<String, TrustedApp>,
}

impl TrustedApps {
    /// An empty, non-persistent trust list (for tests and dry runs).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Load from `path` (missing file means nothing is trusted).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            path: Some(path.clone()),
            ..Self::default()
        };
        match fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    let f: Vec<&str> = line.split('\t').collect();
                    let Some(exe) = f.first().filter(|s| !s.is_empty()).map(|s| s.to_string())
                    else {
                        continue;
                    };
                    let name = f
                        .get(1)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| app_name(&exe));
                    let first_trusted = f.get(2).and_then(|t| t.parse().ok()).unwrap_or(0);
                    store.apps.entry(exe).or_insert(TrustedApp {
                        name,
                        first_trusted,
                    });
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        Ok(store)
    }

    pub fn is_trusted(&self, exe: &str) -> bool {
        self.apps.contains_key(exe)
    }

    pub fn len(&self) -> usize {
        self.apps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }

    /// Every trusted app with its metadata, for display, sorted by name.
    pub fn entries(&self) -> Vec<(String, TrustedApp)> {
        let mut out: Vec<(String, TrustedApp)> = self
            .apps
            .iter()
            .map(|(e, a)| (e.clone(), a.clone()))
            .collect();
        out.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        out
    }

    /// Trust `exe` (idempotent) and persist the list.
    pub fn trust(&mut self, exe: &str, ts: u64) -> io::Result<()> {
        self.apps.entry(exe.to_string()).or_insert(TrustedApp {
            name: app_name(exe),
            first_trusted: ts,
        });
        self.rewrite()
    }

    /// Remove trust from `exe` (idempotent) and persist the list.
    pub fn untrust(&mut self, exe: &str) -> io::Result<()> {
        if self.apps.remove(exe).is_none() {
            return Ok(());
        }
        self.rewrite()
    }

    fn rewrite(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut lines: Vec<String> = self
            .apps
            .iter()
            .map(|(exe, app)| format!("{exe}\t{}\t{}\n", app.name, app.first_trusted))
            .collect();
        lines.sort();
        fs::write(path, lines.concat())
    }
}

/// The display name of an executable: its basename.
pub fn app_name(exe: &str) -> String {
    exe.rsplit('/').next().unwrap_or(exe).to_string()
}

/// The name to show for a resolved identifier. When the identifier is still a
/// bare interpreter the real script could not be resolved, so the name is
/// marked `_unknown` (`python3.12_unknown`) rather than passing the interpreter
/// off as the app.
pub fn display_name(identifier: &str) -> String {
    let name = app_name(identifier);
    if is_interpreter(identifier) {
        format!("{name}_unknown")
    } else {
        name
    }
}

/// Whether an executable is a known script interpreter, in which case the real
/// app is the script it was handed rather than the binary.
pub fn is_interpreter(exe: &str) -> bool {
    let name = app_name(exe).to_ascii_lowercase();
    match name.as_str() {
        "python" | "python3" | "node" | "nodejs" | "deno" | "bun" | "ruby" | "perl" | "php" => true,
        // python3.12, python3.11, ... but not python3-config or pythonic.
        _ => name
            .strip_prefix("python3.")
            .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit())),
    }
}

/// A script path found in a command line, before filesystem verification.
#[derive(Debug, PartialEq, Eq)]
enum Candidate {
    /// Contains a `/`; resolve against the cwd if relative.
    Path(String),
    /// A bare name; search `PATH`.
    Name(String),
}

fn classify_candidate(token: &str) -> Candidate {
    if token.contains('/') {
        Candidate::Path(token.to_string())
    } else {
        Candidate::Name(token.to_string())
    }
}

/// Find the script candidate in a command line, without touching the filesystem.
///
/// `argv[0]` is the program as invoked: if it is not an interpreter it names the
/// app (some processes rename themselves this way). If it is an interpreter, the
/// script is the first following non-flag argument; `-m MODULE` has no file and
/// yields none.
fn script_candidate(argv: &[String]) -> Option<Candidate> {
    let first = argv.first()?;
    if !is_interpreter(first) {
        return Some(classify_candidate(first));
    }
    for token in argv.iter().skip(1) {
        if token == "-m" {
            return None;
        }
        if token.starts_with('-') {
            continue;
        }
        return Some(classify_candidate(token));
    }
    None
}

/// Whether `path` is a readable regular file.
fn is_readable_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false) && fs::File::open(path).is_ok()
}

/// Standard directories searched when a process ships no `PATH`.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin";

/// Resolve a candidate to an absolute, canonicalised readable regular file.
fn resolve_candidate(
    candidate: &Candidate,
    cwd: Option<&Path>,
    path_env: Option<&str>,
) -> Option<String> {
    let resolved = match candidate {
        Candidate::Path(p) => {
            let path = Path::new(p);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                cwd?.join(path)
            }
        }
        Candidate::Name(name) => {
            // Search the process PATH first, then the standard directories, so a
            // bare name still resolves when the process shipped an empty PATH.
            let mut dirs: Vec<PathBuf> = path_env
                .map(std::env::split_paths)
                .into_iter()
                .flatten()
                .collect();
            dirs.extend(std::env::split_paths(DEFAULT_PATH));
            let mut found = None;
            for dir in dirs {
                let candidate = dir.join(name);
                if is_readable_file(&candidate) {
                    found = Some(candidate);
                    break;
                }
            }
            found?
        }
    };
    if !is_readable_file(&resolved) {
        return None;
    }
    Some(
        fs::canonicalize(&resolved)
            .unwrap_or(resolved)
            .display()
            .to_string(),
    )
}

/// The identity of a process: the verified script for an interpreter-hosted app,
/// otherwise the executable. `cwd`/`path_env` resolve bare script names. Fails
/// closed: an unverifiable candidate falls back to the executable.
pub fn app_identity(
    exe: &str,
    argv: &[String],
    cwd: Option<&Path>,
    path_env: Option<&str>,
) -> AppId {
    if is_interpreter(exe) {
        if let Some(candidate) = script_candidate(argv) {
            if let Some(script) = resolve_candidate(&candidate, cwd, path_env) {
                return AppId {
                    label: app_name(&script),
                    key: script,
                };
            }
        }
    }
    AppId {
        key: exe.to_string(),
        label: display_name(exe),
    }
}

/// The non-empty NUL-separated arguments from `/proc/<pid>/cmdline`.
fn read_cmdline(pid: i32) -> Vec<String> {
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/cmdline")) else {
        return Vec::new();
    };
    content
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// The `PATH` entry from `/proc/<pid>/environ`, if present and readable.
fn read_path_env(pid: i32) -> Option<String> {
    let content = fs::read(format!("/proc/{pid}/environ")).ok()?;
    for entry in content.split(|b| *b == 0) {
        let Ok(entry) = std::str::from_utf8(entry) else {
            continue;
        };
        if let Some(path) = entry.strip_prefix("PATH=") {
            return Some(path.to_string());
        }
    }
    None
}

/// Strip the kernel's `" (deleted)"` suffix that `/proc/<pid>/exe` reports when
/// the executable's file has been unlinked — typically a package update that
/// replaced the binary while the process kept running. Without this, the stale
/// path breaks browser detection and every basename-based identity.
fn strip_deleted(path: &str) -> String {
    path.strip_suffix(" (deleted)").unwrap_or(path).to_string()
}

/// Whether an executable looks like a web browser. Browsers churn through CDN
/// endpoints constantly, so they are quiet by default.
pub fn is_browser_exe(exe: &str) -> bool {
    let exe = strip_deleted(exe);
    let name = exe
        .rsplit('/')
        .next()
        .unwrap_or(exe.as_str())
        .to_ascii_lowercase();
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

/// Classify a snapshot against the destination directory and the trust list.
///
/// For each surviving connection `(exe, ip)`:
///
/// - a known pair is silent;
/// - a new pair from a trusted app is recorded `reviewed = safe = true` and does
///   not alert;
/// - a new pair from any other app is recorded `reviewed = safe = false` and
///   alerts.
///
/// Browsers (when `quiet_browsers`) and loopback (when `quiet_local`) are
/// bypassed entirely - neither alerted nor stored - so they cannot whitelist a
/// destination for another app.
pub fn classify(
    store: &mut Destinations,
    trusted: &TrustedApps,
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
        let Some(app) = c.app.as_ref() else {
            continue;
        };
        let Some(remote) = c.remote else { continue };
        if config.quiet_local && remote.ip().is_loopback() {
            continue;
        }
        if config.quiet_browsers && is_browser_exe(exe) {
            continue;
        }
        let is_trusted = trusted.is_trusted(&app.key);
        if store.record(&app.key, remote.ip(), now, is_trusted, is_trusted)? && !is_trusted {
            alerts.push(Alert {
                pid: c.pid,
                exe: exe.to_string(),
                app: c.app.clone(),
                remote,
                first_seen_unix: now,
            });
        }
    }
    Ok(alerts)
}

/// Snapshot the machine and classify it against the directory and trust list.
pub fn scan(
    store: &mut Destinations,
    trusted: &TrustedApps,
    now: u64,
    config: &Config,
) -> io::Result<Vec<Alert>> {
    let conns = list_connections();
    classify(store, trusted, &conns, now, config)
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
            app: Some(AppId {
                key: exe.to_string(),
                label: app_name(exe),
            }),
            local: "0.0.0.0:0".parse().unwrap(),
            remote: Some(format!("{ip}:{port}").parse().unwrap()),
            state: "01".to_string(),
            inode,
        }
    }

    fn app(key: &str) -> AppId {
        AppId {
            key: key.to_string(),
            label: app_name(key),
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
        let trusted = TrustedApps::in_memory();
        let conns = vec![
            conn(100, "/usr/bin/curl", "93.184.216.34", 443, 10),
            conn(100, "/usr/bin/curl", "93.184.216.35", 443, 11),
        ];
        let alerts = classify(&mut store, &trusted, &conns, 1, &Config::default()).unwrap();
        // One alert per new pair; an untrusted pair is stored unverified (G2).
        assert_eq!(alerts.len(), 2);
        assert!(alerts[0].describe().contains("93.184.216.34"));
        assert_eq!(store.len(), 2);
        let d = store.entries().into_iter().next().unwrap().2;
        assert!(!d.reviewed && !d.safe);

        let again = classify(&mut store, &trusted, &conns, 2, &Config::default()).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn alert_names_the_app_not_the_interpreter() {
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        // blueman-applet is a python script: the exe is the interpreter, the app
        // is the resolved script. The alert must name the app, not python3.12.
        let mut resolved = conn(42, "/usr/bin/python3.12", "1.2.3.4", 443, 10);
        resolved.app = Some(app("/usr/bin/blueman-applet"));
        // An interpreter Shield could not resolve keeps the interpreter name,
        // marked `_unknown` so the gap is visible instead of hidden.
        let mut unresolved = conn(43, "/usr/bin/python3.12", "5.6.7.8", 443, 11);
        unresolved.app = Some(AppId {
            key: "/usr/bin/python3.12".to_string(),
            label: display_name("/usr/bin/python3.12"),
        });

        let alerts = classify(
            &mut store,
            &trusted,
            &[resolved, unresolved],
            1,
            &Config::default(),
        )
        .unwrap();
        assert_eq!(alerts.len(), 2);
        let resolved_alert = alerts
            .iter()
            .find(|a| a.remote.ip().to_string() == "1.2.3.4")
            .unwrap();
        assert_eq!(resolved_alert.app.as_ref().unwrap().label, "blueman-applet");
        assert!(resolved_alert.describe().contains("blueman-applet"));
        let unresolved_alert = alerts
            .iter()
            .find(|a| a.remote.ip().to_string() == "5.6.7.8")
            .unwrap();
        assert_eq!(
            unresolved_alert.app.as_ref().unwrap().label,
            "python3.12_unknown"
        );
        assert!(unresolved_alert.describe().contains("python3.12_unknown"));
    }

    #[test]
    fn display_name_marks_unresolved_interpreters() {
        assert_eq!(display_name("/usr/bin/python3.12"), "python3.12_unknown");
        assert_eq!(display_name("python3"), "python3_unknown");
        assert_eq!(display_name("/usr/bin/blueman-applet"), "blueman-applet");
        assert_eq!(display_name("/usr/bin/curl"), "curl");
    }

    #[test]
    fn mark_pair_safe_marks_only_that_pair() {
        fn flag(store: &Destinations, ip: IpAddr) -> (bool, bool) {
            store
                .entries()
                .into_iter()
                .find(|(_, i, _)| *i == ip)
                .map(|(_, _, d)| (d.reviewed, d.safe))
                .unwrap()
        }
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        let mut store = Destinations::in_memory();
        store.record("/usr/bin/curl", ip1, 1, false, false).unwrap();
        store.record("/usr/bin/curl", ip2, 2, false, false).unwrap();

        assert!(store.mark_pair_safe("/usr/bin/curl", ip1).unwrap());
        assert_eq!(flag(&store, ip1), (true, true));
        assert_eq!(
            flag(&store, ip2),
            (false, false),
            "the other pair is untouched"
        );
        // A second call has nothing left to change.
        assert!(!store.mark_pair_safe("/usr/bin/curl", ip1).unwrap());
    }

    #[test]
    fn mark_pair_safe_of_an_unknown_pair_is_a_noop() {
        let mut store = Destinations::in_memory();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!store.mark_pair_safe("/usr/bin/curl", ip).unwrap());
    }

    #[test]
    fn mark_pair_safe_surfaces_a_write_error() {
        let dir = std::env::temp_dir().join(format!("shield-pair-safe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("destinations.tsv");
        let mut store = Destinations::open(&path).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        store.record("/usr/bin/curl", ip, 1, false, false).unwrap();
        // Replace the store's directory with a regular file so the rewrite fails.
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&dir).unwrap();
        fs::write(&dir, b"blocked").unwrap();
        assert!(store.mark_pair_safe("/usr/bin/curl", ip).is_err());
        let _ = fs::remove_file(&dir);
    }

    #[test]
    fn same_ip_from_two_apps_is_two_pairs() {
        // Under (app, ip) keying, a second app reaching a known IP is a new
        // pair, so it alerts. That is the point of A2: trust is per-app.
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        let first = vec![conn(1, "/usr/bin/curl", "1.2.3.4", 443, 10)];
        let second = vec![conn(2, "/usr/bin/wget", "1.2.3.4", 80, 11)];
        assert_eq!(
            classify(&mut store, &trusted, &first, 1, &Config::default())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            classify(&mut store, &trusted, &second, 2, &Config::default())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn ignores_loopback_unowned_and_kernel_rows() {
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        let mut no_pid = conn(0, "/usr/bin/x", "8.8.8.8", 443, 10);
        no_pid.pid = None;
        no_pid.exe = None;
        let conns = vec![
            conn(100, "/usr/bin/curl", "127.0.0.1", 8080, 10),
            no_pid,
            conn(100, "/usr/bin/curl", "8.8.8.8", 443, 0),
        ];
        let alerts = classify(&mut store, &trusted, &conns, 1, &Config::default()).unwrap();
        // loopback (quiet_local on), a missing exe, and a kernel row are skipped.
        assert!(alerts.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn browsers_are_bypassed_entirely() {
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        let conns = vec![conn(1, "/usr/lib/firefox/firefox-bin", "2.2.2.2", 443, 10)];
        let alerts = classify(&mut store, &trusted, &conns, 1, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        // Not stored, so it cannot whitelist the IP for another app.
        assert!(store.is_empty());
    }

    #[test]
    fn deleted_binaries_are_stripped_before_matching() {
        // Setproctitle is not the cause here: the kernel appends " (deleted)" to
        // /proc/<pid>/exe when the binary was replaced on disk under the process.
        let stale = "/usr/lib/firefox/firefox-bin (deleted)";
        assert_eq!(strip_deleted(stale), "/usr/lib/firefox/firefox-bin");
        assert!(is_browser_exe(stale));
        // A path without the suffix is untouched.
        assert_eq!(strip_deleted("/usr/bin/curl"), "/usr/bin/curl");
        assert!(!is_browser_exe("/usr/bin/curl"));
    }

    #[test]
    fn a_browser_running_a_deleted_binary_is_bypassed() {
        // Regression: `quiet_browsers` was not honoured when the browser's
        // binary had been replaced on disk, because its exe ends in " (deleted)".
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        let conns = vec![conn(
            1,
            "/usr/lib/firefox/firefox-bin (deleted)",
            "2.2.2.2",
            443,
            10,
        )];
        let alerts = classify(&mut store, &trusted, &conns, 1, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn loopback_is_alerted_when_quiet_local_is_off() {
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        let conns = vec![conn(1, "/usr/bin/curl", "127.0.0.1", 8080, 10)];
        let config = Config {
            quiet_local: false,
            ..Config::default()
        };
        let alerts = classify(&mut store, &trusted, &conns, 1, &config).unwrap();
        assert_eq!(alerts.len(), 1);
        assert!(store.is_known("/usr/bin/curl", "127.0.0.1".parse().unwrap()));
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
            .record(
                "/usr/bin/curl",
                "93.184.216.34".parse().unwrap(),
                1,
                true,
                true
            )
            .unwrap());

        let reloaded = Destinations::open(&path).unwrap();
        let entries = reloaded.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "/usr/bin/curl");
        assert_eq!(entries[0].1, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].2.first_seen, 1);
        assert!(entries[0].2.reviewed && entries[0].2.safe);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn open_reads_the_current_format() {
        let dir = std::env::temp_dir().join(format!("shield-new-{}", std::process::id()));
        let path = dir.join("destinations.tsv");
        let _ = fs::create_dir_all(&dir);
        fs::write(
            &path,
            "/usr/bin/a\t1.1.1.1\t1700000000\ttrue\ttrue\n\
             /usr/bin/b\t2.2.2.2\t1700000001\tfalse\tfalse\n",
        )
        .unwrap();
        let store = Destinations::open(&path).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.is_known("/usr/bin/a", "1.1.1.1".parse().unwrap()));
        let entries = store.entries();
        let a = entries
            .iter()
            .find(|(exe, _, _)| exe == "/usr/bin/a")
            .unwrap();
        assert_eq!(a.2.first_seen, 1_700_000_000);
        assert!(a.2.reviewed && a.2.safe);
        let b = entries
            .iter()
            .find(|(exe, _, _)| exe == "/usr/bin/b")
            .unwrap();
        assert!(!b.2.reviewed && !b.2.safe);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn migrate_store_converts_both_legacy_shapes() {
        let dir = std::env::temp_dir().join(format!("shield-mig-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let legacy = dir.join("first-seen.tsv");
        let dest = dir.join("destinations.tsv");
        let _ = fs::remove_file(&dest);
        // Line 1 is the current legacy shape (first field is the IP); lines 2-3
        // are the original shape (exe, ip, port, ts); line 3 is a browser row.
        fs::write(
            &legacy,
            "1.1.1.1\t1700000000\ttrue\ttrue\t/usr/bin/a\n\
             /usr/bin/b\t2.2.2.2\t80\t1700000001\n\
             /usr/lib/firefox/firefox-bin\t3.3.3.3\t443\t1700000002\n",
        )
        .unwrap();
        assert!(migrate_store(&legacy, &dest).unwrap());
        let store = Destinations::open(&dest).unwrap();
        // The browser row is dropped; the other two become (exe, ip) pairs.
        assert_eq!(store.len(), 2);
        assert!(store.is_known("/usr/bin/a", "1.1.1.1".parse().unwrap()));
        assert!(store.is_known("/usr/bin/b", "2.2.2.2".parse().unwrap()));
        assert!(!store.is_known("/usr/lib/firefox/firefox-bin", "3.3.3.3".parse().unwrap()));
        // Re-running does nothing once the destination file exists.
        assert!(!migrate_store(&legacy, &dest).unwrap());
        let _ = fs::remove_file(&legacy);
        let _ = fs::remove_file(&dest);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn open_surfaces_an_unreadable_store_instead_of_empty() {
        // A path whose parent component is a file can be neither read nor
        // written; `open` must report that, not return an empty store that
        // makes a broken store look like "nothing has ever happened".
        let dir = std::env::temp_dir().join(format!("shield-open-err-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let blocker = dir.join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("destinations.tsv");
        assert!(Destinations::open(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_processes_collapses_by_app_key() {
        let procs = vec![
            Process {
                pid: 30,
                app: app("/usr/bin/b"),
                connections: 1,
            },
            Process {
                pid: 10,
                app: app("/usr/bin/a"),
                connections: 2,
            },
            Process {
                pid: 11,
                app: app("/usr/bin/a"),
                connections: 3,
            },
        ];
        let rows = group_processes(&procs);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "/usr/bin/a");
        assert_eq!(rows[0].label, "a");
        assert_eq!(rows[0].pids, vec![10, 11]);
        assert_eq!(rows[0].connections, 5);
        assert_eq!(rows[1].key, "/usr/bin/b");
        assert_eq!(rows[1].connections, 1);
    }

    #[test]
    fn build_processes_attaches_connection_counts() {
        let apps = vec![(2, app("/b")), (1, app("/a"))];
        let mut counts = HashMap::new();
        counts.insert(1, 4usize);
        let procs = build_processes(apps, &counts);
        assert_eq!(procs.len(), 2);
        // Sorted by key, so /a comes first.
        assert_eq!(procs[0].app.key, "/a");
        assert_eq!(procs[0].connections, 4);
        assert_eq!(procs[1].app.key, "/b");
        assert_eq!(procs[1].connections, 0);
    }

    #[test]
    fn count_connections_by_pid_skips_loopback_and_unowned() {
        let c1 = conn(1, "/usr/bin/a", "1.2.3.4", 443, 10);
        let c2 = conn(1, "/usr/bin/a", "127.0.0.1", 8080, 11);
        let mut c3 = conn(9, "/usr/bin/b", "5.6.7.8", 443, 12);
        c3.pid = None;
        let counts = count_connections_by_pid(&[c1, c2, c3]);
        // The loopback link and the unattributed row are not counted.
        assert_eq!(counts.get(&1).copied(), Some(1));
        assert_eq!(counts.get(&9), None);
    }

    #[test]
    fn group_connections_counts_external_links_by_app() {
        let conns = vec![
            conn(1, "/usr/bin/a", "1.2.3.4", 443, 10),
            conn(1, "/usr/bin/a", "5.6.7.8", 443, 11),
            conn(2, "/usr/bin/a", "127.0.0.1", 8080, 12),
            conn(3, "/usr/bin/b", "9.9.9.9", 80, 13),
        ];
        let rows = group_connections(&conns);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "/usr/bin/a");
        // The loopback link is excluded, so only two external links remain.
        assert_eq!(rows[0].connections, 2);
        assert_eq!(rows[0].pids, vec![1]);
        assert_eq!(rows[1].key, "/usr/bin/b");
        assert_eq!(rows[1].connections, 1);
    }

    #[test]
    fn clear_empties_memory_and_truncates_file() {
        let dir = std::env::temp_dir().join(format!("shield-clear-{}", std::process::id()));
        let path = dir.join("destinations.tsv");
        let _ = fs::create_dir_all(&dir);
        let mut store = Destinations::open(&path).unwrap();
        assert!(store
            .record("/usr/bin/a", "1.1.1.1".parse().unwrap(), 5, true, true)
            .unwrap());
        assert_eq!(store.len(), 1);
        store.clear().unwrap();
        assert!(store.is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn duplicate_pair_does_not_append_but_a_new_pair_does() {
        let dir = std::env::temp_dir().join(format!("shield-dup-{}", std::process::id()));
        let path = dir.join("destinations.tsv");
        let _ = fs::create_dir_all(&dir);
        let mut store = Destinations::open(&path).unwrap();
        assert!(store
            .record("/usr/bin/a", "1.1.1.1".parse().unwrap(), 5, false, false)
            .unwrap());
        // Same pair again: no append and no change.
        assert!(!store
            .record("/usr/bin/a", "1.1.1.1".parse().unwrap(), 99, true, true)
            .unwrap());
        // A different app on the same IP is a different pair: recorded.
        assert!(store
            .record("/usr/bin/b", "1.1.1.1".parse().unwrap(), 7, false, false)
            .unwrap());
        assert_eq!(store.len(), 2);
        let entries = store.entries();
        let a = entries
            .iter()
            .find(|(exe, _, _)| exe == "/usr/bin/a")
            .unwrap();
        assert_eq!(a.2.first_seen, 5);
        assert!(!a.2.safe);
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn trusted_app_records_safe_and_is_silent() {
        let mut store = Destinations::in_memory();
        let mut trusted = TrustedApps::in_memory();
        trusted.trust("/usr/bin/curl", 1).unwrap();
        let conns = vec![conn(1, "/usr/bin/curl", "1.2.3.4", 443, 10)];
        let alerts = classify(&mut store, &trusted, &conns, 5, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        let d = store.entries().into_iter().next().unwrap().2;
        assert!(d.reviewed && d.safe);
    }

    #[test]
    fn trusting_an_app_marks_existing_rows_safe() {
        let mut store = Destinations::in_memory();
        let trusted = TrustedApps::in_memory();
        let conns = vec![conn(1, "/usr/bin/curl", "1.2.3.4", 443, 10)];
        classify(&mut store, &trusted, &conns, 1, &Config::default()).unwrap();
        assert!(!store.entries()[0].2.safe);
        store.mark_app_safe("/usr/bin/curl").unwrap();
        assert!(store.entries()[0].2.safe);
    }

    #[test]
    fn trusted_apps_round_trip_and_untrust() {
        let dir = std::env::temp_dir().join(format!("shield-trust-{}", std::process::id()));
        let path = dir.join("trusted-apps.tsv");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::remove_file(&path);
        let mut trusted = TrustedApps::open(&path).unwrap();
        assert!(trusted.is_empty());
        trusted.trust("/usr/bin/curl", 42).unwrap();
        assert!(trusted.is_trusted("/usr/bin/curl"));
        let reloaded = TrustedApps::open(&path).unwrap();
        let entries = reloaded.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "/usr/bin/curl");
        assert_eq!(entries[0].1.name, "curl");
        assert_eq!(entries[0].1.first_trusted, 42);
        trusted.untrust("/usr/bin/curl").unwrap();
        assert!(!trusted.is_trusted("/usr/bin/curl"));
        assert!(TrustedApps::open(&path).unwrap().is_empty());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn is_interpreter_matches_only_real_interpreters() {
        for exe in [
            "/usr/bin/python3.12",
            "python",
            "python3",
            "/usr/bin/node",
            "/usr/bin/ruby",
        ] {
            assert!(is_interpreter(exe), "{exe} should be an interpreter");
        }
        for exe in [
            "/usr/bin/python3-config",
            "/usr/bin/pythonic",
            "/home/x/node_modules",
            "/usr/bin/curl",
        ] {
            assert!(!is_interpreter(exe), "{exe} should not be an interpreter");
        }
    }

    #[test]
    fn script_candidate_reads_the_shapes_we_saw() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // python3 /abs/script
        assert_eq!(
            script_candidate(&s(&["/usr/bin/python3", "/usr/bin/blueman-applet"])),
            Some(Candidate::Path("/usr/bin/blueman-applet".into()))
        );
        // python3 -m module has no file
        assert_eq!(
            script_candidate(&s(&["/usr/bin/python3", "-m", "proton.vpn.daemon"])),
            None
        );
        // a flag before the script
        assert_eq!(
            script_candidate(&s(&["/usr/bin/python3", "-u", "/x/y.py"])),
            Some(Candidate::Path("/x/y.py".into()))
        );
        // a process that renamed argv[0] to a bare name
        assert_eq!(
            script_candidate(&s(&["cinnamon-settings"])),
            Some(Candidate::Name("cinnamon-settings".into()))
        );
        // node with a relative script path
        assert_eq!(
            script_candidate(&s(&["node", "dist/server/server.js"])),
            Some(Candidate::Path("dist/server/server.js".into()))
        );
        // interpreter with no script at all
        assert_eq!(script_candidate(&s(&["/usr/bin/python3"])), None);
    }

    #[test]
    fn app_identity_verifies_the_script_and_falls_back() {
        let dir = std::env::temp_dir().join(format!("shield-appid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("myscript.py");
        fs::write(&script, b"print(1)\n").unwrap();
        let canon = fs::canonicalize(&script).unwrap().display().to_string();

        // interpreter + absolute existing script -> the script identity
        let id = app_identity(
            "/usr/bin/python3.12",
            &["/usr/bin/python3".to_string(), script.display().to_string()],
            None,
            None,
        );
        assert_eq!(id.key, canon);
        assert_eq!(id.label, "myscript.py");

        // a script that does not exist -> fall back to the exe
        let id = app_identity(
            "/usr/bin/python3.12",
            &[
                "/usr/bin/python3".to_string(),
                dir.join("nope.py").display().to_string(),
            ],
            None,
            None,
        );
        assert_eq!(id.key, "/usr/bin/python3.12");
        assert_eq!(id.label, "python3.12_unknown");

        // a bare name resolved via a supplied PATH
        let id = app_identity(
            "/usr/bin/python3.12",
            &["myscript.py".to_string()],
            None,
            Some(&dir.display().to_string()),
        );
        assert_eq!(id.key, canon);
        assert_eq!(id.label, "myscript.py");

        // a non-interpreter is itself
        let id = app_identity("/usr/bin/curl", &[], None, None);
        assert_eq!(id.key, "/usr/bin/curl");
        assert_eq!(id.label, "curl");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn trusting_a_script_does_not_trust_the_interpreter() {
        let mut store = Destinations::in_memory();
        let mut trusted = TrustedApps::in_memory();
        let script = "/opt/tools/foo.py";
        trusted.trust(script, 1).unwrap();

        // The trusted script's pair: recorded safe, no alert.
        let mut script_conn = conn(1, "/usr/bin/python3.12", "1.2.3.4", 443, 10);
        script_conn.app = Some(app(script));
        let alerts = classify(&mut store, &trusted, &[script_conn], 5, &Config::default()).unwrap();
        assert!(alerts.is_empty());
        assert!(store.is_known(script, "1.2.3.4".parse().unwrap()));

        // The interpreter itself (fallback identity) is not trusted: it alerts.
        let plain = conn(2, "/usr/bin/python3.12", "5.6.7.8", 443, 11);
        let alerts = classify(&mut store, &trusted, &[plain], 6, &Config::default()).unwrap();
        assert_eq!(alerts.len(), 1);
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
