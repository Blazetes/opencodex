use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, String>;
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| "io-failed".into())
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub const RECORD_LIMIT: usize = 64 * 1024;
const JOURNAL_LIMIT: usize = 8 * 1024 * 1024;
pub fn platform() -> &'static str {
    if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}
fn absolute_for(s: &str, host: &str) -> bool {
    if s.chars().count() > 4096 || s.contains(['\0', '\n', '\r']) {
        return false;
    }
    let absolute = if host == "win32" {
        let b = s.as_bytes();
        (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'/' | b'\\'))
            || s.starts_with("\\\\")
            || s.starts_with("//")
    } else {
        s.starts_with('/')
    };
    absolute
        && !s
            .split(if host == "win32" {
                &['/', '\\'][..]
            } else {
                &['/'][..]
            })
            .any(|part| matches!(part, "." | ".."))
}
fn absolute(s: &str) -> bool {
    absolute_for(s, platform())
}
fn bundle_valid(b: &Bundle, host: &str) -> bool {
    b.platform == host
        && absolute_for(&b.app_executable, host)
        && absolute_for(&b.cli_executable, host)
        && !b.version.is_empty()
        && matches!(
            (host, b.kind.as_str()),
            ("darwin", "macos-app") | ("win32", "windows-install") | ("linux", "linux-deb")
        )
}
fn fingerprint(bytes: Option<&[u8]>) -> String {
    bytes.map(hash).unwrap_or_else(|| "absent".into())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub platform: String,
    pub app_executable: String,
    pub cli_executable: String,
    pub version: String,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnedFile {
    pub kind: String,
    pub path: String,
    pub sha256: String,
    pub created: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RcFile {
    pub shell: String,
    pub path: String,
    pub block_sha256: String,
    pub created: bool,
    pub backup_path: Option<String>,
    pub result: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Posix {
    pub bin_directory: String,
    pub files: Vec<OwnedFile>,
    pub rc_files: Vec<RcFile>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Windows {
    pub key: String,
    pub value: String,
    pub entry: String,
    pub value_type: String,
    pub action: String,
    pub previous_before: Option<String>,
    pub previous_after: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub kind: String,
    pub path: String,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
    pub mode: u32,
    pub backup_path: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingChange {
    pub kind: String,
    pub path: String,
    pub mode: u32,
    pub backup_path: Option<String>,
    pub journal_file: String,
    pub before_sha256: String,
    pub after_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Journal {
    pub operation: String,
    pub changes: Vec<PendingChange>,
    pub next: Box<Record>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalFile {
    version: u32,
    kind: String,
    path: String,
    mode: Option<u32>,
    before: Option<String>,
    after: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub owner_id: String,
    pub install_id: String,
    pub generation: u64,
    pub enabled: bool,
    pub bundle: Option<Bundle>,
    pub posix: Option<Posix>,
    pub windows: Option<Windows>,
    pub pending: Option<Journal>,
}
impl Record {
    pub fn fresh(bundle: Bundle) -> Self {
        let install_id = Uuid::new_v4().to_string();
        Self {
            version: 1,
            owner_id: Uuid::new_v4().to_string(),
            install_id,
            generation: 1,
            enabled: true,
            bundle: Some(bundle),
            posix: None,
            windows: None,
            pending: None,
        }
    }
}
// Desired targets authorize new writes; persisted rc ownership survives environment changes.
pub struct Store {
    pub root: PathBuf,
    pub rc_allowed: Vec<PathBuf>,
    _lock: fs::File,
}
#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
    fn flock(fd: i32, op: i32) -> i32;
}
pub fn check(path: &Path, directory: bool) -> Result<()> {
    let m = io(fs::symlink_metadata(path))?;
    for parent in path.ancestors().skip(1) {
        if fs::symlink_metadata(parent)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
        {
            return Err("unsafe-parent".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if fs::symlink_metadata(parent)
                .map(|m| m.file_attributes() & 0x400 != 0)
                .unwrap_or(true)
            {
                return Err("unsafe-parent".into());
            }
        }
    }
    if m.file_type().is_symlink() || (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        return Err("unsafe-file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != unsafe { geteuid() } {
            return Err("foreign-owner".into());
        }
        if m.mode() & 0o222 == 0 {
            return Err("read-only".into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err("unsafe-file".into());
        }
    }
    if m.permissions().readonly() {
        return Err("read-only".into());
    }
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => check(path, true)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut b = fs::DirBuilder::new();
                b.mode(0o700);
                io(b.create(path))?;
            }
            #[cfg(not(unix))]
            io(fs::create_dir(path))?;
        }
        Err(_) => return Err("io-failed".into()),
    }
    check(path, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if io(fs::metadata(path))?.permissions().mode() & 0o777 != 0o700 {
            return Err("directory-permissions".into());
        }
    }
    Ok(())
}
fn read_limited(path: &Path, limit: usize, reason: &str) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("io-failed".into()),
        Ok(m) if m.len() > limit as u64 => return Err(reason.into()),
        Ok(_) => check(path, false)?,
    }
    let mut f = io(fs::File::open(path))?;
    let mut out = Vec::new();
    io((&mut f).take(limit as u64 + 1).read_to_end(&mut out))?;
    if out.len() > limit {
        return Err(reason.into());
    }
    Ok(Some(out))
}
pub fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    read_limited(path, JOURNAL_LIMIT, "rc-too-large")
}
fn private_bytes(path: &Path, limit: usize, reason: &str) -> Result<Option<Vec<u8>>> {
    let bytes = read_limited(path, limit, reason)?;
    #[cfg(unix)]
    if bytes.is_some() {
        use std::os::unix::fs::PermissionsExt;
        if io(fs::metadata(path))?.permissions().mode() & 0o777 != 0o600 {
            return Err("record-permissions".into());
        }
    }
    Ok(bytes)
}
fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    io(fs::File::open(path).and_then(|f| f.sync_all()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn new_file(path: &Path, mode: u32) -> Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    io(o.open(path))
}
#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(a: *const u16, b: *const u16, flags: u32) -> i32;
    }
    let a: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let b: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), 0x1 | 0x8) } == 0 {
        Err("rename-failed".into())
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> Result<()> {
    io(fs::rename(from, to))
}
pub fn atomic(path: &Path, before: Option<&[u8]>, after: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or("unsafe-file")?;
    check(parent, true)?;
    let tmp = parent.join(format!(".ocx-cli-{}", Uuid::new_v4()));
    let result = (|| {
        let original = fs::symlink_metadata(path).ok();
        let mut f = new_file(&tmp, mode)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            io(f.set_permissions(fs::Permissions::from_mode(mode)))?;
        }
        io(f.write_all(after))?;
        io(f.sync_all())?;
        let observed = fs::symlink_metadata(path).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if original
                .as_ref()
                .map(|m| (m.dev(), m.ino(), m.mode(), m.mtime(), m.mtime_nsec()))
                != observed
                    .as_ref()
                    .map(|m| (m.dev(), m.ino(), m.mode(), m.mtime(), m.mtime_nsec()))
            {
                return Err("concurrent-edit".into());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if original
                .as_ref()
                .map(|m| (m.creation_time(), m.last_write_time(), m.file_attributes()))
                != observed
                    .as_ref()
                    .map(|m| (m.creation_time(), m.last_write_time(), m.file_attributes()))
            {
                return Err("concurrent-edit".into());
            }
        }
        if read_bytes(path)?.as_deref() != before {
            return Err("concurrent-edit".into());
        }
        replace(&tmp, path)?;
        #[cfg(unix)]
        io(fs::File::open(parent).and_then(|f| f.sync_all()))?;
        Ok(())
    })();
    let _ = fs::remove_file(tmp);
    result
}
fn lock(root: &Path) -> Result<fs::File> {
    let p = root.join("cli.lock");
    if fs::symlink_metadata(&p).is_ok() {
        check(&p, false)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if io(fs::metadata(&p))?.permissions().mode() & 0o777 != 0o600 {
                return Err("lock-permissions".into());
            }
        }
    }
    let mut o = fs::OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let f = io(o.open(&p))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // LOCK_EX | LOCK_NB: OS releases the lock on close/process death; no stale PID deletion.
        if unsafe { flock(f.as_raw_fd(), 2 | 4) } != 0 {
            return Err("lock-busy".into());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            high: usize,
            offset: u32,
            offset_high: u32,
            event: *mut std::ffi::c_void,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LockFileEx(
                h: *mut std::ffi::c_void,
                flags: u32,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut Overlapped,
            ) -> i32;
        }
        let mut v = Overlapped {
            internal: 0,
            high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        };
        if unsafe { LockFileEx(f.as_raw_handle(), 1 | 2, 0, 1, 0, &mut v) } == 0 {
            return Err("lock-busy".into());
        }
    }
    Ok(f)
}
impl Store {
    pub fn open(root: PathBuf, rc_allowed: Vec<PathBuf>) -> Result<Self> {
        private_dir(&root)?;
        let guard = lock(&root)?;
        for name in ["bin", "backups", "journal"] {
            private_dir(&root.join(name))?;
        }
        Ok(Self {
            root,
            rc_allowed,
            _lock: guard,
        })
    }
    fn owned_path(&self, s: &str, r: &Record, next: &Record) -> bool {
        let p = Path::new(s);
        absolute(s)
            && (p == self.root.join("bin/ocx")
                || p == self.root.join("path.sh")
                || self.rc_allowed.iter().any(|r| r == p)
                || [r, next].iter().any(|r| {
                    r.posix
                        .as_ref()
                        .is_some_and(|v| v.rc_files.iter().any(|f| f.path == s))
                }))
    }
    fn backup_path(&self, s: &str) -> bool {
        absolute(s) && Path::new(s).parent() == Some(self.root.join("backups").as_path())
    }
    fn journal_path(&self, s: &str) -> bool {
        let p = Path::new(s);
        if !absolute(s)
            || p.parent() != Some(self.root.join("journal").as_path())
            || p.extension().and_then(|s| s.to_str()) != Some("json")
        {
            return false;
        }
        p.file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.split_once('-'))
            .is_some_and(|(g, i)| {
                g.parse::<u64>()
                    .is_ok_and(|n| n > 0 && n <= 9_007_199_254_740_991)
                    && i.parse::<usize>().is_ok_and(|n| n < 32)
            })
    }
    pub fn validate(&self, r: &Record, nested: bool) -> Result<()> {
        self.validate_for(r, nested, platform())
    }
    fn validate_for(&self, r: &Record, nested: bool, host: &str) -> Result<()> {
        let invalid = || "record-invalid".to_owned();
        if r.version != 1
            || Uuid::parse_str(&r.owner_id).is_err()
            || r.install_id.is_empty()
            || r.install_id.len() > 256
            || r.generation == 0
            || r.generation > 9_007_199_254_740_991
        {
            return Err(invalid());
        }
        if let Some(b) = &r.bundle {
            if !bundle_valid(b, host)
                || (b.platform == "win32" && r.posix.is_some())
                || (b.platform != "win32" && r.windows.is_some())
            {
                return Err(invalid());
            }
        } else if r.enabled || r.posix.is_some() || r.windows.is_some() {
            return Err(invalid());
        }
        if let Some(p) = &r.posix {
            if p.bin_directory != self.root.join("bin").to_string_lossy()
                || p.files.len() > 2
                || p.rc_files.len() > 16
            {
                return Err(invalid());
            }
            let mut paths = std::collections::HashSet::new();
            for f in &p.files {
                let expected = match f.kind.as_str() {
                    "shim" => self.root.join("bin/ocx"),
                    "path-helper" => self.root.join("path.sh"),
                    _ => return Err(invalid()),
                };
                if Path::new(&f.path) != expected || !digest(&f.sha256) || !paths.insert(&f.path) {
                    return Err(invalid());
                }
            }
            for f in &p.rc_files {
                if !matches!(f.shell.as_str(), "zsh" | "bash" | "fish")
                    || !absolute(&f.path)
                    || !paths.insert(&f.path)
                    || !digest(&f.block_sha256)
                    || f.result != "installed"
                    || f.backup_path
                        .as_deref()
                        .is_some_and(|s| !self.backup_path(s))
                {
                    return Err(invalid());
                }
            }
        }
        if let Some(w) = &r.windows {
            if w.key != "HKCU\\Environment"
                || w.value != "Path"
                || !absolute_for(&w.entry, "win32")
                || w.entry.contains(';')
                || !matches!(w.value_type.as_str(), "REG_SZ" | "REG_EXPAND_SZ")
                || !matches!(w.action.as_str(), "inserted" | "moved-existing")
                || [&w.previous_before, &w.previous_after].iter().any(|s| {
                    s.as_ref()
                        .is_some_and(|s| s.contains([';', '\0', '\r', '\n']))
                })
            {
                return Err(invalid());
            }
        }
        if let Some(j) = &r.pending {
            if nested
                || !matches!(j.operation.as_str(), "install" | "remove")
                || j.changes.len() > 32
                || j.next.pending.is_some()
                || r.owner_id != j.next.owner_id
                || r.install_id != j.next.install_id
                || r.enabled != j.next.enabled
                || j.next.generation != r.generation + 1
            {
                return Err(invalid());
            }
            self.validate_for(&j.next, true, host)?;
            let mut paths = std::collections::HashSet::new();
            let mut journals = std::collections::HashSet::new();
            for c in &j.changes {
                if !paths.insert(&c.path)
                    || !journals.insert(&c.journal_file)
                    || !self.journal_path(&c.journal_file)
                    || ![&c.before_sha256, &c.after_sha256]
                        .iter()
                        .all(|s| *s == "absent" || digest(s))
                    || c.backup_path
                        .as_deref()
                        .is_some_and(|s| !self.backup_path(s))
                {
                    return Err(invalid());
                }
                match c.kind.as_str() {
                    "file" if self.owned_path(&c.path, r, &j.next) && c.mode <= 0o777 => {}
                    "registry-sz" | "registry-expand"
                        if host == "win32"
                            && c.path == "HKCU\\Environment\\Path"
                            && c.mode == 0
                            && c.backup_path.is_none() => {}
                    _ => return Err(invalid()),
                }
            }
        }
        Ok(())
    }
    pub fn read(&self) -> Result<Option<Record>> {
        let Some(b) = private_bytes(
            &self.root.join("cli.json"),
            RECORD_LIMIT,
            "record-too-large",
        )?
        else {
            return Ok(None);
        };
        let r: Record = serde_json::from_slice(&b).map_err(|_| "record-invalid")?;
        self.validate(&r, false)?;
        Ok(Some(r))
    }
    fn encoded(&self, r: &Record) -> Result<Vec<u8>> {
        self.validate(r, false)?;
        let b = serde_json::to_vec(r).map_err(|_| "record-invalid")?;
        if b.len() > RECORD_LIMIT {
            return Err("record-too-large".into());
        }
        Ok(b)
    }
    pub fn save(&self, r: &Record) -> Result<()> {
        let b = self.encoded(r)?;
        let p = self.root.join("cli.json");
        let old = private_bytes(&p, RECORD_LIMIT, "record-too-large")?;
        if old.as_deref() == Some(b.as_slice()) {
            return Ok(());
        }
        atomic(&p, old.as_deref(), &b, 0o600)
    }
    fn prepare(
        &self,
        current: &Record,
        mut next: Record,
        changes: &[Change],
        op: &str,
    ) -> Result<Record> {
        next.generation = current.generation + 1;
        next.pending = None;
        let mut refs = Vec::new();
        let mut payloads = Vec::new();
        for (i, c) in changes.iter().enumerate() {
            let journal_file = self
                .root
                .join("journal")
                .join(format!("{}-{i}.json", next.generation));
            let payload = JournalFile {
                version: 1,
                kind: c.kind.clone(),
                path: c.path.clone(),
                mode: (c.kind == "file").then_some(c.mode),
                before: c.before.as_ref().map(|b| STANDARD.encode(b)),
                after: c.after.as_ref().map(|b| STANDARD.encode(b)),
            };
            let bytes = serde_json::to_vec(&payload).map_err(|_| "journal-invalid")?;
            if bytes.len() > JOURNAL_LIMIT {
                return Err("rc-too-large".into());
            }
            refs.push(PendingChange {
                kind: c.kind.clone(),
                path: c.path.clone(),
                mode: c.mode,
                backup_path: c.backup_path.clone(),
                journal_file: journal_file.to_string_lossy().into_owned(),
                before_sha256: fingerprint(c.before.as_deref()),
                after_sha256: fingerprint(c.after.as_deref()),
            });
            payloads.push((journal_file, bytes));
        }
        let mut pending = current.clone();
        pending.pending = Some(Journal {
            operation: op.into(),
            changes: refs,
            next: Box::new(next),
        });
        self.encoded(&pending)?; // Validate all paths and the 64 KiB bound before creating any journal.
        for (path, bytes) in payloads {
            let old = private_bytes(&path, JOURNAL_LIMIT, "journal-too-large")?;
            if old.as_deref().is_some_and(|old| old != bytes) {
                return Err("journal-conflict".into());
            }
            if old.is_none() {
                atomic(&path, None, &bytes, 0o600)?;
            }
        }
        sync_dir(&self.root.join("journal"))?;
        Ok(pending)
    }
    pub fn transact(
        &self,
        current: &mut Record,
        next: Record,
        changes: Vec<Change>,
        op: &str,
    ) -> Result<()> {
        if changes.is_empty() && *current == next {
            return Ok(());
        }
        let pending = self.prepare(current, next, &changes, op)?;
        self.save(&pending)?;
        *current = pending;
        self.recover(current)
    }
    fn load_change(&self, c: &PendingChange) -> Result<Change> {
        let bytes = private_bytes(
            Path::new(&c.journal_file),
            JOURNAL_LIMIT,
            "journal-too-large",
        )?
        .ok_or("journal-missing")?;
        let j: JournalFile = serde_json::from_slice(&bytes).map_err(|_| "journal-invalid")?;
        let decode = |s: Option<String>| {
            s.map(|s| STANDARD.decode(s).map_err(|_| "journal-invalid".to_owned()))
                .transpose()
        };
        let before = decode(j.before)?;
        let after = decode(j.after)?;
        if j.version != 1
            || j.kind != c.kind
            || j.path != c.path
            || j.mode != (c.kind == "file").then_some(c.mode)
            || fingerprint(before.as_deref()) != c.before_sha256
            || fingerprint(after.as_deref()) != c.after_sha256
        {
            return Err("journal-digest-mismatch".into());
        }
        Ok(Change {
            kind: c.kind.clone(),
            path: c.path.clone(),
            before,
            after,
            mode: c.mode,
            backup_path: c.backup_path.clone(),
        })
    }
    pub fn recover(&self, current: &mut Record) -> Result<()> {
        self.validate(current, false)?;
        let Some(j) = current.pending.clone() else {
            return Ok(());
        };
        let wanted = (j.operation == "install") == current.enabled;
        // State table for BOTH operations: wanted: before -> after, after -> done.
        // Cancelled: before -> leave, after -> before (reverse completed prefix).
        // Any third state or unverifiable journal -> stop, preserve pending and backups.
        let mut changes = j
            .changes
            .iter()
            .map(|c| self.load_change(c))
            .collect::<Result<Vec<_>>>()?;
        if !wanted {
            changes.reverse();
        }
        for c in changes {
            let (before, after) = if wanted {
                (&c.before, &c.after)
            } else {
                (&c.after, &c.before)
            };
            let found = if c.kind == "file" {
                read_bytes(Path::new(&c.path))?
            } else {
                crate::cli_command_windows::read_change(&c)?
            };
            if found == *after {
                continue;
            }
            if found != *before {
                return Err("journal-conflict".into());
            }
            if wanted {
                if let (Some(name), Some(bytes)) = (&c.backup_path, &c.before) {
                    let p = Path::new(name);
                    if let Some(old) = private_bytes(p, JOURNAL_LIMIT, "backup-too-large")? {
                        if old != *bytes {
                            return Err("backup-conflict".into());
                        }
                    } else {
                        atomic(p, None, bytes, 0o600)?;
                    }
                }
            }
            if c.kind == "file" {
                let p = Path::new(&c.path);
                if let Some(b) = after {
                    atomic(p, before.as_deref(), b, c.mode)?;
                } else {
                    if read_bytes(p)? != *before {
                        return Err("concurrent-edit".into());
                    }
                    io(fs::remove_file(p))?;
                    sync_dir(p.parent().ok_or("unsafe-file")?)?;
                }
            } else {
                let mut step = c.clone();
                step.before = before.clone();
                step.after = after.clone();
                crate::cli_command_windows::apply_change(&step)?;
            }
        }
        let mut settled = if wanted { *j.next } else { current.clone() };
        settled.pending = None;
        settled.generation = current.generation + 1;
        self.save(&settled)?;
        *current = settled;
        for c in j.changes {
            io(fs::remove_file(c.journal_file))?;
        }
        sync_dir(&self.root.join("journal"))
    }
    pub fn journal_issues(&self, r: &Record) -> Vec<String> {
        let referenced: std::collections::HashSet<_> = r
            .pending
            .as_ref()
            .map(|j| j.changes.iter().map(|c| c.journal_file.as_str()).collect())
            .unwrap_or_default();
        let orphan = fs::read_dir(self.root.join("journal"))
            .map(|v| {
                v.filter_map(|e| e.ok())
                    .any(|e| !referenced.contains(e.path().to_string_lossy().as_ref()))
            })
            .unwrap_or(true);
        if orphan {
            vec!["orphan-journal".into()]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) struct Temp(pub PathBuf);
    impl Temp {
        pub(crate) fn new() -> Self {
            let p = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("ocx-cli-{}", Uuid::new_v4()));
            private_dir(&p).unwrap();
            Self(p)
        }
        pub(crate) fn store(&self) -> Store {
            Store::open(self.0.join("record"), vec![self.0.join(".zshrc")]).unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    pub(crate) fn bundle() -> Bundle {
        let (app, cli, kind) = match platform() {
            "win32" => (
                "C:\\Desktop\\app.exe",
                "C:\\Desktop\\ocx.exe",
                "windows-install",
            ),
            "darwin" => (
                "/Applications/Desktop.app/Contents/MacOS/app",
                "/Applications/Desktop.app/Contents/MacOS/ocx",
                "macos-app",
            ),
            _ => ("/usr/bin/app", "/usr/bin/ocx", "linux-deb"),
        };
        Bundle {
            platform: platform().into(),
            kind: kind.into(),
            app_executable: app.into(),
            cli_executable: cli.into(),
            version: "1".into(),
        }
    }
    fn change(p: &Path) -> Change {
        Change {
            kind: "file".into(),
            path: p.to_string_lossy().into_owned(),
            before: Some(b"old".to_vec()),
            after: Some(b"new".to_vec()),
            mode: 0o600,
            backup_path: None,
        }
    }
    #[test]
    fn shared_record_fixtures_match_host_contract_and_first_pending_shape() {
        let t = Temp::new();
        let s = t.store();
        for (json, host, valid) in [
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/valid-darwin.json"),
                "darwin",
                true,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/valid-win32.json"),
                "win32",
                true,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/valid-linux.json"),
                "linux",
                true,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/disabled-tombstone.json"),
                "darwin",
                true,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/pending-enabled.json"),
                "darwin",
                true,
            ),
            (
                include_str!(
                    "../../../tests/fixtures/desktop-cli-record/disabled-with-pending.json"
                ),
                "darwin",
                true,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/appimage-kind.json"),
                "darwin",
                false,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/relative-target.json"),
                "darwin",
                false,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/dotdot-target.json"),
                "darwin",
                false,
            ),
            (
                include_str!("../../../tests/fixtures/desktop-cli-record/first-pending.json"),
                "darwin",
                true,
            ),
        ] {
            // Windows roots carry backslashes, which must stay escaped inside the JSON text.
            let root = s.root.to_str().unwrap().replace('\\', "\\\\");
            let json = json.replace("/fixture/desktop", &root);
            let r: Record = serde_json::from_str(&json).unwrap();
            // Path rules follow the real host, so a Windows test run cannot simulate a POSIX host.
            // There it checks the real contract instead: any record carrying another platform's
            // bundle is refused, and only a bundle-less disabled tombstone stays valid.
            if cfg!(windows) && host != "win32" {
                let tombstone = !r.enabled && r.bundle.is_none();
                assert_eq!(
                    s.validate(&r, false).is_ok(),
                    tombstone,
                    "{host} fixture on win32"
                );
                continue;
            }
            assert_eq!(
                s.validate_for(&r, false, host).is_ok(),
                valid,
                "{host} fixture: {json}"
            );
            if r.enabled && r.bundle.as_ref().unwrap().platform != platform() {
                assert!(s.validate(&r, false).is_err());
            }
        }
    }
    #[test]
    fn record_roundtrip_validation_and_limits() {
        let t = Temp::new();
        let s = t.store();
        let r = Record::fresh(bundle());
        s.save(&r).unwrap();
        assert_eq!(s.read().unwrap(), Some(r.clone()));
        let mut bad = r.clone();
        bad.version = 2;
        assert!(s.save(&bad).is_err());
        bad = r.clone();
        bad.bundle = None;
        assert!(s.save(&bad).is_err());
        bad = r.clone();
        bad.generation = 9_007_199_254_740_992;
        assert!(s.save(&bad).is_err());
        bad = r.clone();
        bad.owner_id = "bad".into();
        assert!(s.save(&bad).is_err());
        bad = r.clone();
        bad.bundle.as_mut().unwrap().version = "x".repeat(RECORD_LIMIT);
        assert_eq!(s.save(&bad).unwrap_err(), "record-too-large");
        let p = s.root.join("cli.json");
        let old = read_bytes(&p).unwrap().unwrap();
        atomic(&p, Some(&old), &vec![b' '; RECORD_LIMIT + 1], 0o600).unwrap();
        assert_eq!(s.read().unwrap_err(), "record-too-large");
    }
    #[test]
    fn corrupt_record_does_not_become_first_run() {
        let t = Temp::new();
        let s = t.store();
        atomic(&s.root.join("cli.json"), None, b"{", 0o600).unwrap();
        assert_eq!(s.read().unwrap_err(), "record-invalid");
    }
    #[test]
    fn external_journal_recovery_state_table_and_idempotence() {
        for op in ["install", "remove"] {
            for wanted in [false, true] {
                for state in ["before", "after", "other"] {
                    let t = Temp::new();
                    let s = t.store();
                    let p = t.0.join(".zshrc");
                    let mut r = Record::fresh(bundle());
                    r.enabled = (op == "install") == wanted;
                    let c = change(&p);
                    let bytes = match state {
                        "before" => b"old",
                        "after" => b"new",
                        _ => b"usr",
                    };
                    atomic(&p, None, bytes, 0o600).unwrap();
                    r = s.prepare(&r, r.clone(), &[c], op).unwrap();
                    s.save(&r).unwrap();
                    let result = s.recover(&mut r);
                    if state == "other" {
                        assert_eq!(result.unwrap_err(), "journal-conflict");
                        assert_eq!(fs::read(&p).unwrap(), b"usr");
                        assert!(s.read().unwrap().unwrap().pending.is_some());
                    } else {
                        result.unwrap();
                        assert_eq!(fs::read(&p).unwrap(), if wanted { b"new" } else { b"old" });
                        assert!(r.pending.is_none());
                        s.recover(&mut r).unwrap();
                        assert_eq!(fs::read_dir(s.root.join("journal")).unwrap().count(), 0);
                    }
                }
            }
        }
    }
    #[test]
    fn journal_digest_mismatch_and_unauthorized_paths_are_refused() {
        let t = Temp::new();
        let s = t.store();
        let mut r = Record::fresh(bundle());
        assert!(s
            .prepare(&r, r.clone(), &[change(&t.0.join("unowned"))], "install")
            .is_err());
        r = s
            .prepare(&r, r.clone(), &[change(&t.0.join(".zshrc"))], "install")
            .unwrap();
        let c = &r.pending.as_ref().unwrap().changes[0];
        let p = Path::new(&c.journal_file);
        let old = read_bytes(p).unwrap().unwrap();
        let mut j: JournalFile = serde_json::from_slice(&old).unwrap();
        j.after = Some(STANDARD.encode(b"tampered"));
        atomic(p, Some(&old), &serde_json::to_vec(&j).unwrap(), 0o600).unwrap();
        s.save(&r).unwrap();
        assert_eq!(s.recover(&mut r).unwrap_err(), "journal-digest-mismatch");
        assert!(s.read().unwrap().unwrap().pending.is_some());
    }
    #[test]
    fn oversize_journal_and_change_roster_are_refused_before_save() {
        let t = Temp::new();
        let s = t.store();
        let r = Record::fresh(bundle());
        let mut c = change(&t.0.join(".zshrc"));
        c.after = Some(vec![b'x'; JOURNAL_LIMIT]);
        assert_eq!(
            s.prepare(&r, r.clone(), &[c], "install").unwrap_err(),
            "rc-too-large"
        );
        assert!(s
            .prepare(
                &r,
                r.clone(),
                &vec![change(&t.0.join(".zshrc")); 33],
                "install"
            )
            .is_err());
        assert!(s.read().unwrap().is_none());
        assert_eq!(fs::read_dir(s.root.join("journal")).unwrap().count(), 0);
    }
    #[test]
    fn disabled_pending_install_rolls_back_every_completed_prefix() {
        for prefix in 0..=2 {
            let t = Temp::new();
            let s = t.store();
            let mut r = Record::fresh(bundle());
            let changes: Vec<_> = [s.root.join("bin/ocx"), s.root.join("path.sh")]
                .iter()
                .map(|p| {
                    let mut c = change(p);
                    c.before = None;
                    c
                })
                .collect();
            r = s.prepare(&r, r.clone(), &changes, "install").unwrap();
            s.save(&r).unwrap();
            for c in changes.iter().take(prefix) {
                atomic(Path::new(&c.path), None, c.after.as_ref().unwrap(), c.mode).unwrap();
            }
            r.enabled = false;
            r.generation += 1;
            let j = r.pending.as_mut().unwrap();
            j.next.enabled = false;
            j.next.generation = r.generation + 1;
            s.save(&r).unwrap();
            let mut reloaded = s.read().unwrap().unwrap();
            s.recover(&mut reloaded).unwrap();
            assert!(!reloaded.enabled && reloaded.pending.is_none());
            for c in changes {
                assert!(!Path::new(&c.path).exists());
            }
        }
    }
    #[test]
    fn large_rc_bytes_stay_in_external_private_journal_and_backup() {
        let t = Temp::new();
        let s = t.store();
        let p = t.0.join(".zshrc");
        let r = Record::fresh(bundle());
        let mut c = change(&p);
        c.before = Some(vec![b'x'; 256 * 1024]);
        c.backup_path = Some(
            s.root
                .join("backups/original")
                .to_string_lossy()
                .into_owned(),
        );
        atomic(&p, None, c.before.as_ref().unwrap(), 0o600).unwrap();
        let mut pending = s.prepare(&r, r.clone(), &[c.clone()], "install").unwrap();
        s.save(&pending).unwrap();
        assert!(fs::metadata(s.root.join("cli.json")).unwrap().len() < RECORD_LIMIT as u64);
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(s.root.join("cli.json")).unwrap()).unwrap();
        assert!(json["pending"]["changes"][0].get("before").is_none());
        assert!(private_bytes(
            Path::new(&pending.pending.as_ref().unwrap().changes[0].journal_file),
            JOURNAL_LIMIT,
            "limit"
        )
        .unwrap()
        .is_some());
        s.recover(&mut pending).unwrap();
        assert_eq!(fs::read(c.backup_path.unwrap()).unwrap(), c.before.unwrap());
    }
    #[cfg(unix)]
    #[test]
    fn rc_ownership_limit_and_lexical_path_validation_are_independent_of_desired_targets() {
        let t = Temp::new();
        let s = t.store();
        let mut r = Record::fresh(bundle());
        r.posix = Some(Posix {
            bin_directory: s.root.join("bin").to_string_lossy().into_owned(),
            files: vec![],
            rc_files: (0..16)
                .map(|i| RcFile {
                    shell: "zsh".into(),
                    path: t.0.join(format!("old-{i}")).to_string_lossy().into_owned(),
                    block_sha256: hash(b"block"),
                    created: true,
                    backup_path: None,
                    result: "installed".into(),
                })
                .collect(),
        });
        s.validate(&r, false).unwrap();
        let mut extra = r.posix.as_ref().unwrap().rc_files[0].clone();
        extra.path = t.0.join("extra").to_string_lossy().into_owned();
        r.posix.as_mut().unwrap().rc_files.push(extra);
        assert!(s.validate(&r, false).is_err());
        r.posix.as_mut().unwrap().rc_files.pop();
        for bad in [
            "relative",
            "/example/./ocx",
            "/example/../ocx",
            "/example/ocx\n",
            "/example/ocx\0",
        ] {
            r.bundle.as_mut().unwrap().cli_executable = bad.into();
            assert!(s.validate(&r, false).is_err());
        }
        r.bundle.as_mut().unwrap().cli_executable = format!("/{}", "x".repeat(4096));
        assert!(s.validate(&r, false).is_err());
    }
    #[test]
    fn lock_and_atomic_write_preserve_concurrent_user_edits() {
        let t = Temp::new();
        let s = t.store();
        assert!(Store::open(s.root.clone(), vec![]).is_err());
        drop(s);
        let _s = t.store();
        let p = t.0.join("file");
        atomic(&p, None, b"user", 0o600).unwrap();
        assert_eq!(
            atomic(&p, Some(b"old"), b"replacement", 0o600).unwrap_err(),
            "concurrent-edit"
        );
        assert_eq!(fs::read(p).unwrap(), b"user");
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_special_files_readonly_and_unsafe_parents_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let t = Temp::new();
        let p = t.0.join("file");
        atomic(&p, None, b"bytes", 0o600).unwrap();
        symlink(&p, t.0.join("link")).unwrap();
        assert!(read_bytes(&t.0.join("link")).is_err());
        assert!(check(&t.0, false).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(read_bytes(&p).is_err());
        symlink(&t.0, t.0.join("parent")).unwrap();
        assert!(atomic(&t.0.join("parent/child"), None, b"x", 0o600).is_err());
    }
}
