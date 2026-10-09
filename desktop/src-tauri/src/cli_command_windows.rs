#[cfg(any(windows, test))]
use crate::cli_command_record::Windows;
#[cfg(windows)]
use crate::cli_command_record::{Bundle, Record};
use crate::cli_command_record::{Change, Result};
#[cfg(windows)]
use std::path::Path;
#[cfg(any(windows, test))]
fn normalized(s: &str) -> String {
    s.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}
#[cfg(any(windows, test))]
fn parts(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(';').map(str::to_owned).collect()
    }
}
#[cfg(any(windows, test))]
fn index(v: &[String], entry: &str) -> Result<Option<usize>> {
    let hits: Vec<_> = v
        .iter()
        .enumerate()
        .filter(|(_, s)| normalized(s) == normalized(entry))
        .map(|(i, _)| i)
        .collect();
    if hits.len() > 1 {
        Err("path-entry-ambiguous".into())
    } else {
        Ok(hits.first().copied())
    }
}
#[cfg(any(windows, test))]
fn entry_ok(s: &str) -> bool {
    !s.is_empty() && !s.contains([';', '\0', '\r', '\n'])
}
#[cfg(any(windows, test))]
pub fn prepend(raw: &str, entry: &str, ty: &str) -> Result<(String, Windows)> {
    if !entry_ok(entry) || !matches!(ty, "REG_SZ" | "REG_EXPAND_SZ") {
        return Err("path-invalid".into());
    }
    let mut v = parts(raw);
    let found = index(&v, entry)?;
    let before = found.and_then(|i| i.checked_sub(1)).map(|i| v[i].clone());
    let after = found.and_then(|i| v.get(i + 1)).cloned();
    let actual = found.map(|i| v.remove(i)).unwrap_or_else(|| entry.into());
    v.insert(0, actual);
    let result = v.join(";");
    if result.encode_utf16().count() + 1 > 32_767 {
        return Err("path-too-long".into());
    }
    Ok((
        result,
        Windows {
            key: "HKCU\\Environment".into(),
            value: "Path".into(),
            entry: entry.into(),
            value_type: ty.into(),
            action: if found.is_some() {
                "moved-existing"
            } else {
                "inserted"
            }
            .into(),
            previous_before: before,
            previous_after: after,
        },
    ))
}
#[cfg(any(windows, test))]
pub fn remove(raw: &str, owned: &Windows) -> Result<String> {
    let mut v = parts(raw);
    let Some(i) = index(&v, &owned.entry)? else {
        return Ok(raw.into());
    };
    if owned.action == "inserted" {
        v.remove(i);
        return Ok(v.join(";"));
    }
    let actual = v.remove(i);
    let before = owned
        .previous_before
        .as_deref()
        .map(|s| index(&v, s))
        .transpose()?
        .flatten();
    let after = owned
        .previous_after
        .as_deref()
        .map(|s| index(&v, s))
        .transpose()?
        .flatten();
    let position = match (
        before,
        after,
        owned.previous_before.is_none(),
        owned.previous_after.is_none(),
    ) {
        (Some(b), Some(a), _, _) if b + 1 == a => a,
        (Some(b), None, _, true) if b + 1 == v.len() => v.len(),
        (None, Some(0), true, _) => 0,
        (None, None, true, true) if v.is_empty() => 0,
        _ => return Err("path-restore-ambiguous".into()),
    };
    v.insert(position, actual);
    Ok(v.join(";"))
}
#[cfg(any(windows, test))]
pub fn replace_owned_entry(
    raw: &str,
    owned: Option<&Windows>,
    entry: &str,
    ty: &str,
) -> Result<(String, Windows)> {
    if let Some(old) = owned {
        if normalized(&old.entry) == normalized(entry) {
            if index(&parts(raw), entry)?.is_none() {
                return prepend(raw, entry, ty);
            }
            let (out, _) = prepend(raw, entry, ty)?;
            let mut retained = old.clone();
            retained.value_type = ty.into();
            return Ok((out, retained));
        }
        prepend(&remove(raw, old)?, entry, ty)
    } else {
        prepend(raw, entry, ty)
    }
}
#[cfg(windows)]
pub fn stable_bundle(exe: &Path, debug: bool, version: &str) -> Result<Bundle> {
    if debug {
        return Err("development-launch".into());
    }
    let real = std::fs::canonicalize(exe).map_err(|_| "bundle-unavailable")?;
    let parent = real.parent().ok_or("unpackaged-launch")?;
    // current_exe is already absolute. Do not persist canonical Windows \\?\ extended syntax.
    let app = exe.to_str().ok_or("path-not-utf8")?;
    let cli = exe.parent().ok_or("unpackaged-launch")?.join("ocx.exe");
    let raw = cli.to_str().ok_or("path-not-utf8")?;
    let canonical = real
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('/', "\\");
    let lower = app.to_ascii_lowercase().replace('/', "\\");
    if lower.contains("\\target\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || canonical.contains("\\target\\")
        || canonical.contains("\\temp\\")
        || canonical.contains("\\tmp\\")
        || !std::fs::symlink_metadata(parent.join("ocx.exe"))
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
    {
        return Err("unpackaged-launch".into());
    }
    if !entry_ok(raw) || !exe.is_absolute() {
        return Err("path-invalid".into());
    }
    Ok(Bundle {
        platform: "win32".into(),
        kind: "windows-install".into(),
        app_executable: app.into(),
        cli_executable: raw.into(),
        version: version.into(),
    })
}
#[cfg(windows)]
mod os {
    use super::*;
    use winreg::{
        enums::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ,
        },
        RegKey, RegValue,
    };
    pub fn raw() -> Result<Option<RegValue>> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ)
            .map_err(|_| "registry-read-failed")?;
        match key.get_raw_value("Path") {
            Ok(v) if matches!(v.vtype, REG_SZ | REG_EXPAND_SZ) => Ok(Some(v)),
            Ok(_) => Err("path-type-unsupported".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("registry-read-failed".into()),
        }
    }
    pub fn decode(b: &[u8]) -> Result<String> {
        if b.len() % 2 != 0 {
            return Err("path-invalid-utf16".into());
        }
        let mut words: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if words.pop() != Some(0) || words.contains(&0) {
            return Err("path-invalid-utf16".into());
        }
        String::from_utf16(&words).map_err(|_| "path-invalid-utf16".into())
    }
    pub fn encode(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    pub fn type_name(v: &RegValue) -> &'static str {
        if v.vtype == REG_EXPAND_SZ {
            "REG_EXPAND_SZ"
        } else {
            "REG_SZ"
        }
    }
    pub fn write(c: &Change) -> Result<()> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_SET_VALUE)
            .map_err(|_| "registry-write-failed")?;
        match &c.after {
            Some(b) => {
                decode(b)?;
                key.set_raw_value(
                    "Path",
                    &RegValue {
                        bytes: b.clone(),
                        vtype: if c.kind == "registry-expand" {
                            REG_EXPAND_SZ
                        } else {
                            REG_SZ
                        },
                    },
                )
                .map_err(|_| "registry-write-failed".into())
            }
            None => match key.delete_value("Path") {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err("registry-write-failed".into()),
            },
        }
    }
    pub fn machine_conflict() -> Result<bool> {
        let k = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                KEY_READ,
            )
            .map_err(|_| "machine-path-unobserved")?;
        let v = match k.get_raw_value("Path") {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("machine-path-unobserved".into()),
        };
        let raw = decode(&v.bytes)?;
        // Preserve raw text in storage; expansion below is observe-only for conflict detection.
        for p in parts(&raw) {
            let expanded = expand(&p)?;
            for name in ["ocx.exe", "ocx.com", "ocx.cmd", "ocx.bat"] {
                if Path::new(expanded.trim_matches('"')).join(name).is_file() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn expand(s: &str) -> Result<String> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ExpandEnvironmentStringsW(src: *const u16, dst: *mut u16, size: u32) -> u32;
        }
        let src: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
        let mut dst = vec![0u16; 32_767];
        let n =
            unsafe { ExpandEnvironmentStringsW(src.as_ptr(), dst.as_mut_ptr(), dst.len() as u32) };
        if n == 0 || n as usize > dst.len() {
            return Err("machine-path-unobserved".into());
        }
        let out =
            String::from_utf16(&dst[..n as usize - 1]).map_err(|_| "machine-path-unobserved")?;
        if out.contains('%') {
            return Err("machine-path-unobserved".into());
        }
        Ok(out)
    }
    pub fn broadcast() -> Result<()> {
        #[link(name = "user32")]
        unsafe extern "system" {
            fn SendMessageTimeoutW(
                hwnd: *mut std::ffi::c_void,
                msg: u32,
                wparam: usize,
                lparam: isize,
                flags: u32,
                timeout: u32,
                result: *mut usize,
            ) -> isize;
        }
        let environment: Vec<u16> = "Environment".encode_utf16().chain(Some(0)).collect();
        let mut result = 0usize;
        // HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG; bounded per recipient.
        if unsafe {
            SendMessageTimeoutW(
                0xffffusize as *mut _,
                0x001a,
                0,
                environment.as_ptr() as isize,
                0x0002,
                1000,
                &mut result,
            )
        } == 0
        {
            Err("environment-broadcast-failed".into())
        } else {
            Ok(())
        }
    }
}
#[cfg(windows)]
pub fn read_change(c: &Change) -> Result<Option<Vec<u8>>> {
    let found = os::raw()?;
    if let Some(v) = &found {
        if (c.kind == "registry-expand") != (os::type_name(v) == "REG_EXPAND_SZ") {
            return Err("path-type-changed".into());
        }
    }
    Ok(found.map(|v| v.bytes))
}
#[cfg(not(windows))]
pub fn read_change(_: &Change) -> Result<Option<Vec<u8>>> {
    Err("registry-unsupported".into())
}
#[cfg(windows)]
pub fn apply_change(c: &Change) -> Result<()> {
    if read_change(c)? != c.before {
        return Err("concurrent-edit".into());
    }
    os::write(c)
}
#[cfg(not(windows))]
pub fn apply_change(_: &Change) -> Result<()> {
    Err("registry-unsupported".into())
}
#[cfg(windows)]
pub fn plan(
    current: &Record,
    bundle: Bundle,
    remove_owned: bool,
) -> Result<(Record, Vec<Change>, Vec<String>)> {
    let old = os::raw()?;
    let ty = old.as_ref().map(os::type_name).unwrap_or("REG_EXPAND_SZ");
    let raw = old
        .as_ref()
        .map(|v| os::decode(&v.bytes))
        .transpose()?
        .unwrap_or_default();
    let mut next = current.clone();
    let mut issues = Vec::new();
    let result = if remove_owned {
        if let Some(owned) = &current.windows {
            remove(&raw, owned)?
        } else {
            return Ok((next, Vec::new(), issues));
        }
    } else {
        let entry = Path::new(&bundle.cli_executable)
            .parent()
            .and_then(|p| p.to_str())
            .ok_or("path-invalid")?;
        let (s, owned) = replace_owned_entry(&raw, current.windows.as_ref(), entry, ty)?;
        next.bundle = Some(bundle);
        next.windows = Some(owned);
        s
    };
    if remove_owned {
        next.windows = None;
    }
    next.posix = None;
    let after = if old.is_none() && result.is_empty() {
        None
    } else {
        Some(os::encode(&result))
    };
    let before = old.map(|v| v.bytes);
    let changes = if before == after {
        Vec::new()
    } else {
        vec![Change {
            kind: if ty == "REG_EXPAND_SZ" {
                "registry-expand"
            } else {
                "registry-sz"
            }
            .into(),
            path: "HKCU\\Environment\\Path".into(),
            before,
            after,
            mode: 0,
            backup_path: None,
        }]
    };
    if !remove_owned {
        match os::machine_conflict() {
            Ok(true) => issues.push("machine-path-conflict".into()),
            Ok(false) => {}
            Err(e) => issues.push(e),
        }
    }
    Ok((next, changes, issues))
}
#[cfg(windows)]
pub fn notify() -> Result<()> {
    os::broadcast()
}
#[cfg(not(windows))]
pub fn notify() -> Result<()> {
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepend_preserves_raw_expansions_type_and_empty_entries() {
        let raw = r"%APPDATA%\npm;;C:\Tools;";
        for ty in ["REG_SZ", "REG_EXPAND_SZ"] {
            let (out, owned) = prepend(raw, r"C:\Program Files\OpenCodex", ty).unwrap();
            assert_eq!(out, format!(r"C:\Program Files\OpenCodex;{raw}"));
            assert_eq!(owned.value_type, ty);
            assert_eq!(owned.action, "inserted");
            assert_eq!(remove(&out, &owned).unwrap(), raw);
        }
    }
    #[test]
    fn moved_existing_entry_is_restored_and_same_entry_repair_keeps_ownership() {
        let raw = r"A;C:\Desktop;B";
        let (out, owned) = prepend(raw, r"c:/desktop/", "REG_SZ").unwrap();
        assert_eq!(owned.action, "moved-existing");
        let (twice, retained) =
            replace_owned_entry(&out, Some(&owned), r"C:\Desktop", "REG_SZ").unwrap();
        assert_eq!(twice, out);
        assert_eq!(retained, owned);
        assert_eq!(remove(&out, &owned).unwrap(), raw);
    }
    #[test]
    fn removal_preserves_concurrent_unrelated_entries_and_ambiguity() {
        let (out, owned) = prepend(r"A;B", r"C:\Desktop", "REG_EXPAND_SZ").unwrap();
        assert_eq!(remove(&format!("{out};NEW"), &owned).unwrap(), "A;B;NEW");
        let (out, moved) = prepend(r"A;C:\Desktop;B", r"C:\Desktop", "REG_SZ").unwrap();
        assert_eq!(
            remove(&out.replace("A;B", "A;NEW;B"), &moved).unwrap_err(),
            "path-restore-ambiguous"
        );
    }
    #[test]
    fn replacing_owned_entry_removes_only_the_previous_insertion() {
        let (out, old) = prepend("A;B", r"C:\Old", "REG_SZ").unwrap();
        let (new, owned) = replace_owned_entry(&out, Some(&old), r"C:\New", "REG_SZ").unwrap();
        assert_eq!(new, r"C:\New;A;B");
        assert_eq!(remove(&new, &owned).unwrap(), "A;B");
        assert_eq!(remove("A;B", &old).unwrap(), "A;B");
        let (_, moved) = prepend(r"A;C:\Old;B", r"C:\Old", "REG_SZ").unwrap();
        let (repaired, inserted) =
            replace_owned_entry("A;B", Some(&moved), r"C:\Old", "REG_SZ").unwrap();
        assert_eq!(inserted.action, "inserted");
        assert_eq!(remove(&repaired, &inserted).unwrap(), "A;B");
    }
    #[test]
    fn duplicate_invalid_and_oversize_entries_are_refused() {
        assert!(prepend(r"C:\Desktop;c:/desktop/", r"C:\Desktop", "REG_SZ").is_err());
        assert!(prepend("A", "bad;entry", "REG_SZ").is_err());
        assert!(prepend("A", r"C:\Desktop", "REG_BINARY").is_err());
        assert!(prepend(&"X".repeat(32_767), r"C:\Desktop", "REG_SZ").is_err());
    }
}
