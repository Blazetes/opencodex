#[cfg(unix)]
use crate::cli_command_posix as posix;
use crate::{
    cli_command_record::{self as record, Bundle, Record, Result, Store},
    cli_command_windows as windows,
};
use serde::Serialize;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use tauri::{AppHandle, Manager};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub enabled: bool,
    pub configured: bool,
    pub phase: String,
    pub expected_executable: Option<String>,
    pub issues: Vec<String>,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            enabled: true,
            configured: false,
            phase: "unobserved".into(),
            expected_executable: None,
            issues: Vec::new(),
        }
    }
}
#[derive(Default)]
pub struct State {
    scheduled: AtomicBool,
    serial: Mutex<()>,
    latest: Mutex<Status>,
}
#[derive(Clone, Copy)]
pub enum Action {
    Reconcile,
    Repair,
    Enable(bool),
    Remove,
}
pub fn status(app: &AppHandle) -> Status {
    app.state::<State>()
        .latest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}
fn perform(app: &AppHandle, action: Action) -> Result<Status> {
    let home = app.path().home_dir().map_err(|_| "home-unavailable")?;
    if !home.is_absolute() {
        return Err("home-unavailable".into());
    }
    record::check(&home, true)?;
    let root = home.join(".opencodex-desktop");
    let exists = root.try_exists().map_err(|_| "io-failed")?;
    // First run checks the bundle before creating even the record directory (AM-10).
    let observed = if !exists
        || !root
            .join("cli.json")
            .try_exists()
            .map_err(|_| "io-failed")?
    {
        Some(observe_bundle(app)?)
    } else {
        None
    };
    #[cfg(unix)]
    let selected = posix::targets(&home)?;
    #[cfg(not(unix))]
    let selected: Vec<(String, std::path::PathBuf)> = Vec::new();
    let allowed = selected.iter().map(|(_, p)| p.clone()).collect();
    let store = Store::open(root, allowed)?;
    let initial = observed
        .map(|b| -> Result<Record> {
            let mut r = Record::fresh(b);
            r.install_id = crate::identity::install_id(app).ok_or("install-id-unavailable")?;
            Ok(r)
        })
        .transpose()?;
    perform_in(
        &store,
        &home,
        selected,
        action,
        initial,
        || observe_bundle(app),
        |enabled| {
            app.state::<State>()
                .latest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .enabled = enabled;
        },
    )
}
fn observe_bundle(app: &AppHandle) -> Result<Bundle> {
    let exe = std::env::current_exe().map_err(|_| "bundle-unavailable")?;
    let version = app.package_info().version.to_string();
    #[cfg(unix)]
    {
        posix::stable_bundle(&exe, cfg!(debug_assertions), &version)
    }
    #[cfg(windows)]
    {
        windows::stable_bundle(&exe, cfg!(debug_assertions), &version)
    }
}
fn perform_in(
    store: &Store,
    home: &std::path::Path,
    selected: Vec<(String, std::path::PathBuf)>,
    action: Action,
    initial: Option<Record>,
    observe: impl FnOnce() -> Result<Bundle>,
    publish_enabled: impl FnOnce(bool),
) -> Result<Status> {
    let observed = initial.as_ref().and_then(|r| r.bundle.clone());
    let mut r = match store.read()? {
        Some(r) => r,
        None => initial.ok_or("bundle-unavailable")?,
    };
    let explicit_remove = matches!(action, Action::Remove | Action::Enable(false));
    let desired = match action {
        Action::Enable(v) => Some(v),
        Action::Remove => Some(false),
        _ => None,
    };
    let install_bundle = if desired == Some(true) || (desired != Some(false) && r.enabled) {
        Some(match observed {
            Some(b) => b,
            None => observe()?,
        })
    } else {
        None
    };
    if desired == Some(true) {
        r.bundle = install_bundle.clone();
    }
    if let Some(enabled) = desired {
        if r.enabled != enabled {
            r.enabled = enabled;
            r.generation += 1;
            if let Some(j) = &mut r.pending {
                j.next.enabled = enabled;
                j.next.generation = r.generation + 1;
            }
        }
        // Off is durable even if journal conflict prevents this cleanup attempt.
        store.save(&r)?;
    }
    publish_enabled(r.enabled);
    // A disabled interrupted install rolls back its completed prefix. It never finishes installing.
    store.recover(&mut r)?;
    let remove = explicit_remove || (!r.enabled && matches!(action, Action::Reconcile));
    if !remove && !r.enabled {
        return Ok(Status {
            enabled: false,
            phase: "disabled".into(),
            ..Status::default()
        });
    }
    let (next, changes, mut issues) = if remove {
        #[cfg(unix)]
        {
            posix::remove_plan(store, &r)?
        }
        #[cfg(windows)]
        {
            if let Some(b) = r.bundle.clone() {
                windows::plan(&r, b, true)?
            } else {
                (r.clone(), Vec::new(), Vec::new())
            }
        }
    } else {
        let b = install_bundle.ok_or("bundle-unavailable")?;
        #[cfg(unix)]
        {
            posix::plan(store, &r, b, home, selected)?
        }
        #[cfg(windows)]
        {
            let _ = (home, selected);
            windows::plan(&r, b, false)?
        }
    };
    let registry_changed = changes.iter().any(|c| c.kind.starts_with("registry-"));
    store.transact(
        &mut r,
        next,
        changes,
        if remove { "remove" } else { "install" },
    )?;
    issues.extend(store.journal_issues(&r));
    if registry_changed {
        if let Err(e) = windows::notify() {
            issues.push(e);
        }
    }
    let configured = r.enabled
        && r.bundle.is_some()
        && (r.posix.is_some() || r.windows.is_some())
        && issues.is_empty();
    let phase = if !issues.is_empty() {
        "partial"
    } else if !r.enabled {
        "disabled"
    } else if configured {
        "configured"
    } else {
        "unobserved"
    };
    Ok(Status {
        enabled: r.enabled,
        configured,
        phase: phase.into(),
        expected_executable: r.bundle.as_ref().map(|b| b.cli_executable.clone()),
        issues,
    })
}
fn run(app: &AppHandle, action: Action) -> Status {
    let state = app.state::<State>();
    let _serial = state
        .serial
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = match perform(app, action) {
        Ok(v) => v,
        Err(code) => {
            crate::logging::log_once("terminal command", &code);
            let mut v = status(app);
            v.configured = false;
            v.phase = if v.enabled { "blocked" } else { "partial" }.into();
            v.issues = if v.enabled {
                vec![code]
            } else {
                vec![code, "cleanup-pending".into()]
            };
            v
        }
    };
    *state
        .latest
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = result.clone();
    result
}
async fn execute(app: AppHandle, action: Action) -> Result<Status> {
    let worker_app = app.clone();
    match tauri::async_runtime::spawn_blocking(move || run(&worker_app, action)).await {
        Ok(v) => Ok(v),
        Err(_) => {
            let mut v = status(&app);
            v.configured = false;
            v.phase = "blocked".into();
            v.issues = vec!["worker-failed".into()];
            *app.state::<State>()
                .latest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = v.clone();
            Ok(v)
        }
    }
}
pub fn reconcile_on_launch(app: &AppHandle) {
    if app.state::<State>().scheduled.swap(true, Ordering::AcqRel) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if execute(app, Action::Reconcile).await.is_err() {
            crate::logging::log_once("terminal command", "worker-failed");
        }
    });
}
pub async fn set_enabled(app: AppHandle, enabled: bool) -> Result<Status> {
    execute(app, Action::Enable(enabled)).await
}
pub async fn install(app: AppHandle) -> Result<Status> {
    execute(app, Action::Repair).await
}
pub async fn remove(app: AppHandle) -> Result<Status> {
    execute(app, Action::Remove).await
}
pub fn show_page(app: &AppHandle) {
    crate::popup::hide(app);
    if let Some(w) = app.get_webview_window("main") {
        // Fixed local URL; this works before a proxy exists, like the bundled update page.
        let origin = if cfg!(target_os = "windows") {
            "http://tauri.localhost/cli.html"
        } else {
            "tauri://localhost/cli.html"
        };
        if tauri::Url::parse(origin)
            .ok()
            .is_some_and(|url| w.navigate(url).is_ok())
        {
            crate::window::show(&w);
        } else {
            crate::logging::log_once("terminal command", "page-unavailable");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use record::tests::{bundle, Temp};
    fn selected(t: &Temp) -> Vec<(String, std::path::PathBuf)> {
        vec![("zsh".into(), t.0.join(".zshrc"))]
    }
    #[test]
    fn fresh_stable_bundle_installs_without_npm() {
        let t = Temp::new();
        let store = t.store();
        let result = perform_in(
            &store,
            &t.0,
            selected(&t),
            Action::Reconcile,
            Some(Record::fresh(bundle())),
            || panic!("fresh bundle is already observed"),
            |_| {},
        )
        .unwrap();
        assert!(result.enabled && result.configured);
        let r = store.read().unwrap().unwrap();
        assert!(r.bundle.is_some() && r.pending.is_none());
        assert!(store.root.join("bin/ocx").is_file());
        let generation = r.generation;
        perform_in(
            &store,
            &t.0,
            selected(&t),
            Action::Reconcile,
            None,
            || Ok(bundle()),
            |_| {},
        )
        .unwrap();
        assert_eq!(store.read().unwrap().unwrap().generation, generation);
    }
    #[test]
    fn disabled_record_survives_relaunch_repair_and_tombstone_can_be_enabled() {
        let t = Temp::new();
        let store = t.store();
        let mut r = Record::fresh(bundle());
        r.enabled = false;
        r.bundle = None;
        store.save(&r).unwrap();
        for action in [Action::Reconcile, Action::Repair] {
            let result = perform_in(
                &store,
                &t.0,
                selected(&t),
                action,
                None,
                || panic!("off does not observe an install target"),
                |_| {},
            )
            .unwrap();
            assert!(!result.enabled);
            assert_eq!(result.phase, "disabled");
            assert!(!store.root.join("bin/ocx").exists());
        }
        let result = perform_in(
            &store,
            &t.0,
            selected(&t),
            Action::Enable(true),
            None,
            || Ok(bundle()),
            |_| {},
        )
        .unwrap();
        assert!(result.configured);
    }
    #[test]
    fn remove_persists_disabled_intent_before_first_cleanup_write() {
        let t = Temp::new();
        let store = t.store();
        perform_in(
            &store,
            &t.0,
            selected(&t),
            Action::Reconcile,
            Some(Record::fresh(bundle())),
            || Ok(bundle()),
            |_| {},
        )
        .unwrap();
        let shim = store.root.join("bin/ocx");
        let result = perform_in(
            &store,
            &t.0,
            selected(&t),
            Action::Remove,
            None,
            || panic!("remove has no bundle gate"),
            |enabled| {
                assert!(!enabled);
                assert!(!store.read().unwrap().unwrap().enabled);
                assert!(shim.exists());
            },
        )
        .unwrap();
        assert!(!result.enabled);
        assert_eq!(result.phase, "disabled");
        assert!(!shim.exists());
    }
    #[test]
    fn unstable_bundle_keeps_existing_record_and_files_unchanged() {
        let t = Temp::new();
        let store = t.store();
        let r = Record::fresh(bundle());
        store.save(&r).unwrap();
        let before = std::fs::read(store.root.join("cli.json")).unwrap();
        assert_eq!(
            perform_in(
                &store,
                &t.0,
                selected(&t),
                Action::Reconcile,
                None,
                || Err("development-launch".into()),
                |_| {}
            )
            .unwrap_err(),
            "development-launch"
        );
        assert_eq!(std::fs::read(store.root.join("cli.json")).unwrap(), before);
    }
}
