//! Keep interactive copies from reapplying conflicting settings.
//!
//! Two windows of different versions share one settings file, one service and
//! one set of switches, and each re-applies its own idea of them on every
//! refresh - an older one put its relay and route state back under the newer
//! one, and the model did not answer until the old window was closed by hand
//! (field report, 2026-10-15). Only *windows* are matched: the services run
//! under other names (`ag_dns.exe` on Windows, `ag_proxy` on Linux) and carry a
//! flag, and the pkexec helper carries one too, so none of them is touched.

#[cfg(target_os = "macos")]
pub fn lock_macos(dir: &std::path::Path) -> Result<std::fs::File, String> {
    use std::fs::{self, File, TryLockError};

    // Keep the same file across launches. Removing it could let a new process
    // lock a different inode while another process still holds the old lock.
    let path = dir.join("window.lock");
    let file = fs::create_dir_all(dir)
        .and_then(|()| {
            File::options()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
        })
        .map_err(|err| format!("Не удалось открыть {}: {err}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err("Antigravity Unlocker уже открыт.".to_string()),
        Err(TryLockError::Error(err)) => Err(format!(
            "Не удалось заблокировать {}: {err}",
            path.display()
        )),
    }
}

/// Whether a process image name is a copy of the unlocker window: the exe this
/// one runs as, or any other release of it (`AG_<version>.exe` on Windows).
#[cfg(any(not(target_os = "macos"), test))]
fn is_window_name(name: &str, own: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == own.to_ascii_lowercase() {
        return true;
    }
    lower
        .strip_prefix("ag_")
        .and_then(|rest| rest.strip_suffix(".exe"))
        .is_some_and(|ver| ver.chars().next().is_some_and(|c| c.is_ascii_digit()))
}

/// Flags that make a process a service or helper, never a window.
#[cfg(any(all(not(target_os = "macos"), not(windows)), test))]
fn is_service_args(args: &[String]) -> bool {
    args.iter().any(|a| {
        matches!(
            a.as_str(),
            "--dns-forwarder" | "--watchdog" | "--proxy" | "--patch-root" | "--unpatch-root"
        )
    })
}

/// Closes every other copy of the window. Best effort and silent: a copy that
/// refuses to die (another user's, a higher integrity level) is left running.
#[cfg(not(target_os = "macos"))]
pub fn close_others() {
    let Ok(me) = std::env::current_exe() else {
        return;
    };
    let own = me
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    platform::close_others(&own);
}

#[cfg(target_os = "windows")]
mod platform {
    use std::process::Command;

    use super::is_window_name;

    pub fn close_others(own: &str) {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FO", "CSV", "/NH"]);
        let Ok(out) = crate::utils::no_window(&mut cmd).output() else {
            return;
        };
        let me = std::process::id();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut cols = line.split("\",\"").map(|c| c.trim_matches('"'));
            let (Some(name), Some(pid)) = (cols.next(), cols.next()) else {
                continue;
            };
            let Ok(pid) = pid.parse::<u32>() else {
                continue;
            };
            if pid == me || !is_window_name(name, own) {
                continue;
            }
            let mut kill = Command::new("taskkill");
            kill.args(["/F", "/PID", &pid.to_string()]);
            let _ = crate::utils::no_window(&mut kill).output();
        }
    }
}

#[cfg(all(not(target_os = "macos"), not(windows)))]
mod platform {
    use super::{is_service_args, is_window_name};

    pub fn close_others(own: &str) {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        let me = std::process::id();
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == me {
                continue;
            }
            let base = entry.path();
            // `comm` is cut at 15 bytes; the exe link is the whole name.
            let Some(name) = std::fs::read_link(base.join("exe"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            else {
                continue;
            };
            if !is_window_name(&name, own) {
                continue;
            }
            let args: Vec<String> = std::fs::read(base.join("cmdline"))
                .map(|raw| {
                    raw.split(|b| *b == 0)
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect()
                })
                .unwrap_or_default();
            if is_service_args(&args) {
                continue;
            }
            // The `kill` tool, not libc: one signal does not earn an `unsafe` block.
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .output();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn second_macos_instance_is_rejected_until_the_first_exits() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "agunlocker-window-lock-{}-{}",
            std::process::id(),
            timestamp.as_nanos()
        ));
        let first = lock_macos(&dir).unwrap();
        assert_eq!(
            lock_macos(&dir).unwrap_err(),
            "Antigravity Unlocker уже открыт."
        );
        drop(first);
        drop(lock_macos(&dir).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn other_releases_of_the_window_are_windows_and_the_services_are_not() {
        assert!(is_window_name("AG_2.22.0.exe", "AG_2.23.1.exe"));
        assert!(is_window_name("AG_2.23.1.exe", "AG_2.23.1.exe"));
        assert!(is_window_name("ag_unlocker", "ag_unlocker"));
        assert!(!is_window_name("ag_dns.exe", "AG_2.23.1.exe"));
        assert!(!is_window_name("ag_proxy", "ag_unlocker"));
        assert!(!is_window_name("Antigravity.exe", "AG_2.23.1.exe"));
    }

    #[test]
    fn a_flagged_process_is_a_service() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(is_service_args(&a(&["ag", "--proxy"])));
        assert!(is_service_args(&a(&["ag", "--unpatch-root", "/opt/x"])));
        assert!(!is_service_args(&a(&["ag"])));
    }
}
