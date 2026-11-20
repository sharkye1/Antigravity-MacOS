//! Migrate Unlocker's system jobs and root-owned state left by a sudo launch.

use super::{launchctl, ENV_LABEL, PROXY_LABEL, WATCHDOG_LABEL};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const ROOT_FLAG: &str = "--repair-launch-agents-root";
const DATA: &str = ".local/share/agunlocker";
const AGENTS: &str = "Library/LaunchAgents";
const JOBS: [&str; 2] = [WATCHDOG_LABEL, PROXY_LABEL];
const STATE_FILES: &[&str] = &[
    "settings.json",
    "ag_proxy",
    ".ag_proxy.new",
    "gate.json",
    "renderer.txt",
    "watchdog.log",
    "forwarder.log",
    "proxy_port",
    "relay.version",
    "upstream.txt",
];

pub enum Outcome {
    NotNeeded,
    Cancelled,
    Recovered,
}

pub fn with_confirmation() -> Result<Outcome, String> {
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let home = account_home(uid)?;
    let agents = home.join(AGENTS);
    let data = home.join(DATA);
    let default_data = crate::background::install_dir() == data;
    let has_root_state = default_data
        && (owned_by_root(&data)
            || STATE_FILES
                .iter()
                .any(|file| owned_by_root(&data.join(file))));
    let has_root_plist = [PROXY_LABEL, WATCHDOG_LABEL, ENV_LABEL]
        .iter()
        .any(|label| owned_by_root(&agents.join(format!("{label}.plist"))));
    let has_old_job = JOBS
        .iter()
        .any(|label| system_job_matches(&home, label).unwrap_or(false));
    if !has_root_state && !has_root_plist && !has_old_job {
        return Ok(Outcome::NotNeeded);
    }
    if !default_data {
        return Err("Восстановление старых служб рассчитано на стандартный каталог ~/.local/share/agunlocker.".into());
    }

    let prompt = r#"display dialog "Найдены службы или файлы Unlocker, оставшиеся после запуска через sudo. Восстановление остановит старые службы Unlocker и вернёт вашему аккаунту доступ к настройкам. Затем приложение попробует запустить службу заново. macOS может запросить пароль администратора." with title "Восстановление Antigravity Unlocker" buttons {"Отмена", "Восстановить"} default button "Отмена" cancel button "Отмена" with icon caution"#;
    let answer = Command::new("/usr/bin/osascript")
        .args(["-e", prompt])
        .output()
        .map_err(|err| format!("Не удалось показать подтверждение: {err}"))?;
    if !answer.status.success() {
        let err = String::from_utf8_lossy(&answer.stderr);
        return if err.contains("(-128)") {
            Ok(Outcome::Cancelled)
        } else {
            Err(format!("Не удалось показать подтверждение: {}", err.trim()))
        };
    }

    let result = crate::elevate::recover_as_root(uid)
        .map_err(|err| format!("Не удалось запросить права администратора: {err}"))?;
    match result.status.code() {
        Some(0) => Ok(Outcome::Recovered),
        Some(126) => Ok(Outcome::Cancelled),
        _ => Err(String::from_utf8_lossy(&result.stderr).trim().to_string()),
    }
}

fn owned_by_root(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.uid() == 0 && (m.is_dir() || m.is_file()))
}

fn account_home(uid: u32) -> Result<PathBuf, String> {
    if uid == 0 {
        return Err("Для восстановления нужен обычный пользователь.".into());
    }
    let mut account = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = [0; 16384];
    let mut result = std::ptr::null_mut();
    // SAFETY: storage for passwd and its strings is writable for the call. The
    // returned record is valid only on success with a non-null result.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            account.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(format!("Не найден локальный пользователь UID {uid}."));
    }
    // SAFETY: getpwuid_r supplied a NUL-terminated home string in the buffer.
    let bytes = unsafe { CStr::from_ptr((*result).pw_dir) }.to_bytes();
    let path = PathBuf::from(OsStr::from_bytes(bytes));
    if !path.is_absolute() || path == Path::new("/") {
        return Err("Не найден домашний каталог пользователя.".into());
    }
    Ok(path)
}

fn matches_registration(output: &str, home: &Path, label: &str) -> bool {
    let plist = home.join(AGENTS).join(format!("{label}.plist"));
    let exe = home.join(DATA).join("ag_proxy");
    let (Some(plist), Some(exe)) = (plist.to_str(), exe.to_str()) else {
        return false;
    };
    output
        .lines()
        .any(|line| line.trim().strip_prefix("path = ") == Some(plist))
        && output
            .lines()
            .any(|line| line.trim().strip_prefix("program = ") == Some(exe))
}

fn system_job_matches(home: &Path, label: &str) -> Result<bool, String> {
    let target = format!("system/{label}");
    let out = launchctl(&["print", &target]).ok_or("Не удалось запустить launchctl.")?;
    if out.status.success() {
        return Ok(matches_registration(
            &String::from_utf8_lossy(&out.stdout),
            home,
            label,
        ));
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("Could not find service") {
        return Ok(false);
    }
    Err(format!("Не удалось проверить {target}: {}", err.trim()))
}

pub fn run_root(uid: Option<&str>) -> ! {
    let result = if !crate::utils::is_admin() {
        Err("Восстановление служб требует прав администратора.".into())
    } else {
        uid.and_then(|v| v.parse::<u32>().ok())
            .ok_or_else(|| "Не указан пользователь для восстановления.".to_string())
            .and_then(restore)
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn restore(uid: u32) -> Result<(), String> {
    let home = account_home(uid)?;
    let home_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&home)
        .map_err(|err| format!("Не удалось открыть домашний каталог: {err}"))?;
    if home_dir.metadata().map_err(|err| err.to_string())?.uid() != uid {
        return Err("Домашний каталог принадлежит другому пользователю.".into());
    }
    let data = open_dir_chain(&home_dir, DATA, uid)?;
    let agents = open_dir_chain(&home_dir, AGENTS, uid)?;

    for label in JOBS {
        if !system_job_matches(&home, label)? {
            continue;
        }
        let target = format!("system/{label}");
        let out = launchctl(&["bootout", &target]).ok_or("Не удалось запустить launchctl.")?;
        if !out.status.success() && system_job_matches(&home, label)? {
            return Err(format!(
                "Не удалось остановить {target}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }

    if let Some(data) = data {
        for name in STATE_FILES {
            restore_file(&data, name, uid)?;
        }
        restore_owner(&data, uid)
            .map_err(|err| format!("Не удалось вернуть права на {DATA}: {err}"))?;
    }
    if let Some(agents) = agents {
        for label in [WATCHDOG_LABEL, PROXY_LABEL, ENV_LABEL] {
            restore_file(&agents, &format!("{label}.plist"), uid)?;
        }
    }
    Ok(())
}

fn open_dir_chain(home: &File, relative: &str, uid: u32) -> Result<Option<File>, String> {
    let mut dir = home.try_clone().map_err(|err| err.to_string())?;
    for name in relative.split('/') {
        match open_child(&dir, name, libc::O_DIRECTORY) {
            Ok(next) => dir = next,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("Не удалось открыть {relative}: {err}")),
        }
        let owner = dir.metadata().map_err(|err| err.to_string())?.uid();
        if owner != 0 && owner != uid {
            return Err(format!(
                "Каталог {relative} принадлежит другому пользователю."
            ));
        }
    }
    Ok(Some(dir))
}

fn open_child(dir: &File, name: &str, flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: the directory fd is borrowed and the name is a single path
    // component. O_NOFOLLOW rejects symlinks; File takes ownership of the fd.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat returned a newly owned file descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn restore_file(dir: &File, name: &str, uid: u32) -> Result<(), String> {
    let file = match open_child(dir, name, 0) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("Не удалось открыть {name}: {err}")),
    };
    let meta = file.metadata().map_err(|err| err.to_string())?;
    if meta.uid() != 0 {
        return Ok(());
    }
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(format!(
            "Не удалось проверить тип или жёсткие ссылки файла {name}."
        ));
    }
    restore_owner(&file, uid).map_err(|err| format!("Не удалось вернуть права на {name}: {err}"))
}

fn restore_owner(file: &File, uid: u32) -> io::Result<()> {
    if file.metadata()?.uid() == 0 {
        // SAFETY: the fd is live and gid -1 preserves the existing group.
        if unsafe { libc::fchown(file.as_raw_fd(), uid, libc::gid_t::MAX) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_job_in_the_current_home_matches() {
        let home = Path::new("/Users/Example User");
        let plist = home.join(AGENTS).join(format!("{PROXY_LABEL}.plist"));
        let exe = home.join(DATA).join("ag_proxy");
        let registered = format!(
            "\tpath = {}\n\tprogram = {}\n",
            plist.display(),
            exe.display()
        );
        assert!(matches_registration(&registered, home, PROXY_LABEL));
        assert!(!matches_registration(&registered, home, WATCHDOG_LABEL));
        assert!(!matches_registration(
            &registered,
            Path::new("/Users/Other"),
            PROXY_LABEL
        ));
        assert!(!matches_registration(
            &format!("path = {}\nprogram = /bin/sh", plist.display()),
            home,
            PROXY_LABEL
        ));
    }

    #[test]
    fn recovery_never_opens_a_symlink_for_ownership_changes() {
        let dir = std::env::temp_dir().join(format!("ag-recovery-symlink-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("original"), b"keep").unwrap();
        std::os::unix::fs::symlink("original", dir.join("settings.json")).unwrap();
        let opened = File::open(&dir).unwrap();
        let uid = opened.metadata().unwrap().uid();
        assert!(restore_file(&opened, "settings.json", uid).is_err());
        assert_eq!(fs::read(dir.join("original")).unwrap(), b"keep");
        fs::remove_dir_all(dir).unwrap();
    }
}
