//! Native macOS integration. Services and state belong to the logged-in user;
//! only writing protected application files and /etc/resolver needs elevation.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

pub const DNS_FLAG: &str = "--macos-dns";
const DNS_MARKER: &str = "# AG_UNLOCKER_RESOLVER_V1";

pub fn application_support() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("Library/Application Support")
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn plist(label: &str, args: &[String], keep_alive: bool) -> String {
    let args: String = args
        .iter()
        .map(|a| format!("<string>{}</string>", xml(a)))
        .collect();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\"><dict><key>Label</key><string>{}</string>\
        <key>ProgramArguments</key><array>{args}</array>\
        <key>RunAtLoad</key><true/><key>KeepAlive</key><{}/>
        <key>ThrottleInterval</key><integer>5</integer></dict></plist>\n",
        xml(label), if keep_alive { "true" } else { "false" })
}

pub fn launchctl(args: &[&str]) -> Result<Output, String> {
    crate::utils::bounded_output(
        Command::new("/bin/launchctl").args(args),
        Duration::from_secs(20),
    )
    .ok_or_else(|| "launchctl не ответил за 20 секунд".to_string())
}

fn checked(output: Output, action: &str) -> Result<Output, String> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "{action}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn domain() -> Result<String, String> {
    let out = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if uid.is_empty() || !uid.bytes().all(|c| c.is_ascii_digit()) || uid == "0" {
        return Err("Запустите анлокер от обычного пользователя, без sudo".into());
    }
    Ok(format!("gui/{uid}"))
}

pub fn agent_path(label: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("Library/LaunchAgents")
        .join(format!("{label}.plist"))
}

fn install_agent(label: &str, args: &[String], keep_alive: bool) -> Result<(), String> {
    let path = agent_path(label);
    let text = plist(label, args, keep_alive);
    let changed = std::fs::read_to_string(&path).ok().as_deref() != Some(&text);
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    let domain = domain()?;
    let service = format!("{domain}/{label}");
    if changed || !launchctl(&["print", &service]).is_ok_and(|o| o.status.success()) {
        let _ = launchctl(&["bootout", &service]);
        std::fs::write(&path, text).map_err(|e| e.to_string())?;
        checked(launchctl(&["enable", &service])?, "launchctl enable")?;
        checked(
            launchctl(&["bootstrap", &domain, &path.to_string_lossy()])?,
            "launchctl bootstrap",
        )?;
    }
    Ok(())
}

fn remove_agent(label: &str) -> Result<(), String> {
    let path = agent_path(label);
    let service = format!("{}/{label}", domain()?);
    if launchctl(&["print", &service]).is_ok_and(|o| o.status.success()) {
        checked(launchctl(&["bootout", &service])?, "launchctl bootout")?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn session_env(name: &str) -> Option<String> {
    let out = launchctl(&["getenv", name]).ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

pub fn set_session_env(name: &str, value: Option<&str>) -> Result<(), String> {
    let args = match value {
        Some(v) => vec!["setenv", name, v],
        None => vec!["unsetenv", name],
    };
    checked(launchctl(&args)?, "настройка среды launchd")?;
    Ok(())
}

pub const ENV_LABEL: &str = "com.agunlocker.environment";
pub fn persist_proxy(url: &str) -> Result<(), String> {
    install_agent(
        ENV_LABEL,
        &[
            "/bin/launchctl".into(),
            "setenv".into(),
            crate::endpoint::PROXY_ENV_VAR.into(),
            url.into(),
        ],
        false,
    )?;
    set_session_env(crate::endpoint::PROXY_ENV_VAR, Some(url))
}

pub fn remove_proxy() -> Result<(), String> {
    remove_agent(ENV_LABEL)?;
    set_session_env(crate::endpoint::PROXY_ENV_VAR, None)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Arguments travel through osascript's argv, never through AppleScript source.
pub fn privileged(flag: &str, value: &Path) -> Result<Output, String> {
    use std::io::Write;
    use std::process::Stdio;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let command = [
        exe.to_string_lossy().as_ref(),
        flag,
        value.to_string_lossy().as_ref(),
    ]
    .iter()
    .map(|s| shell_quote(s))
    .collect::<Vec<_>>()
    .join(" ");
    let mut child = Command::new("/usr/bin/osascript")
        .args(["-", &command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("не запустился запрос пароля: {e}"))?;
    child.stdin.take().unwrap().write_all(b"on run argv\nreturn do shell script (item 1 of argv) with administrator privileges without altering line endings\nend run\n")
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    checked(out, "действие с правами администратора")
}

/// Sign before replacing a native executable: Apple Silicon refuses modified
/// Mach-O code with its old signature. Non-Mach-O fixtures are left untouched.
pub fn sign_native(path: &Path) -> std::io::Result<()> {
    use std::io::Read;
    let mut magic = [0; 4];
    if std::fs::File::open(path)?.read(&mut magic)? < 4 {
        return Ok(());
    }
    if !matches!(
        u32::from_be_bytes(magic),
        0xfeedface
            | 0xfeedfacf
            | 0xcefaedfe
            | 0xcffaedfe
            | 0xcafebabe
            | 0xbebafeca
            | 0xcafebabf
            | 0xbfbafeca
    ) {
        return Ok(());
    }
    codesign(path).map_err(std::io::Error::other)
}

fn codesign(path: &Path) -> Result<(), String> {
    let out = crate::utils::bounded_output(
        Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--preserve-metadata=identifier,entitlements,flags,runtime",
            ])
            .arg(path),
        Duration::from_secs(120),
    )
    .ok_or("codesign не ответил")?;
    checked(out, "codesign")?;
    Ok(())
}

pub fn sign_enclosing_bundle(path: &Path) -> Result<(), String> {
    if let Some(bundle) = path
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
    {
        codesign(bundle)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn interface_index(name: &str) -> Option<u32> {
    extern "C" {
        fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
    }
    let name = std::ffi::CString::new(name).ok()?;
    let index = unsafe { if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(target_os = "macos")]
pub fn bind_interface(fd: std::os::fd::RawFd, ipv6: bool, index: u32) -> std::io::Result<()> {
    extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, value: *const u32, len: u32) -> i32;
    }
    // Darwin's IP_BOUND_IF / IPV6_BOUND_IF take a host-order interface index.
    let (level, option) = if ipv6 { (41, 125) } else { (0, 25) };
    let rc = unsafe { setsockopt(fd, level, option, &index, std::mem::size_of::<u32>() as u32) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
pub fn route_interface(dest: &str) -> Option<String> {
    let out = crate::utils::bounded_output(
        Command::new("/sbin/route").args(["-n", "get", dest]),
        Duration::from_secs(5),
    )?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix("interface:")
            .map(|s| s.trim().to_string())
    })
}

#[cfg(target_os = "macos")]
pub mod background {
    use super::*;
    const PROXY: &str = "com.agunlocker.proxy";
    const WATCHDOG: &str = "com.agunlocker.watchdog";
    pub fn install_dir() -> PathBuf {
        application_support().join("AGUnlocker")
    }
    pub fn installed_exe() -> PathBuf {
        install_dir().join("ag_service")
    }
    pub fn is_enabled() -> bool {
        agent_path(PROXY).is_file()
    }
    pub fn is_watchdog_enabled() -> bool {
        agent_path(WATCHDOG).is_file()
    }
    pub fn is_running() -> bool {
        domain()
            .ok()
            .and_then(|d| launchctl(&["print", &format!("{d}/{PROXY}")]).ok())
            .is_some_and(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .any(|l| l.trim() == "state = running")
            })
    }
    pub fn relay_is_outdated() -> bool {
        is_running()
            && crate::dns_forwarder::installed_version() != crate::dns_forwarder::RELAY_VERSION
    }
    fn install_copy() -> Result<bool, String> {
        use std::os::unix::fs::PermissionsExt;
        let src = std::env::current_exe().map_err(|e| e.to_string())?;
        let dest = installed_exe();
        std::fs::create_dir_all(install_dir()).map_err(|e| e.to_string())?;
        if src == dest
            || std::fs::read(&dest).ok() == Some(std::fs::read(&src).map_err(|e| e.to_string())?)
        {
            return Ok(false);
        }
        let temp = install_dir().join(format!(".ag_service.{}.new", std::process::id()));
        std::fs::copy(src, &temp).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        std::fs::rename(temp, dest).map_err(|e| e.to_string())?;
        Ok(true)
    }
    fn restart(label: &str) -> Result<(), String> {
        checked(
            launchctl(&["kickstart", "-k", &format!("{}/{label}", domain()?)])?,
            "перезапуск launchd",
        )?;
        Ok(())
    }
    pub fn ensure_installed() -> Result<(), String> {
        if install_copy()? {
            if is_enabled() {
                restart(PROXY)?;
            }
            if is_watchdog_enabled() {
                restart(WATCHDOG)?;
            }
        }
        Ok(())
    }
    pub fn ensure_running() -> Result<(), String> {
        let replaced = install_copy()?;
        install_agent(
            PROXY,
            &[
                installed_exe().to_string_lossy().into_owned(),
                crate::background::PROXY_FLAG.into(),
            ],
            true,
        )?;
        if replaced {
            restart(PROXY)?;
            if is_watchdog_enabled() {
                restart(WATCHDOG)?;
            }
        }
        Ok(())
    }
    pub fn enable() -> Result<(), String> {
        ensure_running()?;
        restart(PROXY)
    }
    pub fn enable_watchdog() -> Result<(), String> {
        let replaced = install_copy()?;
        install_agent(
            WATCHDOG,
            &[
                installed_exe().to_string_lossy().into_owned(),
                crate::background::WATCHDOG_FLAG.into(),
            ],
            true,
        )?;
        if replaced {
            restart(WATCHDOG)?;
            if is_enabled() {
                restart(PROXY)?;
            }
        }
        Ok(())
    }
    pub fn disable_watchdog() {
        let _ = remove_agent(WATCHDOG);
    }
    pub fn disable() -> Result<(), String> {
        if dns_rules_present() {
            return Err("Сначала снимите DNS-правила: они указывают на эту службу".into());
        }
        remove_agent(PROXY)?;
        if !is_watchdog_enabled() {
            let _ = std::fs::remove_file(installed_exe());
        }
        Ok(())
    }
}

fn resolver_path(host: &str) -> PathBuf {
    Path::new("/etc/resolver").join(host)
}
fn resolver_body() -> String {
    format!(
        "{DNS_MARKER}\nnameserver 127.0.0.1\nport {}\ntimeout 5\n",
        crate::dns_forwarder::LISTEN_PORT
    )
}

/// This root helper accepts only two fixed operations and two fixed hostnames.
pub fn dns_helper(action: &str) -> Result<(), String> {
    if !crate::utils::is_admin() {
        return Err("нужны права администратора".into());
    }
    if !matches!(action, "enable" | "disable") {
        return Err("неизвестное действие DNS".into());
    }
    // Check every file before writing any, preserving another tool's resolvers.
    for host in crate::dns::core_namespaces() {
        match std::fs::read_to_string(resolver_path(host)) {
            Ok(s) if action == "enable" && !s.starts_with(DNS_MARKER) => {
                return Err(format!(
                    "{} уже настроен другой программой",
                    resolver_path(host).display()
                ))
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
    }
    if action == "enable" {
        std::fs::create_dir_all("/etc/resolver").map_err(|e| e.to_string())?;
    }
    for host in crate::dns::core_namespaces() {
        let path = resolver_path(host);
        if action == "enable" {
            let temp = path.with_extension(format!("{}.agtmp", std::process::id()));
            std::fs::write(&temp, resolver_body()).map_err(|e| e.to_string())?;
            std::fs::rename(temp, path).map_err(|e| e.to_string())?;
        } else if std::fs::read_to_string(&path).is_ok_and(|s| s.starts_with(DNS_MARKER)) {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .status();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .status();
    Ok(())
}

pub fn dns_enabled() -> bool {
    crate::dns::core_namespaces().iter().all(|h| {
        std::fs::read_to_string(resolver_path(h)).ok().as_deref() == Some(resolver_body().as_str())
    })
}

fn dns_rules_present() -> bool {
    crate::dns::core_namespaces()
        .iter()
        .any(|h| std::fs::read_to_string(resolver_path(h)).is_ok_and(|s| s.starts_with(DNS_MARKER)))
}

pub fn configure_dns(enable: bool) -> Result<(), String> {
    if (enable && dns_enabled()) || (!enable && !dns_rules_present()) {
        return Ok(());
    }
    let action = if enable { "enable" } else { "disable" };
    if crate::utils::is_admin() {
        dns_helper(action)
    } else {
        privileged(DNS_FLAG, Path::new(action)).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_agent_arguments_are_xml_escaped() {
        let s = plist(
            "com.agunlocker.proxy",
            &["/Users/A & B/it's <app>".into(), "--proxy".into()],
            true,
        );
        assert!(s.contains("/Users/A &amp; B/it&apos;s &lt;app&gt;"));
        assert!(s.contains("<key>KeepAlive</key><true/>"));
        assert!(plist("env", &[], false).contains("<key>KeepAlive</key><false/>"));
    }
    #[test]
    fn shell_arguments_cannot_escape_their_quotes() {
        assert_eq!(shell_quote("a'$(id)"), "'a'\\''$(id)'");
    }
}
