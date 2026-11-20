use crate::{background, endpoint, patch_binary, proxy};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub enum Mode {
    System,
    DnsAi,
}

pub const DESKTOP_BUNDLE_ID: &str = "com.google.antigravity";

pub fn switch(mode: Mode) -> Result<bool, String> {
    let app = desktop_bundle().ok_or("Antigravity Desktop не найден.")?;
    if matches!(mode, Mode::DnsAi) {
        let server = app.join("Contents/Resources/bin/language_server");
        let data = std::fs::read(&server)
            .map_err(|err| format!("Не удалось проверить языковой сервер Desktop: {err}"))?;
        if !patch_binary::contains_subslice(&data, endpoint::PROXY_ENV_VAR.as_bytes()) {
            return Err("Desktop ещё не умеет читать адрес прокси Unlocker. Сначала пропатчите Antigravity Desktop.".into());
        }
    }
    let running = app_action(&app, "running")?;
    if running && !confirm_restart()? {
        return Ok(false);
    }
    if matches!(mode, Mode::DnsAi) {
        // Check the actual listener before touching the Desktop process.
        background::ensure_running()?;
        check_listener()?;
    }
    if app_action(&app, "running")? {
        if !running {
            return Err("Antigravity открылся во время проверки. Повторите переключение.".into());
        }
        if !app_action(&app, "quit")? {
            return Err("Antigravity не принял запрос на завершение.".into());
        }
        let until = Instant::now() + Duration::from_secs(15);
        while app_action(&app, "running")? {
            if Instant::now() >= until {
                return Err("Antigravity всё ещё открыт. Смена маршрута остановлена.".into());
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    let mut command = Command::new("/usr/bin/open");
    command.arg("-a").arg(&app);
    for variable in launch_environment(mode) {
        command.args(["--env", &variable]);
    }
    output(command, "Не удалось открыть Antigravity")?;
    Ok(true)
}

fn launch_environment(mode: Mode) -> [String; 6] {
    let proxy = match mode {
        Mode::System => String::new(),
        Mode::DnsAi => proxy::url_at(proxy::DNS_AI_PORT),
    };
    [
        format!("{}={proxy}", endpoint::PROXY_ENV_VAR),
        format!("{}={proxy}", endpoint::PROXY_ENV_VAR.to_ascii_lowercase()),
        "HTTPS_PROXY=".into(),
        "https_proxy=".into(),
        "NO_PROXY=".into(),
        "no_proxy=".into(),
    ]
}

fn desktop_bundle() -> Option<PathBuf> {
    [
        PathBuf::from("/Applications/Antigravity.app"),
        super::home().join("Applications/Antigravity.app"),
    ]
    .into_iter()
    .find(|p| p.join("Contents/Info.plist").is_file())
}

fn app_action(app: &Path, action: &str) -> Result<bool, String> {
    const SCRIPT: &str = r#"
ObjC.import('AppKit');
function run(args) {
    const apps = $.NSRunningApplication.runningApplicationsWithBundleIdentifier(args[0]);
    let found = false;
    for (let i = 0; i < apps.count; i++) {
        const app = apps.objectAtIndex(i);
        if (ObjC.unwrap(app.bundleURL.path) !== args[1]) continue;
        found = true;
        if (args[2] === 'quit' && !app.terminate) return 'no';
    }
    return found ? 'yes' : 'no';
}
"#;
    let mut command = Command::new("/usr/bin/osascript");
    command
        .args(["-l", "JavaScript", "-e", SCRIPT, DESKTOP_BUNDLE_ID])
        .arg(app)
        .arg(action);
    let result = output(command, "Не удалось проверить состояние Antigravity")?;
    match String::from_utf8_lossy(&result.stdout).trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err("macOS вернула неизвестное состояние Antigravity.".into()),
    }
}

fn confirm_restart() -> Result<bool, String> {
    const SCRIPT: &str = r#"display dialog "Для смены маршрута нужно перезапустить Antigravity Desktop. Текущий запрос может прерваться." with title "Перезапустить Antigravity?" buttons {"Отмена", "Перезапустить"} default button "Отмена" cancel button "Отмена" with icon caution"#;
    let result = Command::new("/usr/bin/osascript")
        .args(["-e", SCRIPT])
        .output()
        .map_err(|err| format!("Не удалось показать подтверждение: {err}"))?;
    if result.status.success() {
        return Ok(true);
    }
    let err = String::from_utf8_lossy(&result.stderr);
    if err.contains("(-128)") {
        return Ok(false);
    }
    Err(format!("Не удалось показать подтверждение: {}", err.trim()))
}

fn check_listener() -> Result<(), String> {
    const HOST: &str = "daily-cloudcode-pa.googleapis.com";
    let port = proxy::DNS_AI_PORT;
    let until = Instant::now() + Duration::from_secs(5);
    while !super::traffic::proxy_owns_listener(port) {
        if Instant::now() >= until {
            return Err(format!("Служба Unlocker не открыла порт DNS-AI {port}."));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut socket =
        TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2))
            .map_err(|err| format!("Локальный порт DNS-AI недоступен: {err}"))?;
    socket.set_read_timeout(Some(Duration::from_secs(10))).ok();
    socket.set_write_timeout(Some(Duration::from_secs(2))).ok();
    socket
        .write_all(format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes())
        .map_err(|err| format!("Проверка локального прокси не отправилась: {err}"))?;
    let mut line = String::new();
    let mut response = BufReader::new(socket);
    response
        .read_line(&mut line)
        .map_err(|err| format!("DNS-AI не подтвердил открытие соединения: {err}"))?;
    if !line.starts_with("HTTP/1.1 200 ") {
        return Err(
            "DNS-AI не открыл соединение вне VPN. Причина записана в журнал службы.".into(),
        );
    }
    // Unlocker's CONNECT reply has no response body or extra headers.
    line.clear();
    response
        .read_line(&mut line)
        .map_err(|err| err.to_string())?;
    if line != "\r\n" || !response.buffer().is_empty() {
        return Err("Локальный порт DNS-AI вернул неожиданный ответ.".into());
    }
    let mut socket = response.into_inner();
    socket.set_read_timeout(Some(Duration::from_secs(4))).ok();
    let server = rustls::pki_types::ServerName::try_from(HOST).map_err(|err| err.to_string())?;
    let mut tls = rustls::ClientConnection::new(proxy::probe_config(), server)
        .map_err(|err| err.to_string())?;
    tls.complete_io(&mut socket)
        .map_err(|err| format!("DNS-AI открыл TCP, но TLS до Antigravity не прошёл: {err}"))?;
    Ok(())
}

fn output(mut command: Command, message: &str) -> Result<std::process::Output, String> {
    let result = command
        .output()
        .map_err(|err| format!("{message}: {err}"))?;
    if result.status.success() {
        Ok(result)
    } else {
        Err(format!(
            "{message}: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_launch_modes_change_only_the_new_process_environment() {
        let [upper, lower, ..] = launch_environment(Mode::DnsAi);
        assert_eq!(
            upper,
            format!("AG_LS_PROXY=http://127.0.0.1:{}", proxy::DNS_AI_PORT)
        );
        assert_eq!(
            lower,
            format!("ag_ls_proxy=http://127.0.0.1:{}", proxy::DNS_AI_PORT)
        );
        let [upper, lower, ..] = launch_environment(Mode::System);
        assert_eq!(upper, "AG_LS_PROXY=");
        assert_eq!(lower, "ag_ls_proxy=");
    }
}
