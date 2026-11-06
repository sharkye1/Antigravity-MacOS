# Antigravity Unlocker для macOS

Порт использует тот же Rust-код интерфейса, патчей, прокси, выбора маршрутов,
проверки ключа, отчётов и наблюдения за обновлениями, что Windows/Linux.
Нативные части macOS: обнаружение `.app`, `launchd`, `Library/Application Support`,
выбор сетевого интерфейса и повторная локальная подпись изменённых Mach-O файлов.

## Сборка

Нужны Mac, Rust **1.95 или новее**, Python 3 и Xcode Command Line Tools.
Команды выполняются из корня проекта:

```sh
xcode-select --install
python3 macos/build.py
```

Результат: `dist/macos/Antigravity Unlocker.app` и архив
`AG_<версия>_macos_universal.tar.gz`. Универсальная сборка содержит Apple Silicon
и Intel. Для одной архитектуры: `--arch arm64` или `--arch x86_64`.
Папку результата можно задать через `--output`.

Workflow `.github/workflows/macos.yml` проверяет Rust-код, запускает тесты
на macOS и собирает универсальный архив. Его можно запустить вручную в Actions.
Сборка не публикуется в Releases автоматически.

В исходной версии воспроизводятся два падающих теста:
`group_key::tests::parse_key_errors` и
`resolvers::tests::the_warm_path_re_probes_instead_of_trusting_what_it_knows`.
Workflow явно исключает их; остальные тесты запускаются последовательно.

## Запуск

1. Переместите `.app` в `~/Applications` или `/Applications`, откройте её.
2. Введите ключ для текущей версии, нажмите «Включить всё».
3. Если Antigravity установлен в защищённой папке, macOS запросит пароль
   только для записи патча. Отдельный запрос нужен для DNS-правил.
4. Полностью закройте и заново откройте Antigravity, чтобы он получил
   `AG_LS_PROXY` из среды `launchd`.

Запускайте анлокер от обычного пользователя. Весь GUI через `sudo` запускать
не следует: службы и настройки должны принадлежать вашей сессии.

Терминальный режим:

```sh
"$HOME/Applications/Antigravity Unlocker.app/Contents/MacOS/ag_unlocker" --tui
```

Уже открытый Terminal не получает переменные из `launchctl setenv` задним числом.
Для запуска CLI через локальный прокси из такого терминала:

```sh
AG_LS_PROXY="$(launchctl getenv AG_LS_PROXY)" agy
```

## Что устанавливается

- `~/Library/Application Support/AGUnlocker/ag_service`: копия программы
  для фоновых служб, рядом настройки, ключ и журнал.
- `~/Library/LaunchAgents/com.agunlocker.proxy.plist`: прокси и DNS-служба.
- `~/Library/LaunchAgents/com.agunlocker.watchdog.plist`: автопатч.
- `~/Library/LaunchAgents/com.agunlocker.environment.plist`: восстановление
  `AG_LS_PROXY` при входе в систему.
- `/etc/resolver/cloudcode-pa.googleapis.com` и
  `/etc/resolver/daily-cloudcode-pa.googleapis.com`: только эти два домена
  направляются на локальный DNS `127.0.0.1:53130`. Основной DNS не меняется.

Все переключатели используют общий механизм отката. При отказе в пароле
при снятии DNS служба остаётся запущенной: правила не должны указывать
на остановленный процесс. Чужие файлы `/etc/resolver` не перезаписываются.

## Проверка и ограничения

Порт необходимо проверить на настоящем Mac: GUI/Metal, выдачу прав,
ответ модели, VPN, перезапуск сессии, обновление Antigravity и откат.
Наличие кода и успешная компиляция сами по себе не подтверждают работу
на конкретной версии Antigravity.

Автопатч работает только там, где пользователь может изменять приложение и
его подпись. Защищённую установку после обновления нужно пропатчить кнопкой
с запросом пароля; для автоматического режима используйте установку
Antigravity в `~/Applications`, принадлежащую вашему пользователю.

Изменённые исполняемые файлы и `.app` получают локальную ad-hoc подпись.
Это не подпись Google или Developer ID и не нотарификация Apple.
Откат возвращает содержимое патчей, но исходную подпись производителя
возвращает переустановка официального Antigravity. Некоторые версии Electron
могут дополнительно проверять целостность ASAR — это нужно проверить на Mac.

Приватных серверов и встроенных выходов автора в публичных исходниках нет:
перенос ОС их не добавляет. Доступны публичные маршруты и свой прокси.
Запрет трафика со стороны VPN kill switch также может препятствовать обходу.

Используются стандартные механизмы Apple:
[службы launchd](https://support.apple.com/guide/terminal/apdc6c1077b-5d5d-4d35-9c19-60f2397b2369/mac),
[подпись кода](https://developer.apple.com/documentation/Xcode/using-the-latest-code-signature-format),
[IP_BOUND_IF](https://github.com/apple/darwin-xnu/blob/main/bsd/netinet/in.h) и
[IPV6_BOUND_IF](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6.h).
