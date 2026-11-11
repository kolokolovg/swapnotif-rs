# Tasks

## 1. Подсказка `desktop-entry` в вызове Notify

- [x] 1.1 В `src/notify.rs` выделить источник hints уведомления (чистая функция/константа с ключом `desktop-entry` и значением `swapnotif`) и использовать его в `send_notify` вместо пустого словаря; проверить сборкой `cargo build`.
- [x] 1.2 Юнит-тест на hints: ровно один hint с ключом `desktop-entry`, значение совпадает с `APP_NAME` (сторож расхождения имени пакета и идентификатора desktop-файла, design D1/Risks); проверить `cargo test --locked`.

## 2. Desktop-файл и deb-пакет

- [x] 2.1 Создать `packaging/swapnotif.desktop` по design D2/D3 (`Type=Application`, `Name=swapnotif`, `Exec=/usr/bin/swapnotif`, `NoDisplay=true`, `Terminal=false`); проверить `desktop-file-validate packaging/swapnotif.desktop` (или ручной разбор INI, если валидатор не установлен).
- [x] 2.2 В `debian/rules` в `override_dh_auto_install` добавить установку `packaging/swapnotif.desktop` в `debian/swapnotif/usr/share/applications/swapnotif.desktop` (`install -Dm644`); проверить сборкой `dpkg-buildpackage -us -uc -b` и `dpkg -c` собранного deb: файл лежит по пути `/usr/share/applications/swapnotif.desktop`.

## 3. Документация

- [x] 3.1 Запись в `CHANGELOG.md` в секцию `[Unreleased]` → `### Fixed`: уведомления остаются в истории Plasma (hint `desktop-entry`, desktop-файл в пакете); проверить просмотром секции.

## 4. Приёмка на живой машине

- [x] 4.1 Установить собранный deb поверх текущего, отправить уведомление одноразовым режимом (`swapnotif notify-session 1000 <summary> <body>`) или дождаться события; проверить: баннер показан, уведомление осталось в истории колокольчика Plasma, `dpkg -L swapnotif | grep swapnotif.desktop` находит файл; старый тестовый файл `~/.local/share/applications/swapnotif.desktop` не требуется.
