# Proposal

## Why

Приложения способны за минуты заполнить swap и довести систему до деградации, но пользователь узнаёт об этом только когда интерфейс уже «зависает». Нужен фоновый монитор, который сам замечает рост занятости swap и сразу сообщает, какое приложение его заполняет, — без участия человека в настройке: поставил deb-пакет, и демон работает.

## What Changes

- Новый демон `swapnotif-rs` в виде systemd **system**-сервиса:
  - цикл мониторинга занятости swap по `/proc/meminfo` (опрос каждые 5 с, дефолт);
  - триггер на **пересечение** порога заполненности (дефолт 80%) с защитой от спама: повторная нотификация только после возврата ниже порога −5% и cooldown 5 мин;
  - скорость обмена (`pswpin`/`pswpout` из `/proc/vmstat`) включается в тело нотификации как деталь.
- Атрибуция виновника: дельта `VmSwap` per-pid (`/proc/<pid>/status`) за окно 60 с, группировка по cgroup до уровня «приложение»; процесс идентифицируется парой `(pid, starttime)` против переиспользования PID. Если рост виновника < 50 МБ — в уведомлении честно пишется «приложение не определено».
- Доставка уведомлений: демон (root) находит графические сессии через logind (system bus) и сокеты `/run/user/<uid>/bus`, подключается к каждой сессионной шине и вызывает `org.freedesktop.Notifications.Notify`. Данные из сессионной шины не доверяются и не разбираются.
- Жизненный цикл: юнит `Type=notify`, `Restart=on-failure`, скромный hardening (`ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`); `swap_total == 0` не фатален — дем ждёт включения swap.
- Упаковка deb: бинарник + юнит в `/usr/lib/systemd/system/`; `dh_installsystemd` включает и запускает сервис при установке. Конфиг `/etc/swapnotif/config.toml` опционален (дефолты в коде), пример — в `/usr/share/doc/swapnotif/examples/`.
- CI релиза (GitHub Actions): workflow `.github/workflows/release.yml` собирает deb (`dpkg-buildpackage`, тот же путь упаковки, что и локально) на пуш тега `v*` и по ручному запуску; deb — артефакт каждого запуска; публикация GitHub Release с .deb — автоматически с тега (или вручную с флагом publish) и только при совпадении тега с версией в `Cargo.toml`.
- Структура кода: тонкий `src/main.rs` поверх библиотечных модулей `monitor`, `attribute`, `notify`, `config` в `src/lib.rs`.

## Capabilities

### New Capabilities

- `swap-monitoring`: наблюдение занятости swap и решение «порог превышен» — цикл опроса, вычисление процента, edge-trigger с гистерезисом и cooldown, поведение при выключенном swap.
- `swap-usage-attribution`: определение приложения, внёсшего нагрузку на swap, — снапшоты `VmSwap` per-pid, дельты за окно, группировка по cgroup, выбор виновника с минимальным весом.
- `desktop-notifications`: доставка уведомления в сессионные шины активных графических сессий — discovery сессий через logind, подключение к user bus, вызов `Notify`, формат сообщения.
- `daemon-lifecycle`: работа как system-демон и поставка пакетом — юнит systemd (автозапуск, перезапуск, hardening), deb-упаковка с включением при установке, опциональный конфиг с дефолтами в коде; CI-сборка deb (GitHub Actions) и публикация GitHub Release с .deb по тегу `v*` с проверкой соответствия версии.

### Modified Capabilities

<!-- Нет: проект только что создан, существующих спецификаций не имеет
     (openspec list --specs пуст). -->

## Impact

- **Код**: `src/lib.rs` (новые модули `monitor`, `attribute`, `notify`, `config`), `src/main.rs` (запуск runtime); каркас bin+lib сохраняется.
- **Новые зависимости**: `zbus` (D-Bus), `serde` + `toml` (конфиг), `tracing`/`tracing-subscriber` (логи → journald), `tokio` (runtime), `zvariant` (через zbus); парсер `/proc` — собственный, без крейта `procfs`.
- **Сборка/упаковка**: новый `debian/` (control, rules с `dh_installsystemd`, установка юнита в `/usr/lib/systemd/system/`); `.github/workflows/release.yml` — CI-сборка deb и публикация релиза.
- **Система**: демон работает от root; читает общедоступные `/proc/*`; подключается к user bus сокетам; шлёт только `Notify` и не интерпретирует ответы.
- **Совместимость**: Linux с cgroup v2 unified и systemd; для desktop-уведомлений нужен активный менеджер уведомлений (plasmashell и совместимые).
