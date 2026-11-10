//! Обнаружение графических сессий (logind с fallback на сокеты
//! `/run/user/<uid>/bus`), доставка уведомлений
//! `org.freedesktop.Notifications.Notify` и форматирование сообщения
//! (спека `desktop-notifications`, design D6).
//!
//! Доставка в сессию — self-exec дочерний процесс от uid сессии
//! (обновление design D6, см. [`deliver_to_session`]); модуль публичен,
//! потому что точка входа использует одноразовый режим
//! [`notify_once`] до подъёма рантайма демона (см. `main.rs`).
//!
//! Граница доверия (спека «Недоверие к данным сессионной шины»): ответы
//! сессионной шины пользователей не разбираются — после вызова `Notify`
//! учитывается только факт Ok/Err, полученные строки не используются в
//! логике и сообщениях; текст ошибки — только в лог (`tracing::warn`).

use std::{
    collections::HashMap,
    fs,
    os::unix::process::ExitStatusExt as _,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};

use tokio::process::Command;

use crate::attribute::Attribution;
use crate::config::DEFAULT_WINDOW_SECS;
use crate::daemon::ThresholdEvent;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

/// КиБ в одном МиБ: единственная точка конверсии единиц модуля
/// (конвенция: КиБ↔МиБ в одном месте, не рассыпана по коду).
const KIB_PER_MIB: u64 = 1024;

/// Имя приложения в вызове `Notify`: показывает менеджер уведомлений.
const APP_NAME: &str = "swapnotif";
/// Иконка уведомления: стандартное имя freedesktop (design, открытый
/// вопрос про иконку закрыт в пользу `drive-multidisk`).
const APP_ICON: &str = "drive-multidisk";
/// Id заменяемого уведомления: 0 — новое уведомление (замена вне скоупа).
const NOTIFY_REPLACES_ID: u32 = 0;
/// Таймаут уведомления, мс: −1 — умолчание менеджера уведомлений.
const NOTIFY_EXPIRE_TIMEOUT_MS: i32 = -1;

/// Таймаут одного D-Bus-вызова: zbus 6 по умолчанию не ограничивает
/// ожидание ответа (`method_timeout == None`), и зависшая, но живая
/// шина блокировала бы единственный таск демона навсегда.
const DBUS_METHOD_TIMEOUT: Duration = Duration::from_secs(10);

/// Таймаут дочернего процесса доставки (self-exec): меньше внешнего
/// таймаута доставки демона (`daemon::DELIVERY_TIMEOUT` = 30 с), чтобы
/// ребёнок завершался раньше общего лимита, и больше внутреннего
/// [`DBUS_METHOD_TIMEOUT`] (10 с), чтобы ребёнку хватило времени на
/// подключение к шине и вызов `Notify`.
const CHILD_TIMEOUT: Duration = Duration::from_secs(15);

/// Максимум символов первой строки stderr ребёнка в тексте ошибки для
/// лога: строка — диагностика, длинное сообщение обрезается.
const CHILD_STDERR_MAX_CHARS: usize = 200;

/// Подкоманда одноразового режима точки входа:
/// `swapnotif notify-session <uid> <summary> <body>`.
const HELPER_SUBCOMMAND: &str = "notify-session";

/// Служба и объект `org.freedesktop.Notifications` на сессионной шине.
const NOTIFICATIONS_SERVICE: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";

/// Служба и объекты logind на system bus.
const LOGIN1_SERVICE: &str = "org.freedesktop.login1";
const LOGIN1_PATH: &str = "/org/freedesktop/login1";
const LOGIN1_MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const LOGIN1_SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
/// Стандартный интерфейс свойств D-Bus (чтение `Type` сессии).
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

/// КиБ → МиБ с округлением до целых (половина — вверх). Вся конверсия
/// модуля — только здесь.
fn kib_to_mib(kib: u64) -> u64 {
    (kib.saturating_add(KIB_PER_MIB / 2)) / KIB_PER_MIB
}

/// Графическая сессия пользователя: для доставки нужен только uid — адрес
/// сессионной шины выводится из него (`/run/user/<uid>/bus`, design D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GraphicalSession {
    pub(crate) uid: u32,
}

/// Запись logind о сессии для чистой фильтрации по типу: продакшн-данные
/// читает [`SessionSource`], логика фильтрации тестируется на моках.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogindSession {
    pub(crate) uid: u32,
    /// Тип сессии logind (`Type`): "x11", "wayland", "tty", "mir", …
    pub(crate) session_type: String,
}

/// Графический ли тип сессии logind: фиксированный список по спеке
/// («Обнаружение активных графических сессий», фильтр по `Type`).
fn is_graphical_type(session_type: &str) -> bool {
    matches!(session_type, "x11" | "wayland")
}

/// Фильтрует сессии logind, оставляя графические (`x11`/`wayland`);
/// `tty`, `console` и прочие типы уведомлений не получают. Дубликаты uid
/// (две графические сессии одного пользователя) схлопываются: шина
/// `/run/user/<uid>/bus` одна на пользователя (design D6), дубль
/// уведомления пользователю не нужен. Результат упорядочен по uid —
/// доставка и логи детерминированы.
pub(crate) fn filter_graphical(sessions: &[LogindSession]) -> Vec<GraphicalSession> {
    let mut graphical: Vec<GraphicalSession> = sessions
        .iter()
        .filter(|session| is_graphical_type(&session.session_type))
        .map(|session| GraphicalSession { uid: session.uid })
        .collect();
    graphical.sort_unstable_by_key(|session| session.uid);
    graphical.dedup_by_key(|session| session.uid);
    graphical
}

/// Fallback-обнаружение без logind (design D6): каждый существующий сокет
/// `<run_user_dir>/<uid>/bus` — кандидат-сессия, uid читается из имени
/// каталога. Нечисловые каталоги и каталоги без `bus` пропускаются;
/// отсутствующий корень — не ошибка (графических сессий просто нет).
pub(crate) fn fallback_bus_sockets(run_user_dir: &Path) -> Vec<GraphicalSession> {
    let Ok(entries) = fs::read_dir(run_user_dir) else {
        return Vec::new();
    };
    let mut sessions: Vec<GraphicalSession> = entries
        .flatten()
        .filter_map(|entry| {
            let uid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            entry
                .path()
                .join("bus")
                .exists()
                .then_some(GraphicalSession { uid })
        })
        .collect();
    sessions.sort_unstable_by_key(|session| session.uid);
    sessions
}

/// Источник графических сессий: граница системы для подмены в тестах.
/// Опрос происходит в момент доставки события (design D6), кэшировать
/// сессии между событиями нельзя — сессия может появиться позже события.
///
/// Нативный `async fn` в трейте (Rust ≥ 75): трейт не object-safe,
/// потребляется генериком (`S: SessionSource`), не `dyn`.
pub(crate) trait SessionSource {
    /// Графические сессии на момент вызова.
    async fn graphical_sessions(&self) -> Vec<GraphicalSession>;
}

/// Продакшн-источник сессий (design D6): logind на system bus; если
/// logind недоступен — fallback-перебор сокетов `/run/user/<uid>/bus`.
pub(crate) struct LogindSessionSource {
    /// Корень пользовательских runtime-каталогов (параметр — для
    /// тестирования fallback-логики; продакшн — `/run/user`).
    run_user_dir: PathBuf,
}

impl LogindSessionSource {
    /// Источник с системным путём по умолчанию (`/run/user`).
    pub(crate) fn new() -> Self {
        Self {
            run_user_dir: PathBuf::from("/run/user"),
        }
    }
}

impl Default for LogindSessionSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionSource for LogindSessionSource {
    async fn graphical_sessions(&self) -> Vec<GraphicalSession> {
        match logind_graphical_sessions().await {
            Ok(sessions) => sessions,
            Err(error) => {
                // Недоступность logind — не ошибка доставки: сессии ищем
                // fallback-перебором сокетов (design D6).
                tracing::warn!(%error, "logind недоступен, fallback на /run/user");
                fallback_bus_sockets(&self.run_user_dir)
            }
        }
    }
}

/// Запись `ListSessions` (`a(susso)`): id, uid, пользователь, seat, путь
/// объекта сессии. Сигнатура стабильна (проверена по logind systemd).
type LogindSessionRow = (String, u32, String, String, OwnedObjectPath);

/// Графические сессии по logind: `ListSessions` → тип каждой сессии из
/// её объекта (`org.freedesktop.login1.Session.Type`) → [`filter_graphical`].
/// Ошибка соединения с шиной или `ListSessions` — наверх (вызывающий
/// включит fallback); нечитаемый тип одной сессии — пропуск этой сессии,
/// остальные обрабатываются.
async fn logind_graphical_sessions() -> zbus::Result<Vec<GraphicalSession>> {
    // Собственное соединение к system bus (вместо разделяемого
    // `Connection::system`) — единственный способ задать method_timeout;
    // соединение живёт до конца функции (design D6: без постоянных шин).
    let system = zbus::connection::Builder::system()
        .method_timeout(DBUS_METHOD_TIMEOUT)
        .build()
        .await?;
    let reply = system
        .call_method(
            Some(LOGIN1_SERVICE),
            LOGIN1_PATH,
            Some(LOGIN1_MANAGER_INTERFACE),
            "ListSessions",
            &(),
        )
        .await?;
    let rows: Vec<LogindSessionRow> = reply.body().deserialize()?;
    let mut sessions = Vec::with_capacity(rows.len());
    for (_id, uid, _user, _seat, path) in rows {
        match query_session_type(&system, &path).await {
            Ok(session_type) => sessions.push(LogindSession { uid, session_type }),
            Err(error) => {
                // Это system bus logind, не пользовательская шина: свойство
                // нужно только фильтру; сбой одного объекта не валит поиск.
                tracing::debug!(uid, %error, "тип сессии logind не прочитан, пропускаем");
            }
        }
    }
    Ok(filter_graphical(&sessions))
}

/// Тип сессии logind (`x11`/`wayland`/`tty`/…) через `Properties.Get` по
/// пути объекта сессии.
async fn query_session_type(
    system: &zbus::Connection,
    session_path: &OwnedObjectPath,
) -> zbus::Result<String> {
    let reply = system
        .call_method(
            Some(LOGIN1_SERVICE),
            session_path.as_str(),
            Some(PROPERTIES_INTERFACE),
            "Get",
            &(LOGIN1_SESSION_INTERFACE, "Type"),
        )
        .await?;
    let value: OwnedVariant = reply.body().deserialize()?;
    // TryFrom<OwnedVariant> для String отдаёт ошибку шины — конвертация
    // не нужна.
    String::try_from(value)
}

/// Готовое сообщение уведомления: summary и body формирует
/// [`format_notification`], доставка текст не интерпретирует.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Notification {
    pub(crate) summary: String,
    pub(crate) body: String,
}

/// Результат доставки в одну сессию: `delivered` — единственное поле для
/// логики решений; `error` — диагностический текст для лога, в логику и
/// сообщения пользователя не попадает (граница доверия).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NotifyOutcome {
    pub(crate) uid: u32,
    pub(crate) delivered: bool,
    pub(crate) error: Option<String>,
}

/// Доставка уведомлений: граница системы, в тестах подменяется фейками.
///
/// Нативный `async fn` в трейте (Rust ≥ 75): трейт не object-safe,
/// потребляется генериком (`N: Notifier`), не `dyn`.
pub(crate) trait Notifier {
    /// Доставляет уведомление во все сессии источника, по одной за раз
    /// (D1: последовательная модель, без конкурентного I/O). Возврат —
    /// исход по каждой сессии; пустой список — сессий не было (спека
    /// «Нет графических сессий»: доставка не выполняется, ошибки нет).
    async fn notify_all(&self, notification: &Notification) -> Vec<NotifyOutcome>;
}

/// Доставка через `org.freedesktop.Notifications.Notify` на сессионные
/// шины пользователей (design D6): обнаружение сессий — в момент
/// доставки; подключение к шине выполняет дочерний self-exec процесс от
/// uid сессии (dbus 1.16+ same-uid policy, см. [`deliver_to_session`]),
/// после его завершения никаких ресурсов шины у демона не остаётся.
pub(crate) struct SessionBusNotifier<S> {
    sessions: S,
}

impl<S: SessionSource> SessionBusNotifier<S> {
    /// Оборачивает источник сессий в доставщик.
    pub(crate) fn new(sessions: S) -> Self {
        Self { sessions }
    }
}

impl<S: SessionSource> Notifier for SessionBusNotifier<S> {
    async fn notify_all(&self, notification: &Notification) -> Vec<NotifyOutcome> {
        let mut outcomes = Vec::new();
        for session in self.sessions.graphical_sessions().await {
            let outcome = deliver_to_session(&session, notification).await;
            if let Some(error) = &outcome.error {
                // Неудача одной сессии не прерывает остальные (спека
                // «Недоступная сессия не блокирует остальные»); текст
                // ошибки шины — только в лог, Debug-экранированным:
                // владелец шины контролирует текст (в т.ч. \n и ANSI).
                tracing::warn!(
                    uid = session.uid,
                    ?error,
                    "уведомление не доставлено в сессию"
                );
            } else {
                // Спека «результат доставки по каждой сессии»: успех
                // тоже логируется, не только неуспех.
                tracing::info!(uid = session.uid, "уведомление доставлено");
            }
            outcomes.push(outcome);
        }
        outcomes
    }
}

/// Адрес сессионной шины пользователя: `/run/user/<uid>/bus` (design D6).
fn user_bus_address(uid: u32) -> String {
    format!("unix:path=/run/user/{uid}/bus")
}

/// Доставка в одну сессию — self-exec дочернего процесса от uid сессии.
///
/// dbus-daemon 1.16+ принимает соединения к пользовательской шине
/// `/run/user/<uid>/bus` только от uid-владельца: root-процесс получает
/// разрыв соединения на SASL-шаге BEGIN (обновление design D6). Поэтому
/// шину открывает копия этого бинарника, запущенная от uid сессии
/// (`CommandExt::uid`) в одноразовом режиме `notify-session`: 0 —
/// доставлено, 1 — нет (текст ошибки — первая строка stderr). Дочерний
/// режим самодостаточен: адрес шины строит из uid, окружение демона
/// ребёнку не нужно.
async fn deliver_to_session(
    session: &GraphicalSession,
    notification: &Notification,
) -> NotifyOutcome {
    let uid = session.uid;
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            return NotifyOutcome {
                uid,
                delivered: false,
                error: Some(format!("путь собственного бинарника не получен: {error}")),
            };
        }
    };
    let spawned = Command::new(exe)
        .arg(HELPER_SUBCOMMAND)
        .arg(uid.to_string())
        .arg(&notification.summary)
        .arg(&notification.body)
        .uid(uid)
        // Отмена future (таймаут ниже или внешний DELIVERY_TIMEOUT
        // демона) дропает Child — kill_on_drop убивает зависшего ребёнка,
        // зомби переапает orphan reaper tokio; вручную kill невозможен:
        // wait_with_output забирает Child по значению.
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return NotifyOutcome {
                uid,
                delivered: false,
                error: Some(format!("дочерний процесс доставки не запущен: {error}")),
            };
        }
    };
    match tokio::time::timeout(CHILD_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) if output.status.success() => NotifyOutcome {
            uid,
            delivered: true,
            error: None,
        },
        Ok(Ok(output)) => NotifyOutcome {
            uid,
            delivered: false,
            error: Some(child_error_text(&output.stderr, &output.status)),
        },
        Ok(Err(error)) => NotifyOutcome {
            uid,
            delivered: false,
            error: Some(format!("дочерний процесс доставки не ожидается: {error}")),
        },
        Err(_elapsed) => NotifyOutcome {
            uid,
            delivered: false,
            error: Some("таймаут дочернего процесса".to_owned()),
        },
    }
}

/// Первая строка stderr ребёнка: piped-stderr даёт текст ошибки
/// одноразового режима без файлов и каналов. Байты декодируются с
/// потерей невалидных последовательностей — это диагностика для лога,
/// не данные.
fn first_stderr_line(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().next()?;
    Some(line.trim().to_owned())
}

/// Текст ошибки неудачного ребёнка для лога: первая строка его stderr
/// (обрезанная до [`CHILD_STDERR_MAX_CHARS`]), а при пустом stderr —
/// формат завершения процесса (`exit=N` / `signal=N`).
fn child_error_text(stderr: &[u8], status: &ExitStatus) -> String {
    match first_stderr_line(stderr).filter(|line| !line.is_empty()) {
        Some(line) => line.chars().take(CHILD_STDERR_MAX_CHARS).collect(),
        None => exit_status_text(status),
    }
}

/// Формат завершения ребёнка для текста ошибки: код возврата либо
/// завершивший его сигнал.
fn exit_status_text(status: &ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit={code}"),
        // code() == None — процесс завершён сигналом.
        None => format!("signal={}", status.signal().unwrap_or_default()),
    }
}

/// Подключение к шине пользователя и вызов `Notify`; ошибка любого шага —
/// наверх, вызывающий превращает её в исход сессии. Должна выполняться
/// процессом от uid сессии (dbus same-uid policy): в демоне — дочерним
/// self-exec-процессом ([`deliver_to_session`]), в одноразовом режиме —
/// напрямую ([`notify_once`]). Тело ответа (id уведомления) не читается:
/// Ok вызова == доставлено, мусорный ответ не влияет на работу
/// (граница доверия).
async fn send_notify(uid: u32, summary: &str, body: &str) -> zbus::Result<()> {
    let connection = zbus::connection::Builder::address(user_bus_address(uid).as_str())
        .method_timeout(DBUS_METHOD_TIMEOUT)
        .build()
        .await?;
    // Кнопки действий и hints уведомления — вне скоупа (design Non-Goals).
    let no_actions: Vec<&str> = Vec::new();
    let no_hints: HashMap<&str, Variant> = HashMap::new();
    connection
        .call_method(
            Some(NOTIFICATIONS_SERVICE),
            NOTIFICATIONS_PATH,
            Some(NOTIFICATIONS_INTERFACE),
            "Notify",
            &(
                APP_NAME,
                NOTIFY_REPLACES_ID,
                APP_ICON,
                summary,
                body,
                no_actions,
                no_hints,
                NOTIFY_EXPIRE_TIMEOUT_MS,
            ),
        )
        .await?;
    Ok(())
}

/// Аргументы одноразового режима `notify-session`: uid сессии и текст
/// уведомления. Разбираются [`parse_helper_args`] в точке входа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    pub uid: u32,
    pub summary: String,
    pub body: String,
}

/// Разбирает argv (без имени программы) одноразового режима
/// `notify-session <uid> <summary> <body>`: `Some` — валидные аргументы
/// хелпера, `None` — всё остальное (не та подкоманда, нечисловой uid,
/// неверное число аргументов); вызывающий различает исходы кодом
/// выхода (2 — плохие аргументы). Чистая функция для тестирования.
pub fn parse_helper_args(args: &[String]) -> Option<HelperArgs> {
    match args {
        [subcommand, uid, summary, body] if subcommand == HELPER_SUBCOMMAND => {
            uid.parse::<u32>().ok().map(|uid| HelperArgs {
                uid,
                summary: summary.clone(),
                body: body.clone(),
            })
        }
        _ => None,
    }
}

/// Одноразовый режим доставки (`notify-session`): подключение к шине
/// пользователя и один вызов `Notify`. Выполняется процессом, уже
/// работающим от uid сессии (setuid через `CommandExt::uid` в
/// [`deliver_to_session`]), — шина примет соединение. Поднимает
/// собственный current-thread рантайм: вызывается тонким диспетчером
/// точки входа до подъёма основного рантайма демона.
pub fn notify_once(uid: u32, summary: &str, body: &str) -> zbus::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("однопоточный рантайм одноразовой доставки собирается")
        .block_on(send_notify(uid, summary, body))
}

/// Экранирует разметку и вырезает управляющие символы из недоверенного
/// имени приложения (cgroup-имя или comm) перед подстановкой в body:
/// body `org.freedesktop.Notifications` поддерживает разметку (`<b>`,
/// `<a href>`, `<img>`), и владелец cgroup не должен получать
/// кликабельную ссылку в системном уведомлении от root (граница доверия).
fn sanitize_app_name(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    // Unicode Cc, включая \n и \r: управляющие символы в body не нужны.
    for c in name.chars().filter(|c| !c.is_control()) {
        match c {
            '&' => sanitized.push_str("&amp;"),
            '<' => sanitized.push_str("&lt;"),
            '>' => sanitized.push_str("&gt;"),
            _ => sanitized.push(c),
        }
    }
    sanitized
}

/// Форматирует сообщение уведомления из данных события и атрибуции
/// (спека «Вызов Notify и формат сообщения»). Чистая функция.
///
/// КиБ→МиБ (прирост, скорость) конвертируются здесь — в одном месте;
/// скорость обмена — суммарная (in + out). `window_secs` задаёт
/// формулировку окна атрибуции: дефолтные 60 с — «за последнюю минуту»,
/// иное значение проговаривается явно («за последние N с»).
pub(crate) fn format_notification(
    event: &ThresholdEvent,
    attribution: &Attribution,
    window_secs: u64,
) -> Notification {
    let usage_pct = event.usage_pct.round();
    let rate_mb_s = kib_to_mib(event.swap_in_kbps.saturating_add(event.swap_out_kbps));
    let context = format!("Swap занят на {usage_pct:.0}%, скорость обмена {rate_mb_s} МБ/с");
    let window = if window_secs == DEFAULT_WINDOW_SECS {
        "за последнюю минуту".to_owned()
    } else {
        format!("за последние {window_secs} с")
    };
    let body = match &attribution.app_name {
        Some(app_name) => format!(
            "{}: +{} МБ {window}. {context}",
            sanitize_app_name(app_name),
            kib_to_mib(attribution.delta_kb)
        ),
        None => format!("Приложение не определено. {context}"),
    };
    Notification {
        summary: format!("Высокая занятость swap: {usage_pct:.0}%"),
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// КиБ в тестах задаём через МиБ — как в сценариях спеки.
    fn kib(mib: u64) -> u64 {
        mib * 1024
    }

    /// Событие с занятостью и скоростью обмена (in + out, КиБ/с).
    fn event(usage_pct: f64, swap_in_kbps: u64, swap_out_kbps: u64) -> ThresholdEvent {
        ThresholdEvent {
            usage_pct,
            swap_in_kbps,
            swap_out_kbps,
        }
    }

    /// Атрибуция: имя виновника (`None` — не определено) и прирост, КиБ.
    fn attribution(app_name: Option<&str>, delta_kb: u64) -> Attribution {
        Attribution {
            app_name: app_name.map(str::to_owned),
            delta_kb,
        }
    }

    /// Запись logind для тестов фильтрации.
    fn logind_session(uid: u32, session_type: &str) -> LogindSession {
        LogindSession {
            uid,
            session_type: session_type.to_owned(),
        }
    }

    /// Спека «Обнаружение активных графических сессий», сценарий «Одна
    /// графическая сессия» / «Мультикользовательская доставка»: x11 и
    /// wayland — графические типы, каждая сессия даёт свой uid.
    #[test]
    fn notify_filter_graphical_passes_x11_and_wayland() {
        let sessions = [logind_session(1000, "x11"), logind_session(1001, "wayland")];
        assert_eq!(
            filter_graphical(&sessions),
            vec![
                GraphicalSession { uid: 1000 },
                GraphicalSession { uid: 1001 }
            ]
        );
    }

    /// Спека «Обнаружение активных графических сессий», фильтр по `Type`:
    /// tty и console — не графические, уведомлений не получают; пустой
    /// тип — тоже.
    #[test]
    fn notify_filter_graphical_skips_non_graphical_types() {
        let sessions = [
            logind_session(1000, "tty"),
            logind_session(1001, "console"),
            logind_session(1002, ""),
        ];
        assert!(filter_graphical(&sessions).is_empty());
    }

    /// Design D6: шина `/run/user/<uid>/bus` одна на пользователя — две
    /// графические сессии одного uid (например, wayland и унаследованный
    /// x11) схлопываются в одну доставку без дубля уведомления.
    #[test]
    fn notify_filter_graphical_deduplicates_same_uid() {
        let sessions = [logind_session(1000, "wayland"), logind_session(1000, "x11")];
        assert_eq!(
            filter_graphical(&sessions),
            vec![GraphicalSession { uid: 1000 }]
        );
    }

    /// Временный каталог под тесты fallback-обнаружения: уникален per
    /// тест и per процесс, удаляется в `Drop` (самозачистка).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("swapnotif-notify-{label}-{}", std::process::id()));
            fs::create_dir_all(&dir).expect("создать временный каталог");
            Self(dir)
        }

        /// Каталог `<name>` с файлом-заглушкой сокета `bus`.
        fn dir_with_bus(&self, name: &str) {
            let dir = self.0.join(name);
            fs::create_dir_all(&dir).expect("создать каталог uid");
            fs::write(dir.join("bus"), b"").expect("создать заглушку сокета bus");
        }

        /// Каталог `<name>` без файла `bus`.
        fn dir_without_bus(&self, name: &str) {
            fs::create_dir_all(self.0.join(name)).expect("создать каталог без bus");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    /// Спека «Обнаружение активных графических сессий» + design D6
    /// (fallback): существующие сокеты `/run/user/1000/bus` и
    /// `/run/user/1001/bus` дают сессии uid 1000 и 1001; нечисловой
    /// каталог (даже с сокетом) и числовой каталог без `bus` пропускаются;
    /// после теста временное дерево удаляется (самозачистка).
    #[test]
    fn notify_fallback_bus_sockets_finds_uid_sockets() {
        let tmp = TempDir::new("fallback");
        tmp.dir_with_bus("1000");
        tmp.dir_with_bus("1001");
        tmp.dir_with_bus("gleb");
        tmp.dir_without_bus("1002");

        assert_eq!(
            fallback_bus_sockets(&tmp.0),
            vec![
                GraphicalSession { uid: 1000 },
                GraphicalSession { uid: 1001 }
            ]
        );

        let root = tmp.0.clone();
        drop(tmp);
        assert!(!root.exists(), "временный каталог должен удалиться в Drop");
    }

    /// Спека «Нет графических сессий» на стороне fallback: отсутствующий
    /// корень `/run/user` — не ошибка, сессий нет.
    #[test]
    fn notify_fallback_bus_sockets_missing_root_is_empty() {
        let tmp = TempDir::new("fallback-missing");
        assert!(fallback_bus_sockets(&tmp.0.join("absent")).is_empty());
    }

    /// argv в слова теста: `["a", "b"]` из строк.
    fn words(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    /// Одноразовый режим: валидные аргументы
    /// `notify-session <uid> <summary> <body>` разбираются в [`HelperArgs`].
    #[test]
    fn notify_parse_helper_args_valid() {
        assert_eq!(
            parse_helper_args(&words(&["notify-session", "1000", "s", "b"])),
            Some(HelperArgs {
                uid: 1000,
                summary: "s".to_owned(),
                body: "b".to_owned(),
            })
        );
    }

    /// Одноразовый режим: нечисловой uid — плохие аргументы (`None`,
    /// вызывающий выходит с кодом 2).
    #[test]
    fn notify_parse_helper_args_rejects_non_numeric_uid() {
        assert_eq!(
            parse_helper_args(&words(&["notify-session", "gleb", "s", "b"])),
            None
        );
    }

    /// Одноразовый режим: неверное число аргументов (недобор и перебор),
    /// как и пустой argv (это режим демона, не хелпера), — `None`.
    #[test]
    fn notify_parse_helper_args_rejects_wrong_arg_count() {
        assert_eq!(parse_helper_args(&[]), None);
        assert_eq!(
            parse_helper_args(&words(&["notify-session", "1000", "s"])),
            None
        );
        assert_eq!(
            parse_helper_args(&words(&["notify-session", "1000", "s", "b", "extra"])),
            None
        );
    }

    /// Одноразовый режим: чужая подкоманда — `None`, даже с четырьмя
    /// аргументами.
    #[test]
    fn notify_parse_helper_args_rejects_other_subcommand() {
        assert_eq!(
            parse_helper_args(&words(&["status", "1000", "s", "b"])),
            None
        );
    }

    /// Текст ошибки ребёнка: непустая первая строка stderr выигрывает
    /// (перевод строки и пробелы отбрасываются, дальше — только первая
    /// строка) и обрезается до [`CHILD_STDERR_MAX_CHARS`].
    #[test]
    fn notify_child_error_prefers_and_truncates_stderr_line() {
        let status = ExitStatus::from_raw(1 << 8); // завершён с кодом 1
        assert_eq!(
            child_error_text("шина недоступна\nsecond line\n".as_bytes(), &status),
            "шина недоступна"
        );
        let long = "x".repeat(CHILD_STDERR_MAX_CHARS + 50);
        let truncated = child_error_text(format!("{long}\n").as_bytes(), &status);
        assert_eq!(truncated.chars().count(), CHILD_STDERR_MAX_CHARS);
    }

    /// Текст ошибки ребёнка: пустая stderr-строка (пробелы/перевод) или
    /// её отсутствие — формат завершения процесса, а не пустой текст.
    #[test]
    fn notify_child_error_empty_stderr_falls_back_to_status() {
        let status = ExitStatus::from_raw(1 << 8); // завершён с кодом 1
        assert_eq!(child_error_text(b"   \n", &status), "exit=1");
        assert_eq!(child_error_text(b"", &status), "exit=1");
    }

    /// Формат завершения: код возврата — `exit=N`, сигнал — `signal=N`.
    #[test]
    fn notify_exit_status_text_exit_and_signal() {
        assert_eq!(exit_status_text(&ExitStatus::from_raw(0)), "exit=0");
        assert_eq!(exit_status_text(&ExitStatus::from_raw(9 << 8)), "exit=9");
        assert_eq!(exit_status_text(&ExitStatus::from_raw(15)), "signal=15");
    }

    /// Ручной фейк `Notifier` (без mockall): исходы по сессиям заданы
    /// заранее, D-Bus не затрагивается.
    struct FakeNotifier {
        outcomes: Vec<NotifyOutcome>,
    }

    impl Notifier for FakeNotifier {
        async fn notify_all(&self, _notification: &Notification) -> Vec<NotifyOutcome> {
            self.outcomes.clone()
        }
    }

    /// Спека «Недоступная сессия не блокирует остальные»: неудача uid
    /// 1000 не мешает uid 1001 — в результате обе сессии, исход каждой
    /// отражён отдельно.
    #[tokio::test]
    async fn notify_failed_session_does_not_block_the_rest() {
        let notifier = FakeNotifier {
            outcomes: vec![
                NotifyOutcome {
                    uid: 1000,
                    delivered: false,
                    error: Some("шина сессии недоступна".to_owned()),
                },
                NotifyOutcome {
                    uid: 1001,
                    delivered: true,
                    error: None,
                },
            ],
        };
        let outcomes = notifier
            .notify_all(&Notification {
                summary: "Высокая занятость swap: 92%".to_owned(),
                body: "тело".to_owned(),
            })
            .await;
        let [failed, delivered] = &outcomes[..] else {
            panic!("ожидались исходы обеих сессий, получено {outcomes:?}");
        };
        assert_eq!(failed.uid, 1000);
        assert!(!failed.delivered);
        assert!(failed.error.is_some());
        assert_eq!(delivered.uid, 1001);
        assert!(delivered.delivered);
        assert_eq!(delivered.error, None);
    }

    /// Мок-источник сессий: фиксированный список, D-Bus не затрагивается.
    struct FixedSessions(Vec<GraphicalSession>);

    impl SessionSource for FixedSessions {
        async fn graphical_sessions(&self) -> Vec<GraphicalSession> {
            self.0.clone()
        }
    }

    /// Спека «Нет графических сессий»: доставка не выполняется, ошибки
    /// нет — пустой список исходов. Реальный код `notify_all` с пустым
    /// мок-источником: шины не открываются.
    #[tokio::test]
    async fn notify_without_sessions_delivers_nothing() {
        let notifier = SessionBusNotifier::new(FixedSessions(Vec::new()));
        let outcomes = notifier
            .notify_all(&Notification {
                summary: "Высокая занятость swap: 92%".to_owned(),
                body: "тело".to_owned(),
            })
            .await;
        assert!(outcomes.is_empty());
    }

    /// Спека «Полное сообщение с виновником»: Firefox, прирост 850 МБ,
    /// занятость 92 %, скорость 12 МБ/с (in + out = 12288 КиБ/с) — тело
    /// содержит имя, «+850 МБ», «92%», «12 МБ/с»; summary — процент.
    /// Дефолтное окно атрибуции 60 с — «за последнюю минуту».
    #[test]
    fn notify_format_full_message_with_culprit() {
        let notification = format_notification(
            &event(92.0, 2288, 10000),
            &attribution(Some("Firefox"), kib(850)),
            DEFAULT_WINDOW_SECS,
        );
        assert!(notification.summary.contains("Высокая занятость swap"));
        assert!(notification.summary.contains("92%"));
        for expected in [
            "Firefox",
            "+850 МБ",
            "92%",
            "12 МБ/с",
            "за последнюю минуту",
        ] {
            assert!(
                notification.body.contains(expected),
                "тело {:?} должно содержать {expected:?}",
                notification.body
            );
        }
    }

    /// Спека «Сообщение без определённого виновника»: тело содержит
    /// «приложение не определено» и общий контекст — процент и скорость.
    #[test]
    fn notify_format_message_without_culprit() {
        let notification =
            format_notification(&event(92.0, 0, 8192), &attribution(None, kib(30)), 60);
        assert!(
            notification
                .body
                .to_lowercase()
                .contains("приложение не определено")
        );
        assert!(notification.body.contains("92%"));
        assert!(notification.body.contains("8 МБ/с"));
    }

    /// Нулевая скорость обмена («Отсутствие обмена»): «0 МБ/с», без
    /// паники и мусора в округлении.
    #[test]
    fn notify_format_zero_speed() {
        let notification = format_notification(&event(85.0, 0, 0), &attribution(None, 0), 60);
        assert!(notification.body.contains("0 МБ/с"));
    }

    /// Нестандартное окно атрибуции: формулировка проговаривается явно
    /// («за последние 30 с»), а не выдаёт себя за минуту.
    #[test]
    fn notify_format_custom_window_secs() {
        let notification = format_notification(
            &event(92.0, 0, 8192),
            &attribution(Some("Firefox"), kib(850)),
            30,
        );
        assert!(notification.body.contains("за последние 30 с"));
        assert!(!notification.body.contains("за последнюю минуту"));
    }

    /// Граница доверия: имя приложения (cgroup/comm) недоверено, body
    /// поддерживает разметку — экранирование не даёт вставить кликабельную
    /// ссылку в системное уведомление от root.
    #[test]
    fn notify_format_escapes_markup_in_app_name() {
        let notification = format_notification(
            &event(92.0, 0, 0),
            &attribution(Some(r#"<a href="https://evil">Firefox</a>"#), kib(100)),
            DEFAULT_WINDOW_SECS,
        );
        assert!(
            notification.body.contains("&lt;a href="),
            "имя должно попасть в body экранированным: {:?}",
            notification.body
        );
        assert!(
            !notification.body.contains("<a href"),
            "сырая разметка не должна попадать в body: {:?}",
            notification.body
        );
    }
}
