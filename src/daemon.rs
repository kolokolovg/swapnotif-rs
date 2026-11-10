//! Главный цикл демона: state machine Normal/Exceeded (edge-trigger с
//! гистерезисом и cooldown), тестируемое ядро цикла, async-обёртка и
//! ручной sd_notify (design D1/D5/D7).
//!
//! Слои модуля: [`ThresholdMachine`] — чистая логика переходов порога;
//! [`LoopEngine`] — синхронное ядро цикла (скорость обмена → машина →
//! атрибуция → решение о доставке) без I/O; [`run_loop`] — async-обёртка
//! с `interval`-циклом и мгновенным выходом по shutdown (design D1);
//! [`run`] — композиция продакшн-реализаций для `main`; sd_notify —
//! ручная отправка `READY=1` (~30 строк, design D7). Ядро тестируется
//! синхронно: обёртка выполняет только доставку и возвращает результат
//! в движок через [`LoopEngine::on_delivered`].

use std::ffi::OsStr;
use std::fs::File;
use std::future::Future;
use std::io::{self, Read};
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::pin::pin;
use std::time::{Duration, Instant};

use anyhow::Context as _;

use crate::attribute::{Attribution, Attributor};
use crate::config::Config;
use crate::monitor::{
    ProcEntry, SwapRate, VmStat, parse_meminfo, parse_vmstat, scan_swap_processes, swap_rate_over,
    swap_usage_pct,
};
use crate::notify::{
    LogindSessionSource, Notification, Notifier, SessionBusNotifier, format_notification,
};

/// Показания одного цикла опроса: занятость swap (%, 0–100) и скорость
/// обмена на этом цикле. `usage_pct == None` — swap выключен
/// (`SwapTotal == 0`), это не ошибка (спека `swap-monitoring`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Sample {
    pub usage_pct: Option<f64>,
    pub swap_rate: SwapRate,
}

/// Данные события «порог превышен» на момент пересечения (спека
/// `swap-monitoring`): занятость и скорость обмена. Атрибуция виновника
/// прикрепляется слоем доставки поверх этих данных.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ThresholdEvent {
    pub usage_pct: f64,
    pub swap_in_kbps: u64,
    pub swap_out_kbps: u64,
}

/// Решение машины состояний по одному циклу опроса.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum TickAction {
    /// Занятость в пределах текущего состояния — действий нет.
    Nothing,
    /// Пересечение порога снизу (edge): ровно одно событие на
    /// пересечение, независимо от cooldown.
    Raised { event: ThresholdEvent },
    /// Сброс состояния «порог превышен» по гистерезису: недоставленное
    /// уведомление отменяется (design D5).
    BackToNormal,
}

/// Состояние порога. Только эти два варианта выразимы — некорректная
/// комбинация флагов («выше порога, но сброшено») неотображаема.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Занятость ниже порога или swap выключен.
    Normal,
    /// Занятость превысила порог; сброс — только гистерезисом.
    Exceeded,
}

/// Машина состояний порога (design D5): edge-триггер с гистерезисом и
/// cooldown. Переходы зависят только от сэмпла; cooldown ограничивает
/// отправку уведомлений, но не генерацию событий.
pub(crate) struct ThresholdMachine {
    /// Порог превышения, %: занятость ровно на пороге — уже превышение.
    threshold_pct: f64,
    /// Уровень сброса `threshold − hysteresis`, %: сброс строго ниже.
    reset_below_pct: f64,
    /// Минимальный интервал между отправками уведомлений.
    cooldown: Duration,
    /// Текущее состояние порога.
    state: State,
    /// Момент последней успешной отправки; `None` — отправок ещё не было,
    /// отправка разрешена. Переживает переходы Normal↔Exceeded: cooldown
    /// относится к доставке, а не к состоянию порога.
    last_notified: Option<Instant>,
}

impl ThresholdMachine {
    /// Машина начинается в `Normal`: превышение фиксируется только
    /// переходом, а не стартовым уровнем.
    pub(crate) fn new(threshold_pct: u8, hysteresis_pct: u8, cooldown: Duration) -> Self {
        Self {
            threshold_pct: f64::from(threshold_pct),
            // Вычитаем в f64: u8-разность переполнилась бы при гистерезисе
            // больше порога (конфиг такого не допускает, но паника здесь
            // неуместна).
            reset_below_pct: f64::from(threshold_pct) - f64::from(hysteresis_pct),
            cooldown,
            state: State::Normal,
            last_notified: None,
        }
    }

    /// Один цикл опроса (спека `swap-monitoring`, design D5):
    ///
    /// - `usage_pct == None` (swap выключен) — `Normal` без событий;
    /// - `Normal` и `usage >= threshold` — [`TickAction::Raised`] ровно в
    ///   момент пересечения;
    /// - `Exceeded` и `usage < threshold − hysteresis` (строго) —
    ///   [`TickAction::BackToNormal`];
    /// - всё остальное, включая колебания в зоне
    ///   `[threshold − hysteresis, threshold)`, — [`TickAction::Nothing`].
    ///
    /// `now` на переходы не влияет: время нужно только cooldown-гейту
    /// ([`notify_allowed`](Self::notify_allowed) /
    /// [`record_notified`](Self::record_notified)); параметр оставлен для
    /// единообразия вызова из главного цикла.
    pub(crate) fn on_tick(&mut self, sample: Sample, _now: Instant) -> TickAction {
        // Swap выключен — не «0 %», а отсутствие наблюдения: превышения
        // нет, состояние тихо возвращается в Normal без события; после
        // включения swap мониторинг возобновляется сам, без блокировки.
        let Some(usage_pct) = sample.usage_pct else {
            self.state = State::Normal;
            return TickAction::Nothing;
        };
        match self.state {
            State::Normal if usage_pct >= self.threshold_pct => {
                self.state = State::Exceeded;
                TickAction::Raised {
                    event: ThresholdEvent {
                        usage_pct,
                        swap_in_kbps: sample.swap_rate.in_kbps,
                        swap_out_kbps: sample.swap_rate.out_kbps,
                    },
                }
            }
            State::Exceeded if usage_pct < self.reset_below_pct => {
                self.state = State::Normal;
                TickAction::BackToNormal
            }
            _ => TickAction::Nothing,
        }
    }

    /// Событие актуально, пока машина в `Exceeded`: недоставленное
    /// уведомление ретраится каждый цикл, пока метод возвращает true.
    pub(crate) fn is_exceeded(&self) -> bool {
        self.state == State::Exceeded
    }

    /// Cooldown-гейт отправки: false, пока с последней успешной отправки
    /// прошло меньше cooldown; до первой отправки — всегда true. Гейтит
    /// только отправку: генерация `Raised` от cooldown не зависит.
    pub(crate) fn notify_allowed(&self, now: Instant) -> bool {
        match self.last_notified {
            None => true,
            Some(last) => now.duration_since(last) >= self.cooldown,
        }
    }

    /// Фиксирует успешную отправку уведомления и запускает cooldown.
    pub(crate) fn record_notified(&mut self, now: Instant) {
        self.last_notified = Some(now);
    }
}

/// Показания одного цикла опроса: занятость swap (`None` — swap
/// выключен), счётчики `/proc/vmstat` для скорости обмена и снапшот
/// процессов со swap-следом для окна атрибуции. Собирается
/// [`SampleSource`]-реализацией.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TickData {
    pub usage_pct: Option<f64>,
    pub vmstat: VmStat,
    pub entries: Vec<ProcEntry>,
}

/// Источник показаний цикла: граница системы для подмены в тестах.
/// Синхронный по конвенции «Async-рантайм»: `/proc` локален и крошечен,
/// `spawn_blocking` не вводится без профилирования.
pub(crate) trait SampleSource {
    /// Показания текущего тика; `None` — тик пропускается (источник сам
    /// логирует причину через `tracing::warn`).
    fn read(&self) -> Option<TickData>;
}

/// Продакшн-файлы и корень `/proc` источника показаний.
const PROC_MEMINFO: &str = "/proc/meminfo";
const PROC_VMSTAT: &str = "/proc/vmstat";
const PROC_ROOT: &str = "/proc";

/// Таймаут доставки одного события целиком (сбор сессий + все шины):
/// заметно больше таймаута одной D-Bus-шины (10 с,
/// `notify::DBUS_METHOD_TIMEOUT`), но меньше `TimeoutStopSec` systemd,
/// чтобы остановка демона не ждала зависшую шину. Параметр обёртки —
/// для быстрого теста.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Ограничение чтения файлов `/proc`: содержимое не доверено, читаем не
/// более 64 КиБ — тот же лимит, что у `monitor::read_limited` (там
/// константа приватна).
const MAX_PROC_FILE_BYTES: u64 = 64 * 1024;

/// Продакшн-источник показаний: `/proc/meminfo`, `/proc/vmstat` и обход
/// `/proc/[pid]` через `monitor` (design D2). Ошибка чтения или разбора
/// meminfo/vmstat — тик пропускается с предупреждением, не паникой и не
/// остановкой демона; ошибки отдельных pid уже поглощаются сканером.
pub(crate) struct ProcSampleSource;

impl SampleSource for ProcSampleSource {
    fn read(&self) -> Option<TickData> {
        let (raw_meminfo, raw_vmstat) =
            match (read_proc_file(PROC_MEMINFO), read_proc_file(PROC_VMSTAT)) {
                (Ok(meminfo), Ok(vmstat)) => (meminfo, vmstat),
                (Err(error), _) | (_, Err(error)) => {
                    tracing::warn!(%error, "тик пропущен: файл /proc не читается");
                    return None;
                }
            };
        let meminfo = match parse_meminfo(&raw_meminfo) {
            Ok(meminfo) => meminfo,
            Err(error) => {
                tracing::warn!(%error, "тик пропущен: /proc/meminfo не разобран");
                return None;
            }
        };
        let vmstat = match parse_vmstat(&raw_vmstat) {
            Ok(vmstat) => vmstat,
            Err(error) => {
                tracing::warn!(%error, "тик пропущен: /proc/vmstat не разобран");
                return None;
            }
        };
        Some(TickData {
            usage_pct: swap_usage_pct(&meminfo),
            vmstat,
            entries: scan_swap_processes(Path::new(PROC_ROOT)),
        })
    }
}

/// Читает файл `/proc` не более [`MAX_PROC_FILE_BYTES`] байт.
fn read_proc_file(path: &str) -> io::Result<String> {
    let mut buf = String::new();
    File::open(path)?
        .take(MAX_PROC_FILE_BYTES)
        .read_to_string(&mut buf)?;
    Ok(buf)
}

/// Недоставленное событие: данные события фиксируются на момент Raised;
/// доставка может случиться позже (cooldown/ретраи) — процент и скорость
/// соответствуют моменту пересечения порога, атрибуция привязана к
/// событию (осознанное решение, см. ревью). Живёт, пока машина в
/// `Exceeded` (ретраи каждый цикл), отменяется возвратом в Normal
/// (спека `desktop-notifications` «Повтор доставки недоставленного
/// события»).
struct PendingNotification {
    event: ThresholdEvent,
    attribution: Attribution,
    /// Предупреждение «графические сессии не обнаружены» уже выдано для
    /// этого события — не спамить каждый неудачный цикл; новый Raised
    /// начинает новое событие и сбрасывает флаг.
    no_sessions_warned: bool,
}

/// Решение ядра цикла по одному тику. Async-обёртка выполняет только
/// `Deliver` и возвращает результат в [`LoopEngine::on_delivered`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoopAction {
    /// Доставлять нечего: событий нет либо cooldown держит отправку.
    Nothing,
    /// Событие актуально и cooldown пройден — доставить уведомление.
    Deliver { notification: Notification },
    /// Событие потеряло актуальность (возврат в Normal, swap исчез) —
    /// недоставленное уведомление отменено (design D5).
    Cancel,
}

/// Ядро главного цикла без I/O (тестируется синхронно, без рантайма):
/// связывает машину порога, окно атрибуции и жизнь недоставленного
/// события. Скорость обмена считается здесь же, по счётчикам vmstat
/// между тиками.
pub(crate) struct LoopEngine {
    machine: ThresholdMachine,
    attributor: Attributor,
    pending: Option<PendingNotification>,
    /// Счётчики vmstat прошлого тика; `None` до первого тика.
    prev_vmstat: Option<VmStat>,
    /// Момент прошлого успешного тика: скорость обмена считается по
    /// фактическому времени между тиками, а не по интервалу конфига
    /// (тики пропускаются — нечитаемый `/proc`, долгая доставка);
    /// `None` до первого тика.
    last_tick: Option<Instant>,
    /// Предупреждение «swap не активен» уже выдано (не спамить каждый
    /// тик, спека `swap-monitoring` «Устойчивость к выключенному swap»).
    no_swap_logged: bool,
    min_culprit_mib: u64,
    window_secs: u64,
}

impl LoopEngine {
    /// Ядро цикла из конфига: пороги и cooldown — в машину порога, окно
    /// — в атрибутор, остальное — параметры шага.
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            machine: ThresholdMachine::new(
                config.threshold_pct,
                config.hysteresis_pct,
                Duration::from_secs(config.cooldown_secs),
            ),
            attributor: Attributor::new(config.snapshot_depth()),
            pending: None,
            prev_vmstat: None,
            last_tick: None,
            no_swap_logged: false,
            min_culprit_mib: config.min_culprit_mb,
            window_secs: config.window_secs,
        }
    }

    /// Один тик цикла (синхронное ядро без I/O):
    ///
    /// - скорость обмена — дельта vmstat за фактически прошедшее между
    ///   успешными тиками время (первый тик без предыдущих счётчиков —
    ///   0);
    /// - снапшот атрибуции пополняется каждым тиком, независимо от
    ///   событий порога;
    /// - `Raised` фиксирует событие с атрибуцией на момент пересечения;
    /// - `BackToNormal` и тихий уход из `Exceeded` (swap исчез) отменяют
    ///   недоставленное событие — [`LoopAction::Cancel`];
    /// - пока событие актуально и cooldown пройден — формируется
    ///   [`LoopAction::Deliver`] с готовым сообщением.
    pub(crate) fn step(&mut self, data: TickData, now: Instant) -> LoopAction {
        let swap_rate = match (
            self.prev_vmstat.replace(data.vmstat),
            self.last_tick.replace(now),
        ) {
            (Some(prev), Some(last_tick)) => {
                swap_rate_over(&prev, &data.vmstat, now.duration_since(last_tick))
            }
            // Первый тик: предыдущих счётчиков нет — скорость 0.
            _ => SwapRate::default(),
        };
        // Окно атрибуции заполняется каждым тиком: к моменту пересечения
        // порога дельты уже посчитаны по полному окну.
        self.attributor.observe(&data.entries);
        self.track_swap_presence(data.usage_pct);

        let sample = Sample {
            usage_pct: data.usage_pct,
            swap_rate,
        };
        let mut cancelled = false;
        match self.machine.on_tick(sample, now) {
            TickAction::Raised { event } => {
                let attribution = self.attributor.attribute(self.min_culprit_mib);
                tracing::info!(
                    usage_pct = event.usage_pct,
                    app_name = attribution
                        .app_name
                        .as_deref()
                        .unwrap_or("приложение не определено"),
                    delta_kb = attribution.delta_kb,
                    swap_in_kbps = event.swap_in_kbps,
                    swap_out_kbps = event.swap_out_kbps,
                    "порог занятости swap превышен"
                );
                self.pending = Some(PendingNotification {
                    event,
                    attribution,
                    no_sessions_warned: false,
                });
            }
            // Возврат в Normal гасит недоставленное событие; уже
            // доставленное просто завершается само.
            TickAction::BackToNormal => cancelled = self.pending.take().is_some(),
            TickAction::Nothing => {}
        }
        // Swap исчез в Exceeded: on_tick тихо вернул Normal (без
        // BackToNormal) — событие тоже теряет актуальность.
        if !self.machine.is_exceeded() && self.pending.take().is_some() {
            cancelled = true;
        }
        if cancelled {
            tracing::info!("недоставленное уведомление отменено: занятость вернулась в норму");
            return LoopAction::Cancel;
        }
        match &self.pending {
            Some(pending) if self.machine.notify_allowed(now) => LoopAction::Deliver {
                notification: format_notification(
                    &pending.event,
                    &pending.attribution,
                    self.window_secs,
                ),
            },
            _ => LoopAction::Nothing,
        }
    }

    /// Предупреждение «swap не активен» — ровно один раз на переход в
    /// это состояние (не каждый тик), возобновление мониторинга — info.
    fn track_swap_presence(&mut self, usage_pct: Option<f64>) {
        match usage_pct {
            None if !self.no_swap_logged => {
                tracing::warn!("swap не активен (SwapTotal == 0), ожидаем включения");
                self.no_swap_logged = true;
            }
            Some(_) if self.no_swap_logged => {
                tracing::info!("swap активен, мониторинг возобновлён");
                self.no_swap_logged = false;
            }
            _ => {}
        }
    }

    /// Результат доставки от async-обёртки: хотя бы одна доставленная
    /// сессия фиксирует отправку (запускает cooldown) и снимает событие;
    /// ни одной (сессий нет или все неудачны) — событие остаётся для
    /// ретрая следующим тиком (спека «Сессия появилась позже события»).
    /// `attempted` — число сессий, по которым пытались: ноль при живом
    /// событии — предупреждение ровно один раз на событие (спека
    /// daemon-lifecycle «Журналирование работы»).
    pub(crate) fn on_delivered(&mut self, any_delivered: bool, attempted: usize, now: Instant) {
        if !any_delivered {
            if attempted == 0
                && let Some(pending) = &mut self.pending
                && !pending.no_sessions_warned
            {
                tracing::warn!("графические сессии не обнаружены, уведомление будет повторено");
                pending.no_sessions_warned = true;
            }
            return;
        }
        self.machine.record_notified(now);
        self.pending = None;
    }
}

/// Async-обёртка ядра (design D1: один последовательный таск): тик
/// `interval` (первый — сразу) → опрос источника → [`LoopEngine::step`];
/// на [`LoopAction::Deliver`] доставляет через `notifier` и возвращает
/// результат в движок. Вся доставка ограничена `delivery_timeout`
/// (продакшн — [`DELIVERY_TIMEOUT`]): зависшая шина не блокирует цикл
/// навсегда, событие ретраится следующим тиком. Сбор сессий и
/// подключение к шине происходят внутри `notify_all` в момент доставки
/// (design D6). Выход по `shutdown` мгновенный: всё состояние локально в
/// движке, ветки `select!` cancellation-safe.
pub(crate) async fn run_loop<S, N, F>(
    config: &Config,
    source: S,
    notifier: N,
    delivery_timeout: Duration,
    shutdown: F,
) where
    S: SampleSource,
    N: Notifier,
    F: Future<Output = ()>,
{
    let mut engine = LoopEngine::new(config);
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
    // Пропущенные по занятости доставки тики не догоняются пачкой:
    // скорость обмена считается на реальный интервал между тиками.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("получен сигнал остановки: демон завершает работу");
                return;
            }
            _ = interval.tick() => {
                let Some(data) = source.read() else {
                    continue; // причина уже залоггирована источником
                };
                if let LoopAction::Deliver { notification } = engine.step(data, Instant::now()) {
                    match tokio::time::timeout(
                        delivery_timeout,
                        notifier.notify_all(&notification),
                    )
                    .await
                    {
                        Ok(outcomes) => {
                            let any_delivered =
                                outcomes.iter().any(|outcome| outcome.delivered);
                            engine.on_delivered(any_delivered, outcomes.len(), Instant::now());
                        }
                        Err(_elapsed) => {
                            tracing::warn!(
                                "доставка превысила таймаут, повтор на следующем цикле"
                            );
                            engine.on_delivered(false, 0, Instant::now());
                        }
                    }
                }
            }
        }
    }
}

/// Точка входа демона для `main` (композиция продакшн-реализаций):
/// сигнализирует готовность systemd, собирает источник `/proc`,
/// logind-обнаружение сессий с D-Bus-доставкой и запускает цикл до
/// сигнала остановки. Ошибки — на границе `main` (`anyhow`).
pub async fn run<F>(config: Config, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()>,
{
    // Готовность — после успешной инициализации (спека daemon-lifecycle,
    // `Type=notify`): зависимости здесь уже собраны, цикл — единственная
    // долгоживущая часть. Ошибка отправки фатальна: без READY=1 systemd
    // завис бы в activating.
    sd_notify_ready().context("sd_notify READY=1 не отправлен")?;
    let notifier = SessionBusNotifier::new(LogindSessionSource::new());
    run_loop(
        &config,
        ProcSampleSource,
        notifier,
        DELIVERY_TIMEOUT,
        shutdown,
    )
    .await;
    Ok(())
}

/// sd_notify `READY=1` (design D7: ручная реализация ~30 строк, без
/// крейта): отправка в unix-датаграммный сокет из `$NOTIFY_SOCKET`.
/// Нет переменной — ручной запуск вне systemd, no-op `Ok(())`.
pub(crate) fn sd_notify_ready() -> io::Result<()> {
    let Some(socket_path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let addr = notify_socket_addr(&socket_path)?;
    let socket = UnixDatagram::unbound()?;
    // connect (а не send_to с путём) фиксирует получателя и работает
    // одинаково для файлового и абстрактного адреса сокета.
    socket.connect_addr(&addr)?;
    socket.send(b"READY=1")?;
    Ok(())
}

/// Адрес сокета notify: путь файловой системы либо абстрактный сокет
/// Linux — systemd кодирует его префиксом `@`, который в AF_UNIX
/// представляется нулевым первым байтом.
fn notify_socket_addr(path: &OsStr) -> io::Result<SocketAddr> {
    let bytes = path.as_encoded_bytes();
    if bytes.first() == Some(&b'@') {
        SocketAddr::from_abstract_name(&bytes[1..])
    } else {
        SocketAddr::from_pathname(Path::new(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Дефолты спеки swap-monitoring: порог 80 %, гистерезис 5 п.п.,
    /// cooldown 5 мин, период опроса 5 с.
    const THRESHOLD_PCT: u8 = 80;
    const HYSTERESIS_PCT: u8 = 5;
    const COOLDOWN: Duration = Duration::from_secs(5 * 60);
    const TICK: Duration = Duration::from_secs(5);

    /// Свежая машина на дефолтах спеки.
    fn machine_spec() -> ThresholdMachine {
        ThresholdMachine::new(THRESHOLD_PCT, HYSTERESIS_PCT, COOLDOWN)
    }

    /// Сэмпл с заданной занятостью (`None` — swap выключен) и нулевой
    /// скоростью обмена.
    fn sample(usage_pct: Option<f64>) -> Sample {
        Sample {
            usage_pct,
            swap_rate: SwapRate::default(),
        }
    }

    /// Пересекает порог сэмплом 85 % с заданной скоростью обмена и
    /// возвращает событие Raised.
    fn raise_with_rate(
        machine: &mut ThresholdMachine,
        now: Instant,
        swap_rate: SwapRate,
    ) -> ThresholdEvent {
        let action = machine.on_tick(
            Sample {
                usage_pct: Some(85.0),
                swap_rate,
            },
            now,
        );
        let TickAction::Raised { event } = action else {
            panic!("ожидалось Raised, получено {action:?}");
        };
        event
    }

    /// Сценарий «Переход через порог»: рост 75 % → 85 % при пороге 80 % —
    /// ровно одно событие с данными на момент пересечения.
    #[test]
    fn daemon_crossing_threshold_raises_once() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        assert!(matches!(
            machine.on_tick(sample(Some(75.0)), now),
            TickAction::Nothing
        ));
        now += TICK;

        let event = raise_with_rate(
            &mut machine,
            now,
            SwapRate {
                in_kbps: 300,
                out_kbps: 12000,
            },
        );
        assert_eq!(
            event,
            ThresholdEvent {
                usage_pct: 85.0,
                swap_in_kbps: 300,
                swap_out_kbps: 12000,
            }
        );
        assert!(machine.is_exceeded());
    }

    /// Сценарий «Устойчивое превышение без повторов»: занятость выше
    /// порога много циклов — одно Raised, дальше Nothing.
    #[test]
    fn daemon_sustained_high_no_repeat() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
        for _ in 0..100 {
            now += TICK;
            assert!(matches!(
                machine.on_tick(sample(Some(90.0)), now),
                TickAction::Nothing
            ));
        }
        assert!(machine.is_exceeded());
    }

    /// Сценарий «Колебание в узкой зоне не сбрасывает состояние»:
    /// 85 % → 78 % (порог 80, гистерезис 5) — Exceeded сохраняется;
    /// 78 % → 85 % — повторного события нет (сброса не было).
    #[test]
    fn daemon_band_oscillation_keeps_exceeded() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        machine.on_tick(sample(Some(85.0)), now);
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(78.0)), now),
            TickAction::Nothing
        ));
        assert!(machine.is_exceeded());
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Nothing
        ));
        assert!(machine.is_exceeded());
    }

    /// Сценарий «Возврат ниже гистерезиса разрешает новое событие»:
    /// 85 % → 70 % — BackToNormal (однократно), новое пересечение 80 % —
    /// новое Raised.
    #[test]
    fn daemon_reset_below_hysteresis_allows_new_event() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(70.0)), now),
            TickAction::BackToNormal
        ));
        assert!(!machine.is_exceeded());
        // Сброс однократный: в Normal низкая занятость — просто Nothing.
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(70.0)), now),
            TickAction::Nothing
        ));
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
    }

    /// Ровно на пороге (80 %) — уже превышение: переход из Normal
    /// порождает событие.
    #[test]
    fn daemon_exact_threshold_raises() {
        let mut machine = machine_spec();
        let now = Instant::now();

        assert!(matches!(
            machine.on_tick(sample(Some(f64::from(THRESHOLD_PCT))), now),
            TickAction::Raised { .. }
        ));
    }

    /// Ровно на уровне сброса (75 % = 80 − 5) сброса нет: сброс строго
    /// ниже `threshold − hysteresis`.
    #[test]
    fn daemon_exact_reset_level_keeps_exceeded() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        machine.on_tick(sample(Some(85.0)), now);
        now += TICK;
        let reset_level = f64::from(THRESHOLD_PCT - HYSTERESIS_PCT);
        assert!(matches!(
            machine.on_tick(sample(Some(reset_level)), now),
            TickAction::Nothing
        ));
        assert!(machine.is_exceeded());
    }

    /// Сценарий «Быстрое повторное срабатывание подавляется»: отправка
    /// была, сброс и новое пересечение через 1 мин при cooldown 5 мин —
    /// Raised есть (cooldown гейтит отправку, не событие) и
    /// notify_allowed false; через 5 мин с отправки — true. До первой
    /// отправки отправка разрешена.
    #[test]
    fn daemon_cooldown_gates_notify_not_event() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        assert!(machine.notify_allowed(now));
        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
        machine.record_notified(now);

        now += Duration::from_secs(60);
        assert!(matches!(
            machine.on_tick(sample(Some(70.0)), now),
            TickAction::BackToNormal
        ));
        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
        assert!(!machine.notify_allowed(now));

        now += COOLDOWN - Duration::from_secs(60);
        assert!(machine.notify_allowed(now));
    }

    /// Сценарии «Скорость обмена как деталь события» и «Отсутствие
    /// обмена»: скорости сэмпла (расчёт — в monitor, здесь — перенос в
    /// событие) попадают в данные события как есть; без обмена — нули.
    #[test]
    fn daemon_event_carries_swap_rate() {
        let mut machine = machine_spec();
        let now = Instant::now();

        let event = raise_with_rate(
            &mut machine,
            now,
            SwapRate {
                in_kbps: 0,
                out_kbps: 12000,
            },
        );
        assert_eq!((event.swap_in_kbps, event.swap_out_kbps), (0, 12000));

        let mut machine = machine_spec();
        let event = raise_with_rate(&mut machine, now, SwapRate::default());
        assert_eq!((event.swap_in_kbps, event.swap_out_kbps), (0, 0));
    }

    /// Сценарий «Старт без swap»: `SwapTotal == 0` — не ошибка, машина
    /// работает и не порождает событий.
    #[test]
    fn daemon_start_without_swap_no_events() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        for _ in 0..10 {
            assert!(matches!(
                machine.on_tick(sample(None), now),
                TickAction::Nothing
            ));
            assert!(!machine.is_exceeded());
            now += TICK;
        }
    }

    /// Сценарий «Swap включили после старта»: None → 85 % — мониторинг
    /// возобновляется сам, пересечение порождает Raised.
    #[test]
    fn daemon_swap_enabled_after_start_raises() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        assert!(matches!(
            machine.on_tick(sample(None), now),
            TickAction::Nothing
        ));
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
        assert!(machine.is_exceeded());
    }

    /// Swap выключили в состоянии Exceeded: без наблюдаемой занятости
    /// машина тихо возвращается в Normal (без BackToNormal) и после
    /// включения swap снова фиксирует пересечение — блокировки нет.
    #[test]
    fn daemon_swap_disabled_while_exceeded_resumes_freely() {
        let mut machine = machine_spec();
        let mut now = Instant::now();

        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(None), now),
            TickAction::Nothing
        ));
        assert!(!machine.is_exceeded());
        now += TICK;
        assert!(matches!(
            machine.on_tick(sample(Some(85.0)), now),
            TickAction::Raised { .. }
        ));
    }

    // --- Главный цикл: синхронное ядро LoopEngine ---

    use std::cell::Cell;
    use std::rc::Rc;

    use crate::notify::NotifyOutcome;

    /// Ядро цикла на дефолтном конфиге спеки.
    fn loop_engine() -> LoopEngine {
        LoopEngine::new(&Config::default())
    }

    /// Счётчики vmstat, КиБ.
    fn vmstat(pswpin_kb: u64, pswpout_kb: u64) -> VmStat {
        VmStat {
            pswpin_kb,
            pswpout_kb,
        }
    }

    /// Тик с заданной занятостью, нулевыми счётчиками и без процессов.
    fn tick(usage_pct: Option<f64>) -> TickData {
        TickData {
            usage_pct,
            vmstat: vmstat(0, 0),
            entries: Vec::new(),
        }
    }

    /// Запись процесса со swap-следом для окна атрибуции (cgroup-путь
    /// даёт имя приложения «app-demo», см. attribute-тесты).
    fn proc(pid: u32, vm_swap_kb: u64) -> ProcEntry {
        ProcEntry {
            pid,
            starttime: 1,
            vm_swap_kb,
            comm: "demo-proc".to_owned(),
            cgroup: Some("/user.slice/app.slice/app-demo.service".to_owned()),
        }
    }

    /// Событие → доставка успешна → событие снято; устойчивое превышение
    /// повторной доставки не порождает. Атрибуция считается по окну
    /// (прирост 200 МБ между тиками) и попадает в текст уведомления.
    #[test]
    fn daemon_loop_delivered_event_not_repeated() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        // Тик ниже порога заполняет базу окна атрибуции (100 МБ).
        let mut base = tick(Some(50.0));
        base.entries = vec![proc(1, 100 * 1024)];
        assert_eq!(engine.step(base, now), LoopAction::Nothing);

        now += TICK;
        let mut raised = tick(Some(85.0));
        raised.entries = vec![proc(1, 300 * 1024)]; // +200 МБ за окно
        let LoopAction::Deliver { notification } = engine.step(raised, now) else {
            panic!("ожидалась доставка после пересечения порога");
        };
        assert!(
            notification.body.contains("app-demo"),
            "тело {:?} должно содержать имя виновника",
            notification.body
        );
        assert!(
            notification.body.contains("+200 МБ"),
            "тело {:?} должно содержать прирост",
            notification.body
        );
        engine.on_delivered(true, 1, now);

        // Событие доставлено: устойчивое превышение ничего не доставляет.
        now += TICK;
        assert_eq!(engine.step(tick(Some(90.0)), now), LoopAction::Nothing);
    }

    /// Спека «Сессия появилась позже события»: доставка не удалась (нет
    /// сессий) — событие живёт, следующий тик ретраит доставку; успех
    /// снимает событие, дальнейших доставок нет.
    #[test]
    fn daemon_loop_failed_delivery_retried_next_tick() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        engine.on_delivered(false, 0, now + TICK); // сессий не найдено

        now += TICK;
        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        engine.on_delivered(true, 1, now);

        now += TICK;
        assert_eq!(engine.step(tick(Some(85.0)), now), LoopAction::Nothing);
    }

    /// Спека daemon-lifecycle «Журналирование работы»: попытка доставки
    /// с нулём найденных сессий — предупреждение ровно один раз на время
    /// жизни текущего события (флаг), новый Raised сбрасывает флаг;
    /// появившаяся сессия доставляется.
    #[test]
    fn daemon_loop_no_sessions_warned_once_per_pending() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        engine.on_delivered(false, 0, now); // сессий не найдено
        let warned = |engine: &LoopEngine| {
            engine
                .pending
                .as_ref()
                .expect("событие живо для ретрая")
                .no_sessions_warned
        };
        assert!(
            warned(&engine),
            "первая попытка без сессий — предупреждение"
        );

        now += TICK;
        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        engine.on_delivered(false, 0, now); // повтор — без нового предупреждения
        assert!(
            warned(&engine),
            "флаг предупреждения не сбрасывается ретраем"
        );

        now += TICK;
        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        engine.on_delivered(true, 1, now); // сессия появилась — доставлено
        assert!(engine.pending.is_none(), "событие снято успешной доставкой");

        // Новый Raised (сброс и повторное пересечение после cooldown)
        // начинает новое событие с чистым флагом предупреждения.
        now += COOLDOWN;
        assert_eq!(engine.step(tick(Some(70.0)), now), LoopAction::Nothing);
        now += TICK;
        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        assert!(!warned(&engine), "новое событие — флаг сброшен");
    }

    /// Спека «Порог сбросился до доставки»: возврат ниже гистерезиса
    /// отменяет недоставленное событие (Cancel); доставка не вызывается,
    /// повторных решений тоже нет.
    #[test]
    fn daemon_loop_back_to_normal_cancels_pending() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        now += TICK;
        assert_eq!(engine.step(tick(Some(70.0)), now), LoopAction::Cancel);
        now += TICK;
        assert_eq!(engine.step(tick(Some(70.0)), now), LoopAction::Nothing);
    }

    /// Спека «Быстрое повторное срабатывание подавляется» на уровне
    /// цикла: после доставки сброс и новое пересечение внутри cooldown
    /// не формируют доставку; по истечении cooldown доставляется.
    #[test]
    fn daemon_loop_cooldown_defers_new_delivery() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        engine.on_delivered(true, 1, now); // cooldown отсчитывается отсюда

        now += TICK;
        assert_eq!(engine.step(tick(Some(70.0)), now), LoopAction::Nothing); // сброс
        now += Duration::from_secs(60);
        assert_eq!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Nothing,
            "новое событие внутри cooldown не доставляется"
        );
        now += TICK;
        assert_eq!(engine.step(tick(Some(85.0)), now), LoopAction::Nothing);

        now += COOLDOWN;
        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
    }

    /// Спека «Старт без swap» / «Swap включили после старта»:
    /// предупреждение выдаётся ровно один раз на переход (флаг состояния
    /// движка), не спамится каждым тиком; появление swap — info.
    #[test]
    fn daemon_loop_no_swap_warning_once() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        assert_eq!(engine.step(tick(None), now), LoopAction::Nothing);
        assert!(
            engine.no_swap_logged,
            "первый тик без swap — предупреждение"
        );
        now += TICK;
        assert_eq!(engine.step(tick(None), now), LoopAction::Nothing);
        assert!(
            engine.no_swap_logged,
            "повторные тики не выдают предупреждение снова"
        );
        now += TICK;
        assert_eq!(engine.step(tick(Some(10.0)), now), LoopAction::Nothing);
        assert!(
            !engine.no_swap_logged,
            "swap появился — мониторинг возобновлён"
        );
    }

    /// Swap исчез в состоянии Exceeded: событие теряет актуальность
    /// (Cancel), после включения swap новое пересечение доставляется
    /// свободно, без блокировки.
    #[test]
    fn daemon_loop_swap_gone_in_exceeded_cancels_pending() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
        now += TICK;
        assert_eq!(engine.step(tick(None), now), LoopAction::Cancel);
        now += TICK;
        assert!(matches!(
            engine.step(tick(Some(85.0)), now),
            LoopAction::Deliver { .. }
        ));
    }

    /// Скорость обмена считается ядром по дельте vmstat между тиками
    /// (спека «Скорость обмена со swap как деталь события»: +60 000 КиБ
    /// за 5 с → 12 000 КиБ/с → «12 МБ/с» в сообщении); первый тик без
    /// предыдущих счётчиков даёт нулевую скорость.
    #[test]
    fn daemon_loop_swap_rate_from_vmstat_delta() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        let mut base = tick(Some(50.0));
        base.vmstat = vmstat(300, 1000);
        assert_eq!(engine.step(base, now), LoopAction::Nothing);

        now += TICK;
        let mut raised = tick(Some(85.0));
        raised.vmstat = vmstat(300, 61000);
        let LoopAction::Deliver { notification } = engine.step(raised, now) else {
            panic!("ожидалась доставка после пересечения порога");
        };
        assert!(
            notification.body.contains("12 МБ/с"),
            "тело {:?} должно содержать скорость обмена",
            notification.body
        );

        // Первый тик свежего ядра: предыдущих счётчиков нет — скорость 0.
        let mut fresh = loop_engine();
        let mut first = tick(Some(85.0));
        first.vmstat = vmstat(0, 100000);
        let LoopAction::Deliver { notification } = fresh.step(first, now) else {
            panic!("ожидалась доставка на первом тике");
        };
        assert!(
            notification.body.contains("0 МБ/с"),
            "тело {:?} первого тика должно содержать нулевую скорость",
            notification.body
        );
    }

    /// Скорость обмена считается по фактическому времени между тиками,
    /// а не по интервалу конфига: +12 000 КиБ pswpout за 10 с (тиг был
    /// пропущен) при интервале 5 с → 1200 КиБ/с («1 МБ/с»), наивное
    /// деление на конфиг-интервал дало бы 2400 («2 МБ/с»).
    #[test]
    fn daemon_loop_swap_rate_uses_actual_elapsed() {
        let mut engine = loop_engine();
        let mut now = Instant::now();

        let mut base = tick(Some(50.0));
        base.vmstat = vmstat(0, 0);
        assert_eq!(engine.step(base, now), LoopAction::Nothing);

        now += TICK + TICK; // 2× интервала: один тик пропущен
        let mut raised = tick(Some(85.0));
        raised.vmstat = vmstat(0, 12000);
        let LoopAction::Deliver { notification } = engine.step(raised, now) else {
            panic!("ожидалась доставка после пересечения порога");
        };
        assert!(
            notification.body.contains("1 МБ/с"),
            "тело {:?} должно содержать скорость по фактическому интервалу",
            notification.body
        );
        assert!(
            !notification.body.contains("2 МБ/с"),
            "тело {:?} не должно содержать скорость по конфиг-интервалу",
            notification.body
        );
    }

    /// Ручной запуск вне systemd: `$NOTIFY_SOCKET` нет — sd_notify
    /// молча no-op, ошибки нет.
    #[test]
    fn daemon_loop_sd_notify_without_socket_is_noop() {
        // SAFETY: изменение окружения из единственного теста, читающего
        // NOTIFY_SOCKET; остальные тесты эту переменную не трогают.
        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        assert!(sd_notify_ready().is_ok());
    }

    // --- Главный цикл: async-обёртка run_loop ---

    /// Ручной фейк источника (без mockall): тики по очереди, после
    /// исчерпания повторяется последний; `Clone` — мелкий (`Rc`, тест
    /// однопоточный), чтобы тест наблюдал курсор переданной копии.
    #[derive(Clone)]
    struct FakeSource {
        ticks: Rc<Vec<TickData>>,
        cursor: Rc<Cell<usize>>,
    }

    impl SampleSource for FakeSource {
        fn read(&self) -> Option<TickData> {
            let idx = self.cursor.get().min(self.ticks.len() - 1);
            self.cursor.set(self.cursor.get() + 1);
            Some(self.ticks[idx].clone())
        }
    }

    /// Ручной фейк доставки (без mockall): программируемый исход каждого
    /// вызова (список delivered по сессиям) и счётчик вызовов.
    #[derive(Clone)]
    struct FakeNotifier {
        outcomes_per_call: Rc<Vec<Vec<bool>>>,
        calls: Rc<Cell<usize>>,
    }

    impl Notifier for FakeNotifier {
        async fn notify_all(&self, _notification: &Notification) -> Vec<NotifyOutcome> {
            let idx = self.calls.get().min(self.outcomes_per_call.len() - 1);
            self.calls.set(self.calls.get() + 1);
            self.outcomes_per_call[idx]
                .iter()
                .map(|&delivered| NotifyOutcome {
                    uid: 1000,
                    delivered,
                    error: None,
                })
                .collect()
        }
    }

    /// Async-обёртка целиком: событие первого тика доставляется успешно,
    /// второй тик (устойчивое превышение) ничего не доставляет — счётчик
    /// вызовов notifier ровно один; выход по shutdown. Интервал цикла —
    /// минимум валидного диапазона (1 с), shutdown срабатывает после
    /// второго чтения источника.
    #[tokio::test]
    async fn daemon_loop_run_loop_delivers_once() {
        let config = Config {
            interval_secs: 1,
            ..Config::default()
        };
        let source = FakeSource {
            ticks: Rc::new(vec![tick(Some(85.0)), tick(Some(90.0))]),
            cursor: Rc::new(Cell::new(0)),
        };
        let notifier = FakeNotifier {
            outcomes_per_call: Rc::new(vec![vec![true]]),
            calls: Rc::new(Cell::new(0)),
        };
        let watched_cursor = Rc::clone(&source.cursor);
        let shutdown = async move {
            while watched_cursor.get() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };

        run_loop(
            &config,
            source,
            notifier.clone(),
            DELIVERY_TIMEOUT,
            shutdown,
        )
        .await;

        assert_eq!(
            notifier.calls.get(),
            1,
            "после успешной доставки повторной быть не должно"
        );
    }

    /// Фейк доставки с задержкой ответа: каждый вызов спит заданную для
    /// него задержку (потом повторяется последняя) и «успешно» доставляет
    /// одну сессию — для теста таймаута доставки (200 мс против 50 мс).
    #[derive(Clone)]
    struct SlowNotifier {
        delays_per_call: Rc<Vec<Duration>>,
        calls: Rc<Cell<usize>>,
    }

    impl Notifier for SlowNotifier {
        async fn notify_all(&self, _notification: &Notification) -> Vec<NotifyOutcome> {
            let idx = self.calls.get().min(self.delays_per_call.len() - 1);
            self.calls.set(self.calls.get() + 1);
            tokio::time::sleep(self.delays_per_call[idx]).await;
            vec![NotifyOutcome {
                uid: 1000,
                delivered: true,
                error: None,
            }]
        }
    }

    /// Доставка дольше `delivery_timeout` трактуется как неудача:
    /// событие не снимается, цикл продолжает тикать, следующий тик
    /// ретраит и доставляет успешно (после успеха повторных вызовов
    /// нет). Интервал цикла 1 с: тест живёт ≈2 с реального времени.
    #[tokio::test]
    async fn daemon_loop_delivery_timeout_treated_as_failure() {
        let config = Config {
            interval_secs: 1,
            ..Config::default()
        };
        let source = FakeSource {
            ticks: Rc::new(vec![tick(Some(85.0))]),
            cursor: Rc::new(Cell::new(0)),
        };
        let notifier = SlowNotifier {
            delays_per_call: Rc::new(vec![
                Duration::from_millis(200), // первый вызов — дольше таймаута
                Duration::ZERO,             // ретрай — мгновенно
            ]),
            calls: Rc::new(Cell::new(0)),
        };
        let watched_cursor = Rc::clone(&source.cursor);
        // Три тика: первый — таймаут доставки, второй — успешный ретрай,
        // третий — устойчивое превышение без повторной доставки.
        let shutdown = async move {
            while watched_cursor.get() < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };

        run_loop(
            &config,
            source,
            notifier.clone(),
            Duration::from_millis(50),
            shutdown,
        )
        .await;

        assert_eq!(
            notifier.calls.get(),
            2,
            "таймаут — неудача с ретраем, успех — без повторных вызовов"
        );
    }
}
