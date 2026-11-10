//! Парсинг `/proc` (дизайн D2: собственный мини-парсер, без крейта
//! `procfs`): `/proc/meminfo` (занятость swap), `/proc/vmstat` (скорость
//! обмена), per-pid `status` (`VmSwap`), `stat` (`starttime`), `cgroup`
//! (путь cgroup v2) и обход `[pid]`-каталогов для снапшотов использования
//! swap per-pid (спека `swap-usage-attribution`). КиБ — базовая единица
//! модуля; единственная конверсия единиц здесь — страницы ядра → КиБ в
//! [`parse_vmstat`] ([`PAGE_KIB`]). Данные `/proc` не доверены: строки
//! могут отсутствовать, быть обрезанными или содержать мусор.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Ограничение размера читаемого файла `/proc`: содержимое не доверено,
/// читаем не более 64 КиБ (границы доверия).
const MAX_PROC_FILE_BYTES: u64 = 64 * 1024;

/// Ошибка разбора файла `/proc`: обязательное поле отсутствует, значение
/// не парсится или строка не соответствует формату. Вызывающий трактует
/// все варианты одинаково — «файл не разобран» (пропуск pid).
#[derive(Debug, thiserror::Error)]
pub(crate) enum MonitorError {
    /// Обязательная строка файла отсутствует (обрезанное содержимое).
    #[error("отсутствует обязательное поле {field}")]
    MissingField { field: &'static str },

    /// Значение поля не парсится как u64 или единица не кБ.
    #[error("поле {field}: некорректное значение «{value}»")]
    InvalidField { field: &'static str, value: String },

    /// Строка не соответствует формату файла целиком.
    #[error("некорректная запись: {what}")]
    Malformed { what: &'static str },
}

/// Показания `/proc/meminfo` по swap, кБ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemInfo {
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

/// Разбирает `SwapTotal`/`SwapFree` из `/proc/meminfo`.
///
/// `SwapTotal: 0 kB` валиден (swap выключен — не ошибка, спека
/// `swap-monitoring`); отсутствие обязательной строки или мусор в числе —
/// [`MonitorError`].
pub(crate) fn parse_meminfo(input: &str) -> Result<MemInfo, MonitorError> {
    let mut swap_total_kb = None;
    let mut swap_free_kb = None;
    for line in input.lines() {
        if let Some(rest) = line.strip_prefix("SwapTotal:") {
            swap_total_kb = Some(parse_kb_field("SwapTotal", rest)?);
        } else if let Some(rest) = line.strip_prefix("SwapFree:") {
            swap_free_kb = Some(parse_kb_field("SwapFree", rest)?);
        }
    }
    Ok(MemInfo {
        swap_total_kb: swap_total_kb.ok_or(MonitorError::MissingField { field: "SwapTotal" })?,
        swap_free_kb: swap_free_kb.ok_or(MonitorError::MissingField { field: "SwapFree" })?,
    })
}

/// Процент занятости swap: `(total - free) / total * 100`. `None`, если
/// swap выключен (`swap_total_kb == 0`, спека `swap-monitoring`).
pub(crate) fn swap_usage_pct(mi: &MemInfo) -> Option<f64> {
    if mi.swap_total_kb == 0 {
        return None;
    }
    // Вычитаем в f64: аномальное free > total не должно паниковать.
    let used_kb = mi.swap_total_kb as f64 - mi.swap_free_kb as f64;
    Some((used_kb / mi.swap_total_kb as f64 * 100.0).max(0.0))
}

/// Счётчики `/proc/vmstat`, кБ: ядро ведёт их в страницах, конвертация
/// в КиБ выполнена в [`parse_vmstat`] через [`PAGE_KIB`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VmStat {
    pub pswpin_kb: u64,
    pub pswpout_kb: u64,
}

/// Размер страницы ядра в КиБ: целевая платформа — Debian amd64
/// (CI-артефакт `*_amd64.deb`), страница 4 КиБ. Ядро считает
/// `pswpin`/`pswpout` страницами; по конвенции «единицы конвертируются в
/// одном месте» этим местом будет `monitor`. При порте на платформу с
/// другой страницей меняется одна константа (или заменяется на
/// определение размера страницы).
const PAGE_KIB: u64 = 4;

/// Разбирает `pswpin`/`pswpout` из `/proc/vmstat` и конвертирует
/// страницы в КиБ; отсутствие ключа или мусор в числе — [`MonitorError`].
pub(crate) fn parse_vmstat(input: &str) -> Result<VmStat, MonitorError> {
    let mut pswpin_pages = None;
    let mut pswpout_pages = None;
    for line in input.lines() {
        // Сравнение первого токена на точное равенство: `strip_prefix`
        // без границы слова принял бы гипотетический `pswpin_x` за ключ
        // `pswpin` и сломал бы весь тик на его значении.
        let mut tokens = line.split_whitespace();
        match tokens.next() {
            Some("pswpin") => {
                pswpin_pages = Some(parse_counter("pswpin", tokens.next().unwrap_or(""))?);
            }
            Some("pswpout") => {
                pswpout_pages = Some(parse_counter("pswpout", tokens.next().unwrap_or(""))?);
            }
            _ => {}
        }
    }
    // saturating_mul: абсурдно большой мусор не должен паниковать.
    Ok(VmStat {
        pswpin_kb: pswpin_pages
            .ok_or(MonitorError::MissingField { field: "pswpin" })?
            .saturating_mul(PAGE_KIB),
        pswpout_kb: pswpout_pages
            .ok_or(MonitorError::MissingField { field: "pswpout" })?
            .saturating_mul(PAGE_KIB),
    })
}

/// Скорость обмена со swap, КБ/с.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SwapRate {
    pub in_kbps: u64,
    pub out_kbps: u64,
}

/// Скорость обмена как прирост счётчиков за интервал опроса (спека
/// `swap-monitoring`: 60 000 КБ за 5 с → 12 000 КБ/с): делегирует
/// [`swap_rate_over`] с интервалом конфига. Продакшн-цикл считает по
/// фактическому времени между тиками; эта обёртка остаётся для
/// сценарных тестов спеки, поэтому компилируется только в тестах.
/// Отрицательная (сброс счётчика) и нулевая дельта → 0. Интервал 0
/// исключён валидным конфигом (1–3600 с), здесь — защита от деления на
/// ноль.
#[cfg(test)]
pub(crate) fn swap_rate(prev: &VmStat, cur: &VmStat, interval_secs: u64) -> SwapRate {
    swap_rate_over(prev, cur, Duration::from_secs(interval_secs))
}

/// Скорость обмена как прирост счётчиков за фактически прошедшее время
/// между тиками (не конфиг-интервал: тики пропускаются при нечитаемом
/// `/proc` или долгой доставке, деление на интервал конфига завышало бы
/// скорость кратно). Точность — до миллисекунд:
/// `delta_kb * 1000 / elapsed_ms`, целочисленно; `elapsed == 0` → 0.
pub(crate) fn swap_rate_over(prev: &VmStat, cur: &VmStat, elapsed: Duration) -> SwapRate {
    let elapsed_ms = elapsed.as_millis();
    if elapsed_ms == 0 {
        return SwapRate::default();
    }
    let rate_kbps = |delta_kb: u64| delta_kb.saturating_mul(1000) / elapsed_ms as u64;
    SwapRate {
        in_kbps: rate_kbps(cur.pswpin_kb.saturating_sub(prev.pswpin_kb)),
        out_kbps: rate_kbps(cur.pswpout_kb.saturating_sub(prev.pswpout_kb)),
    }
}

/// Запись процесса для снапшота атрибуции: пара `(pid, starttime)`
/// защищает от переиспользования PID (спека `swap-usage-attribution`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcEntry {
    pub pid: u32,
    pub starttime: u64,
    pub vm_swap_kb: u64,
    pub comm: String,
    pub cgroup: Option<String>,
}

/// Разбирает `VmSwap` (кБ) и `Name` (comm) из `/proc/<pid>/status`.
/// Отсутствие строки `VmSwap` или `Name`, мусор в числе —
/// [`MonitorError`].
pub(crate) fn parse_status(input: &str) -> Result<(u64, String), MonitorError> {
    let mut vm_swap_kb = None;
    let mut comm = None;
    for line in input.lines() {
        if let Some(rest) = line.strip_prefix("VmSwap:") {
            vm_swap_kb = Some(parse_kb_field("VmSwap", rest)?);
        } else if let Some(rest) = line.strip_prefix("Name:") {
            comm = Some(rest.trim().to_owned());
        }
    }
    Ok((
        vm_swap_kb.ok_or(MonitorError::MissingField { field: "VmSwap" })?,
        comm.ok_or(MonitorError::MissingField { field: "Name" })?,
    ))
}

/// Разбирает поле 22 (`starttime`) из `/proc/<pid>/stat`. comm в скобках
/// может содержать пробелы и `)`, поэтому поля считаем после последней
/// закрывающей скобки.
pub(crate) fn parse_stat(input: &str) -> Result<u64, MonitorError> {
    let after_comm =
        input
            .rfind(')')
            .map(|idx| &input[idx + 1..])
            .ok_or(MonitorError::Malformed {
                what: "stat: нет закрывающей скобки comm",
            })?;
    // После `)` первым идёт поле 3 (state); starttime — поле 22 → индекс 19.
    let field = after_comm
        .split_whitespace()
        .nth(19)
        .ok_or(MonitorError::Malformed {
            what: "stat: нет поля 22 (starttime)",
        })?;
    field
        .parse::<u64>()
        .map_err(|_| MonitorError::InvalidField {
            field: "starttime",
            value: field.to_owned(),
        })
}

/// Разбирает путь cgroup v2 (строка `0::/path`) из `/proc/<pid>/cgroup`.
/// `None` — строки `0::` нет (cgroup v1, гибрид или файл пуст).
pub(crate) fn parse_cgroup(input: &str) -> Option<String> {
    input
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .map(str::to_owned)
}

/// Обходит каталоги `[pid]` в `proc_root` (продакшн — `/proc`, тесты —
/// временная директория с фикстурами) и собирает процессы со swap-следом
/// (`vm_swap_kb > 0`). Ошибка чтения/разбора одного pid (процесс исчез
/// или нечитаем) молча пропускается — это не ошибка мониторинга (спека
/// `swap-usage-attribution`); недоступная cgroup даёт `cgroup: None`.
/// Сортировка не гарантируется.
pub(crate) fn scan_swap_processes(proc_root: &Path) -> Vec<ProcEntry> {
    let mut entries = Vec::new();
    let Ok(dir) = fs::read_dir(proc_root) else {
        tracing::debug!(?proc_root, "каталог процессов не читается");
        return entries;
    };
    // Один путь-буфер на весь скан, а не новая строка на каждый pid.
    let mut path = PathBuf::new();
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue; // не [pid]-каталог: self, irq, acpi…
        };
        path.clear();
        path.push(proc_root);
        path.push(entry.file_name());
        match read_pid(&mut path, pid) {
            Some(entry) => entries.push(entry),
            None => tracing::debug!(pid, "pid пропущен: нечитаем или некорректен"),
        }
    }
    entries
}

/// Читает `status`/`stat`/`cgroup` одного pid; `None` — pid пропускается.
fn read_pid(pid_dir: &mut PathBuf, pid: u32) -> Option<ProcEntry> {
    let status = read_pid_file(pid_dir, "status")?;
    let (vm_swap_kb, comm) = parse_status(&status).ok()?;
    // Типичный процесс не имеет swap-следа — stat/cgroup для него не читаем.
    if vm_swap_kb == 0 {
        return None;
    }
    let stat = read_pid_file(pid_dir, "stat")?;
    let starttime = parse_stat(&stat).ok()?;
    // Недоступная cgroup не ломает расчёт (спека «Группировка процессов
    // по cgroup»): процесс относится к группе «неизвестная cgroup».
    let cgroup = read_pid_file(pid_dir, "cgroup").and_then(|s| parse_cgroup(&s));
    Some(ProcEntry {
        pid,
        starttime,
        vm_swap_kb,
        comm,
        cgroup,
    })
}

/// Читает файл `name` из каталога pid не более [`MAX_PROC_FILE_BYTES`]
/// байт; восстанавливает путь-буфер после чтения.
fn read_pid_file(pid_dir: &mut PathBuf, name: &str) -> Option<String> {
    pid_dir.push(name);
    let content = read_limited(pid_dir).ok();
    pid_dir.pop();
    content
}

/// Читает файл `/proc` ограниченным объёмом: содержимое не доверено.
/// Байты конвертируются лениво: не-UTF8 comm (например, `exec -a` с
/// байтами >0x7F) не должен выбрасывать процесс из атрибуции целиком —
/// невалидные байты становятся U+FFFD.
fn read_limited(path: &Path) -> io::Result<String> {
    let mut buf = Vec::new();
    File::open(path)?
        .take(MAX_PROC_FILE_BYTES)
        .read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Разбирает значение поля формата `<число> [kB]` (meminfo, `VmSwap`).
/// Отсутствие числа, мусор или неподдерживаемая единица — ошибка.
fn parse_kb_field(field: &'static str, rest: &str) -> Result<u64, MonitorError> {
    let invalid = || MonitorError::InvalidField {
        field,
        value: rest.trim().to_owned(),
    };
    let mut parts = rest.split_whitespace();
    let raw = parts.next().ok_or(MonitorError::MissingField { field })?;
    let value = raw.parse::<u64>().map_err(|_| invalid())?;
    match parts.next() {
        // Обрезанная строка без единицы ещё валидна; /proc отдаёт кБ.
        None | Some("kB") => Ok(value),
        Some(_) => Err(invalid()),
    }
}

/// Разбирает значение счётчика `<ключ> <число>` из vmstat (без единиц).
fn parse_counter(field: &'static str, rest: &str) -> Result<u64, MonitorError> {
    rest.trim()
        .parse::<u64>()
        .map_err(|_| MonitorError::InvalidField {
            field,
            value: rest.trim().to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    const MEMINFO_TYPICAL: &str = include_str!("monitor/testdata/meminfo_typical");
    const MEMINFO_NO_SWAP: &str = include_str!("monitor/testdata/meminfo_no_swap");
    const MEMINFO_MISSING_SWAP: &str = include_str!("monitor/testdata/meminfo_missing_swap");
    const VMSTAT: &str = include_str!("monitor/testdata/vmstat");
    const STATUS_WITH_VMSWAP: &str = include_str!("monitor/testdata/status_with_vmswap");
    const STATUS_WITHOUT_VMSWAP: &str = include_str!("monitor/testdata/status_without_vmswap");
    const STATUS_GARBAGE: &str = include_str!("monitor/testdata/status_garbage");
    const STAT_MULTIWORD_COMM: &str = include_str!("monitor/testdata/stat_multiword_comm");
    const CGROUP_V2: &str = include_str!("monitor/testdata/cgroup_v2");
    const CGROUP_V1: &str = include_str!("monitor/testdata/cgroup_v1");
    const CGROUP_EMPTY: &str = include_str!("monitor/testdata/cgroup_empty");

    /// Сравнение с допуском: процент занятости считаем в f64.
    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 0.01,
            "ожидалось ≈{expected}, получено {actual}"
        );
    }

    /// Уникальный подкаталог временной директории (тест сам её удаляет).
    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swapnotif-monitor-test-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn monitor_parse_meminfo_typical() {
        let mi = parse_meminfo(MEMINFO_TYPICAL).unwrap();
        assert_eq!(
            mi,
            MemInfo {
                swap_total_kb: 4194304,
                swap_free_kb: 838861,
            }
        );
    }

    #[test]
    fn monitor_parse_meminfo_no_swap_is_valid() {
        let mi = parse_meminfo(MEMINFO_NO_SWAP).unwrap();
        assert_eq!(
            mi,
            MemInfo {
                swap_total_kb: 0,
                swap_free_kb: 0,
            }
        );
        // Swap выключен — не ошибка (спека swap-monitoring).
        assert_eq!(swap_usage_pct(&mi), None);
    }

    #[test]
    fn monitor_parse_meminfo_missing_field_is_err() {
        assert!(matches!(
            parse_meminfo(MEMINFO_MISSING_SWAP),
            Err(MonitorError::MissingField { field: "SwapTotal" })
        ));
    }

    #[test]
    fn monitor_parse_meminfo_garbage_is_err() {
        for input in [
            "SwapTotal: lots kB\nSwapFree: 0 kB\n",
            "SwapTotal: 100 MB\nSwapFree: 0 kB\n",
            "SwapTotal: -5 kB\nSwapFree: 0 kB\n",
            "SwapTotal:\nSwapFree: 0 kB\n",
        ] {
            assert!(matches!(
                parse_meminfo(input),
                Err(MonitorError::InvalidField { .. }) | Err(MonitorError::MissingField { .. })
            ));
        }
    }

    #[test]
    fn monitor_swap_usage_pct_table() {
        // Спека swap-monitoring: SwapTotal 4 GiB, SwapFree 0.8 GiB → 80 %.
        let table = [
            (4194304_u64, 838861_u64, Some(80.0)),
            (1000, 0, Some(100.0)),
            (1000, 250, Some(75.0)),
            (1000, 1000, Some(0.0)),
            (0, 0, None),
        ];
        for (total, free, expected) in table {
            let mi = MemInfo {
                swap_total_kb: total,
                swap_free_kb: free,
            };
            let actual = swap_usage_pct(&mi);
            assert_eq!(actual.is_some(), expected.is_some());
            if let (Some(actual), Some(expected)) = (actual, expected) {
                assert_close(actual, expected);
            }
        }
    }

    #[test]
    fn monitor_parse_vmstat_typical() {
        // Фикстура — страницы (100 и 1000), парсер конвертирует в КиБ (×4).
        let vs = parse_vmstat(VMSTAT).unwrap();
        assert_eq!(
            vs,
            VmStat {
                pswpin_kb: 400,
                pswpout_kb: 4000,
            }
        );
    }

    #[test]
    fn monitor_parse_vmstat_converts_pages_to_kib() {
        // pswpout 4096 страниц = 16384 КиБ; pswpin 1 страница = 4 КиБ.
        let vs = parse_vmstat("pswpin 1\npswpout 4096\n").unwrap();
        assert_eq!(
            vs,
            VmStat {
                pswpin_kb: 4,
                pswpout_kb: 16384,
            }
        );
    }

    #[test]
    fn monitor_parse_vmstat_missing_key_is_err() {
        assert!(matches!(
            parse_vmstat("nr_free_pages 42\npswpin 100\n"),
            Err(MonitorError::MissingField { field: "pswpout" })
        ));
    }

    #[test]
    fn monitor_swap_rate_counters_grow() {
        // Спека swap-monitoring: прирост 60 000 КБ за 5 с → 12 000 КБ/с.
        // На входе — страницы: pswpout +15 000 стр × 4 КиБ = 60 000 КиБ,
        // pswpin +75 стр = 300 КиБ.
        let prev = parse_vmstat("pswpin 25\npswpout 250\n").unwrap();
        let cur = parse_vmstat("pswpin 100\npswpout 15250\n").unwrap();
        assert_eq!(
            swap_rate(&prev, &cur, 5),
            SwapRate {
                in_kbps: 60,
                out_kbps: 12000,
            }
        );
    }

    #[test]
    fn monitor_swap_rate_no_change_is_zero() {
        let vs = VmStat {
            pswpin_kb: 100,
            pswpout_kb: 1000,
        };
        assert_eq!(
            swap_rate(&vs, &vs, 5),
            SwapRate {
                in_kbps: 0,
                out_kbps: 0,
            }
        );
    }

    #[test]
    fn monitor_swap_rate_counter_reset_is_zero() {
        // Отрицательная дельта (сброс счётчика) → 0.
        let prev = VmStat {
            pswpin_kb: 500,
            pswpout_kb: 9000,
        };
        let cur = VmStat {
            pswpin_kb: 100,
            pswpout_kb: 1000,
        };
        assert_eq!(
            swap_rate(&prev, &cur, 5),
            SwapRate {
                in_kbps: 0,
                out_kbps: 0,
            }
        );
    }

    #[test]
    fn monitor_swap_rate_zero_interval_is_zero() {
        // Интервал ≥ 1 гарантирует конфиг; здесь защита от деления на ноль.
        let prev = VmStat {
            pswpin_kb: 0,
            pswpout_kb: 0,
        };
        let cur = VmStat {
            pswpin_kb: 100,
            pswpout_kb: 100,
        };
        assert_eq!(
            swap_rate(&prev, &cur, 0),
            SwapRate {
                in_kbps: 0,
                out_kbps: 0,
            }
        );
    }

    /// Скорость по фактическому интервалу с точностью до мс: 1200 КиБ
    /// за 1500 мс → 800 КиБ/с (секундная точность дала бы 1200).
    #[test]
    fn monitor_swap_rate_over_millisecond_precision() {
        let prev = VmStat {
            pswpin_kb: 0,
            pswpout_kb: 0,
        };
        let cur = VmStat {
            pswpin_kb: 300,
            pswpout_kb: 1200,
        };
        assert_eq!(
            swap_rate_over(&prev, &cur, Duration::from_millis(1500)),
            SwapRate {
                in_kbps: 200,
                out_kbps: 800,
            }
        );
        // Нулевой elapsed — защита от деления на ноль.
        assert_eq!(
            swap_rate_over(&prev, &cur, Duration::ZERO),
            SwapRate::default()
        );
    }

    /// Точное равенство ключа vmstat: гипотетический `pswpin_x` —
    /// неизвестное поле, а не ключ `pswpin`; оно игнорируется и не
    /// ломает тик, валидные ключи рядом парсятся.
    #[test]
    fn monitor_parse_vmstat_requires_exact_key_match() {
        let vs = parse_vmstat("pswpin_x 5\npswpin 1\npswpout 2\n").unwrap();
        assert_eq!(
            vs,
            VmStat {
                pswpin_kb: 4,
                pswpout_kb: 8,
            }
        );
    }

    #[test]
    fn monitor_parse_status_with_vmswap() {
        let (vm_swap_kb, comm) = parse_status(STATUS_WITH_VMSWAP).unwrap();
        assert_eq!(vm_swap_kb, 123456);
        assert_eq!(comm, "demo-proc");
    }

    #[test]
    fn monitor_parse_status_without_vmswap_is_err() {
        assert!(matches!(
            parse_status(STATUS_WITHOUT_VMSWAP),
            Err(MonitorError::MissingField { field: "VmSwap" })
        ));
    }

    #[test]
    fn monitor_parse_status_garbage_is_err() {
        assert!(matches!(
            parse_status(STATUS_GARBAGE),
            Err(MonitorError::InvalidField { .. })
        ));
    }

    #[test]
    fn monitor_parse_status_missing_name_is_err() {
        assert!(matches!(
            parse_status("VmSwap:\t123456 kB\n"),
            Err(MonitorError::MissingField { field: "Name" })
        ));
    }

    #[test]
    fn monitor_parse_stat_multiword_comm() {
        // comm в скобках содержит пробелы, '(' и ')'.
        assert_eq!(parse_stat(STAT_MULTIWORD_COMM).unwrap(), 888777);
    }

    #[test]
    fn monitor_parse_stat_truncated_is_err() {
        assert!(matches!(
            parse_stat("42 (demo) R 1\n"),
            Err(MonitorError::Malformed { .. })
        ));
    }

    #[test]
    fn monitor_parse_stat_no_paren_is_err() {
        assert!(matches!(
            parse_stat("no comm here\n"),
            Err(MonitorError::Malformed { .. })
        ));
    }

    #[test]
    fn monitor_parse_cgroup_v2() {
        assert_eq!(
            parse_cgroup(CGROUP_V2),
            Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-demo-4242.scope"
                    .to_owned()
            )
        );
    }

    #[test]
    fn monitor_parse_cgroup_v1_is_none() {
        assert_eq!(parse_cgroup(CGROUP_V1), None);
    }

    #[test]
    fn monitor_parse_cgroup_empty_is_none() {
        assert_eq!(parse_cgroup(CGROUP_EMPTY), None);
    }

    #[test]
    fn monitor_scan_swap_processes_filters_and_skips() {
        let root = unique_temp_dir("scan");
        for pid in ["100", "200", "300", "400"] {
            fs::create_dir_all(root.join(pid)).unwrap();
        }
        // Валидный pid со swap-следом и cgroup v2.
        fs::write(root.join("100/status"), STATUS_WITH_VMSWAP).unwrap();
        fs::write(root.join("100/stat"), STAT_MULTIWORD_COMM).unwrap();
        fs::write(root.join("100/cgroup"), CGROUP_V2).unwrap();
        // Мусорный status → pid молча пропускается.
        fs::write(root.join("200/status"), STATUS_GARBAGE).unwrap();
        fs::write(root.join("200/stat"), STAT_MULTIWORD_COMM).unwrap();
        // Отсутствующий stat → pid молча пропускается.
        fs::write(root.join("300/status"), STATUS_WITH_VMSWAP).unwrap();
        // VmSwap == 0 → записи нет (фильтр swap-следа).
        fs::write(root.join("400/status"), "Name:\tidleproc\nVmSwap:\t0 kB\n").unwrap();
        fs::write(root.join("400/stat"), STAT_MULTIWORD_COMM).unwrap();
        fs::write(root.join("400/cgroup"), CGROUP_V2).unwrap();

        let entries = scan_swap_processes(&root);
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(
            entries,
            vec![ProcEntry {
                pid: 100,
                starttime: 888777,
                vm_swap_kb: 123456,
                comm: "demo-proc".to_owned(),
                cgroup: Some(
                    "/user.slice/user-1000.slice/user@1000.service/app.slice/app-demo-4242.scope"
                        .to_owned()
                ),
            }]
        );
    }

    /// Не-UTF8 comm (`exec -a` с байтами >0x7F): чтение байтами +
    /// ленивая конвертация не выбрасывает pid из атрибуции — имя
    /// содержит U+FFFD на месте невалидного байта, запись валидна.
    #[test]
    fn monitor_scan_status_non_utf8_name_is_lossy() {
        let root = unique_temp_dir("non-utf8");
        fs::create_dir_all(root.join("500")).unwrap();
        fs::write(
            root.join("500/status"),
            b"Name:\tla\xfftin-proc\nVmSwap:\t4096 kB\n",
        )
        .unwrap();
        fs::write(root.join("500/stat"), STAT_MULTIWORD_COMM).unwrap();
        fs::write(root.join("500/cgroup"), CGROUP_V2).unwrap();

        let entries = scan_swap_processes(&root);
        fs::remove_dir_all(&root).unwrap();

        let [entry] = &entries[..] else {
            panic!("ожидалась одна запись, получено {entries:?}");
        };
        assert_eq!(entry.comm, "la\u{FFFD}tin-proc");
        assert_eq!(entry.vm_swap_kb, 4096);
    }

    #[test]
    fn monitor_scan_swap_processes_missing_root_is_empty() {
        // Несуществующий корень — не паника, пустой результат.
        let root = unique_temp_dir("missing");
        assert!(scan_swap_processes(&root).is_empty());
    }
}
