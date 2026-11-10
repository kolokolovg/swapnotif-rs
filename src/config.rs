//! Загрузка и валидация TOML-конфига демона (пороги, интервалы, окна),
//! дефолты — единственный источник констант (D8).

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

/// Путь к конфигу по умолчанию (proposal, спека `daemon-lifecycle`).
pub const DEFAULT_PATH: &str = "/etc/swapnotif/config.toml";

/// Дефолтный порог занятости swap, %.
pub const DEFAULT_THRESHOLD_PCT: u8 = 80;
/// Дефолтный гистерезис возврата в Normal, п.п.
pub const DEFAULT_HYSTERESIS_PCT: u8 = 5;
/// Дефолтный интервал опроса, с.
pub const DEFAULT_INTERVAL_SECS: u64 = 5;
/// Дефолтное окно атрибуции, с.
pub const DEFAULT_WINDOW_SECS: u64 = 60;
/// Дефолтный cooldown между уведомлениями, с.
pub const DEFAULT_COOLDOWN_SECS: u64 = 300;
/// Дефолтный минимальный вес виновника, МБ.
pub const DEFAULT_MIN_CULPRIT_MB: u64 = 50;

// Границы диапазонов применяются в `validate` и попадают в сообщения об
// ошибках из одного источника, чтобы текст не разошёлся с проверкой.
const THRESHOLD_PCT_MIN: u64 = 10;
const THRESHOLD_PCT_MAX: u64 = 99;
const HYSTERESIS_PCT_MIN: u64 = 1;
const HYSTERESIS_PCT_MAX: u64 = 20;
const INTERVAL_SECS_MIN: u64 = 1;
const INTERVAL_SECS_MAX: u64 = 3600;
const WINDOW_SECS_MIN: u64 = 10;
const WINDOW_SECS_MAX: u64 = 3600;
const COOLDOWN_SECS_MIN: u64 = 10;
const COOLDOWN_SECS_MAX: u64 = 86400;
const MIN_CULPRIT_MB_MIN: u64 = 1;
const MIN_CULPRIT_MB_MAX: u64 = 10240;

/// Ошибка загрузки конфига: фатальна для демона (fail-fast, D8),
/// сообщение попадает в journald.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Файл есть, но не читается (нет прав, не UTF-8, это каталог и т.п.).
    #[error("не удалось прочитать конфиг {path}: {source}")]
    Read {
        /// Путь к конфигу.
        path: PathBuf,
        /// Первичная ошибка ввода-вывода.
        source: io::Error,
    },

    /// TOML не разобрался: синтаксис, неверный тип значения или
    /// неизвестное поле (`deny_unknown_fields`).
    #[error("невалидный TOML в {path}: {source}")]
    Parse {
        /// Путь к конфигу.
        path: PathBuf,
        /// Ошибка парсера toml.
        source: toml::de::Error,
    },

    /// Значение поля вне допустимого диапазона.
    #[error("{path}: поле `{field}` = {value} вне допустимого диапазона {min}–{max}")]
    OutOfRange {
        /// Путь к конфигу.
        path: PathBuf,
        /// Имя TOML-поля.
        field: &'static str,
        /// Фактическое значение.
        value: u64,
        /// Нижняя граница допустимого диапазона.
        min: u64,
        /// Верхняя граница допустимого диапазона.
        max: u64,
    },

    /// Окно атрибуции меньше интервала опроса: кольцевой буфер
    /// снапшотов не может покрыть окно.
    #[error(
        "{path}: поле `window_secs` = {window} меньше `interval_secs` = {interval}; \
         окно атрибуции должно быть не меньше интервала опроса"
    )]
    WindowBelowInterval {
        /// Путь к конфигу.
        path: PathBuf,
        /// Значение `window_secs`.
        window: u64,
        /// Значение `interval_secs`.
        interval: u64,
    },

    /// Гистерезис не строго меньше порога: уровень сброса
    /// `threshold − hysteresis` опустился бы до нуля или ниже — состояние
    /// «порог превышен» стало бы несбрасываемым (тихая потеря
    /// уведомлений).
    #[error(
        "{path}: поле `hysteresis_pct` = {hysteresis} должно быть строго меньше \
         `threshold_pct` = {threshold}: гистерезис должен быть меньше порога"
    )]
    HysteresisNotBelowThreshold {
        /// Путь к конфигу.
        path: PathBuf,
        /// Значение `threshold_pct`.
        threshold: u64,
        /// Значение `hysteresis_pct`.
        hysteresis: u64,
    },
}

/// Конфигурация демона. Каждое поле опционально: пропущенный ключ
/// берётся из встроенного дефолта; неизвестный ключ — ошибка, а не
/// молчаливый дефолт (D8: опечатка в `treshold` не должна выключать
/// порог).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Порог занятости swap, % (10–99); событие при `fill >= threshold`.
    #[serde(default = "default_threshold_pct")]
    pub threshold_pct: u8,
    /// Гистерезис возврата в Normal, п.п. (1–20): `fill < threshold - hysteresis`.
    #[serde(default = "default_hysteresis_pct")]
    pub hysteresis_pct: u8,
    /// Интервал опроса, с (1–3600).
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Окно атрибуции виновника, с (10–3600); обязан быть не меньше
    /// `interval_secs`.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Cooldown между отправками уведомлений, с (10–86400); гейтит
    /// отправку, но не генерацию события (design D5).
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Минимальный вес виновника, МБ (1–10240); при меньшем приросте —
    /// «приложение не определено».
    #[serde(default = "default_min_culprit_mb")]
    pub min_culprit_mb: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold_pct: DEFAULT_THRESHOLD_PCT,
            hysteresis_pct: DEFAULT_HYSTERESIS_PCT,
            interval_secs: DEFAULT_INTERVAL_SECS,
            window_secs: DEFAULT_WINDOW_SECS,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
            min_culprit_mb: DEFAULT_MIN_CULPRIT_MB,
        }
    }
}

impl Config {
    /// Загружает конфиг из `path`. Отсутствие файла — не ошибка: демону
    /// предписано работать на встроенных дефолтах (спека
    /// `daemon-lifecycle`). Любая другая проблема (чтение, TOML,
    /// неизвестное поле, диапазон) — `Err` для fail-fast старта.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(Config::default());
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        let config: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate(path)?;
        Ok(config)
    }

    /// Глубина кольцевого буфера снапшотов атрибуции: сколько интервалов
    /// помещается в окно (design D3). Не меньше 1 — на случай `Config`,
    /// собранного напрямую, минуя [`Config::load`].
    pub fn snapshot_depth(&self) -> usize {
        (self.window_secs / self.interval_secs).max(1) as usize
    }

    /// Проверяет диапазоны и кросс-поле «окно >= интервал»; границы
    /// диапазонов попадают в сообщение об ошибке из тех же констант.
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        check_range(
            path,
            "threshold_pct",
            u64::from(self.threshold_pct),
            THRESHOLD_PCT_MIN,
            THRESHOLD_PCT_MAX,
        )?;
        check_range(
            path,
            "hysteresis_pct",
            u64::from(self.hysteresis_pct),
            HYSTERESIS_PCT_MIN,
            HYSTERESIS_PCT_MAX,
        )?;
        check_range(
            path,
            "interval_secs",
            self.interval_secs,
            INTERVAL_SECS_MIN,
            INTERVAL_SECS_MAX,
        )?;
        check_range(
            path,
            "window_secs",
            self.window_secs,
            WINDOW_SECS_MIN,
            WINDOW_SECS_MAX,
        )?;
        check_range(
            path,
            "cooldown_secs",
            self.cooldown_secs,
            COOLDOWN_SECS_MIN,
            COOLDOWN_SECS_MAX,
        )?;
        check_range(
            path,
            "min_culprit_mb",
            self.min_culprit_mb,
            MIN_CULPRIT_MB_MIN,
            MIN_CULPRIT_MB_MAX,
        )?;
        if self.window_secs < self.interval_secs {
            return Err(ConfigError::WindowBelowInterval {
                path: path.to_owned(),
                window: self.window_secs,
                interval: self.interval_secs,
            });
        }
        // Инвариант гистерезиса: сброс строго ниже `threshold −
        // hysteresis`; при hysteresis >= threshold уровень сброса
        // неположителен и Exceeded не сбрасывается никогда.
        if self.hysteresis_pct >= self.threshold_pct {
            return Err(ConfigError::HysteresisNotBelowThreshold {
                path: path.to_owned(),
                threshold: u64::from(self.threshold_pct),
                hysteresis: u64::from(self.hysteresis_pct),
            });
        }
        Ok(())
    }
}

fn default_threshold_pct() -> u8 {
    DEFAULT_THRESHOLD_PCT
}

fn default_hysteresis_pct() -> u8 {
    DEFAULT_HYSTERESIS_PCT
}

fn default_interval_secs() -> u64 {
    DEFAULT_INTERVAL_SECS
}

fn default_window_secs() -> u64 {
    DEFAULT_WINDOW_SECS
}

fn default_cooldown_secs() -> u64 {
    DEFAULT_COOLDOWN_SECS
}

fn default_min_culprit_mb() -> u64 {
    DEFAULT_MIN_CULPRIT_MB
}

fn check_range(
    path: &Path,
    field: &'static str,
    value: u64,
    min: u64,
    max: u64,
) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::OutOfRange {
            path: path.to_owned(),
            field,
            value,
            min,
            max,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Временный каталог под конфиги тестов: уникален per тест и per
    /// процесс, удаляется в `Drop`.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("swapnotif-config-{label}-{}", std::process::id(),));
            fs::create_dir_all(&dir).expect("создать временный каталог");
            Self(dir)
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, contents).expect("записать временный конфиг");
            path
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_file_returns_defaults() {
        let tmp = TempDir::new("missing");
        let config = Config::load(&tmp.path("absent.toml")).expect("нет файла — дефолты");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn empty_file_returns_defaults() {
        let tmp = TempDir::new("empty");
        let path = tmp.write("empty.toml", "");
        let config = Config::load(&path).expect("пустой файл — дефолты");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn threshold_override_applies() {
        let tmp = TempDir::new("override");
        let path = tmp.write("override.toml", "threshold_pct = 90\n");
        let config = Config::load(&path).expect("валидный конфиг");
        assert_eq!(
            config,
            Config {
                threshold_pct: 90,
                ..Config::default()
            }
        );
    }

    #[test]
    fn invalid_toml_is_error() {
        let tmp = TempDir::new("invalid-toml");
        let path = tmp.write("invalid.toml", "[unclosed\n");
        let err = Config::load(&path).expect_err("битый TOML — ошибка");
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "неожиданная ошибка: {err}"
        );
        assert!(
            err.to_string()
                .contains(path.to_str().expect("путь — UTF-8")),
            "в сообщении нет пути файла: {err}"
        );
    }

    #[test]
    fn unknown_field_is_error() {
        let tmp = TempDir::new("unknown-field");
        let path = tmp.write("unknown.toml", "treshold_pct = 90\n");
        let err = Config::load(&path).expect_err("опечатка в ключе — ошибка");
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "неожиданная ошибка: {err}"
        );
    }

    #[test]
    fn threshold_out_of_range_is_error() {
        let tmp = TempDir::new("out-of-range");
        let path = tmp.write("range.toml", "threshold_pct = 5\n");
        let err = Config::load(&path).expect_err("порог вне диапазона — ошибка");
        assert!(
            matches!(err, ConfigError::OutOfRange { .. }),
            "неожиданная ошибка: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("threshold_pct"), "нет имени поля: {msg}");
        assert!(msg.contains("10–99"), "нет ожидаемого диапазона: {msg}");
    }

    #[test]
    fn window_below_interval_is_error() {
        let tmp = TempDir::new("window-below-interval");
        let path = tmp.write("window.toml", "interval_secs = 60\nwindow_secs = 30\n");
        let err = Config::load(&path).expect_err("окно меньше интервала — ошибка");
        assert!(
            matches!(err, ConfigError::WindowBelowInterval { .. }),
            "неожиданная ошибка: {err}"
        );
        assert!(
            err.to_string().contains("window_secs"),
            "нет имени поля: {err}"
        );
    }

    /// Инвариант гистерезиса: порог 10 + гистерезис 20 (reset_below = −10)
    /// и равные значения (80/80 и 20/20 внутри диапазонов) делают Exceeded
    /// несбрасываемым — ошибка; строго меньше (80/5) — валидно.
    #[test]
    fn hysteresis_not_below_threshold_is_error() {
        let tmp = TempDir::new("hysteresis");
        for contents in [
            "threshold_pct = 10\nhysteresis_pct = 20\n",
            "threshold_pct = 20\nhysteresis_pct = 20\n",
        ] {
            let path = tmp.write("hysteresis.toml", contents);
            let err = Config::load(&path).expect_err("гистерезис ≥ порога — ошибка");
            assert!(
                matches!(err, ConfigError::HysteresisNotBelowThreshold { .. }),
                "неожиданная ошибка: {err}"
            );
            assert!(
                err.to_string()
                    .contains("гистерезис должен быть меньше порога"),
                "нет причины в сообщении: {err}"
            );
        }
        // 80/80 — тоже ошибка (наряду с выходом гистерезиса за диапазон).
        let path = tmp.write(
            "hysteresis-eq.toml",
            "threshold_pct = 80\nhysteresis_pct = 80\n",
        );
        assert!(
            Config::load(&path)
                .expect_err("гистерезис ≥ порога — ошибка")
                .to_string()
                .contains("hysteresis_pct")
        );
        let ok = tmp.write(
            "hysteresis-ok.toml",
            "threshold_pct = 80\nhysteresis_pct = 5\n",
        );
        assert!(Config::load(&ok).is_ok());
    }

    #[test]
    fn snapshot_depth_is_window_over_interval() {
        assert_eq!(Config::default().snapshot_depth(), 12); // 60 с / 5 с
    }

    #[test]
    fn snapshot_depth_is_at_least_one() {
        let window_eq_interval = Config {
            window_secs: 30,
            interval_secs: 30,
            ..Config::default()
        };
        assert_eq!(window_eq_interval.snapshot_depth(), 1);
        // Прямая сборка в обход load: деление дало бы 0 — ограждаемся.
        let window_below_interval = Config {
            window_secs: 5,
            interval_secs: 10,
            ..Config::default()
        };
        assert_eq!(window_below_interval.snapshot_depth(), 1);
    }
}
