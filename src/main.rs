//! Тонкий composition root: диспетчер одноразового режима доставки
//! (`notify-session`), инициализация логов, загрузка конфига
//! (fail-fast, design D8) и запуск демона до сигнала остановки
//! (Ctrl-C или SIGTERM). Вся логика — в библиотечных модулях.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use tokio::select;
use tracing_subscriber::EnvFilter;

use swapnotif_rs::config::{self, Config};
use swapnotif_rs::daemon;
use swapnotif_rs::notify;

/// Фильтр логов по умолчанию, если `RUST_LOG` не задан или невалиден.
const DEFAULT_LOG_FILTER: &str = "info";

fn main() -> ExitCode {
    // Одноразовый режим разбирается первым, до какой-либо инициализации
    // демона: ребёнок self-exec доставки молчит (без tracing), его
    // сообщение — единственная строка stderr. eprintln здесь —
    // задокументированное исключение из конвенции «только tracing»:
    // это хелпер, а не демон.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if !argv.is_empty() {
        return run_helper(&argv);
    }

    // Логи — stdout → journald (systemd `StandardOutput=journal`);
    // фильтрация по `RUST_LOG` с дефолтом `info`.
    let env_filter = EnvFilter::try_from_default_env();
    let invalid_rust_log = match &env_filter {
        // RUST_LOG задан, но не разобран: причину сообщим после init
        // (warn до подписчика теряется), а не молча уходим в дефолт.
        Err(error) if std::env::var_os("RUST_LOG").is_some() => Some(error.to_string()),
        _ => None,
    };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter.unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER)))
        .init();
    if let Some(error) = invalid_rust_log {
        tracing::warn!(
            error,
            "RUST_LOG задан, но не разобран — используется дефолт «info»"
        );
    }

    // Fail-fast (спека «Конфигурация с дефолтами», D8): невалидный
    // конфиг — ошибка с кодом 1; `Restart=on-failure` + `StartLimit`
    // остановят цикл перезапусков — осознанное поведение.
    let config = match Config::load(Path::new(config::DEFAULT_PATH)) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("ошибка конфигурации: {error}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        threshold_pct = config.threshold_pct,
        hysteresis_pct = config.hysteresis_pct,
        interval_secs = config.interval_secs,
        window_secs = config.window_secs,
        cooldown_secs = config.cooldown_secs,
        "старт демона мониторинга swap"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("токийский рантайм собран");

    let result = runtime.block_on(daemon::run(config, shutdown_signal()));
    runtime.shutdown_timeout(Duration::from_secs(1));

    match result {
        Ok(()) => {
            tracing::info!("демон остановлен");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!("ошибка демона: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Диспетчер одноразового режима доставки (`notify-session <uid>
/// <summary> <body>` — ребёнок self-exec от uid сессии, обновление
/// design D6): 0 — доставлено, 1 — не доставлено, 2 — плохие
/// аргументы (не та подкоманда, нечисловой uid, неверное их число).
fn run_helper(argv: &[String]) -> ExitCode {
    let Some(args) = notify::parse_helper_args(argv) else {
        eprintln!("неизвестные аргументы: {}", argv.join(" "));
        return ExitCode::from(2);
    };
    match notify::notify_once(args.uid, &args.summary, &args.body) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Завершение по Ctrl-C ИЛИ SIGTERM (путь systemd): мгновенный
/// graceful выход — future резолвится на первый пришедший сигнал.
async fn shutdown_signal() {
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("обработчик SIGTERM установлен")
            .recv()
            .await;
    };
    select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm => {}
    }
}
