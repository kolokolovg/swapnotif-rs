//! Библиотечная часть `swapnotif-rs`.
//!
//! Логика приложения живёт здесь, чтобы её можно было покрыть тестами;
//! бинарный крейт ([`main.rs`]) — тонкий диспетчер поверх этого API.

pub mod config;
pub mod daemon;

mod attribute;
mod monitor;
/// Публичен для одноразового режима точки входа: `main.rs` до подъёма
/// рантайма демона разбирает argv (`notify::parse_helper_args`) и
/// выполняет `notify::notify_once` от uid сессии (self-exec доставка,
/// обновление design D6).
pub mod notify;
