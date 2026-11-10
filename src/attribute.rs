//! Атрибуция виновника свопинга (спека `swap-usage-attribution`, дизайн
//! D3/D4): кольцевое окно снапшотов `VmSwap` per-pid, дельты за окно по
//! ключу `(pid, starttime)`, группировка процессов по cgroup v2 до
//! уровня приложения и выбор виновника события превышения. КиБ —
//! базовая единица модуля; конверсия МиБ→КиБ (порог значимости)
//! выполняется в одном месте — [`Attributor::attribute`].

use std::collections::{HashMap, VecDeque};

use crate::monitor::ProcEntry;

/// Ключ процесса в снапшотах: пара `(pid, starttime)` из
/// `/proc/<pid>/stat` защищает от переиспользования PID (design D3) —
/// переиспользованный PID получает другой starttime и не наследует
/// свап-след старого процесса.
type ProcKey = (u32, u64);

/// КиБ в одном МиБ: порог значимости задаётся конфигом в МиБ, дельты
/// модуль считает в КиБ (конвенция: конверсии единиц в одном месте).
const KIB_PER_MIB: u64 = 1024;

/// Результат атрибуции: приложение с наибольшим приростом swap за окно
/// и величина этого прироста, КиБ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribution {
    /// Имя приложения-виновника; `None` — «приложение не определено»
    /// (прирост ниже порога значимости либо окно пусто).
    pub app_name: Option<String>,
    /// Прирост swap виновника за окно, КиБ; сообщается и без имени.
    pub delta_kb: u64,
}

/// Группировочные данные процесса из последнего снапшота: по ним дельта
/// живого процесса относится к группе приложения.
struct Grouping {
    /// comm из `/proc/<pid>/status` — fallback-имя группы (design D4).
    comm: String,
    /// Путь cgroup v2 из `/proc/<pid>/cgroup` — ключ группы; `None` —
    /// cgroup v1 или путь не прочитан, группировка по comm.
    cgroup: Option<String>,
}

/// Суммарный прирост swap одной группы (юнит cgroup либо comm) за окно.
struct GroupTotal {
    /// Отображаемое имя группы: последний сегмент cgroup-пути без
    /// суффикса `.service`, fallback — comm (design D4).
    name: String,
    /// Сумма приростов процессов группы, КиБ.
    delta_kb: u64,
}

/// Хранилище снапшотов занятости swap и расчёт виновника события:
/// кольцевой буфер глубиной `окно / интервал` (design D3).
pub(crate) struct Attributor {
    /// Снапшоты окна, от старейшего к текущему: `VmSwap` (КиБ) по ключу
    /// `(pid, starttime)`.
    snapshots: VecDeque<HashMap<ProcKey, u64>>,
    /// Группировочные данные процессов последнего снапшота: в атрибуции
    /// участвуют только живые на момент расчёта процессы.
    grouping: HashMap<ProcKey, Grouping>,
    /// Глубина окна в снапшотах (`Config::snapshot_depth()`, ≥ 1).
    depth: usize,
}

impl Attributor {
    /// Создаёт атрибутор с окном глубины `snapshot_depth` снапшотов
    /// (глубина передаётся снаружи из `Config::snapshot_depth()`).
    pub(crate) fn new(snapshot_depth: usize) -> Self {
        Self {
            snapshots: VecDeque::with_capacity(snapshot_depth),
            grouping: HashMap::new(),
            depth: snapshot_depth,
        }
    }

    /// Принимает текущий снапшот процессов со swap-следом (вызывается
    /// каждый цикл мониторинга) и сдвигает окно: снапшотов старше
    /// `depth` в кольце не остаётся — следы умерших процессов вытесняются
    /// вместе со своими снапшотами.
    pub(crate) fn observe(&mut self, entries: &[ProcEntry]) {
        let mut snapshot = HashMap::with_capacity(entries.len());
        let mut grouping = HashMap::with_capacity(entries.len());
        for entry in entries {
            let key = (entry.pid, entry.starttime);
            snapshot.insert(key, entry.vm_swap_kb);
            grouping.insert(
                key,
                Grouping {
                    comm: entry.comm.clone(),
                    cgroup: entry.cgroup.clone(),
                },
            );
        }
        self.snapshots.push_back(snapshot);
        while self.snapshots.len() > self.depth {
            self.snapshots.pop_front();
        }
        self.grouping = grouping;
    }

    /// Считает виновника по накопленному окну, не мутируя буфер:
    /// дельты за окно группируются по приложениям, побеждает группа с
    /// максимальным суммарным приростом; прирост ниже `min_culprit_mib`
    /// — «приложение не определено» (спека `swap-usage-attribution`).
    pub(crate) fn attribute(&self, min_culprit_mib: u64) -> Attribution {
        let Some(best) = self.top_group(self.window_deltas()) else {
            return Attribution {
                app_name: None,
                delta_kb: 0,
            };
        };
        // Порог значимости задан в МиБ, дельты — в КиБ; конверсия в
        // одном месте. Ниже порога имя не сообщается, прирост — сообщается.
        let min_culprit_kb = min_culprit_mib.saturating_mul(KIB_PER_MIB);
        if best.delta_kb < min_culprit_kb {
            Attribution {
                app_name: None,
                delta_kb: best.delta_kb,
            }
        } else {
            Attribution {
                app_name: Some(best.name),
                delta_kb: best.delta_kb,
            }
        }
    }

    /// Дельты прироста swap за окно по живым ключам, КиБ (спека «Дельты
    /// за окно атрибуции», design D3): текущий снапшот − старейший
    /// снапшот окна; ключа в старейшем нет → прирост от 0; отрицательная
    /// дельта → 0. Умерший процесс в текущем снапшоте отсутствует и
    /// дельту не получает.
    fn window_deltas(&self) -> Vec<(ProcKey, u64)> {
        let (Some(oldest), Some(current)) = (self.snapshots.front(), self.snapshots.back()) else {
            return Vec::new(); // окно ещё пустое (до первого observe)
        };
        current
            .iter()
            .filter_map(|(key, swap_kb)| {
                let base = oldest.get(key).copied().unwrap_or_default();
                let delta = swap_kb.saturating_sub(base);
                (delta > 0).then_some((*key, delta))
            })
            .collect()
    }

    /// Группирует дельты по приложениям (ключ группы — полный путь
    /// cgroup v2, fallback — comm, design D4), суммирует вклады и
    /// возвращает группу с максимальным приростом (спека «Выбор
    /// виновника»). Равные приросты разрешаются лексикографически
    /// меньшим именем — результат не зависит от порядка итерации
    /// HashMap.
    fn top_group(&self, mut deltas: Vec<(ProcKey, u64)>) -> Option<GroupTotal> {
        // Убывание дельты, затем ключ: отображаемое имя группы (fallback
        // comm при пустом сегменте cgroup) берётся у крупнейшего
        // вкладчика группы детерминированно.
        deltas.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut groups: HashMap<&str, GroupTotal> = HashMap::new();
        for (key, delta) in deltas {
            // Инвариант: grouping строится в observe из тех же записей,
            // что и последний снапшот кольца, поэтому ключ обязан найтись.
            let grouping = self
                .grouping
                .get(&key)
                .expect("ключ текущего снапшота есть в grouping по построению observe");
            let (group_key, name) = match &grouping.cgroup {
                Some(path) => (
                    path.as_str(),
                    unit_name(path).unwrap_or(grouping.comm.as_str()),
                ),
                None => (grouping.comm.as_str(), grouping.comm.as_str()),
            };
            let group = groups.entry(group_key).or_insert_with(|| GroupTotal {
                name: name.to_owned(),
                delta_kb: 0,
            });
            // saturating: сумма вкладов группы — та же ограда от
            // переполнения, что и в остальной арифметике модуля.
            group.delta_kb = group.delta_kb.saturating_add(delta);
        }
        groups.into_values().max_by(|a, b| {
            a.delta_kb
                .cmp(&b.delta_kb)
                .then_with(|| a.name.cmp(&b.name))
        })
    }
}

/// Отображаемое имя группы из пути cgroup: последний сегмент без
/// суффикса `.service` (design D4). `None` — сегмент пуст (корень
/// cgroup): вызывающий откатывается на comm процесса.
fn unit_name(cgroup_path: &str) -> Option<&str> {
    let segment = cgroup_path.rsplit('/').next()?;
    let name = segment.strip_suffix(".service").unwrap_or(segment);
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Спека «Порог значимости виновника»: минимальный вес, МиБ.
    const MIN_CULPRIT_MIB: u64 = 50;

    /// Глубина окна в тестах: 3 снапшота достаточно, чтобы проверить
    /// вытеснение старейшего кольцом.
    const TEST_DEPTH: usize = 3;

    /// Синтетический путь cgroup v2 (имена юнитов условные).
    const UNIT_CGROUP: &str = "/user.slice/app.slice/app-demo.service";

    /// Путь второго юнита: независимая группа для сравнения вкладов.
    const OTHER_UNIT_CGROUP: &str = "/system.slice/app-other.service";

    /// Переводит МиБ в КиБ (1 МБ = 1024 КиБ): размеры в тестах задаём в
    /// МиБ, модуль считает в КиБ.
    fn mib(mib: u64) -> u64 {
        mib * KIB_PER_MIB
    }

    /// Хелпер-конструктор записи процесса: `vm_swap_mib` в МиБ.
    fn entry(
        pid: u32,
        starttime: u64,
        vm_swap_mib: u64,
        comm: &str,
        cgroup: Option<&str>,
    ) -> ProcEntry {
        ProcEntry {
            pid,
            starttime,
            vm_swap_kb: mib(vm_swap_mib),
            comm: comm.to_owned(),
            cgroup: cgroup.map(str::to_owned),
        }
    }

    /// Спека «Прирост за окно»: 100 МБ в начале окна → 300 МБ в конце =
    /// 200 МБ; база дельты — старейший снапшот окна.
    #[test]
    fn attribute_growth_over_window_from_oldest_snapshot() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        for swap_mib in [100, 200, 300] {
            attributor.observe(&[entry(1, 10, swap_mib, "demo-a", Some(UNIT_CGROUP))]);
        }
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("app-demo".to_owned()),
                delta_kb: mib(200),
            }
        );
        // Четвёртый снапшот вытесняет старейший (100 МБ) из окна
        // глубиной 3: базой становится 200 МБ, прирост не «помнит»
        // вытесненный снапшот.
        attributor.observe(&[entry(1, 10, 400, "demo-a", Some(UNIT_CGROUP))]);
        assert_eq!(attributor.attribute(MIN_CULPRIT_MIB).delta_kb, mib(200));
    }

    /// Спека «Отрицательная дельта трактуется как ноль»: занятость за
    /// окно уменьшилась → прирост для атрибуции равен 0.
    #[test]
    fn attribute_negative_delta_is_zero() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[entry(1, 10, 300, "demo-a", Some(UNIT_CGROUP))]);
        attributor.observe(&[entry(1, 10, 100, "demo-a", Some(UNIT_CGROUP))]);
        // Нулевой прирост ниже порога значимости — приложение не определено.
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: None,
                delta_kb: 0,
            }
        );
    }

    /// Спека «Завершение процесса между снапшотами»: записи умершего нет
    /// в новом снапшоте, это не ошибка мониторинга, его вклад пропадает;
    /// расчёт остальных продолжается.
    #[test]
    fn attribute_dead_process_excluded() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[
            entry(1, 10, 100, "gone", Some(OTHER_UNIT_CGROUP)),
            entry(2, 20, 100, "demo-a", Some(UNIT_CGROUP)),
        ]);
        // pid 1 завершился; pid 2 вырос на 50 МБ от базовых 100 МБ.
        attributor.observe(&[entry(2, 20, 150, "demo-a", Some(UNIT_CGROUP))]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("app-demo".to_owned()),
                delta_kb: mib(50),
            }
        );
    }

    /// Спека «Переиспользованный PID не наследует след»: тот же pid с
    /// другим starttime — другой ключ; прирост нового процесса считается
    /// от 0 (300 МБ), а не от следа старого (100 МБ).
    #[test]
    fn attribute_pid_reuse_starts_from_zero() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[entry(7, 100, 100, "old-proc", None)]);
        attributor.observe(&[entry(7, 999, 300, "new-proc", None)]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("new-proc".to_owned()),
                delta_kb: mib(300),
            }
        );
    }

    /// Спека «Вклад нескольких процессов одного приложения
    /// суммируется»: +100 МБ и +50 МБ в одной cgroup → вклад приложения
    /// 150 МБ, а не максимум из процессов.
    #[test]
    fn attribute_same_cgroup_contributions_sum() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[
            entry(1, 10, 50, "demo-a", Some(UNIT_CGROUP)),
            entry(2, 20, 30, "demo-b", Some(UNIT_CGROUP)),
        ]);
        attributor.observe(&[
            entry(1, 10, 150, "demo-a", Some(UNIT_CGROUP)),
            entry(2, 20, 80, "demo-b", Some(UNIT_CGROUP)),
        ]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("app-demo".to_owned()),
                delta_kb: mib(150),
            }
        );
    }

    /// Спека «Имя виновника»: имя берётся из последнего сегмента
    /// cgroup-пути без суффикса `.service`
    /// (…/app-firefox.service → «app-firefox»).
    #[test]
    fn attribute_unit_name_strips_service_suffix() {
        let path = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.service";
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[entry(1, 10, 100, "demo-firefox", Some(path))]);
        attributor.observe(&[entry(1, 10, 300, "demo-firefox", Some(path))]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("app-firefox".to_owned()),
                delta_kb: mib(200),
            }
        );
    }

    /// Спека «Имя виновника», fallback: cgroup недоступна (None) → имя
    /// приложения из comm процесса.
    #[test]
    fn attribute_fallback_name_is_comm() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[entry(1, 10, 100, "legacy-app", None)]);
        attributor.observe(&[entry(1, 10, 200, "legacy-app", None)]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("legacy-app".to_owned()),
                delta_kb: mib(100),
            }
        );
    }

    /// Design D4, деградация cgroup v1 (строки `0::` нет → cgroup
    /// None): группы по cgroup не строятся, процессы группируются по
    /// comm — два процесса «worker» образуют одну группу.
    #[test]
    fn attribute_cgroup_v1_groups_by_comm() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[
            entry(1, 10, 50, "worker", None),
            entry(2, 20, 30, "worker", None),
        ]);
        attributor.observe(&[
            entry(1, 10, 150, "worker", None),
            entry(2, 20, 80, "worker", None),
        ]);
        // 100 МБ + 50 МБ = 150 МБ на группу comm «worker».
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("worker".to_owned()),
                delta_kb: mib(150),
            }
        );
    }

    /// Спека «Выбор максимума»: приложения выросли на 850 МБ и 300 МБ —
    /// виновником признаётся первое.
    #[test]
    fn attribute_max_growth_wins() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        attributor.observe(&[
            entry(1, 10, 100, "big", Some(UNIT_CGROUP)),
            entry(2, 20, 100, "small", Some(OTHER_UNIT_CGROUP)),
        ]);
        attributor.observe(&[
            entry(1, 10, 950, "big", Some(UNIT_CGROUP)),
            entry(2, 20, 400, "small", Some(OTHER_UNIT_CGROUP)),
        ]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: Some("app-demo".to_owned()),
                delta_kb: mib(850),
            }
        );
    }

    /// Спека «Порог значимости виновника»: прирост 2 МБ < 50 МБ →
    /// «приложение не определено» (прирост всё равно сообщается);
    /// прирост ровно 50 МБ (граница «меньше») и 500 МБ атрибуируется.
    #[test]
    fn attribute_min_culprit_threshold() {
        let scenarios = [
            (
                102_u64,
                100,
                Attribution {
                    app_name: None,
                    delta_kb: mib(2),
                },
            ),
            (
                150,
                100,
                Attribution {
                    app_name: Some("app-demo".to_owned()),
                    delta_kb: mib(50),
                },
            ),
            (
                600,
                100,
                Attribution {
                    app_name: Some("app-demo".to_owned()),
                    delta_kb: mib(500),
                },
            ),
        ];
        for (now_mib, before_mib, expected) in scenarios {
            let mut attributor = Attributor::new(TEST_DEPTH);
            attributor.observe(&[entry(1, 10, before_mib, "demo-a", Some(UNIT_CGROUP))]);
            attributor.observe(&[entry(1, 10, now_mib, "demo-a", Some(UNIT_CGROUP))]);
            assert_eq!(attributor.attribute(MIN_CULPRIT_MIB), expected);
        }
    }

    /// Пустое окно (до первого observe или снапшот без swap-следа) —
    /// не ошибка: «приложение не определено», нулевой прирост.
    #[test]
    fn attribute_empty_window_is_unknown() {
        let mut attributor = Attributor::new(TEST_DEPTH);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: None,
                delta_kb: 0,
            }
        );
        attributor.observe(&[]);
        assert_eq!(
            attributor.attribute(MIN_CULPRIT_MIB),
            Attribution {
                app_name: None,
                delta_kb: 0,
            }
        );
    }
}
