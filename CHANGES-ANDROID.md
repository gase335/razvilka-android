# Правки в вашем коде для Android-порта

Ядро `backend/` (`csqtt-core`) — **без изменений** (идентично исходнику). Все правки —
в `client/` и локализованы под `#[cfg(target_os = "android")]`: десктопные пути
(Windows/Linux) не затронуты. Это подтверждено регрессионной сборкой `client` под хост.

| Файл | Было → стало | Зачем |
|---|---|---|
| `client/src/sys/android.rs` | **новый файл** (~330 строк) | Платформенный слой Android: `TunIo` поверх fd от `VpnService` (`poll`+`eventfd`), `VpnNetwork` (маршруты/DNS делает Kotlin), `set_tun_fd`/`clear_tun_fd`/`set_direct_dns`, заглушки per-app/root. |
| `client/src/sys/mod.rs` | +8 −2 | Третья ветка `cfg`: `windows` → `android` → `other`. |
| `client/src/paths.rs` | +16 −1 | `component()` ищет `geoip.dat` сперва в каталоге данных (на Android — filesDir; рядом с base.apk читать нельзя). Кросс-платформенно-безопасно. |
| `client/src/childhost.rs` | +1 −1 | `into_client_config` стал `pub(crate)` — переиспользуется встроенным запуском на Android. |
| `client/src/engine/session.rs` | +163 −32 | Главная правка (см. ниже). |

## `session.rs` подробно

1. **`process_core_line(...)`** — вынесен общий разбор строки ядра (события
   `__CSQTT_EVENT__|…`, `CAPTCHA_SOLVE|…`, обычные строки). Десктопный цикл чтения
   stdout теперь зовёт его же (рефакторинг без смены поведения — отсюда −32).
2. **`run_child_once` раздвоён по `cfg`:**
   - `#[cfg(not(target_os = "android"))]` — прежний запуск дочернего процесса `--core`
     (без изменений логики).
   - `#[cfg(target_os = "android")]` — **встроенный запуск**: `csqtt_core::run_client`
     в tokio-задаче; события/логи/исключения — через `set_log_callback` +
     `set_exclude_hook` в канал строк; управление — `submit_control_line` /
     `submit_captcha_result`; пакеты — прежний UDP `127.0.0.1`. Супервизор дожидается
     полной остановки ядра перед рестартом (глобали ядра не накладываются).
3. **`send_control` раздвоён по `cfg`:** на Android — в глобальные каналы ядра вместо
   stdin дочернего процесса.
4. **`core_command`** и импорт `tokio::io::{…}` помечены `#[cfg(not(target_os="android"))]`.

## Почему ядро не меняли

`set_log_callback` в `backend/logging.rs` уже отдаёт хосту **и** stdout-события
(`log_output!` → события, `CAPTCHA_SOLVE`), **и** stderr-диагностику — каждую строку
целиком. Поэтому отдельный хук событий не понадобился, а `submit_control_line`,
`submit_captcha_result`, `set_exclude_hook`, `set_events_enabled` уже были в ядре для
встраивания (наследие Android-происхождения csqtt).

## Как пересобрать десктоп
Правки под `cfg(android)` не влияют на Windows/Linux. Ваш обычный процесс сборки
`client` (с `--features gui`) работает как прежде.
