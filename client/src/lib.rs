// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Razvilka — портативный клиент протокола csqtt (форк FOCSQ) с раздельным
//! туннелированием, правилами приложений, несколькими конфигурациями
//! и режимом прокси-сервера.

pub mod app_config;
pub mod childhost;
pub mod engine;
#[cfg(feature = "gui")]
pub mod gui;
pub mod headless;
#[cfg(feature = "mock")]
pub mod mock;
pub mod net;
pub mod paths;
pub mod rules;
pub mod sys;
#[cfg(feature = "webview")]
pub mod webview;
