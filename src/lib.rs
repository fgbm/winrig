//! `winrig` — MCP-сервер удалённого администрирования Windows по WinRM/NTLM.
//!
//! Границы модулей зафиксированы в ADR-0003: конфигурация, политика и
//! исполнение отделены от транспорта и тестируются без Windows-хоста.
//! Профиль учётной записи и CLI-настройка введены ADR-0009.

pub mod app;
pub mod auth;
pub mod cli;
pub mod client_config;
pub mod config;
pub mod executor;
pub mod identity;
pub mod logging;
pub mod paths;
pub mod policy;
pub mod private_fs;
pub mod profile;
pub mod ps;
pub mod server;
pub mod session;
