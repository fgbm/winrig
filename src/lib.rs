//! `winrig` is an MCP server for remote administration of Windows hosts over WinRM/NTLM.
//!
//! ADR-0003 fixes the module boundaries: configuration, policy and execution stay
//! separate from the transport and are tested without a Windows host. ADR-0009
//! introduced the account profile and the CLI setup.

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
