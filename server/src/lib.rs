//! Rust facade mirroring the ONEAI MCP server C header.
//! Exposes a safe, idiomatic API while keeping the same shape for FFI parity.

pub mod rmcp_server;

pub use rmcp_server::*;
