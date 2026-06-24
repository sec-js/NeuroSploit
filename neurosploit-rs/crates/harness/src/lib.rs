//! NeuroSploit v3.4.1 harness — a robust multi-model runtime for the
//! markdown-driven autonomous pentest engine.
//!
//! The harness loads the `agents_md/` library, drives a *pool* of LLM models
//! (any OpenAI-compatible provider) with concurrency + provider failover, runs
//! the specialist agents in parallel, then validates every candidate finding by
//! **N-model voting** before scoring and reporting.

pub mod agents;
pub mod models;
pub mod pipeline;
pub mod pool;
pub mod report;
pub mod rl;
pub mod types;

pub use agents::{Agent, Library};
pub use models::{
    cli_binary_for, ensure_playwright_mcp, installed_cli_backends, mcp_supported, provider_for,
    providers, write_mcp_config, ChatClient, ModelRef, Provider,
};
pub use pipeline::{run_whitebox, RunOutput};
pub use pipeline::run;
pub use pool::ModelPool;
pub use types::{Finding, RunConfig};
