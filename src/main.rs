//! RET — Reverse Engineering Toolkit: the local, evidence-first reverse
//! engineering workbench.
//!
//! Entry point: parse the command line and dispatch to the CLI, which layers
//! on the analysis engine, case file, comparer, renderers, MCP server, web
//! dashboard, and plugin system — all sharing one evidence model.

mod analysis;
mod batch;
mod cli;
mod compare;
mod core;
mod mcp;
mod output;
mod plugins;
mod report;
mod web;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("ret: {e}");
        std::process::exit(1);
    }
}
