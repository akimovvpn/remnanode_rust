//! rcore: Rust port of the Xray-core subset Remnawave Node drives, with Xray's CLI and config format.
mod api;
mod app;
mod browser;
mod config;
#[cfg(test)]
mod fuzz;
mod geodata;
mod mux;
mod reality;
mod reality_probe;
mod reality_profile;
mod router;
mod sniff;
mod socket;
mod socks;
mod stats;
mod tls13;
mod tls_client;
mod transport;
mod vision;
mod vless;
mod vless_out;
mod xhttp;

use anyhow::{Context, Result};
use std::process::ExitCode;

pub fn log_time() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:06}", now.as_secs(), now.subsec_micros())
}

fn version() -> String {
    format!(
        "Xray {}-rcore.{} (rcore: Rust port of Xray-core v{}, {} {})",
        config::VERSION,
        env!("CARGO_PKG_VERSION"),
        config::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

fn load(path: &str) -> Result<config::Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {path}"))?;
    config::Config::parse(&text).context("failed to load config files")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["version" | "-version" | "--version", ..] => {
            println!("{}", version());
            ExitCode::SUCCESS
        }
        ["run", rest @ ..] | rest @ [..] => {
            let test = rest.contains(&"-test");
            let config = rest
                .iter()
                .position(|a| matches!(*a, "-config" | "-c" | "--config"))
                .and_then(|i| rest.get(i + 1))
                .copied()
                .unwrap_or("config.json");
            println!("{}", version());
            let parsed = match load(config) {
                Ok(parsed) => parsed,
                Err(error) => {
                    println!("Failed to start: {error:#}");
                    return ExitCode::from(23);
                }
            };
            if test {
                println!("Configuration OK.");
                return ExitCode::SUCCESS;
            }
            let level = match parsed.log_level.as_str() {
                "debug" => "debug",
                "info" => "info",
                "error" => "error",
                "none" => "off",
                _ => "warn",
            };
            let logs = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(level))
                .with_target(false);
            match parsed.error_log.as_deref().map(|p| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
            }) {
                Some(Ok(file)) => logs
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .init(),
                Some(Err(error)) => {
                    println!("Failed to start: failed to open error log: {error}");
                    return ExitCode::from(23);
                }
                None => logs.init(),
            }
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            runtime.block_on(async move {
                let instance = match app::Instance::new(parsed) {
                    Ok(instance) => instance,
                    Err(error) => {
                        println!("Failed to start: {error:#}");
                        return ExitCode::from(23);
                    }
                };
                if let Err(error) = instance.start().await {
                    println!("Failed to start: {error:#}");
                    return ExitCode::from(23);
                }
                tracing::warn!("Xray {} (rcore) started", config::VERSION);
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                ExitCode::SUCCESS
            })
        }
    }
}
