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

/// common/log: Go's "2006/01/02 15:04:05.000000" in local time.
pub fn log_time() -> String {
    chrono::Local::now()
        .format("%Y/%m/%d %H:%M:%S%.6f")
        .to_string()
}

/// common/log GeneralMessage: "<time> [Info] <message>", as Xray writes its error log.
struct GoFormat;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for GoFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "Error",
            tracing::Level::WARN => "Warning",
            tracing::Level::INFO => "Info",
            _ => "Debug",
        };
        write!(writer, "{} [{level}] ", log_time())?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
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
                .with_ansi(false)
                .with_env_filter(tracing_subscriber::EnvFilter::new(level))
                .event_format(GoFormat);
            match parsed.error_log.as_deref().map(|p| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
            }) {
                Some(Ok(file)) => logs.with_writer(std::sync::Mutex::new(file)).init(),
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
                tracing::warn!("core: Xray {} started", config::VERSION);
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                ExitCode::SUCCESS
            })
        }
    }
}
