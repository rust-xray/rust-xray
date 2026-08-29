//! Buffered tracing output with reloadable sinks for `LoggerService.RestartLogger`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use tracing::debug;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::cli::Command;
use crate::config::LogConfig;

const DEFAULT_BUFFERED_LINES: usize = 65_536;

const ENV_BUFFERED_LINES: &str = "RUST_XRAY_LOG_BUFFERED_LINES";
const ENV_BACKPRESSURE: &str = "RUST_XRAY_LOG_BACKPRESSURE";

/// Used when `RUST_LOG` is unset (`EnvFilter` equivalent to `RUST_LOG=error`).
const DEFAULT_TRACE_FILTER: &str = "error";

static LOGGER_CONTROLLER: OnceLock<Arc<RuntimeLoggerController>> = OnceLock::new();
static TRACING_SUBSCRIBER_INIT: OnceLock<()> = OnceLock::new();
static LOGGING_INIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Keeps the `tracing-appender` worker thread alive until process exit.
pub struct LoggingGuard {
    _worker_guard: Option<WorkerGuard>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOutputKind {
    None,
    Console,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogOutputSpec {
    pub kind: LogOutputKind,
    pub path: Option<PathBuf>,
}

impl LogOutputSpec {
    pub fn none() -> Self {
        Self {
            kind: LogOutputKind::None,
            path: None,
        }
    }

    pub fn console() -> Self {
        Self {
            kind: LogOutputKind::Console,
            path: None,
        }
    }

    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            kind: LogOutputKind::File,
            path: Some(path.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggerRuntimeConfig {
    pub error: LogOutputSpec,
    pub access: LogOutputSpec,
    pub dns_log: bool,
}

impl Default for LoggerRuntimeConfig {
    fn default() -> Self {
        Self {
            error: LogOutputSpec::console(),
            access: LogOutputSpec::none(),
            dns_log: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoggerRestartError {
    Unavailable,
    CloseFailed(String),
    StartFailed(String),
}

impl std::fmt::Display for LoggerRestartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "unable to get logger instance"),
            Self::CloseFailed(message) => write!(f, "failed to close logger: {message}"),
            Self::StartFailed(message) => write!(f, "failed to start logger: {message}"),
        }
    }
}

impl std::error::Error for LoggerRestartError {}

#[derive(Clone)]
struct SwapWriter(Arc<Mutex<Box<dyn Write + Send + Sync>>>);

impl Write for SwapWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("logger writer lock").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().expect("logger writer lock").flush()
    }
}

struct ActiveOutputs {
    error: SwapWriter,
    access: Option<SwapWriter>,
}

/// Runtime logger controller backing `LoggerService.RestartLogger`.
pub struct RuntimeLoggerController {
    restart_lock: Mutex<()>,
    config: RwLock<LoggerRuntimeConfig>,
    outputs: RwLock<ActiveOutputs>,
    active: AtomicBool,
    open_failures_remaining: AtomicBool,
}

impl std::fmt::Debug for RuntimeLoggerController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeLoggerController")
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RuntimeLoggerController {
    pub fn global() -> Option<Arc<Self>> {
        LOGGER_CONTROLLER.get().cloned()
    }

    pub fn install_global(self: Arc<Self>) -> Result<(), Arc<Self>> {
        match LOGGER_CONTROLLER.set(Arc::clone(&self)) {
            Ok(()) => Ok(()),
            Err(existing) => Err(existing),
        }
    }

    pub fn runtime_config(&self) -> LoggerRuntimeConfig {
        self.config.read().expect("logger config lock").clone()
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub fn apply_runtime_config(&self, log: Option<&LogConfig>) {
        let parsed = parse_log_runtime_config(log);
        *self.config.write().expect("logger config lock") = parsed;
    }

    pub fn restart(&self) -> Result<(), LoggerRestartError> {
        let _restart_guard = self.restart_lock.lock().expect("logger restart lock");
        self.close()?;
        self.start()?;
        Ok(())
    }

    pub fn close(&self) -> Result<(), LoggerRestartError> {
        let outputs = self.outputs.write().expect("logger outputs lock");
        flush_writer(&outputs.error)?;
        if let Some(access) = outputs.access.as_ref() {
            flush_writer(access)?;
        }
        replace_writer(&outputs.error, inactive_writer());
        if let Some(access) = outputs.access.as_ref() {
            replace_writer(access, inactive_writer());
        }
        self.active.store(false, Ordering::Release);
        Ok(())
    }

    pub fn start(&self) -> Result<(), LoggerRestartError> {
        let config = self.config.read().expect("logger config lock").clone();
        let error = open_output_for_restart(&config.error)
            .map_err(|err| LoggerRestartError::StartFailed(format!("error logger: {err}")))?;
        let access = open_access_output_for_restart(&config.access)
            .map_err(|err| LoggerRestartError::StartFailed(format!("access logger: {err}")))?;

        let mut outputs = self.outputs.write().expect("logger outputs lock");
        replace_writer(&outputs.error, error);
        match (config.access.kind, access) {
            (LogOutputKind::None, None) => {
                outputs.access = None;
            }
            (_, Some(next)) => {
                if let Some(writer) = outputs.access.as_ref() {
                    replace_writer(writer, next);
                } else {
                    outputs.access = Some(SwapWriter(Arc::new(Mutex::new(next))));
                }
            }
            _ => {
                return Err(LoggerRestartError::StartFailed(
                    "access logger state mismatch".to_string(),
                ));
            }
        }
        self.active.store(true, Ordering::Release);
        Ok(())
    }

    pub fn write_access(&self, data: &[u8]) -> io::Result<()> {
        let outputs = self.outputs.read().expect("logger outputs lock");
        if let Some(access) = outputs.access.as_ref() {
            let mut writer = access.0.lock().expect("access writer lock");
            writer.write_all(data)?;
            writer.flush()?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn set_next_open_failure(&self) {
        self.open_failures_remaining.store(true, Ordering::Release);
    }

    fn new(initial_config: LoggerRuntimeConfig) -> io::Result<Arc<Self>> {
        let controller = Arc::new(Self {
            restart_lock: Mutex::new(()),
            config: RwLock::new(initial_config.clone()),
            outputs: RwLock::new(ActiveOutputs {
                error: SwapWriter(Arc::new(Mutex::new(inactive_writer()))),
                access: None,
            }),
            active: AtomicBool::new(false),
            open_failures_remaining: AtomicBool::new(false),
        });
        {
            let mut outputs = controller.outputs.write().expect("logger outputs lock");
            outputs.error = SwapWriter(Arc::new(Mutex::new(open_output(&initial_config.error)?)));
            outputs.access = if initial_config.access.kind == LogOutputKind::None {
                None
            } else {
                Some(SwapWriter(Arc::new(Mutex::new(
                    open_access_output(&initial_config.access)?.unwrap_or_else(inactive_writer),
                ))))
            };
        }
        controller.active.store(true, Ordering::Release);
        Ok(controller)
    }
}

fn inactive_writer() -> Box<dyn Write + Send + Sync> {
    Box::new(io::sink())
}

fn flush_writer(writer: &SwapWriter) -> Result<(), LoggerRestartError> {
    writer
        .0
        .lock()
        .expect("logger writer lock")
        .flush()
        .map_err(|err| LoggerRestartError::CloseFailed(err.to_string()))
}

fn replace_writer(writer: &SwapWriter, next: Box<dyn Write + Send + Sync>) {
    *writer.0.lock().expect("logger writer lock") = next;
}

fn open_output(spec: &LogOutputSpec) -> io::Result<Box<dyn Write + Send + Sync>> {
    match spec.kind {
        LogOutputKind::None => Ok(inactive_writer()),
        LogOutputKind::Console => Ok(Box::new(io::stdout())),
        LogOutputKind::File => {
            let path = spec
                .path
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing log path"))?;
            Ok(Box::new(open_log_file(path)?))
        }
    }
}

fn open_output_for_restart(spec: &LogOutputSpec) -> io::Result<Box<dyn Write + Send + Sync>> {
    if let Some(controller) = LOGGER_CONTROLLER.get() {
        if controller
            .open_failures_remaining
            .swap(false, Ordering::AcqRel)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected logger open failure",
            ));
        }
    }
    open_output(spec)
}

fn open_access_output(spec: &LogOutputSpec) -> io::Result<Option<Box<dyn Write + Send + Sync>>> {
    if spec.kind == LogOutputKind::None {
        return Ok(None);
    }
    open_output(spec).map(Some)
}

fn open_access_output_for_restart(
    spec: &LogOutputSpec,
) -> io::Result<Option<Box<dyn Write + Send + Sync>>> {
    if spec.kind == LogOutputKind::None {
        return Ok(None);
    }
    open_output_for_restart(spec).map(Some)
}

fn open_log_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}

pub fn parse_log_runtime_config(log: Option<&LogConfig>) -> LoggerRuntimeConfig {
    let Some(log) = log else {
        return LoggerRuntimeConfig::default();
    };

    let mut config = LoggerRuntimeConfig {
        dns_log: log.dns_log,
        ..LoggerRuntimeConfig::default()
    };

    if let Some(access) = log.access.as_deref() {
        config.access = parse_output_field(access);
    } else if let Some(access) = log.extra.get("access").and_then(|value| value.as_str()) {
        config.access = parse_output_field(access);
    }

    if let Some(error) = log.error.as_deref() {
        config.error = parse_output_field(error);
    } else if let Some(error) = log.extra.get("error").and_then(|value| value.as_str()) {
        config.error = parse_output_field(error);
    }

    if log
        .loglevel
        .as_deref()
        .is_some_and(|level| level.eq_ignore_ascii_case("none"))
    {
        config.error = LogOutputSpec::none();
        config.access = LogOutputSpec::none();
    }

    config
}

fn parse_output_field(raw: &str) -> LogOutputSpec {
    let value = raw.trim();
    if value.is_empty() {
        LogOutputSpec::console()
    } else if value.eq_ignore_ascii_case("none") {
        LogOutputSpec::none()
    } else {
        LogOutputSpec::file(value)
    }
}

pub fn default_env_filter(command: &Command) -> &'static str {
    let _ = command;
    DEFAULT_TRACE_FILTER
}

pub fn init_logging(command: &Command) -> io::Result<LoggingGuard> {
    init_logging_with_config(command, LoggerRuntimeConfig::default())
}

pub fn init_logging_with_config(
    command: &Command,
    runtime_config: LoggerRuntimeConfig,
) -> io::Result<LoggingGuard> {
    let init_lock = LOGGING_INIT_LOCK.get_or_init(|| Mutex::new(()));
    let _init_guard = init_lock.lock().expect("logging init lock poisoned");

    if TRACING_SUBSCRIBER_INIT.get().is_some() {
        let controller = RuntimeLoggerController::global().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "logger controller is not installed",
            )
        })?;
        *controller.config.write().expect("logger config lock") = runtime_config;
        controller
            .restart()
            .map_err(|err| io::Error::other(err.to_string()))?;
        return Ok(LoggingGuard {
            _worker_guard: None,
        });
    }

    let controller = RuntimeLoggerController::new(runtime_config)?;
    let error_writer = {
        let outputs = controller.outputs.read().expect("logger outputs lock");
        outputs.error.clone()
    };

    let default_filter = default_env_filter(command);
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let buffered_lines = parse_log_buffered_lines_env();
    let backpressure = parse_log_backpressure_env();
    let lossy = !backpressure;

    let (non_blocking, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(buffered_lines)
        .lossy(lossy)
        .finish(error_writer);

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(non_blocking)
        .init();

    let _ = TRACING_SUBSCRIBER_INIT.set(());
    let _ = controller.install_global();

    debug!(
        writer = "reloadable",
        default_filter,
        rust_log_override = std::env::var("RUST_LOG").is_ok(),
        buffered_lines_limit = buffered_lines,
        backpressure,
        lossy,
        "async buffered logging enabled"
    );

    Ok(LoggingGuard {
        _worker_guard: Some(guard),
    })
}

pub fn parse_log_buffered_lines_env() -> usize {
    parse_buffered_lines(std::env::var(ENV_BUFFERED_LINES).ok().as_deref())
}

pub fn parse_log_backpressure_env() -> bool {
    parse_backpressure(std::env::var(ENV_BACKPRESSURE).ok().as_deref())
}

pub fn parse_buffered_lines(value: Option<&str>) -> usize {
    match value {
        Some(raw) => raw.trim().parse().unwrap_or(DEFAULT_BUFFERED_LINES),
        None => DEFAULT_BUFFERED_LINES,
    }
}

pub fn parse_backpressure(value: Option<&str>) -> bool {
    const TRUE: &[&str] = &["1", "true", "yes", "on"];
    matches!(
        value.map(str::trim).filter(|s| !s.is_empty()),
        Some(raw) if TRUE.iter().any(|t| raw.eq_ignore_ascii_case(t))
    )
}

#[cfg(test)]
#[path = "../tests/unit/logging.rs"]
mod tests;
