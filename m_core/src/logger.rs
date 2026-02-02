use flexi_logger::{
    Cleanup, Criterion, DeferredNow, FileSpec, Logger as FlexiLogger,
    LoggerHandle, Naming, Record, WriteMode,
};
use log::{Level};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Write};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Info,
    Crit,
    Secure,
}

impl LogLevel {
    fn from_log_level(level: Level) -> Self {
        match level {
            Level::Info => LogLevel::Info,
            Level::Error => LogLevel::Crit,
            Level::Trace => LogLevel::Secure,
            _ => LogLevel::Info,
        }
    }

    fn to_log_level(&self) -> Level {
        match self {
            LogLevel::Info => Level::Info,
            LogLevel::Crit => Level::Error,
            LogLevel::Secure => Level::Trace,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Crit => "CRIT",
            LogLevel::Secure => "SECURE",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(LogLevel::Info),
            "crit" | "critical" => Some(LogLevel::Crit),
            "secure" => Some(LogLevel::Secure),
            _ => None,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Конфигурация логгера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    pub log_dir: String,
    pub max_files: usize,
    pub max_file_size: u64,
    pub min_level: String,
    #[serde(default = "default_basename")]
    pub basename: String,
}

fn default_basename() -> String {
    "m_logger".to_string()
}

impl Default for LoggerConfig {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        let log_dir = "/var/log/myapp".to_string();

        #[cfg(target_os = "android")]
        let log_dir = "/data/data/com.example.myapp/logs".to_string();

        Self {
            log_dir,
            max_files: 5,
            max_file_size: 10 * 1024 * 1024,
            min_level: "info".to_string(),
            basename: "app".to_string(),
        }
    }
}

impl LoggerConfig {
    pub fn get_log_level(&self) -> LogLevel {
        LogLevel::from_str(&self.min_level).unwrap_or(LogLevel::Info)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_files == 0 {
            return Err("max_files must be > 0".to_string());
        }
        if self.max_file_size == 0 {
            return Err("max_file_size must be > 0".to_string());
        }
        if LogLevel::from_str(&self.min_level).is_none() {
            return Err(format!("invalid min_level: {}", self.min_level));
        }
        Ok(())
    }
}

fn custom_format(
    w: &mut dyn Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level_str = LogLevel::from_log_level(record.level()).as_str();

    let message = record.args().to_string();

    write!(
        w,
        "[{}] [{}] {}",
        now.format("%Y-%m-%d %H:%M:%S"),
        level_str,
        message
    )
}

pub struct Logger {
    config: LoggerConfig,
    _handle: LoggerHandle,
    min_level: LogLevel,
}

impl Logger {
    pub fn new(config: LoggerConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let min_level = config.get_log_level();

        let level_filter = LogLevel::to_log_level(&min_level);

        let logger_builder = FlexiLogger::try_with_env_or_str(level_filter.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .format(custom_format)
            .log_to_file(
                FileSpec::default()
                    .directory(&config.log_dir)
                    .basename(&config.basename)
                    .suffix("log"),
            )
            .rotate(
                Criterion::Size(config.max_file_size),
                Naming::Numbers,
                Cleanup::KeepLogFiles(config.max_files),
            )
            .write_mode(WriteMode::BufferAndFlush);

        let handle = logger_builder
            .start()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            config,
            _handle: handle,
            min_level,
        })
    }

    pub fn from_file(path: &str) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: LoggerConfig = toml::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Self::new(config)
    }

    pub fn with_defaults() -> io::Result<Self> {
        Self::new(LoggerConfig::default())
    }

    fn should_log(&self, level: LogLevel) -> bool {
        level >= self.min_level
    }

    pub fn info(&self, message: &str) {
        if self.should_log(LogLevel::Info) {
            log::info!("{}", message);
        }
    }

    pub fn crit(&self, message: &str) {
        if self.should_log(LogLevel::Crit) {
            log::error!("{}", message);
        }
    }

    #[cfg(feature = "insecure_log")]
    pub fn secure(&self, message: &str) {
        if self.should_log(LogLevel::Secure) {
            log::warn!("{}", message);
        }
    }

    #[cfg(not(feature = "insecure_log"))]
    pub fn secure(&self, _message: &str) {}

    pub fn get_config(&self) -> &LoggerConfig {
        &self.config
    }

    pub fn info_string(&self) -> String {
        format!(
            "Logger: dir={}, max_files={}, max_size={} bytes, min_level={}, insecure_log={}",
            self.config.log_dir,
            self.config.max_files,
            self.config.max_file_size,
            self.min_level,
            cfg!(feature = "insecure_log")
        )
    }
}

static M_LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub fn init_logger(config: LoggerConfig) -> io::Result<()> {
    let logger = Logger::new(config)?;
    let mut global = M_LOGGER.lock().unwrap();
    *global = Some(logger);
    Ok(())
}

pub fn reconfigure_logger(config: LoggerConfig) -> io::Result<()> {
    let mut global = M_LOGGER.lock().unwrap();
    
    if let Some(logger) = global.take() {
        drop(logger);
    }
    
    init_logger(config)
}
