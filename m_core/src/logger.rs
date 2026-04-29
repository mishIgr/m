use flexi_logger::{
    Cleanup, Criterion, DeferredNow, FileSpec, Logger as FlexiLogger,
    LoggerHandle, Naming, Record, WriteMode,
};
use log::Level;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::sync::Mutex;

const BASENAME: &str = "m_logger";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    pub log_dir: String,
    pub max_files: usize,
    pub max_file_size: u64,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            log_dir: "/var/log/m_server".to_string(),
            max_files: 5,
            max_file_size: 10 * 1024 * 1024,
        }
    }
}

impl LoggerConfig {
    pub fn min_level() -> Level {
        if cfg!(debug_assertions) {
            Level::Debug
        } else {
            Level::Info
        }
    }

    pub fn with_log_dir(log_dir: impl Into<String>) -> Self {
        Self {
            log_dir: log_dir.into(),
            ..Self::default()
        }
    }

    pub fn set_log_dir(mut self, log_dir: impl Into<String>) -> Self {
        self.log_dir = log_dir.into();
        self
    }

    pub fn set_max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    pub fn set_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_files == 0 {
            return Err("max_files must be > 0".to_string());
        }
        if self.max_file_size == 0 {
            return Err("max_file_size must be > 0".to_string());
        }
        Ok(())
    }

    pub fn from_toml_file(path: &str) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}


fn custom_format(
    w: &mut dyn Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    let level_str = record.level();

    write!(
        w,
        "[{}] [{}] {}",
        now.format("%Y-%m-%d %H:%M:%S"),
        level_str,
        record.args()
    )
}

pub struct Logger {
    config: LoggerConfig,
    _handle: LoggerHandle,
    min_level: Level,
}

impl Logger {
    pub fn new(config: LoggerConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let min_level = LoggerConfig::min_level();

        let handle = FlexiLogger::try_with_env_or_str(min_level.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .format(custom_format)
            .log_to_file(
                FileSpec::default()
                    .directory(&config.log_dir)
                    .basename(BASENAME)
                    .suffix("log"),
            )
            .rotate(
                Criterion::Size(config.max_file_size),
                Naming::Numbers,
                Cleanup::KeepLogFiles(config.max_files),
            )
            .write_mode(WriteMode::BufferAndFlush)
            .start()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            config,
            _handle: handle,
            min_level,
        })
    }

    pub fn with_defaults() -> io::Result<Self> {
        Self::new(LoggerConfig::default())
    }

    pub fn from_toml_file(path: &str) -> io::Result<Self> {
        Self::new(LoggerConfig::from_toml_file(path)?)
    }

    fn should_log(&self, level: Level) -> bool {
        level >= self.min_level
    }

    /// Только в debug-сборке. В release вызов компилируется в ничто.
    pub fn debug(&self, message: &str) {
        #[cfg(debug_assertions)]
        if self.should_log(Level::Debug) {
            log::debug!("{}", message);
        }
    }

    pub fn info(&self, message: &str) {
        if self.should_log(Level::Info) {
            log::info!("{}", message);
        }
    }

    pub fn warn(&self, message: &str) {
        if self.should_log(Level::Warn) {
            log::warn!("{}", message);
        }
    }

    pub fn error(&self, message: &str) {
        if self.should_log(Level::Error) {
            log::error!("{}", message);
        }
    }

    pub fn get_config(&self) -> &LoggerConfig {
        &self.config
    }

    pub fn info_string(&self) -> String {
        format!(
            "Logger: dir={}, max_files={}, max_size={} bytes, min_level={}, build={}",
            self.config.log_dir,
            self.config.max_files,
            self.config.max_file_size,
            self.min_level,
            if cfg!(debug_assertions) { "debug" } else { "release" }
        )
    }
}

static M_LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub fn with_logger<F>(f: F)
where
    F: FnOnce(&Logger),
{
    match M_LOGGER.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(logger) => f(logger),
            None => eprintln!("[m_logger] WARNING: logger is not initialized"),
        },
        Err(e) => eprintln!("[m_logger] ERROR: mutex poisoned: {}", e),
    }
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        // макрос тоже раскрывается в ничто в release
        #[cfg(debug_assertions)]
        $crate::logger::with_logger(|logger| {
            logger.debug(&format!($($arg)*));
        });
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logger::with_logger(|logger| {
            logger.info(&format!($($arg)*));
        });
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logger::with_logger(|logger| {
            logger.warn(&format!($($arg)*));
        });
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logger::with_logger(|logger| {
            logger.error(&format!($($arg)*));
        });
    };
}

pub fn init_logger(config: LoggerConfig) -> io::Result<()> {
    let logger = Logger::new(config)?;
    {
        let mut global = M_LOGGER.lock().unwrap();
        *global = Some(logger);
    }
    log_info!("init logger");
    Ok(())
}

pub fn reconfigure_logger(config: LoggerConfig) -> io::Result<()> {
    let logger = Logger::new(config)?;
    {
        let mut global = M_LOGGER.lock().unwrap();
        *global = Some(logger);
    }
    log_info!("reconfigure logger");
    Ok(())
}
