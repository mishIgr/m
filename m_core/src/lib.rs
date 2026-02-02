pub mod codecs;
pub mod config;
pub mod crypto;

mod logger;

pub use config::Config;
pub use logger::{init_logger, reconfigure_logger, Logger, LoggerConfig};

#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        $logger.info(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_crit {
    ($logger:expr, $($arg:tt)*) => {
        $logger.crit(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_secure {
    ($logger:expr, $($arg:tt)*) => {
        $logger.secure(&format!($($arg)*))
    };
}
