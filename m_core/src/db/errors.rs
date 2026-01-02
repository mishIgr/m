use thiserror::Error;

#[derive(Error, Debug)]
pub enum KvError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Key not found")]
    NotFound,
    
    #[error("Table not found: {0}")]
    TableNotFound(String),
}

impl From<redb::Error> for KvError {
    fn from(e: redb::Error) -> Self {
        KvError::Database(e.to_string())
    }
}

impl From<redb::DatabaseError> for KvError {
    fn from(e: redb::DatabaseError) -> Self {
        KvError::Database(e.to_string())
    }
}

impl From<redb::TableError> for KvError {
    fn from(e: redb::TableError) -> Self {
        KvError::Database(e.to_string())
    }
}

impl From<redb::TransactionError> for KvError {
    fn from(e: redb::TransactionError) -> Self {
        KvError::Database(e.to_string())
    }
}

impl From<redb::StorageError> for KvError {
    fn from(e: redb::StorageError) -> Self {
        KvError::Database(e.to_string())
    }
}

impl From<redb::CommitError> for KvError {
    fn from(e: redb::CommitError) -> Self {
        KvError::Database(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, KvError>;
