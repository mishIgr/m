pub mod errors;
pub mod redb;

pub use errors::{KvError, Result};
pub use redb::{RedbStore, RedbTable, BatchWriter};

use serde::{de::DeserializeOwned, Serialize};

pub trait KvKey: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }
}

pub trait KvValue: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }
}

impl<T> KvKey for T where T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}
impl<T> KvValue for T where T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {}

pub trait Table<K: KvKey, V: KvValue> {
    fn get(&self, key: &K) -> Result<Option<V>>;
    
    fn put(&self, key: &K, value: &V) -> Result<()>;
    
    fn delete(&self, key: &K) -> Result<Option<V>>;
    
    fn contains(&self, key: &K) -> Result<bool>;
    
    fn iter(&self) -> Result<Vec<(K, V)>>;
    
    fn len(&self) -> Result<u64>;
    
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

pub trait KvStore: Send + Sync {
    type Table<K: KvKey, V: KvValue>: Table<K, V>;
    
    fn table<K: KvKey, V: KvValue>(&self, name: &str) -> Result<Self::Table<K, V>>;
    
    fn drop_table(&self, name: &str) -> Result<()>;
    
    fn list_tables(&self) -> Result<Vec<String>>;
}
