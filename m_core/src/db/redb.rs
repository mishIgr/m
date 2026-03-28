use super::{Result, KvKey, KvStore, KvValue, Table};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableHandle, ReadableTableMetadata};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = Database::create(path)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn in_memory() -> Result<Self> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl KvStore for RedbStore {
    type Table<K: KvKey, V: KvValue> = RedbTable<K, V>;

    fn table<K: KvKey, V: KvValue>(&self, name: &str) -> Result<Self::Table<K, V>> {
        Ok(RedbTable {
            db: self.db.clone(),
            name: name.to_string(),
            _phantom: PhantomData,
        })
    }

    fn drop_table(&self, name: &str) -> Result<()> {
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(name);
        let write_txn = self.db.begin_write()?;
        let _ = write_txn.delete_table(table_def);
        write_txn.commit()?;
        Ok(())
    }

    fn list_tables(&self) -> Result<Vec<String>> {
        let read_txn = self.db.begin_read()?;
        let tables: Vec<String> = read_txn
            .list_tables()?
            .map(|t| t.name().to_string())
            .collect();
        Ok(tables)
    }
}

pub struct RedbTable<K: KvKey, V: KvValue> {
    db: Arc<Database>,
    name: String,
    _phantom: PhantomData<(K, V)>,
}

impl<K: KvKey, V: KvValue> Table<K, V> for RedbTable<K, V> {
    fn get(&self, key: &K) -> Result<Option<V>> {
        let key_bytes = key.to_bytes()?;
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.name.as_str());
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        match table.get(key_bytes.as_slice())? {
            Some(value) => {
                let v = V::from_bytes(value.value())?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    fn put(&self, key: &K, value: &V) -> Result<()> {
        let key_bytes = key.to_bytes()?;
        let value_bytes = value.to_bytes()?;
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.name.as_str());

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(table_def)?;
            table.insert(key_bytes.as_slice(), value_bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn delete(&self, key: &K) -> Result<Option<V>> {
        let key_bytes = key.to_bytes()?;

        let existing = self.get(key)?;
        if existing.is_none() {
            return Ok(None);
        }

        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.name.as_str());
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(table_def)?;
            table.remove(key_bytes.as_slice())?;
        }
        write_txn.commit()?;

        Ok(existing)
    }


    fn contains(&self, key: &K) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    fn iter(&self) -> Result<Vec<(K, V)>> {
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.name.as_str());
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut results = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            let key = K::from_bytes(k.value())?;
            let value = V::from_bytes(v.value())?;
            results.push((key, value));
        }

        Ok(results)
    }

    fn len(&self) -> Result<u64> {
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(self.name.as_str());
        let read_txn = self.db.begin_read()?;

        let table = match read_txn.open_table(table_def) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        Ok(table.len()?)
    }
}

impl RedbStore {
    pub fn batch<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&BatchWriter) -> Result<R>,
    {
        let write_txn = self.db.begin_write()?;
        let writer = BatchWriter { txn: &write_txn };
        let result = f(&writer)?;
        write_txn.commit()?;
        Ok(result)
    }
}

pub struct BatchWriter<'a> {
    txn: &'a redb::WriteTransaction,
}

impl<'a> BatchWriter<'a> {
    pub fn put<K: KvKey, V: KvValue>(
        &self,
        table_name: &str,
        key: &K,
        value: &V,
    ) -> Result<()> {
        let key_bytes = key.to_bytes()?;
        let value_bytes = value.to_bytes()?;
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(table_name);

        let mut table = self.txn.open_table(table_def)?;
        table.insert(key_bytes.as_slice(), value_bytes.as_slice())?;
        Ok(())
    }

    pub fn delete<K: KvKey>(&self, table_name: &str, key: &K) -> Result<()> {
        let key_bytes = key.to_bytes()?;
        let table_def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(table_name);

        let mut table = self.txn.open_table(table_def)?;
        table.remove(key_bytes.as_slice())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_existing_key() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&42u64, &"hello".to_string()).unwrap();
        assert_eq!(table.get(&42u64).unwrap(), Some("hello".to_string()));
    }

    #[test]
    fn test_get_missing_key() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        assert_eq!(table.get(&999u64).unwrap(), None);
    }

    #[test]
    fn test_get_from_empty_table() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("empty").unwrap();

        assert_eq!(table.get(&1u64).unwrap(), None);
    }

    #[test]
    fn test_get_after_overwrite() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"first".to_string()).unwrap();
        table.put(&1u64, &"second".to_string()).unwrap();

        assert_eq!(table.get(&1u64).unwrap(), Some("second".to_string()));
    }

    #[test]
    fn test_get_multiple_keys_independently() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"one".to_string()).unwrap();
        table.put(&2u64, &"two".to_string()).unwrap();
        table.put(&3u64, &"three".to_string()).unwrap();

        assert_eq!(table.get(&1u64).unwrap(), Some("one".to_string()));
        assert_eq!(table.get(&2u64).unwrap(), Some("two".to_string()));
        assert_eq!(table.get(&3u64).unwrap(), Some("three".to_string()));
        assert_eq!(table.get(&4u64).unwrap(), None);
    }

    #[test]
    fn test_put_single_entry() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"value".to_string()).unwrap();
        assert_eq!(table.len().unwrap(), 1);
    }

    #[test]
    fn test_put_overwrites_existing() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"old".to_string()).unwrap();
        table.put(&1u64, &"new".to_string()).unwrap();

        assert_eq!(table.len().unwrap(), 1);
        assert_eq!(table.get(&1u64).unwrap(), Some("new".to_string()));
    }

    #[test]
    fn test_put_many_entries() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, u64>("t").unwrap();

        for i in 0u64..1000 {
            table.put(&i, &(i * 2)).unwrap();
        }

        assert_eq!(table.len().unwrap(), 1000);
        assert_eq!(table.get(&500u64).unwrap(), Some(1000u64));
    }

    #[test]
    fn test_put_empty_string_value() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"".to_string()).unwrap();
        assert_eq!(table.get(&1u64).unwrap(), Some("".to_string()));
    }

    #[test]
    fn test_put_string_key() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<String, u64>("t").unwrap();

        table.put(&"rust".to_string(), &2024u64).unwrap();
        assert_eq!(table.get(&"rust".to_string()).unwrap(), Some(2024u64));
    }

    #[test]
    fn test_delete_existing_key_returns_value() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"bye".to_string()).unwrap();
        let removed = table.delete(&1u64).unwrap();

        assert_eq!(removed, Some("bye".to_string()));
    }

    #[test]
    fn test_delete_removes_entry() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"bye".to_string()).unwrap();
        table.delete(&1u64).unwrap();

        assert_eq!(table.get(&1u64).unwrap(), None);
        assert_eq!(table.len().unwrap(), 0);
    }

    #[test]
    fn test_delete_missing_key_returns_none() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        let result = table.delete(&404u64).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_delete_does_not_affect_other_keys() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"one".to_string()).unwrap();
        table.put(&2u64, &"two".to_string()).unwrap();
        table.put(&3u64, &"three".to_string()).unwrap();

        table.delete(&2u64).unwrap();

        assert_eq!(table.get(&1u64).unwrap(), Some("one".to_string()));
        assert_eq!(table.get(&2u64).unwrap(), None);
        assert_eq!(table.get(&3u64).unwrap(), Some("three".to_string()));
        assert_eq!(table.len().unwrap(), 2);
    }

    #[test]
    fn test_delete_twice_second_returns_none() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"x".to_string()).unwrap();
        table.delete(&1u64).unwrap();

        let second = table.delete(&1u64).unwrap();
        assert_eq!(second, None);
    }

    #[test]
    fn test_put_after_delete() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"first".to_string()).unwrap();
        table.delete(&1u64).unwrap();
        table.put(&1u64, &"resurrected".to_string()).unwrap();

        assert_eq!(table.get(&1u64).unwrap(), Some("resurrected".to_string()));
        assert_eq!(table.len().unwrap(), 1);
    }

    #[test]
    fn test_contains_existing_key() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&7u64, &"v".to_string()).unwrap();
        assert!(table.contains(&7u64).unwrap());
    }

    #[test]
    fn test_contains_missing_key() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        assert!(!table.contains(&7u64).unwrap());
    }

    #[test]
    fn test_contains_after_delete() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"v".to_string()).unwrap();
        table.delete(&1u64).unwrap();

        assert!(!table.contains(&1u64).unwrap());
    }

    #[test]
    fn test_iter_empty_table() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        assert_eq!(table.iter().unwrap(), vec![]);
    }

    #[test]
    fn test_iter_all_entries_present() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, u64>("t").unwrap();

        let mut expected: Vec<(u64, u64)> = (0u64..5).map(|i| (i, i * 10)).collect();
        for (k, v) in &expected {
            table.put(k, v).unwrap();
        }

        let mut result = table.iter().unwrap();
        result.sort_by_key(|(k, _)| *k);
        expected.sort_by_key(|(k, _)| *k);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_iter_count_matches_len() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, u64>("t").unwrap();

        for i in 0u64..20 {
            table.put(&i, &i).unwrap();
        }

        assert_eq!(table.iter().unwrap().len() as u64, table.len().unwrap());
    }

    #[test]
    fn test_iter_after_delete() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        for i in 0u64..5 {
            table.put(&i, &format!("v{}", i)).unwrap();
        }
        table.delete(&2u64).unwrap();

        let keys: Vec<u64> = {
            let mut r = table.iter().unwrap();
            r.sort_by_key(|(k, _)| *k);
            r.into_iter().map(|(k, _)| k).collect()
        };

        assert_eq!(keys, vec![0u64, 1, 3, 4]);
    }

    #[test]
    fn test_len_empty() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();
        assert_eq!(table.len().unwrap(), 0);
    }

    #[test]
    fn test_len_grows_on_put() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        for i in 0u64..10 {
            table.put(&i, &"x".to_string()).unwrap();
            assert_eq!(table.len().unwrap(), i + 1);
        }
    }

    #[test]
    fn test_len_unchanged_on_overwrite() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"a".to_string()).unwrap();
        table.put(&1u64, &"b".to_string()).unwrap();

        assert_eq!(table.len().unwrap(), 1);
    }

    #[test]
    fn test_len_decreases_on_delete() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("t").unwrap();

        table.put(&1u64, &"a".to_string()).unwrap();
        table.put(&2u64, &"b".to_string()).unwrap();
        table.delete(&1u64).unwrap();

        assert_eq!(table.len().unwrap(), 1);
    }

    #[test]
    fn test_list_tables_empty() {
        let store = RedbStore::in_memory().unwrap();
        assert_eq!(store.list_tables().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_list_tables_after_put() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("alpha").unwrap();
        table.put(&1u64, &"v".to_string()).unwrap();

        assert!(store.list_tables().unwrap().contains(&"alpha".to_string()));
    }

    #[test]
    fn test_drop_table_removes_from_list() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("to_drop").unwrap();
        table.put(&1u64, &"v".to_string()).unwrap();

        store.drop_table("to_drop").unwrap();

        assert!(!store
            .list_tables()
            .unwrap()
            .contains(&"to_drop".to_string()));
    }

    #[test]
    fn test_drop_table_data_gone() {
        let store = RedbStore::in_memory().unwrap();
        let table = store.table::<u64, String>("to_drop").unwrap();
        table.put(&1u64, &"v".to_string()).unwrap();

        store.drop_table("to_drop").unwrap();

        assert_eq!(table.get(&1u64).unwrap(), None);
    }

    #[test]
    fn test_drop_nonexistent_table_ok() {
        let store = RedbStore::in_memory().unwrap();
        // Не должно паниковать или возвращать ошибку
        store.drop_table("ghost").unwrap();
    }

    #[test]
    fn test_batch_put_single_table() {
        let store = RedbStore::in_memory().unwrap();

        store
            .batch(|w| {
                w.put("bt", &1u64, &"one".to_string())?;
                w.put("bt", &2u64, &"two".to_string())?;
                w.put("bt", &3u64, &"three".to_string())?;
                Ok(())
            })
            .unwrap();

        let table = store.table::<u64, String>("bt").unwrap();
        assert_eq!(table.len().unwrap(), 3);
        assert_eq!(table.get(&2u64).unwrap(), Some("two".to_string()));
    }

    #[test]
    fn test_batch_put_multiple_tables() {
        let store = RedbStore::in_memory().unwrap();

        store
            .batch(|w| {
                w.put("t1", &1u64, &"a".to_string())?;
                w.put("t2", &2u64, &"b".to_string())?;
                Ok(())
            })
            .unwrap();

        let t1 = store.table::<u64, String>("t1").unwrap();
        let t2 = store.table::<u64, String>("t2").unwrap();

        assert_eq!(t1.get(&1u64).unwrap(), Some("a".to_string()));
        assert_eq!(t2.get(&2u64).unwrap(), Some("b".to_string()));
    }

    #[test]
    fn test_batch_delete() {
        let store = RedbStore::in_memory().unwrap();

        let table = store.table::<u64, String>("bd").unwrap();
        table.put(&1u64, &"x".to_string()).unwrap();
        table.put(&2u64, &"y".to_string()).unwrap();

        store
            .batch(|w| {
                w.delete::<u64>("bd", &1u64)?;
                Ok(())
            })
            .unwrap();

        assert_eq!(table.get(&1u64).unwrap(), None);
        assert_eq!(table.get(&2u64).unwrap(), Some("y".to_string()));
    }

    #[test]
    fn test_batch_put_and_delete_same_transaction() {
        let store = RedbStore::in_memory().unwrap();

        let table = store.table::<u64, String>("mixed").unwrap();
        table.put(&10u64, &"old".to_string()).unwrap();

        store
            .batch(|w| {
                w.put("mixed", &20u64, &"new".to_string())?;
                w.delete::<u64>("mixed", &10u64)?;
                Ok(())
            })
            .unwrap();

        assert_eq!(table.get(&10u64).unwrap(), None);
        assert_eq!(table.get(&20u64).unwrap(), Some("new".to_string()));
        assert_eq!(table.len().unwrap(), 1);
    }

    #[test]
    fn test_batch_returns_value() {
        let store = RedbStore::in_memory().unwrap();

        let result = store
            .batch(|w| {
                w.put("ret", &1u64, &"v".to_string())?;
                Ok(42u64)
            })
            .unwrap();

        assert_eq!(result, 42u64);
    }

    #[test]
    fn test_batch_overwrite_in_same_txn() {
        let store = RedbStore::in_memory().unwrap();

        store
            .batch(|w| {
                w.put("ow", &1u64, &"first".to_string())?;
                w.put("ow", &1u64, &"second".to_string())?;
                Ok(())
            })
            .unwrap();

        let table = store.table::<u64, String>("ow").unwrap();
        assert_eq!(table.len().unwrap(), 1);
        assert_eq!(table.get(&1u64).unwrap(), Some("second".to_string()));
    }

    #[test]
    fn test_batch_large_write() {
        let store = RedbStore::in_memory().unwrap();

        store
            .batch(|w| {
                for i in 0u64..10_000 {
                    w.put("big", &i, &(i * 3))?;
                }
                Ok(())
            })
            .unwrap();

        let table = store.table::<u64, u64>("big").unwrap();
        assert_eq!(table.len().unwrap(), 10_000);
        assert_eq!(table.get(&9_999u64).unwrap(), Some(29_997u64));
    }
}
