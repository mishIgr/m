use serde::de::DeserializeOwned;
use std::fs;
use std::io;

pub trait Config: DeserializeOwned + Default {
    const SECTION: &'static str;
    
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn load_from_file(path: &str) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }
    
    fn load_from_str(content: &str) -> io::Result<Self> {
        let value: toml::Value = toml::from_str(content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        let section = value.get(Self::SECTION)
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                format!("Section '{}' not found, using default", Self::SECTION)
            ))?;
        
        let config: Self = section.clone().try_into()
            .map_err(|e: toml::de::Error| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        config.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        Ok(config)
    }
    
    fn load_or_default(path: &str) -> Self {
        Self::load_from_file(path).unwrap_or_else(|e| {
            eprintln!("Failed to load config from '{}': {}", path, e);
            eprintln!("Using default configuration for '{}'", Self::SECTION);
            Self::default()
        })
    }
}
