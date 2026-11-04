use thiserror::Error;

pub mod closeable;
pub mod openable;

pub use closeable::Closable;
pub use openable::Openable;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    #[error("not opened")]
    NotOpened,
    #[error("already opened")]
    AlreadyOpened,
    #[error("key is unavailable")]
    KeyUnavailable,
    #[error("encrypted data is too short")]
    EncryptedDataTooShort,
    #[error("tpm error: {0}")]
    Tpm(String),
}

pub type Result<T> = std::result::Result<T, SigningError>;
