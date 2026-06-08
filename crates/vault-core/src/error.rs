use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid header magic")]
    BadMagic,

    #[error("Unsupported vault version")]
    WrongVersion,

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Vault is locked (too many attempts)")]
    Locked,

    #[error("Invalid ciphertext or corrupted data")]
    DecryptFailed,

    #[error("Encryption failed")]
    EncryptFailed,

    #[error("Maximum partition count reached")]
    TooManyPartitions,

    #[error("Partition not found")]
    PartitionNotFound,

    #[error("Already authenticated")]
    AlreadyOpen,

    #[error("Vault not open")]
    NotOpen,

    #[error("{0}")]
    Other(String),
}