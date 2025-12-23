use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct UserPassphrase(String);

#[derive(Debug)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    pub fn hash_message(&self, data: impl AsRef<[u8]>) -> String {
        match self {
            Self::Sha256 => hex::encode(Sha256::digest(data).to_vec()),
        }
    }
}

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct UserKey {
    // Using hex encoded string for now, should change
    // once the type is known
    key: String,
}

impl UserKey {
    pub fn new(passphrase: UserPassphrase, algorithm: HashAlgorithm) -> Self {
        Self {
            key: algorithm.hash_message(passphrase.0.as_bytes()),
        }
    }
}
