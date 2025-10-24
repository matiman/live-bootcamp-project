use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

pub struct HashSetBannedTokenStore {
    pub banned_tokens: HashSet<String>,
}

impl HashSetBannedTokenStore {
    pub fn new() -> Self {
        Self {
            banned_tokens: HashSet::new(),
        }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token);
        Ok(())
    }
    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut store = HashSetBannedTokenStore::new();
        let token = "test_token".to_string();
        assert_eq!(store.add_banned_token(token.clone()).await, Ok(()));
    }

    #[tokio::test]
    async fn test_is_token_banned() {
        let mut store = HashSetBannedTokenStore::new();
        let token = "test_token".to_string();
        store.add_banned_token(token.clone()).await.unwrap();
        assert_eq!(store.is_token_banned(&token).await, Ok(true));
    }
}
