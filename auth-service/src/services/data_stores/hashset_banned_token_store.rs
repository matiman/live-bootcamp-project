use std::collections::HashSet;

use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    pub banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_banned_token(
        &mut self,
        token: Secret<String>,
    ) -> Result<(), BannedTokenStoreError> {
        self.banned_tokens.insert(token.expose_secret().clone());
        Ok(())
    }
    async fn is_token_banned(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token.expose_secret().as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut store = HashSetBannedTokenStore::default();
        let token = "test_token".to_string();

        assert!(store
            .add_banned_token(Secret::new(token.clone()))
            .await
            .is_ok());
        assert!(store.banned_tokens.contains(&token));
    }

    #[tokio::test]
    async fn test_is_token_banned() {
        let mut store = HashSetBannedTokenStore::default();
        let token = "test_token".to_string();

        store.banned_tokens.insert(token.clone());
        assert!(store
            .is_token_banned(&Secret::new(token.clone()))
            .await
            .unwrap());
    }
}
