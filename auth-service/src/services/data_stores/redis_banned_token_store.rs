use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        // 1. Create a new key using the get_key helper function.
        let key = get_key(&token);

        // 2. Cast TOKEN_TTL_SECONDS from i64 to u64
        let ttl = TOKEN_TTL_SECONDS
            .try_into()
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        // 3. Acquire write lock and call set_ex on the Redis connection
        let mut conn = self.conn.write().await;
        conn.set_ex::<_, _, ()>(key, true, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn is_token_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        // 1. Create a key using the get_key helper function
        let key = get_key(token);

        // 2. Acquire read lock and call exists on the Redis connection
        let mut conn = self.conn.write().await;
        let exists: bool = conn
            .exists::<_, bool>(key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;

        Ok(exists)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
