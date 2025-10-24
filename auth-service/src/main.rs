use std::sync::Arc;

use auth_service::{
    app_state::{AppState, BannedTokenStoreType, UserStoreType},
    services::{HashSetBannedTokenStore, HashmapUserStore},
    utils::prod,
    Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default())) as UserStoreType;
    let banned_token_store =
        Arc::new(RwLock::new(HashSetBannedTokenStore::new())) as BannedTokenStoreType;

    let app_state = AppState::new(user_store, banned_token_store);
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
