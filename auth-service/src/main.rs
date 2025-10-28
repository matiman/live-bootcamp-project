use std::sync::Arc;

use auth_service::{
    app_state::{
        AppState, BannedTokenStoreType, EmailClientType, TwoFACodeStoreType, UserStoreType,
    },
    services::{HashSetBannedTokenStore, HashmapTwoFACodeStore, HashmapUserStore, MockEmailClient},
    utils::prod,
    Application,
};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default())) as UserStoreType;
    let banned_token_store =
        Arc::new(RwLock::new(HashSetBannedTokenStore::default())) as BannedTokenStoreType;
    let two_fa_code_store =
        Arc::new(RwLock::new(HashmapTwoFACodeStore::default())) as TwoFACodeStoreType;
    let email_client = Arc::new(RwLock::new(MockEmailClient {})) as EmailClientType;
    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
