use std::sync::Arc;

use auth_service::{
    app_state::{
        AppState, BannedTokenStoreType, EmailClientType, TwoFACodeStoreType, UserStoreType,
    },
    get_postgres_pool, get_redis_client,
    services::{
        redis_banned_token_store::RedisBannedTokenStore,
        redis_two_fa_code_store::RedisTwoFACodeStore, HashSetBannedTokenStore, HashmapUserStore,
        MockEmailClient, PostgresUserStore,
    },
    utils::{init_tracing, prod, DATABASE_URL, REDIS_HOST_NAME},
    Application,
};
use sqlx::PgPool;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing().expect("Failed to initialize tracing");

    let pg_pool = configure_postgresql().await;
    let redis_conn = configure_redis();
    let shared_redis_conn = Arc::new(RwLock::new(redis_conn));

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool))) as UserStoreType;
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        shared_redis_conn.clone(),
    ))) as BannedTokenStoreType;
    let two_fa_code_store =
        Arc::new(RwLock::new(RedisTwoFACodeStore::new(shared_redis_conn))) as TwoFACodeStoreType;
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

async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(DATABASE_URL.clone())
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
