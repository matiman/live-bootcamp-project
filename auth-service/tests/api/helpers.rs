use auth_service::{
    app_state::{
        AppState, BannedTokenStoreType, EmailClientType, TwoFACodeStoreType, UserStoreType,
    },
    get_postgres_pool, get_redis_client,
    services::{
        redis_banned_token_store::RedisBannedTokenStore, HashSetBannedTokenStore,
        HashmapTwoFACodeStore, MockEmailClient, PostgresUserStore,
    },
    utils::{test, DATABASE_URL},
    Application,
};
use reqwest::cookie::Jar;
use sqlx::{postgres::PgConnectOptions, Connection, Executor, PgConnection};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{cell::Cell, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub db_name: String,
    clean_up_called: Cell<bool>,
}

impl TestApp {
    pub async fn new() -> Self {
        let (pg_pool, db_name) = configure_postgresql().await;
        let redis_conn = configure_redis();

        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool))) as UserStoreType;

        let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::new(
            RwLock::new(redis_conn),
        )))) as BannedTokenStoreType;
        let two_fa_code_store =
            Arc::new(RwLock::new(HashmapTwoFACodeStore::default())) as TwoFACodeStoreType;
        let email_client = Arc::new(RwLock::new(MockEmailClient {})) as EmailClientType;

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client.clone(),
        );
        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        // Create a Reqwest http client instance with a cookie jar
        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        Self {
            address,
            cookie_jar,
            http_client,
            banned_token_store,
            two_fa_code_store,
            db_name,
            clean_up_called: Cell::new(false),
        }
    }

    pub async fn clean_up(&self) {
        delete_database(&self.db_name).await;
        self.clean_up_called.set(true);
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // Implement helper functions for all other routes (signup, login, logout, verify-2fa, and verify-token)
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called.get() {
            panic!(
                "TestApp::clean_up() was not called! Database '{}' may not have been cleaned up.",
                self.db_name
            );
        }
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

fn configure_redis() -> redis::Connection {
    get_redis_client(test::DEFAULT_REDIS_HOSTNAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

async fn configure_postgresql() -> (PgPool, String) {
    let mut postgresql_conn_url = DATABASE_URL.to_owned();

    // Replace 'db' hostname with 'localhost' for local testing
    postgresql_conn_url = postgresql_conn_url.replace("@db:", "@localhost:");

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!
    let db_name = Uuid::new_v4().to_string();

    // Connect to default 'postgres' database to create new databases
    let postgresql_conn_url_without_db = format!("{}/postgres", postgresql_conn_url);
    configure_database(&postgresql_conn_url_without_db, &db_name).await;

    // Use the base URL and add the new database name
    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);

    // Create a new connection pool and return it along with the database name
    let pool = get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!");
    (pool, db_name)
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Create database connection to default postgres database
    let connection_options = PgConnectOptions::from_str(db_conn_string)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Create a new database
    sqlx::query(&format!(r#"CREATE DATABASE "{}";"#, db_name))
        .execute(&mut connection)
        .await
        .expect("Failed to create database.");

    // Connect to new database - strip any existing database name first
    let base_conn = db_conn_string
        .strip_suffix("/postgres")
        .unwrap_or(db_conn_string);
    let db_conn_string = format!("{}/{}", base_conn, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let mut postgresql_conn_url = DATABASE_URL.to_owned();

    // Replace 'db' hostname with 'localhost' for local testing
    postgresql_conn_url = postgresql_conn_url.replace("@db:", "@localhost:");

    // Connect to default 'postgres' database to drop the test database
    let postgresql_conn_url_without_db = format!("{}/postgres", postgresql_conn_url);

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url_without_db)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill any active connections to the database
    sqlx::query(&format!(
        r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
        "#,
        db_name
    ))
    .execute(&mut connection)
    .await
    .expect("Failed to terminate connections to the database.");

    // Drop the database
    sqlx::query(&format!(r#"DROP DATABASE "{}";"#, db_name))
        .execute(&mut connection)
        .await
        .expect("Failed to drop the database.");
}
