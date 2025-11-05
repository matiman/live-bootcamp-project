use std::{str::FromStr, sync::Arc};

use auth_service::{
    app_state::{
        AppState, BannedTokenStoreType, EmailClientType, TwoFACodeStoreType, UserStoreType,
    },
    get_postgres_pool,
    services::{
        HashSetBannedTokenStore, HashmapTwoFACodeStore, HashmapUserStore, MockEmailClient,
        PostgresUserStore,
    },
    utils::{test, DATABASE_URL},
    Application,
};
use reqwest::cookie::Jar;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool};
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub db_name: String,
    pool: PgPool,
    _app_handle: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl TestApp {
    pub async fn new() -> Self {
        let db_name = Uuid::new_v4().to_string();
        let pg_pool = configure_postgresql(&db_name).await;

        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool.clone())));

        let banned_token_store =
            Arc::new(RwLock::new(HashSetBannedTokenStore::default())) as BannedTokenStoreType;
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
        // Store the handle so we can abort it during cleanup
        let app_handle = tokio::spawn(app.run());

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
            pool: pg_pool.clone(),
            _app_handle: app_handle,
        }
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

    /// Cleans up test resources by stopping the application server, closing database connections,
    /// and deleting the test database.
    pub async fn clean_up(&self) {
        // Stop the application server to prevent new database connections
        self._app_handle.abort();

        // Close connections in our pool (connections we directly control)
        self.pool.close().await;

        // Wait for connections to fully close before attempting database deletion
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Delete the test database. This will terminate any remaining connections (from app server
        // or other sources) and then drop the database. PostgreSQL requires all connections to be
        // closed before a database can be dropped, so we terminate them from the "postgres" database.
        if let Err(e) = delete_database(&self.db_name).await {
            eprintln!("WARNING: Failed to delete database {}: {}", self.db_name, e);
        }
    }

    // Implement helper functions for all other routes (signup, login, logout, verify-2fa, and verify-token)
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

async fn configure_postgresql(db_name: &str) -> PgPool {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    // We are creating a new database for each test case, and we need to ensure each database has a unique name!

    configure_database(&postgresql_conn_url, &db_name).await;

    // Construct the connection URL with the new database name
    let postgresql_conn_url_with_db = if let Some(last_slash_pos) = postgresql_conn_url.rfind('/') {
        let host_part = &postgresql_conn_url[..last_slash_pos + 1];
        format!("{}{}", host_part, db_name)
    } else {
        format!("{}/{}", postgresql_conn_url, db_name)
    };

    // Create a new connection pool and return it
    get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Ensure we connect to the default "postgres" database to create the test database
    // Find the last '/' after the port number to determine where the database name starts
    let base_url = if let Some(last_slash_pos) = db_conn_string.rfind('/') {
        let host_part = &db_conn_string[..last_slash_pos + 1];
        format!("{}postgres", host_part)
    } else {
        format!("{}/postgres", db_conn_string)
    };

    // Create database connection to default "postgres" database
    let connection = PgPoolOptions::new()
        .connect(&base_url)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    // Connect to new database - replace the database name part (everything after last /)
    let db_conn_string_with_db = if let Some(last_slash_pos) = base_url.rfind('/') {
        let host_part = &base_url[..last_slash_pos + 1];
        format!("{}{}", host_part, db_name)
    } else {
        format!("{}/{}", base_url, db_name)
    };

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string_with_db)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

// Deletes a test database by terminating all active connections and then dropping the database.
// Must connect to a different database (default "postgres") because PostgreSQL does not allow
// dropping a database while connected to it. We connect to "postgres" to execute DROP DATABASE.
async fn delete_database(db_name: &str) -> Result<(), sqlx::Error> {
    // Build connection URL to 'postgres' database by replacing the database name in DATABASE_URL
    let admin_url = DATABASE_URL
        .rsplit_once('/')
        .map(|(base, _)| format!("{}/postgres", base))
        .expect("Invalid DATABASE_URL format");

    let pool = PgPool::connect(&admin_url).await?;

    // Terminate all active connections to the test database (from app server or other sources)
    sqlx::query(&format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}' AND pid <> pg_backend_pid()",
        db_name
    ))
    .execute(&pool)
    .await?;

    // Brief delay to ensure connections are fully terminated before dropping
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Drop the database using IF EXISTS to handle cases where database was already deleted
    sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{}""#, db_name))
        .execute(&pool)
        .await?;

    pool.close().await;

    Ok(())
}
