use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;

use crate::domain::{
    data_stores::{UserStore, UserStoreError},
    Email, Password, User,
};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    // TODO: Implement all required methods. Note that you will need to make SQL queries against our PostgreSQL instance inside these methods.
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Hash the password before storing
        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        // Insert user into database
        let result = sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref(),
            &password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_err)) => {
                // Check if it's a unique constraint violation (email already exists)
                // PostgreSQL error code 23505 = unique_violation
                if db_err.code().as_deref() == Some("23505")
                    || db_err.constraint() == Some("users_pkey")
                {
                    Err(UserStoreError::UserAlreadyExists)
                } else {
                    Err(UserStoreError::UnexpectedError)
                }
            }
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let result = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(row)) => {
                // Parse the email
                let user_email =
                    Email::parse(&row.email).map_err(|_| UserStoreError::UnexpectedError)?;

                // Create Password from the stored hash
                // The password field in User is not used after retrieval, but we store the hash
                // for consistency with the struct definition
                let password = Password::from_hash(row.password_hash);

                Ok(User {
                    email: user_email,
                    password,
                    requires_2fa: row.requires_2fa,
                })
            }
            Ok(None) => Err(UserStoreError::UserNotFound),
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        // First, get the user to retrieve the password hash
        let result = sqlx::query!(
            "SELECT password_hash FROM users WHERE email = $1",
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await;

        match result {
            Ok(Some(row)) => {
                // Verify the password against the stored hash
                verify_password_hash(row.password_hash, password.as_ref().to_string())
                    .await
                    .map_err(|_| UserStoreError::InvalidCredentials)?;

                Ok(())
            }
            Ok(None) => Err(UserStoreError::UserNotFound),
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }
}

// Helper function to verify if a given password matches an expected hash
// Uses spawn_blocking to run CPU-intensive hashing on a separate thread pool
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Only the CPU-intensive verification runs in spawn_blocking
    // PasswordHash parsing is fast, but we keep it here to avoid lifetime issues
    tokio::task::spawn_blocking(move || {
        let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&expected_password_hash)?;

        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
}

// Helper function to hash passwords before persisting them in the database.
// Uses spawn_blocking to run CPU-intensive hashing on a separate thread pool
async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    // Generate salt outside of spawn_blocking (fast operation)
    let salt: SaltString = SaltString::generate(&mut rand::thread_rng());

    // Only the CPU-intensive hashing runs in spawn_blocking
    tokio::task::spawn_blocking(move || {
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)?,
        )
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        Ok(password_hash.to_string())
    })
    .await
    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
}
