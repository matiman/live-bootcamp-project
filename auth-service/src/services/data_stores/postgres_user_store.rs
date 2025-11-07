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

// Helper to convert errors to Send-safe error type for spawn_blocking
fn to_send_error(e: impl std::fmt::Display) -> Box<dyn Error + Send> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    ))
}

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
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Check if user already exists
        let existing_user = sqlx::query!(
            "SELECT email FROM users WHERE email = $1",
            user.email.as_ref() as &str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;

        if existing_user.is_some() {
            return Err(UserStoreError::UserAlreadyExists);
        }

        // Hash the password before storing
        let password_hash = compute_password_hash(user.password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        // Insert the user into the database
        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            user.email.as_ref() as &str,
            password_hash,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user_row = sqlx::query!(
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref() as &str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;

        match user_row {
            Some(row) => {
                let user_email =
                    Email::parse(&row.email).map_err(|_| UserStoreError::UnexpectedError)?;

                let password = Password::parse(&row.password_hash)
                    .map_err(|_| UserStoreError::UnexpectedError)?;

                Ok(User {
                    email: user_email,
                    password,
                    requires_2fa: row.requires_2fa,
                })
            }
            None => Err(UserStoreError::UserNotFound),
        }
    }
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        // Get the stored password hash from the database
        let user_row = sqlx::query!(
            "SELECT password_hash FROM users WHERE email = $1",
            email.as_ref() as &str
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;

        let stored_password_hash = match user_row {
            Some(row) => row.password_hash,
            None => return Err(UserStoreError::UserNotFound),
        };

        // Verify the provided password against the stored hash
        verify_password_hash(stored_password_hash, password.as_ref().to_string())
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)?;

        Ok(())
    }
}

// Helper function to verify if a given password matches an expected hash
// Uses spawn_blocking to avoid blocking async tasks during CPU-intensive hashing
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send>> {
    tokio::task::spawn_blocking(move || {
        let password_hash = PasswordHash::new(&expected_password_hash).map_err(to_send_error)?;
        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &password_hash)
            .map_err(to_send_error)
    })
    .await
    .map_err(to_send_error)?
}

// Helper function to hash passwords before persisting them in the database.
// Uses spawn_blocking to avoid blocking async tasks during CPU-intensive hashing
async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send>> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut rand::thread_rng());
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).map_err(to_send_error)?,
        )
        .hash_password(password.as_bytes(), &salt)
        .map_err(to_send_error)
        .map(|hash| hash.to_string())
    })
    .await
    .map_err(to_send_error)?
}
