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
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
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

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
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

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
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


// Uses spawn_blocking to avoid blocking async tasks during CPU-intensive hashing
#[tracing::instrument(name = "Verify password hash", skip_all)] // New!
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // This line retrieves the current span from the tracing context.
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current(); // New!
    let result = tokio::task::spawn_blocking(move || {
        // This code block ensures that the operations within the closure are executed within the context of the current span.
        // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
        current_span.in_scope(|| {
            // New!
            let expected_password_hash: PasswordHash<'_> =
                PasswordHash::new(&expected_password_hash)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                .map_err(|e| e.into())
        })
    })
    .await;

    result?
}
// Helper function to hash passwords before persisting them in the database.
// Uses spawn_blocking to avoid blocking async tasks during CPU-intensive hashing
#[tracing::instrument(name = "Computing password hash", skip_all)] //New!
async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    // This line retrieves the current span from the tracing context.
    // The span represents the execution context for the compute_password_hash function.
    let current_span: tracing::Span = tracing::Span::current(); // New!

    let result = tokio::task::spawn_blocking(move || {
        // This code block ensures that the operations within the closure are executed within the context of the current span.
        // This is especially useful for tracing operations that are performed in a different thread or task, such as within tokio::task::spawn_blocking.
        current_span.in_scope(|| {
            // New!
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(password_hash)
        })
    })
    .await;
    result?
}
