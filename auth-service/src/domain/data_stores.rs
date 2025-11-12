use crate::domain::{Email, Password};

use super::User;
use color_eyre::eyre::{eyre, Context, Report, Result};
use rand::Rng;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;

#[async_trait::async_trait]
pub trait UserStore {
    // Make sure all methods are async so we can use async user stores in the future
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_banned_token(
        &mut self,
        token: Secret<String>,
    ) -> Result<(), BannedTokenStoreError>;
    async fn is_token_banned(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError>;
}

// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

// New!
impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(Secret<String>);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        // Use the `parse_str` function from the `uuid` crate to ensure `id` is a valid UUID
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?; // Updated!
        Ok(Self(Secret::new(parsed_id.to_string())))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        LoginAttemptId(Secret::new(uuid::Uuid::new_v4().to_string()))
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0.expose_secret()
    }
}

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(Secret<String>);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;

        if (100_000..=999_999).contains(&code_as_u32) {
            Ok(Self(Secret::new(code)))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // The code should be a string of 6 digits in range 100000-999999
        TwoFACode(Secret::new(format!(
            "{:06}",
            rand::thread_rng().gen_range(100_000..=999_999)
        )))
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0.expose_secret()
    }
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Token already banned")]
    TokenAlreadyBanned,
    #[error("Token not found")]
    TokenNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for BannedTokenStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::TokenAlreadyBanned, Self::TokenAlreadyBanned)
                | (Self::TokenNotFound, Self::TokenNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}
