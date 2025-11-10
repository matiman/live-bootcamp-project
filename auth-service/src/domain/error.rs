use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
    #[error("Missing token")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Invalid login attempt ID")]
    InvalidLoginAttemptId,
    #[error("Token already banned")]
    TokenAlreadyBanned,
    #[error("TwoFA code store error")]
    TwoFACodeStoreError,
}
#[derive(Debug, PartialEq, Clone, Error)]
pub enum UserValidationError {
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Unexpected error")]
    UnexpectedError,
}
