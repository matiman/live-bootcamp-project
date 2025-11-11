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
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}
#[derive(Debug, PartialEq, Clone)]
pub enum UserValidationError {
    InvalidEmail,
    InvalidPassword,
    UnexpectedError,
}
