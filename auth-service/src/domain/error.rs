pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
}
#[derive(Debug, PartialEq, Clone)]
pub enum UserValidationError {
    InvalidEmail,
    InvalidPassword,
    UnexpectedError,
}