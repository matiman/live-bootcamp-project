pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    UnexpectedError,
}
#[derive(Debug, PartialEq, Clone)]
pub enum UserValidationError {
    InvalidEmail,
    InvalidPassword,
    UnexpectedError,
}
