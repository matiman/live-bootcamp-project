pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    IncorrectCredentials,
    UnexpectedError,
    MissingToken,
    InvalidToken,
    TokenAlreadyBanned,
}
#[derive(Debug, PartialEq, Clone)]
pub enum UserValidationError {
    InvalidEmail,
    InvalidPassword,
    UnexpectedError,
}
