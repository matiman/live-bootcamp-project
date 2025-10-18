use crate::domain::{Email, Password, UserValidationError};

// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.
#[derive(Clone, PartialEq, Debug)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(
        email: &str,
        password: &str,
        requires_2fa: bool,
    ) -> Result<Self, UserValidationError> {
        return Ok(User {
            email: Email::parse(email).map_err(|_| UserValidationError::InvalidEmail)?,
            password: Password::parse(password)
                .map_err(|_| UserValidationError::InvalidPassword)?,
            requires_2fa,
        });
    }
}
