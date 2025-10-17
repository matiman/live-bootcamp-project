// The User struct should contain 3 fields. email, which is a String;
// password, which is also a String; and requires_2fa, which is a boolean.
#[derive(Clone, PartialEq, Debug)]
pub struct User {
    pub email: String,
    pub password: String,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: &str, password: &str, requires_2fa: bool) -> Self {
        User {
            email: email.to_string(),
            password: password.to_string(),
            requires_2fa,
        }
    }
}
