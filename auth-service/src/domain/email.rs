use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use std::{hash::Hash, hash::Hasher};
use thiserror::Error;
use validator::ValidateEmail;

#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl Email {
    /// Parse and validate an email address
    pub fn parse(s: Secret<String>) -> Result<Self> {
        // Validate using the validator crate
        if !ValidateEmail::validate_email(&s.expose_secret()) {
            return Err(eyre!("{} is invalid email", s.expose_secret()));
        }

        Ok(Self(s))
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

// New!
impl Eq for Email {}

// Updated!
impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}
#[derive(Debug, Error)]
pub enum EmailError {
    #[error("Invalid email")]
    InvalidEmail(String),
    #[error("Unexpected error")]
    UnexpectedError(#[source] color_eyre::eyre::Report),
}

impl PartialEq for EmailError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::InvalidEmail(_), Self::InvalidEmail(_))
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};

    #[test]
    fn test_valid_fake_emails_always_parse() {
        // Generate 10 fake emails and ensure they all parse successfully
        for _ in 0..10 {
            let fake_email: String = SafeEmail().fake();
            let result = Email::parse(Secret::new(fake_email.clone()));
            assert!(result.is_ok(), "Failed to parse fake email: {}", fake_email);
        }
    }

    #[test]
    fn empty_string_is_rejected() {
        let email = "";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }
    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = "ursuladomain.com";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        let email = "@domain.com";
        assert!(Email::parse(Secret::new(email.to_string())).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl Arbitrary for ValidEmailFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let email: String = SafeEmail().fake();
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(Secret::new(valid_email.0)).is_ok()
    }

    #[test]
    fn prop_missing_at_always_fails() {
        // Use quickcheck to generate strings without @
        fn property(s: String) -> TestResult {
            if s.contains('@') {
                return TestResult::discard();
            }

            let result = Email::parse(Secret::new(s));
            TestResult::from_bool(result.is_err())
        }

        quickcheck(property as fn(String) -> TestResult);
    }

    // For invalid emails
    #[derive(Debug, Clone)]
    struct InvalidEmailFixture(pub String);

    impl Arbitrary for InvalidEmailFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let options = [
                "no-at-sign",
                "@missing-local.com",
                "missing-domain@",
                "spaces in@email.com",
                "double@@example.com",
            ];

            // Generate a random usize, then mod it
            let idx = usize::arbitrary(g) % options.len();
            let invalid = options[idx].to_string();

            Self(invalid)
        }
    }
    #[quickcheck_macros::quickcheck]
    fn invalid_emails_are_rejected(invalid_email: InvalidEmailFixture) -> bool {
        Email::parse(Secret::new(invalid_email.0)).is_err()
    }
}
