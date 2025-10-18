//Email should be a tuple struct.

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Deserialize, Serialize)]
pub struct Email(String);

impl Email {
    /// Parse and validate an email address
    pub fn parse(address: &str) -> Result<Self, EmailError> {
        // Validate using the validator crate
        if !validator::validate_email(address) {
            return Err(EmailError::InvalidEmail);
        }

        Ok(Email(address.to_string()))
    }

    // Optional: expose the inner value if needed
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Email {
    // Standard trait for conversion to &str
    fn as_ref(&self) -> &str {
        &self.0
    }
}
#[derive(Debug, PartialEq)]
pub enum EmailError {
    InvalidEmail,
    UnexpectedError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::SafeEmail;
    use fake::Fake;
    use quickcheck::{quickcheck, TestResult};

    #[test]
    fn test_valid_fake_emails_always_parse() {
        // Generate 10 fake emails and ensure they all parse successfully
        for _ in 0..10 {
            let fake_email: String = SafeEmail().fake();
            let result = Email::parse(&fake_email);
            assert!(result.is_ok(), "Failed to parse fake email: {}", fake_email);
        }
    }

    #[test]
    fn prop_missing_at_always_fails() {
        // Use quickcheck to generate strings without @
        fn property(s: String) -> TestResult {
            if s.contains('@') {
                return TestResult::discard();
            }

            let result = Email::parse(&s);
            TestResult::from_bool(result.is_err())
        }

        quickcheck::quickcheck(property as fn(String) -> TestResult);
    }
}
