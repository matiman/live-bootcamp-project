use color_eyre::eyre::{eyre, Result};
use thiserror::Error;

#[derive(Debug, PartialEq, Clone)]
pub struct Password(String);

impl Password {
    pub fn parse(password: &str) -> Result<Self> {
        let len = password.len();
        if len < 8 || password.contains(" ") {
            return Err(eyre!("{} is invalid password", password));
        }
        Ok(Password(password.to_string()))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Invalid password")]
    InvalidPassword(String),
    #[error("Unexpected error")]
    UnexpectedError(#[source] color_eyre::eyre::Report),
}

impl PartialEq for PasswordError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::InvalidPassword(_), Self::InvalidPassword(_))
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::TestResult;

    // ========== Valid Cases ==========

    #[test]
    fn test_valid_passwords() {
        let long_password = "a".repeat(200); // Test that long passwords are now allowed
        let valid_passwords = vec![
            "secureP@ss123",
            "MySecret99",
            "abcd1234",
            long_password.as_str(),
        ];

        for pass in valid_passwords {
            let result = Password::parse(pass);
            assert!(result.is_ok(), "Should accept valid password: {}", pass);

            // Test AsRef
            let parsed = result.unwrap();
            assert_eq!(parsed.as_ref(), pass);
        }
    }

    #[test]
    fn test_fake_passwords_with_constraints() {
        // Generate passwords with fake library (8-20 chars)
        for _ in 0..10 {
            let pass: String = FakePassword(8..20).fake();

            // Skip if contains "password" or spaces (rare but possible)
            if pass.to_lowercase().contains("password") || pass.contains(" ") {
                continue;
            }

            let result = Password::parse(&pass);
            assert!(result.is_ok(), "Fake password should be valid: {}", pass);
        }
    }

    // ========== Invalid Cases ==========

    #[test]
    fn test_invalid_passwords() {
        let invalid_passwords = vec![
            "short",     // too short (< 8)
            "",          // empty
            "has space", // contains space
        ];

        for pass in invalid_passwords {
            let result = Password::parse(pass);
            assert!(
                result.is_err(),
                "Should reject invalid password: {}",
                pass
            );
        }
    }

    #[test]
    fn prop_short_passwords_always_fail() {
        // Use quickcheck to test passwords < 8 chars always fail
        fn property(s: String) -> TestResult {
            if s.len() >= 8 {
                return TestResult::discard();
            }

            let result = Password::parse(&s);
            TestResult::from_bool(result.is_err())
        }

        quickcheck::quickcheck(property as fn(String) -> TestResult);
    }
}
