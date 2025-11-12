use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Password(Secret<String>);

impl Password {
    pub fn parse(s: Secret<String>) -> Result<Self> {
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

impl PartialEq for Password {
    // New!
    fn eq(&self, other: &Self) -> bool {
        // We can use the expose_secret method to expose the secret in a
        // controlled manner when needed!
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

fn validate_password(s: &Secret<String>) -> bool {
    let password = s.expose_secret();
    password.len() >= 8 && !password.contains(" ")
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
            let result = Password::parse(Secret::new(pass.to_string()));
            assert!(result.is_ok(), "Should accept valid password: {}", pass);

            // Test AsRef
            let parsed = result.unwrap();
            assert_eq!(parsed.as_ref().expose_secret(), pass);
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

            let result = Password::parse(Secret::new(pass.to_string()));
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
            let result = Password::parse(Secret::new(pass.to_string()));
            assert!(result.is_err(), "Should reject invalid password: {}", pass);
        }
    }

    #[test]
    fn prop_short_passwords_always_fail() {
        // Use quickcheck to test passwords < 8 chars always fail
        fn property(s: String) -> TestResult {
            if s.len() >= 8 {
                return TestResult::discard();
            }

            let result = Password::parse(Secret::new(s.to_string()));
            TestResult::from_bool(result.is_err())
        }

        quickcheck::quickcheck(property as fn(String) -> TestResult);
    }
}
