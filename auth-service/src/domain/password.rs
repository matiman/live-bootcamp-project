#[derive(Debug, PartialEq, Clone)]
pub struct Password(String);

impl Password {
    pub fn parse(password: &str) -> Result<Self, PasswordError> {
        let len = password.len();
        if len < 8
            || len > 128
            || password.to_lowercase().contains("password")
            || password.contains(" ")
        {
            return Err(PasswordError::InvalidPassword);
        }
        Ok(Password(password.to_string()))
    }

    /// Create a Password from a hash string without validation.
    /// This is used when retrieving a user from the database where we only have the hash.
    pub fn from_hash(hash: String) -> Self {
        Password(hash)
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum PasswordError {
    InvalidPassword,
    UnexpectedError,
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
        let too_long = "a".repeat(127);
        let valid_passwords = vec!["secureP@ss123", "MySecret99", "abcd1234", too_long.as_str()];

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
        let too_long = "a".repeat(129);
        let invalid_passwords = vec![
            "short",         // too short (< 8)
            "",              // empty
            "has space",     // contains space
            "mypassword123", // contains "password"
            "PASSWORD123",
            // contains "password" (case-insensitive)
            too_long.as_str(), // too long (> 128)
        ];

        for pass in invalid_passwords {
            let result = Password::parse(pass);
            assert_eq!(
                result,
                Err(PasswordError::InvalidPassword),
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
