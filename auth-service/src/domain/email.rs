//Email should be a tuple struct.

//use serde::{Deserialize, Serialize};
use validator::validate_email;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Email(String);

impl Email {
    /// Parse and validate an email address
    pub fn parse(address: &str) -> Result<Self, EmailError> {
        // Validate using the validator crate
        if !validate_email(address) {
            return Err(EmailError::InvalidEmail(format!(
                "{} is invalid email",
                address
            )));
        }

        Ok(Self(address.to_string()))
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
    InvalidEmail(String),
    UnexpectedError,
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
            let result = Email::parse(&fake_email);
            assert!(result.is_ok(), "Failed to parse fake email: {}", fake_email);
        }
    }

    #[test]
    fn empty_string_is_rejected() {
        let email = "";
        assert!(Email::parse(email).is_err());
    }
    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = "ursuladomain.com";
        assert!(Email::parse(email).is_err());
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        let email = "@domain.com";
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl Arbitrary for ValidEmailFixture {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let email = SafeEmail().fake_with_rng(g);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(&valid_email.0).is_ok()
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

        quickcheck(property as fn(String) -> TestResult);
    }

    // For invalid emails
    #[derive(Debug, Clone)]
    struct InvalidEmailFixture(pub String);

    impl Arbitrary for InvalidEmailFixture {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
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
        Email::parse(&invalid_email.0).is_err()
    }
}
