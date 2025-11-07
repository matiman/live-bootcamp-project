use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

// TODO: implement TwoFACodeStore for HashmapTwoFACodeStore

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email)
            .cloned()
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    //TODO  Add unit tests and use assertion
    use super::*;

    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@example.com").unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        assert!(store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .is_ok());
        assert!(store.codes.contains_key(&email));
        assert_eq!(store.codes.get(&email).unwrap().0, login_attempt_id);
        assert_eq!(store.codes.get(&email).unwrap().1, code);
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@example.com").unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        assert!(store.remove_code(&email).await.is_ok());
        assert!(!store.codes.contains_key(&email));
    }

    #[tokio::test]
    async fn test_get_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@example.com").unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        assert_eq!(
            store.get_code(&email).await.unwrap(),
            (login_attempt_id, code)
        );
    }

    #[quickcheck_macros::quickcheck]
    fn test_two_fa_code_validation(code: String) -> bool {
        // Valid codes must be exactly 6 characters, parseable as u32, and in range 100000-999999
        let is_valid_length = code.len() == 6;
        let parse_result = TwoFACode::parse(code.clone());

        if is_valid_length {
            // For 6-character strings, check if they parse correctly
            // Valid: numeric and in range 100000-999999
            if let Ok(parsed_u32) = code.parse::<u32>() {
                if (100_000..=999_999).contains(&parsed_u32) {
                    parse_result.is_ok()
                } else {
                    parse_result.is_err()
                }
            } else {
                // Not numeric, should fail
                parse_result.is_err()
            }
        } else {
            // Invalid length should always fail
            parse_result.is_err()
        }
    }
}
