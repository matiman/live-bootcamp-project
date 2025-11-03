use auth_service::{
    domain::{Email, LoginAttemptId},
    routes::TwoFactorAuthResponse,
    utils::JWT_COOKIE_NAME,
};
use quickcheck::{Arbitrary, Gen};
use quickcheck_macros::quickcheck;
use serde_json::Value;

use crate::helpers::{get_random_email, TestApp};

#[derive(Clone, Debug)]
struct MalformedVerify2FARequest {
    include_email: bool,
    include_login_attempt_id: bool,
    include_two_fa_code: bool,
    email_type: FieldType,
    login_attempt_id_type: FieldType,
    two_fa_code_type: FieldType,
}

#[derive(Clone, Debug)]
enum FieldType {
    String,
    Number,
    Boolean,
    Null,
    Missing,
}

impl Arbitrary for MalformedVerify2FARequest {
    fn arbitrary(g: &mut Gen) -> Self {
        MalformedVerify2FARequest {
            include_email: bool::arbitrary(g),
            include_login_attempt_id: bool::arbitrary(g),
            include_two_fa_code: bool::arbitrary(g),
            email_type: FieldType::arbitrary(g),
            login_attempt_id_type: FieldType::arbitrary(g),
            two_fa_code_type: FieldType::arbitrary(g),
        }
    }
}

impl Arbitrary for FieldType {
    fn arbitrary(g: &mut Gen) -> Self {
        match usize::arbitrary(g) % 5 {
            0 => FieldType::String,
            1 => FieldType::Number,
            2 => FieldType::Boolean,
            3 => FieldType::Null,
            _ => FieldType::Missing,
        }
    }
}

impl MalformedVerify2FARequest {
    fn to_json(&self) -> Value {
        let mut json = serde_json::Map::new();

        let email_str = format!("user{}@example.com", uuid::Uuid::new_v4());
        let uuid_str = uuid::Uuid::new_v4().to_string();
        let code_str = "123456".to_string();

        if self.include_email && !matches!(self.email_type, FieldType::Missing) {
            json.insert("email".to_string(), self.email_type.to_value(email_str));
        }

        if self.include_login_attempt_id
            && !matches!(self.login_attempt_id_type, FieldType::Missing)
        {
            json.insert(
                "loginAttemptId".to_string(),
                self.login_attempt_id_type.to_value(uuid_str),
            );
        }

        if self.include_two_fa_code && !matches!(self.two_fa_code_type, FieldType::Missing) {
            json.insert(
                "2FACode".to_string(),
                self.two_fa_code_type.to_value(code_str),
            );
        }

        // Ensure the request is malformed: either missing required fields or has wrong types
        // Check if all fields are present AND all are correct type (String)
        let is_complete_and_valid = self.include_email
            && self.include_login_attempt_id
            && self.include_two_fa_code
            && matches!(self.email_type, FieldType::String)
            && matches!(self.login_attempt_id_type, FieldType::String)
            && matches!(self.two_fa_code_type, FieldType::String);

        // If it's valid, force it to be malformed by removing one field
        if is_complete_and_valid {
            json.remove("email");
        }

        Value::Object(json)
    }
}

impl FieldType {
    fn to_value(&self, string_value: String) -> Value {
        match self {
            FieldType::String => Value::String(string_value),
            FieldType::Number => Value::Number(123.into()),
            FieldType::Boolean => Value::Bool(true),
            FieldType::Null => Value::Null,
            FieldType::Missing => Value::String(string_value), // Fallback
        }
    }
}

#[quickcheck]
fn should_return_422_for_any_malformed_input(request: MalformedVerify2FARequest) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let app = TestApp::new().await;
        let json_body = request.to_json();

        // to_json() ensures the request is malformed (either missing fields or wrong types)
        let response = app.post_verify_2fa(&json_body).await;

        assert_eq!(response.status().as_u16(), 422);
    })
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let json_body = serde_json::json!({
        "email": "invalid_email",
        "loginAttemptId": "invalid_login_attempt_id",
        "2FACode": "invalid_two_fa_code",
    });
    let response = app.post_verify_2fa(&json_body).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    // Step 1: Signup with 2FA enabled
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Step 2: Login to trigger 2FA and get login_attempt_id
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    // Extract login_attempt_id from response
    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let login_attempt_id = LoginAttemptId::parse(two_fa_response.login_attempt_id)
        .expect("Could not parse login_attempt_id");

    // Step 3: Get the actual login_attempt_id from the store to verify it matches
    let email = Email::parse(&random_email).unwrap();
    let stored_login_attempt_id = {
        let two_fa_code_store = app.two_fa_code_store.write().await;
        let (stored_login_attempt_id, _stored_two_fa_code) = two_fa_code_store
            .get_code(&email)
            .await
            .expect("Could not get 2FA code from store");
        assert_eq!(stored_login_attempt_id, login_attempt_id);
        stored_login_attempt_id
    }; // Lock is dropped here

    // Step 4: Test with incorrect 2FA code (wrong code but correct login_attempt_id)
    let json_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": stored_login_attempt_id.as_ref(),
        "2FACode": "123456", // Wrong code (valid format but incorrect value)
    });

    let response = app.post_verify_2fa(&json_body).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-2fa with the 2FA code from the first login request. This should fail.
    let app = TestApp::new().await;
    let random_email = get_random_email();

    // Step 1: Signup with 2FA enabled
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Step 2: First login - get first 2FA code and login_attempt_id
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let first_login_attempt_id = LoginAttemptId::parse(two_fa_response.login_attempt_id)
        .expect("Could not parse login_attempt_id");

    // Get the first 2FA code from store
    let email = Email::parse(&random_email).unwrap();
    let (first_stored_login_attempt_id, first_stored_code) = {
        let two_fa_code_store = app.two_fa_code_store.write().await;
        let result = two_fa_code_store
            .get_code(&email)
            .await
            .expect("Could not get 2FA code from store");
        assert_eq!(result.0, first_login_attempt_id);
        result
    }; // Lock is dropped here

    // Step 3: Second login - this should replace the old code with a new one
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let second_login_attempt_id = LoginAttemptId::parse(two_fa_response.login_attempt_id)
        .expect("Could not parse login_attempt_id");

    // Get the second 2FA code from store - verify it's different from first
    {
        let two_fa_code_store = app.two_fa_code_store.write().await;
        let (second_stored_login_attempt_id, second_stored_code) = two_fa_code_store
            .get_code(&email)
            .await
            .expect("Could not get 2FA code from store");
        assert_eq!(second_stored_login_attempt_id, second_login_attempt_id);
        // Verify the codes are different
        assert_ne!(first_stored_code, second_stored_code);
    } // Lock is dropped here

    // Step 4: Try to verify with the old code from first login - should fail
    let json_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": first_stored_login_attempt_id.as_ref(),
        "2FACode": first_stored_code.as_ref(),
    });

    let response = app.post_verify_2fa(&json_body).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let app = TestApp::new().await;
    let random_email = get_random_email();

    // Step 1: Signup with 2FA enabled
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Step 2: Login to trigger 2FA and get login_attempt_id
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    // Extract login_attempt_id from response
    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let login_attempt_id = LoginAttemptId::parse(two_fa_response.login_attempt_id)
        .expect("Could not parse login_attempt_id");

    // Step 3: Get the actual 2FA code from the store
    let email = Email::parse(&random_email).unwrap();
    let (stored_login_attempt_id, stored_two_fa_code) = {
        let two_fa_code_store = app.two_fa_code_store.write().await;
        two_fa_code_store
            .get_code(&email)
            .await
            .expect("Could not get 2FA code from store")
    }; // Lock is dropped here

    assert_eq!(stored_login_attempt_id, login_attempt_id);

    // Step 4: Verify 2FA with correct code
    let json_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": stored_login_attempt_id.as_ref(),
        "2FACode": stored_two_fa_code.as_ref(),
    });

    let response = app.post_verify_2fa(&json_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // Step 5: Assert auth cookie is set
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    // Verify 2FA with correct code, then try to verify again with the same code - should fail
    let app = TestApp::new().await;
    let random_email = get_random_email();

    // Step 1: Signup with 2FA enabled
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Step 2: Login to trigger 2FA and get login_attempt_id
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    // Extract login_attempt_id from response
    let two_fa_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let login_attempt_id = LoginAttemptId::parse(two_fa_response.login_attempt_id)
        .expect("Could not parse login_attempt_id");

    // Step 3: Get the actual 2FA code from the store
    let email = Email::parse(&random_email).unwrap();
    let (stored_login_attempt_id, stored_two_fa_code) = {
        let two_fa_code_store = app.two_fa_code_store.write().await;
        two_fa_code_store
            .get_code(&email)
            .await
            .expect("Could not get 2FA code from store")
    }; // Lock is dropped here

    assert_eq!(stored_login_attempt_id, login_attempt_id);

    // Step 4: First verification with correct code - should succeed
    let json_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": stored_login_attempt_id.as_ref(),
        "2FACode": stored_two_fa_code.as_ref(),
    });

    let response = app.post_verify_2fa(&json_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // Step 5: Try to verify again with the same code - should fail because code was removed
    let response = app.post_verify_2fa(&json_body).await;
    assert_eq!(response.status().as_u16(), 401);
}
