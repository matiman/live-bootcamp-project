use crate::helpers::{get_random_email, TestApp};
use auth_service::utils::constants::JWT_SECRET;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use quickcheck::{Arbitrary, Gen};
use quickcheck_macros::quickcheck;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
struct ValidJwtToken(String);

#[derive(Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    //token is missing
    let test_cases = [
        serde_json::json!({}),
        serde_json::json!({
            "email": "test@example.com"
        }),
        serde_json::json!({
            "password": "password123"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app
            .http_client
            .post(&format!("{}/verify-token", &app.address))
            .json(test_case)
            .send()
            .await
            .expect("Failed to execute request.");

        // Assert that we get 422 Unprocessable Entity
        assert_eq!(response.status(), 422);
    }
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    // Sign up a user
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Login to get a valid JWT token
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // Extract the JWT token from the login response
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == "jwt")
        .expect("No auth cookie found");
    let jwt_token = auth_cookie.value();

    // Test verify-token with valid JWT
    let verify_body = serde_json::json!({
        "token": jwt_token
    });

    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .json(&verify_body)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert that we get 200 OK
    assert_eq!(response.status(), 200);

    // Parse and verify response
    let response_body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(response_body["message"], "Success verifying token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // Test with invalid JWT token
    let verify_body = serde_json::json!({
        "token": "invalid_jwt_token_here"
    });

    let response = app
        .http_client
        .post(&format!("{}/verify-token", &app.address))
        .json(&verify_body)
        .send()
        .await
        .expect("Failed to execute request.");

    // Assert that we get 401 Unauthorized
    assert_eq!(response.status(), 401);
}

#[quickcheck]
fn should_return_401_for_any_invalid_token(invalid_token: String) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let app = TestApp::new().await;

        // Test with any invalid JWT token
        let verify_body = serde_json::json!({
            "token": invalid_token
        });

        let response = app
            .http_client
            .post(&format!("{}/verify-token", &app.address))
            .json(&verify_body)
            .send()
            .await
            .expect("Failed to execute request.");

        // Should return 401 for any invalid token
        assert_eq!(response.status(), 401);
    })
}

#[quickcheck]
fn should_return_200_for_any_valid_token(valid_token: ValidJwtToken) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let app = TestApp::new().await;

        let verify_body = serde_json::json!({
            "token": valid_token.0
        });

        let response = app
            .http_client
            .post(&format!("{}/verify-token", &app.address))
            .json(&verify_body)
            .send()
            .await
            .expect("Failed to execute request.");

        // Should return 200 for any valid token
        assert_eq!(response.status(), 200);
    })
}

impl Arbitrary for ValidJwtToken {
    fn arbitrary<T: Gen>(g: &mut T) -> Self {
        // Generate random email
        let email = format!("user{}@example.com", g.next_u32());

        // Create JWT claims
        let claims = JwtClaims {
            sub: email,
            exp: Utc::now().timestamp() as usize + 3600, // 1 hour from now
        };

        // Generate valid JWT token using the same secret as the app
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
        .unwrap_or_else(|_| "invalid_token".to_string());

        ValidJwtToken(token)
    }
}
