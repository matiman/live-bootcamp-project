use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Url;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;

    // Make logout request without any JWT cookie
    let response = app.post_logout().await;

    // Assert that we get 400 Bad Request
    assert_eq!(response.status(), 400);

    // Parse and verify error response
    let error_response: ErrorResponse = response
        .json()
        .await
        .expect("Failed to parse error response");
    assert_eq!(error_response.error, "Missing token");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    // Make logout request with invalid token
    let response = app.post_logout().await;

    // Assert that we get 401 Unauthorized
    assert_eq!(response.status(), 401);

    // Parse and verify error response
    let error_response: ErrorResponse = response
        .json()
        .await
        .expect("Failed to parse error response");
    assert_eq!(error_response.error, "Invalid token");
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
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

    // Login to get a valid JWT cookie
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // Verify we got a valid auth cookie
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());

    // Now make logout request with valid JWT cookie
    let response = app.post_logout().await;

    // Assert that we get 200 OK
    assert_eq!(response.status(), 200);

    // Verify that the token is banned
    let banned_token_store = app.banned_token_store.read().await;
    assert!(banned_token_store
        .is_token_banned(&auth_cookie.value())
        .unwrap());
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
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

    // Login to get a valid JWT cookie
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    // First logout - should succeed
    let response = app.post_logout().await;
    assert_eq!(response.status(), 200);

    // Second logout - should fail with 400 (no valid token)
    let response = app.post_logout().await;
    assert_eq!(response.status(), 400);

    // Parse and verify error response
    let error_response: ErrorResponse = response
        .json()
        .await
        .expect("Failed to parse error response");
    //assert_eq!(error_response.error, "Missing token");
}
