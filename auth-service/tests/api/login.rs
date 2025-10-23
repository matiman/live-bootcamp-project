use auth_service::utils::JWT_COOKIE_NAME;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "abc@gmail.com",
        }),
        serde_json::json!({
            "password": "pasworfdd123",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(response.status().as_u16(), 422);
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": "abcgmail.com",
            "password": "password123",
        }),
        serde_json::json!({
            "email": "",
            "password": "",
        }),
        serde_json::json!({
            "email": "abc@gmail.com",
            "password": "password123",
        }),
        serde_json::json!({
            "email": "abcg@mail.com",
            "password": "dfdf",
        }),
        serde_json::json!({
            "email": "abcgmailcom.@",
            "password": "pasword123",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(response.status().as_u16(), 400);
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.
    let app = TestApp::new().await;

    let signup_test_case = serde_json::json!({
        "email": "abcdfd@gmail.com",
        "password": "paswsddord123",
        "requires2FA": true
    });

    let wrong_password_test_case = serde_json::json!({
        "email": "abc@gmail.com",
        "password": "wrongpasword123",
        "requires2FA": true
    });

    //sign up first time
    let response = app.post_signup(&signup_test_case).await;
    assert_eq!(response.status().as_u16(), 201);

    //Try to login with wrong password for existing user
    let response = app.post_login(&wrong_password_test_case).await;
    assert_eq!(response.status().as_u16(), 401);
    //
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "pasword123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}
