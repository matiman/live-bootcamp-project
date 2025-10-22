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

    //Try to login with wrong password
    let response = app.post_login(&wrong_password_test_case).await;
    assert_eq!(response.status().as_u16(), 401);
    //
}
