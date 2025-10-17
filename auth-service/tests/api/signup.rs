use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    // TODO: add more malformed input test cases
    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let test_cases = [serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    })];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_login`
        assert_eq!(response.status().as_u16(), 201);

        let expected_response = SignupResponse {
            message: "User created successfully!".to_owned(),
        };

        // Assert that we are getting the correct response body!
        assert_eq!(
            response
                .json::<SignupResponse>()
                .await
                .expect("Could not deserialize response body to UserBody"),
            expected_response
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.

    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
        "email": "invalid_email",
        "password": "passwordfdff",
        "requires2FA": true
        }),
        serde_json::json!({ "email": "",
        "password": "sdfsdfsdfdf",
        "requires2FA": true
        }),
        serde_json::json!({ "email": "example.com",
        "password": "",
        "requires2FA": true
        }),
        serde_json::json!({ "email": "example@gmail.com",
        "password": "123",
        "requires2FA": true
        }),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await; // call `post_signup`
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    // because the email already exists in the user store.

    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_case = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    //write for loop for 2 calls

    let response = app.post_signup(&test_case).await; // call `post_signup` first time
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_signup(&test_case).await; // call `post_signup` 2nd time
    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
