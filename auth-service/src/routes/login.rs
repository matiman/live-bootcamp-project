use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, Password, TwoFACode, User},
    utils::generate_auth_cookie,
};

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = request.email;
    let password = request.password;

    //USE Email and Passowrd parse method
    let email = match Email::parse(&email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let password = match Password::parse(&password) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let user_store = state.user_store.read().await;

    //Check if user credentials are correct. E.g password is correct.
    match user_store.validate_user(&email, &password).await {
        Ok(_) => {}
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    }

    //Check if user exists
    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    // Call the generate_auth_cookie function defined in the auth module.
    // If the function call fails return AuthAPIError::UnexpectedError.
    let auth_cookie = match generate_auth_cookie(&user.email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let jar = jar.add(auth_cookie);

    // Handle request based on user's 2FA configuration
    match user.requires_2fa {
        true => handle_2fa(user.email, &state, jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

// New!
async fn handle_2fa(
    email: Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    let two_fa_response = TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
    };

    // Add the login attempt ID and 2FA code to the two_fa_code_store
    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    match two_fa_code_store
        .add_code(email.clone(), login_attempt_id, two_fa_code.clone())
        .await
    {
        Ok(_) => {}
        Err(_) => return (jar, Err(AuthAPIError::TwoFACodeStoreError)),
    }

    // Send the 2FA code to the email client
    let email_client = state.email_client.read().await;
    match email_client
        .send_email(&email, "2FA code", two_fa_code.as_ref())
        .await
    {
        Ok(_) => {}
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    }

    (
        jar,
        Ok((
            StatusCode::PARTIAL_CONTENT,
            Json(LoginResponse::TwoFactorAuth(two_fa_response)),
        )),
    )
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    (jar, Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))))
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
