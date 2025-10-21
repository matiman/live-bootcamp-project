use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User},
};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    //USE Email and Passowrd parse method
    let email = Email::parse(&email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(&password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Create a new `User` instance using data in the `request`
    let user = User {
        email: email,
        password,
        requires_2fa: request.requires_2fa,
    };

    let mut user_store = state.user_store.write().await;

    // TODO: early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    if user_store.get_user(&user.email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }
    // TODO: instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    user_store
        .add_user(user)
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

//...

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}
#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
