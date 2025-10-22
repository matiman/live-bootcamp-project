use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User},
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    //USE Email and Passowrd parse method
    let email = Email::parse(&email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(&password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;

    //Check if user exists
    let user = user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    //Check if user credentials are correct. E.g password is correct.
    user_store
        .validate_user(&email, &password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok((
        StatusCode::OK,
        Json(LoginResponse {
            message: "Successful login".to_string(),
        }),
    ))
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LoginResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
