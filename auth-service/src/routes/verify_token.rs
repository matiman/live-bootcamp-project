use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::AuthAPIError, utils::auth::validate_token};

#[tracing::instrument(name = "Verify Token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the JWT token
    match validate_token(&request.token, &state.banned_token_store).await {
        Ok(_) => {
            let response = VerifyTokenResponse {
                message: "Success verifying token".to_string(),
            };
            Ok((StatusCode::OK, Json(response)))
        }
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    pub message: String,
}
