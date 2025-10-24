use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{domain::AuthAPIError, utils::auth::validate_token};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyTokenResponse {
    pub message: String,
}

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Validate the JWT token
    match validate_token(&request.token).await {
        Ok(_) => {
            let response = VerifyTokenResponse {
                message: "Success verifying token".to_string(),
            };
            Ok((StatusCode::OK, Json(response)))
        }
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
