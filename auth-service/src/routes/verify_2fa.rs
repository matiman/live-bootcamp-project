use axum::{response::IntoResponse, Json};
use serde_json::json;


pub async fn verify_2fa() -> impl IntoResponse {
    Json(json!({ "message": "Success verifying 2fa" }))
}