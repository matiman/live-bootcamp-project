use axum::{response::IntoResponse, Json};
use serde_json::json;



pub async fn verify_token() -> impl IntoResponse {
    Json(json!({ "message": "Success verifying token" }))
}