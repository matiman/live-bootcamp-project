use axum::{response::IntoResponse, Json};
use serde_json::json;

pub async fn signup() -> impl IntoResponse {
    Json(json!({ "message": "Successful signup" }))
}
