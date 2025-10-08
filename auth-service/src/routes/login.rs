use axum::{response::IntoResponse, Json};
use serde_json::json;

pub async fn login() -> impl IntoResponse {
    Json(json!({ "message": "Successful login" }))
}
