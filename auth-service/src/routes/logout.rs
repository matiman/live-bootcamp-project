use axum::{response::IntoResponse, Json};
use serde_json::json;


pub async fn logout() -> impl IntoResponse {
    Json(json!({ "message": "Successful logout" }))
}