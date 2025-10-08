use std::error::Error;

use axum::{response::IntoResponse, routing::post, serve::Serve, Json, Router};
use serde_json::json;
use tower_http::services::ServeDir;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        let router = Router::new()
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .nest_service("/", ServeDir::new("assets"));

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();

        let server = axum::serve(listener, router);

        println!("address: {}", address);
        // Create a new Application instance and return it
        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

async fn signup() -> impl IntoResponse {
    Json(json!({ "message": "Successful signup" }))
}

async fn login() -> impl IntoResponse {
    Json(json!({ "message": "Successful login" }))
}

async fn logout() -> impl IntoResponse {
    Json(json!({ "message": "Successful logout" }))
}

async fn verify_2fa() -> impl IntoResponse {
    Json(json!({ "message": "Success verifying 2fa" }))
}

async fn verify_token() -> impl IntoResponse {
    Json(json!({ "message": "Success verifying token" }))
}
