use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};

use crate::{
    domain::AuthAPIError,
    routes::*,
    utils::localhost::{AUTH_SERVICE_DROPLET_URL, AUTH_SERVICE_LOCAL_URL},
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tower_http::{cors::CorsLayer, services::ServeDir};

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use app_state::AppState;
// This struct encapsulates our application-related logic.
pub struct Application {
    router: Router,
    listener: tokio::net::TcpListener,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Allow the app service(running on our local machine and in production) to call the auth service
        let allowed_origins = [
            AUTH_SERVICE_LOCAL_URL.parse()?,
            AUTH_SERVICE_DROPLET_URL.parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors)
            .fallback_service(ServeDir::new("assets"));
        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();

        println!("address: {}", address);
        // Create a new Application instance and return it
        Ok(Application {
            router,
            listener,
            address,
        })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        axum::serve(self.listener, self.router)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::TokenAlreadyBanned => (StatusCode::UNAUTHORIZED, "Token already banned"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
