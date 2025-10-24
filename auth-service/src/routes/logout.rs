use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use time::OffsetDateTime;

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // If the token is valid you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken is validation fails.
    match validate_token(&token).await {
        Ok(_) => {}
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }

    // Clear the JWT cookie by setting expiration to now (immediately expired)
    let now = OffsetDateTime::now_utc();
    let cleared_cookie = Cookie::build((JWT_COOKIE_NAME, ""))
        .path("/")
        .expires(now)
        .build();

    let updated_jar = jar.add(cleared_cookie);

    let mut banned_token_store = state.banned_token_store.write().await;
    banned_token_store.add_banned_token(token).await.unwrap();

    (updated_jar, Ok(StatusCode::OK))
}
