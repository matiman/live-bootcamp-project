use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use secrecy::Secret;

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "Logout", skip_all)]
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
    let _ = match validate_token(&token, &state.banned_token_store).await {
        Ok(claims) => claims,
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    };

    if let Err(e) = state
        .banned_token_store
        .write()
        .await
        .add_banned_token(Secret::new(token.to_owned()))
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    //Remove jwt cookie from jar
    let updated_jar = jar.remove(Cookie::from(JWT_COOKIE_NAME));

    (updated_jar, Ok(StatusCode::OK))
}
