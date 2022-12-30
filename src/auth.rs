use std::env;

use crate::db::Pool;
use crate::models::UserClaims;
use crate::user::UserDTO;
use axum::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::Redirect;
use axum::RequestPartsExt;
use axum_extra::extract::CookieJar;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

const REDIRECT_URL: &str = "/home";

/// Retrieves a UserDTO from request parts if a user is currently authenticated.
#[async_trait]
impl<S> FromRequestParts<S> for UserDTO
where
    Pool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = parts
            .extract::<CookieJar>()
            .await
            .expect("Could not get CookieJar from request parts");
        let _jwt = jar
            .get("auth")
            .ok_or_else(|| Redirect::to(REDIRECT_URL))?
            .value();

        if let Ok(token) = decode::<UserClaims>(
            _jwt,
            &DecodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()),
            &Validation::new(Algorithm::HS256),
        ) {
            return Ok(UserDTO {
                email: token.claims.sub,
                auth_method: token.claims.auth_method,
            });
        }
        Err(Redirect::to(REDIRECT_URL))
    }
}
