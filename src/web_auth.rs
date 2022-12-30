use crate::db::{self, user_exists, DbConn};
use crate::mailer::send_verification_email;
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest, UserClaims,
    VerifyClaims, VerifyQueryContent,
};
use crate::user::{AuthenticationMethod, User, UserDTO};
use crate::validator::{hash_password, validate_email_regex, validate_password, verify_password};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{chrono, MemoryStore, Session, SessionStore};
use axum_sessions::SameSite;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use oauth2::reqwest::async_http_client;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use serde_json::json;
use std::env;
use std::error::Error;

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/_verify-email", get(verify_email))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .with_state(state)
}

/// Endpoint handling login
///
/// POST /login
///
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    let _email = login.login_email;
    let _password = login.login_password;

    let user = db::get_user(&mut _conn, &_email)
        .map_err(|_| {
            FailureResponse::new(
                StatusCode::UNAUTHORIZED,
                "Could not find user with given email".to_string(),
            )
            .into_response()
        })
        .unwrap();

    if user.get_auth_method() != AuthenticationMethod::Password {
        return Err(
            FailureResponse::new(StatusCode::UNAUTHORIZED, "Bad credentials".to_string())
                .into_response(),
        );
    }

    if !verify_password(&user.password, &_password) {
        return Err(
            FailureResponse::new(StatusCode::UNAUTHORIZED, "Bad credentials".to_string())
                .into_response(),
        );
    }

    if !user.email_verified {
        return Err(FailureResponse::new(
            StatusCode::UNAUTHORIZED,
            "Email not verified".to_string(),
        )
        .into_response());
    }

    let jar = add_auth_cookie(jar, &user.to_dto())
        .map_err(|_| {
            FailureResponse::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create JWT cookie".to_string(),
            )
            .into_response()
        })
        .unwrap();

    Ok((jar, AuthResult::Success))
}

/// Endpoint used to register a new account
///
/// POST /register
///
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut _conn: DbConn,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    let _email = register.register_email;
    let _password = register.register_password;
    let _password2 = register.register_password2;

    if _password != _password2 {
        return Err(FailureResponse::new(
            StatusCode::BAD_REQUEST,
            "Passwords do not match".to_string(),
        )
        .into_response());
    }

    if !validate_email_regex(&_email) {
        return Err(
            FailureResponse::new(StatusCode::BAD_REQUEST, "Email is invalid".to_string())
                .into_response(),
        );
    }

    if !validate_password(&_password, 4) {
        return Err(FailureResponse::new(
            StatusCode::BAD_REQUEST,
            "Password is not strong enough".to_string(),
        )
        .into_response());
    }

    if user_exists(&mut _conn, &_email).is_ok() {
        return Err(FailureResponse::new(
            StatusCode::BAD_REQUEST,
            "Email already used".to_string(),
        )
        .into_response());
    }

    let user = User::new(
        &_email,
        &hash_password(&_password),
        AuthenticationMethod::Password,
        false,
    );

    if db::save_user(&mut _conn, user).is_err() {
        return Err(FailureResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to saved user in database".to_string(),
        )
        .into_response());
    }

    let claims = VerifyClaims {
        sub: _email.clone(),
        exp: (chrono::Utc::now().timestamp() + 10 * 60) as usize, // Valid for 10 minutes
    };

    let jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()),
    )
    .unwrap();

    if send_verification_email(&_email, &jwt).is_err() {
        return Err(FailureResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to send email".to_string(),
        )
        .into_response());
    }

    Ok(AuthResult::Success)
}

/// Endpoint used for the verification link sent by email
///
/// GET /_verify-email?token=t
async fn verify_email(
    mut _conn: DbConn,
    _params: Query<VerifyQueryContent>,
) -> Result<Redirect, StatusCode> {
    match decode::<VerifyClaims>(
        &_params.token,
        &DecodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(token) => match db::set_verified(&mut _conn, &token.claims.sub) {
            Ok(value_updated) => {
                if value_updated == 1 {
                    Ok(Redirect::to("/login"))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        },
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let client = crate::oauth::OAUTH_CLIENT.clone();

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    let mut session = Session::new();
    session.insert("csrf_token", csrf_token.secret().clone());
    session.insert("pkce_verifier", pkce_verifier.secret().clone());

    let session_id = _session_store.store_session(session).await.unwrap(); // TODO : a lot of things to check properly

    let cookie = Cookie::build("session_id", session_id.unwrap())
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .http_only(true)
        .finish();

    Ok((jar.add(cookie), Redirect::to(auth_url.as_str())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    mut jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    mut _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // return Ok((jar, Redirect::to("/home")));

    let client = crate::oauth::OAUTH_CLIENT.clone();

    let session_id = jar.get("session_id").unwrap().value().to_string();

    let session = _session_store
        .load_session(session_id)
        .await
        .unwrap()
        .unwrap();

    let csrf_token = CsrfToken::new(session.get("csrf_token").unwrap());

    if csrf_token.secret() != _params.state.as_str() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let pkce_verifier = PkceCodeVerifier::new(session.get("pkce_verifier").unwrap());

    let token_result = client
        .exchange_code(AuthorizationCode::new(_params.code.clone()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .unwrap();

    _session_store.destroy_session(session).await.unwrap();
    jar = jar.remove(Cookie::named("session_id"));

    let email = crate::oauth::get_google_oauth_email(&token_result)
        .await
        .unwrap();

    if user_exists(&mut _conn, &email).is_err() {
        // Save the user in the database
        if let Err(err) = db::save_user(
            &mut _conn,
            User::new(
                &email,
                &hash_password("Yolo"),
                AuthenticationMethod::OAuth,
                true,
            ),
        ) {
            println!("Error: {}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    let user_dto = UserDTO {
        email,
        auth_method: AuthenticationMethod::OAuth,
    };

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
///
/// POST /password_update
///
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    let _old_password = _update.old_password;
    let _new_password = _update.new_password;

    if _old_password == _new_password {
        return Err(FailureResponse::new(
            StatusCode::BAD_REQUEST,
            "Passwords are the same".to_string(),
        )
        .into_response());
    }

    if !validate_password(&_new_password, 4) {
        return Err(FailureResponse::new(
            StatusCode::BAD_REQUEST,
            "Password is not strong enough".to_string(),
        )
        .into_response());
    }

    let user = db::get_user(&mut _conn, &_user.email).unwrap();

    if !verify_password(&user.password, &_old_password) {
        return Err(
            FailureResponse::new(StatusCode::UNAUTHORIZED, "Bad credentials".to_string())
                .into_response(),
        );
    }

    if let Err(err) = db::update_password(&mut _conn, &_user.email, &hash_password(&_new_password))
    {
        println!("Error: {}", err);
        return Err(FailureResponse::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update password".to_string(),
        )
        .into_response());
    }

    Ok(AuthResult::Success)
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

/// Returns a `Result`. Can be a `CookieJar` with the auth cookie added or an error.
///
/// ### Arguments
///
/// * `jar` - A `CookieJar` to add the auth cookie to
/// * `_user` - A `UserDTO` containing the user's email and auth method
///
/// ### Examples
///
/// ```
/// let user_dto = UserDTO {
///   email: "john@doe.com".to_string(),
///   auth_method: AuthenticationMethod::OAuth
/// };
/// let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
/// ```
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    let claims = UserClaims {
        sub: _user.email.clone(),
        exp: (chrono::Utc::now().timestamp() + 30 * 60) as usize, // Valid for 30 minutes
        auth_method: _user.auth_method.clone(),
    };

    let jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(env::var("JWT_SECRET")?.as_ref()),
    )?;

    Ok(jar.add(
        Cookie::build("auth", jwt)
            .path("/")
            .secure(true)
            .http_only(true)
            .finish(),
    ))
}

enum AuthResult {
    Success,
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}

struct FailureResponse {
    status: StatusCode,
    message: String,
}

impl FailureResponse {
    fn new(status: StatusCode, message: String) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for FailureResponse {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "res": self.message }))).into_response()
    }
}
