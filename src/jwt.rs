use crate::user::AuthenticationMethod;
use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::env;

/// The secret key used to sign the JWTs
static ENCODING_KEY: Lazy<EncodingKey> =
    Lazy::new(|| EncodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()));

/// The secret key used to verify the JWTs
static DECODING_KEY: Lazy<DecodingKey> =
    Lazy::new(|| DecodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()));

/// Claims used for the JWT issued for the verification email
#[derive(Serialize, Deserialize)]
pub struct VerifyClaims {
    pub sub: String,
    pub exp: usize,
}

/// Claims used for the JWT issued for the user authentication
#[derive(Serialize, Deserialize)]
pub struct UserClaims {
    pub sub: String,
    pub exp: usize,
    pub auth_method: AuthenticationMethod,
}

/// Returns a string containing the JWT
pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    encode(&Header::default(), claims, &ENCODING_KEY).expect("Failed to create JWT")
}

/// Return a `Result` containing a `TokenData` or an Error. The `TokenData` contains the chosen claims
pub fn decode_jwt<T: DeserializeOwned>(token: &str) -> Result<TokenData<T>, Error> {
    decode::<T>(token, &DECODING_KEY, &Validation::new(Algorithm::HS256))
}
