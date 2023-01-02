use crate::user::AuthenticationMethod;
use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::env;

static ENCODING_KEY: Lazy<EncodingKey> =
    Lazy::new(|| EncodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()));

static DECODING_KEY: Lazy<DecodingKey> =
    Lazy::new(|| DecodingKey::from_secret(env::var("JWT_SECRET").unwrap().as_ref()));

#[derive(Deserialize)]
pub struct VerifyQueryContent {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyClaims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Serialize, Deserialize)]
pub struct UserClaims {
    pub sub: String,
    pub exp: usize,
    pub auth_method: AuthenticationMethod,
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    encode(&Header::default(), claims, &ENCODING_KEY).expect("Failed to create JWT")
}

pub fn decode_jwt<T: DeserializeOwned>(token: &str) -> Result<TokenData<T>, Error> {
    decode::<T>(token, &DECODING_KEY, &Validation::new(Algorithm::HS256))
}
