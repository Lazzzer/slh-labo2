use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use regex::Regex;
use zxcvbn::zxcvbn;

/// Default hashed password to use when :
/// - An standard authentication fails. It will be passed in `verify_password()` to avoid timing attacks.
/// - A user signed up with oauth. It will fill the password field in the database.
pub static DEFAULT_HASHED_PASSWORD: Lazy<String> = Lazy::new(|| hash_password("default_password"));

/// Returns a bool. True if the email is in the right format false otherwise.
///
/// # Arguments
///
/// * `email` - A string containing the email to validate
///
/// # Examples
///
/// ```
/// let accepted = email_regex_validator("toto@toto.ch");
/// ```
pub fn validate_email_regex(email: &str) -> bool {
    lazy_static! {
        static ref MAIL_REGEX: Regex = Regex::new(r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#).unwrap();
    }
    MAIL_REGEX.is_match(email)
}

/// Returns a bool. True if the password respects the minimal score and has a length between 8 and 64 false otherwise
///
/// # Arguments
///
/// * `password` - A string containing the password to validate
/// * `score` - The score that the password has to have at least
///
/// # Examples
///
/// ```
/// let accepted = password_validator("richandfamous", 2);
/// ```
pub fn validate_password(password: &str, score: u8) -> bool {
    if password.len() < 8 || password.len() > 64 {
        return false;
    }
    // zxcvbn will return a score for the password passed in parameter
    let estimate = zxcvbn(password, &[]).unwrap().score();
    estimate >= score
}

/// Ensure that the password is equal to an argon hash. True if that is the case false otherwise
///
/// # Arguments
///
/// * `hash` - An array of u8 that is the hash of a password
/// * `password` - A password entered that will be compared to the hash
///
/// # Examples
///
/// ```
/// let valid = hash_validator("$argon2id$v=19$m=65536,t=2,p=1$A74CWdmhtzx5xlSniFDxOA$X3oYveivo5qGWdQmDJzQbZbZmXjE5JGpG4p5+J0x/+4".as_bytes, "TestAndFame");
/// ```
pub fn verify_password(hash: &str, password: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Returns a String that is the value of the hashed password.
/// The hashed function used here is argon2
///
/// # Arguments
///
/// * `password` - A string that contains the password to hash
///
/// # Examples
///
/// ```
/// let hashed_password = password_hash("MyPassword");
/// ```
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    password_hash
}
