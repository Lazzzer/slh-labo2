use std::env;

use lettre::{
    message::MultiPart,
    transport::smtp::{authentication::Credentials, response::Response, Error},
    Message, SmtpTransport, Transport,
};

pub fn send_verification_email(email: &str, jwt_token: &str) -> Result<Response, Error> {
    let credentials = Credentials::new(
        env::var("SMTP_USERNAME").unwrap(),
        env::var("SMTP_PASSWORD").unwrap(),
    );

    let mailer = SmtpTransport::relay(env::var("SMTP_RELAY").unwrap().as_str())
        .unwrap()
        .credentials(credentials)
        .build();

    let email = Message::builder()
        .from(
            format!("SLH Labo2 <{}>", env::var("SMTP_USERNAME").unwrap())
                .parse()
                .unwrap(),
        )
        .to(format!("{} <{}>", email, email).parse().unwrap())
        .subject("SLH Labo2 - Verify your account")
        .multipart(MultiPart::alternative_plain_html(
            String::from("Welcome to SLH Labo2!"),
            format!(r#"Welcome! Click <a href="http://localhost:8000/_verify-email?token={}">here</a> to verify your account"#, jwt_token),
        ))
        .unwrap();

    mailer.send(&email)
}
