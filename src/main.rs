use clap::{App, Arg};
use serde_json::Value;
use std::fmt;
fn main() -> Result<(), JWTError> {
    let matches = App::new("JWT Decoding")
        .version("1.0")
        .author("Kevin K. <kbknapp@gmail.com>")
        .about("Decodes JWT tokens")
        .arg(
            Arg::with_name("token")
                .short("t")
                .long("token")
                .value_name("TOKEN")
                .help("give a valid jwt token")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let token = matches.value_of("token").unwrap_or("");
    let token = parser(token)?;
    println!("decoded token: {:?}", token);
    Ok(())
}

#[derive(Debug)]
struct JWToken {
    header: Value,
    payload: Value,
    signature: Vec<u8>,
}

#[derive(Debug)]
enum JWTError {
    SerdeJsonError(serde_json::Error),
    UTF8Error(std::str::Utf8Error),
    DecodeError(base64::DecodeError),
    MissingPartError,
    UnknownPartError,
}
impl std::error::Error for JWTError {}
impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error = match self {
            JWTError::SerdeJsonError(e) => format!("Serde Json error: {}", e),
            JWTError::UTF8Error(e) => format!("UTF8 Error: {}", e),
            JWTError::DecodeError(e) => format!("Error in base64 decoding: {}", e),
            JWTError::MissingPartError => format!("Error: Missing part"),
            JWTError::UnknownPartError => format!("Error: Unknown part"),
        };
        write!(f, "{}", error)
    }
}
impl From<serde_json::Error> for JWTError {
    fn from(error: serde_json::Error) -> Self {
        JWTError::SerdeJsonError(error)
    }
}
impl From<std::str::Utf8Error> for JWTError {
    fn from(error: std::str::Utf8Error) -> Self {
        JWTError::UTF8Error(error)
    }
}
impl From<base64::DecodeError> for JWTError {
    fn from(error: base64::DecodeError) -> Self {
        JWTError::DecodeError(error)
    }
}

fn parser<T: AsRef<str>>(jwt: T) -> Result<JWToken, JWTError> {
    let mut splits = jwt.as_ref().split(".");
    let header = parser_header(splits.next())?;
    let payload = parser_payload(splits.next())?;
    let signature = parser_signauture(splits.next())?;
    if splits.next().is_some() {
        return Err(JWTError::UnknownPartError);
    }

    Ok(JWToken {
        header,
        payload,
        signature,
    })
}

fn process_part(part: &str) -> Result<Value, JWTError> {
    let decoded = base64::decode_config(part, base64::URL_SAFE)?;
    let decoded = std::str::from_utf8(&decoded)?;
    let decoded = serde_json::from_str::<serde_json::Value>(decoded)?;
    Ok(decoded)
}

fn parser_header(o: Option<&str>) -> Result<Value, JWTError> {
    match o {
        None => Err(JWTError::MissingPartError),
        Some(part) => {
            let decoded = process_part(part)?;
            Ok(decoded)
        }
    }
}
fn parser_payload(o: Option<&str>) -> Result<Value, JWTError> {
    match o {
        None => Err(JWTError::MissingPartError),
        Some(part) => {
            let decoded = process_part(part)?;
            Ok(decoded)
        }
    }
}
fn parser_signauture(o: Option<&str>) -> Result<Vec<u8>, JWTError> {
    match o {
        None => Err(JWTError::MissingPartError),
        Some(part) => {
            let decoded = base64::decode_config(part, base64::URL_SAFE)?;
            Ok(decoded)
        }
    }
}

#[cfg(test)]
#[test]
fn parsing_success_test() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let token = parser(jwt).unwrap();
    let header = r#"{
      "alg": "HS256",
      "typ": "JWT"
    }"#;
    let header = serde_json::from_str::<serde_json::Value>(header).unwrap();
    let payload = r#"{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}"#;
    let payload = serde_json::from_str::<serde_json::Value>(payload).unwrap();
    assert_eq!(header, token.header);
    assert_eq!(payload, token.payload);
}

#[test]
fn unknown_part_test() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c.extra";
    let token = parser(jwt);
    match token {
        Err(JWTError::UnknownPartError) => (),
        _ => panic!("Received unexpected error. Expected: UnknownPartError"),
    }
}
