use argon2::Error as ArgonError;
use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};
use mongodb::bson::oid::Error as ObjError;
use mongodb::error::{Error as DBError, ErrorKind as DBErrorKind};
use serde::Serialize;
use std::{
    error::Error as StdErrorTrait,
    io::{Error as StdError, ErrorKind as StdErrorKind},
    num::ParseIntError,
};
use tracing::{Level, event};
use warp::{
    Rejection, Reply, cors::CorsForbidden, filters::body::BodyDeserializeError, http::StatusCode,
    reject::Reject,
};

#[derive(Serialize)]
struct ErrorResponse {
    pub message: String,
    pub status_code: u16,
}
impl ErrorResponse {
    pub fn new(message: String, status: StatusCode) -> Self {
        ErrorResponse {
            message,
            status_code: status.as_u16(),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    CannotBindPort(ParseIntError),
    WrongPassword,
    DbError(DBError),
    ArgonLibraryError(ArgonError),
    JwtError(JwtError),
    UserAlreadyExists,
    MissingUserId,
    NotLoggedIn,
    ObjectIdError(ObjError),
}

impl StdErrorTrait for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ArgonLibraryError(e) => {
                eprintln!("{}", e);
                write!(f, "Cannot verifiy password")
            }
            Error::DbError(e) => {
                eprintln!("{}", e);
                writeln!(f, "There's a problem with the database")
            }
            Error::JwtError(e) => {
                eprintln!("{}", e);
                writeln!(f, "Jwt Error")
            }
            Error::WrongPassword => {
                writeln!(f, "Wrong password")
            }
            Error::UserAlreadyExists => {
                writeln!(f, "User Already Exists")
            }
            Error::MissingUserId => {
                writeln!(f, "Missing User Id")
            }
            Error::NotLoggedIn => {
                writeln!(f, "You are not logged in! Please Log in to get access.")
            }
            Error::CannotBindPort(e) => {
                eprintln!("{}", e);
                writeln!(f, "Cannot Bind Port.")
            }
            Error::ObjectIdError(e) => {
                eprintln!("{}", e);
                writeln!(f, "Cannot Bind Port.")
            }
        }
    }
}

impl Reject for Error {}

// Global Error handler
pub async fn return_error(r: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(crate::Error::DbError(e)) = r.find() {
        match *e.kind.clone() {
            DBErrorKind::Authentication { message, .. } => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(message, StatusCode::UNAUTHORIZED)),
                StatusCode::UNAUTHORIZED,
            )),
            DBErrorKind::ServerSelection { message, .. } => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    message,
                    StatusCode::SERVICE_UNAVAILABLE,
                )),
                StatusCode::SERVICE_UNAVAILABLE,
            )),
            _ => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "Internal Server Error".to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else if let Some(crate::Error::JwtError(e)) = r.find() {
        match e.kind() {
            JwtErrorKind::InvalidToken => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "Invalid Token".to_string(),
                    StatusCode::NOT_ACCEPTABLE,
                )),
                StatusCode::NOT_ACCEPTABLE,
            )),
            JwtErrorKind::InvalidSignature => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "Invalid Signature".to_string(),
                    StatusCode::NOT_ACCEPTABLE,
                )),
                StatusCode::NOT_ACCEPTABLE,
            )),
            JwtErrorKind::ExpiredSignature => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "EXpired Token".to_string(),
                    StatusCode::NOT_ACCEPTABLE,
                )),
                StatusCode::NOT_ACCEPTABLE,
            )),
            _ => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "Internal Server Error".to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else if let Some(crate::Error::ArgonLibraryError(e)) = r.find() {
        event!(Level::ERROR, "{}", e);
        match e {
            ArgonError::PwdTooLong => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "Password Too Long".to_string(),
                    StatusCode::NOT_ACCEPTABLE,
                )),
                StatusCode::NOT_ACCEPTABLE,
            )),
            _ => Ok(warp::reply::with_status(
                warp::reply::json(&ErrorResponse::new(
                    "Internal Server Error".to_string(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else if let Some(error) = r.find::<CorsForbidden>() {
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                error.to_string(),
                StatusCode::FORBIDDEN,
            )),
            StatusCode::FORBIDDEN,
        ))
    } else if let Some(error) = r.find::<BodyDeserializeError>() {
        event!(Level::ERROR, "{}", error);
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                error.to_string(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )),
            StatusCode::UNPROCESSABLE_ENTITY,
        ))
    } else if let Some(crate::Error::WrongPassword) = r.find() {
        event!(Level::ERROR, "Wrong E-Mail/Password combination");
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "Wrong E-Mail/Password combination".to_string(),
                StatusCode::UNAUTHORIZED,
            )),
            StatusCode::UNAUTHORIZED,
        ))
    } else if let Some(crate::Error::UserAlreadyExists) = r.find() {
        event!(Level::ERROR, "User already exists");
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "User already exists".to_string(),
                StatusCode::BAD_REQUEST,
            )),
            StatusCode::BAD_REQUEST,
        ))
    } else if let Some(crate::Error::MissingUserId) = r.find() {
        event!(Level::ERROR, "Missing User Id");
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "Missing User Id".to_string(),
                StatusCode::BAD_REQUEST,
            )),
            StatusCode::BAD_REQUEST,
        ))
    } else if let Some(crate::Error::NotLoggedIn) = r.find() {
        event!(Level::ERROR, "You are not logged in");
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "You are not logged in".to_string(),
                StatusCode::UNAUTHORIZED,
            )),
            StatusCode::UNAUTHORIZED,
        ))
    } else if let Some(crate::Error::CannotBindPort(e)) = r.find() {
        event!(Level::ERROR, "Cannot Bind To Port");
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "Cannot Bind To Port".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
            StatusCode::INTERNAL_SERVER_ERROR,
        ))
    } else if let Some(crate::Error::ObjectIdError(e)) = r.find() {
        match e {
            ObjError::InvalidHexStringCharacter { c, index, hex, .. } => {
                event!(Level::ERROR, "{c} {index} {hex}");
            }
            ObjError::InvalidHexStringLength { length, hex, .. } => {
                event!(Level::ERROR, "{length} {hex}");
            }
            _ => event!(Level::ERROR, "Invalid Object ID Error"),
        }
        event!(Level::ERROR, "Cannot Bind To Port");
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "Cannot Bind To Port".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
            StatusCode::INTERNAL_SERVER_ERROR,
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&ErrorResponse::new(
                "Route not found".to_string(),
                StatusCode::NOT_FOUND,
            )),
            StatusCode::NOT_FOUND,
        ))
    }
}
