use argon2::Error as ArgonError;
use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};
use mongodb::error::{Error as DBError, ErrorKind as DBErrorKind};
use std::{error::Error as StdError, f32::consts::E};
use tracing::{Level, event};
use warp::{
    Rejection, Reply, cors::CorsForbidden, filters::body::BodyDeserializeError, http::StatusCode,
    reject::Reject,
};

#[derive(Debug)]
pub enum Error {
    WrongPassword,
    DbError(DBError),
    ArgonLibraryError(ArgonError),
    JwtError(JwtError),
    UserAlreadyExists,
}

impl StdError for Error {}

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
        }
    }
}

impl Reject for Error {}

// Global Error handler
pub async fn return_error(r: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(crate::Error::DbError(e)) = r.find() {
        match *e.kind.clone() {
            DBErrorKind::Authentication { message, .. } => {
                Ok(warp::reply::with_status(message, StatusCode::UNAUTHORIZED))
            }
            DBErrorKind::ServerSelection { message, .. } => Ok(warp::reply::with_status(
                message,
                StatusCode::SERVICE_UNAVAILABLE,
            )),
            _ => Ok(warp::reply::with_status(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else if let Some(crate::Error::JwtError(e)) = r.find() {
        match e.kind() {
            JwtErrorKind::InvalidToken => Ok(warp::reply::with_status(
                "Internal Server Error".to_string(),
                StatusCode::NOT_ACCEPTABLE,
            )),
            _ => Ok(warp::reply::with_status(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else if let Some(crate::Error::ArgonLibraryError(e)) = r.find() {
        event!(Level::ERROR, "{}", e);
        match e {
            ArgonError::PwdTooLong => Ok(warp::reply::with_status(
                "Password too long".to_string(),
                StatusCode::NOT_ACCEPTABLE,
            )),
            _ => Ok(warp::reply::with_status(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else if let Some(error) = r.find::<CorsForbidden>() {
        Ok(warp::reply::with_status(
            error.to_string(),
            StatusCode::FORBIDDEN,
        ))
    } else if let Some(error) = r.find::<BodyDeserializeError>() {
        event!(Level::ERROR, "{}", error);
        Ok(warp::reply::with_status(
            error.to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ))
    } else if let Some(crate::Error::WrongPassword) = r.find() {
        event!(Level::ERROR, "Entered wrong password");
        Ok(warp::reply::with_status(
            "Wrong E-Mail/Password combination".to_string(),
            StatusCode::UNAUTHORIZED,
        ))
    } else if let Some(crate::Error::UserAlreadyExists) = r.find() {
        event!(Level::ERROR, "User already exists");
        Ok(warp::reply::with_status(
            "User already exists".to_string(),
            StatusCode::UNAUTHORIZED,
        ))
    } else {
        Ok(warp::reply::with_status(
            "Route not found".to_string(),
            StatusCode::NOT_FOUND,
        ))
    }
}
