use std::os::unix::raw::mode_t;

use argon2::Error as ArgonError;
use jsonwebtoken::errors::Error as JwtError;
use mongodb::error::{Error as DBError, ErrorKind as DBErrorKind};
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
}

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
            _ => Ok(warp::reply::with_status(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )),
        }
    } else {
        Ok(warp::reply::with_status(
            "Route not found".to_string(),
            StatusCode::NOT_FOUND,
        ))
    }
}
