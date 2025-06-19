use argon2::Error as ArgonError;
use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};
use mongodb::bson::oid::Error as ObjError;
use mongodb::error::{Error as DBError, ErrorKind as DBErrorKind};
use serde::Serialize;
use std::{error::Error as StdErrorTrait, num::ParseIntError};
use tracing::{Level, event};
use warp::{
    Rejection, Reply,
    cors::CorsForbidden,
    filters::body::BodyDeserializeError,
    http::StatusCode,
    reject::Reject,
    reply,
    reply::{WithHeader, WithStatus},
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

    fn format_response(
        &self,
    ) -> warp::reply::WithHeader<warp::reply::WithHeader<WithStatus<warp::reply::Json>>> {
        let json = warp::reply::json(&ErrorResponse::new(
            self.message.to_string(),
            StatusCode::from_u16(self.status_code).unwrap(),
        ));

        let reply = reply::with_status(json, StatusCode::from_u16(self.status_code).unwrap());
        let reply = reply::with_header(
            reply,
            "Access-Control-Allow-Origin",
            "http://localhost:8080",
        );
        let reply = reply::with_header(
            reply,
            "Access-Control-Allow-Headers",
            "content-type, authorization",
        );

        reply
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
pub async fn return_error(
    r: Rejection,
) -> Result<
    warp::reply::WithHeader<warp::reply::WithHeader<WithStatus<warp::reply::Json>>>,
    Rejection,
> {
    if let Some(crate::Error::DbError(e)) = r.find() {
        match *e.kind.clone() {
            DBErrorKind::Authentication { message, .. } => {
                Ok(ErrorResponse::new(message, StatusCode::UNAUTHORIZED).format_response())
            }
            DBErrorKind::ServerSelection { message, .. } => {
                Ok(ErrorResponse::new(message, StatusCode::SERVICE_UNAVAILABLE).format_response())
            }
            _ => Ok(ErrorResponse::new(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .format_response()),
        }
    } else if let Some(crate::Error::JwtError(e)) = r.find() {
        match e.kind() {
            JwtErrorKind::InvalidToken => Ok(ErrorResponse::new(
                "Invalid Token".to_string(),
                StatusCode::NOT_ACCEPTABLE,
            )
            .format_response()),

            JwtErrorKind::InvalidSignature => Ok(ErrorResponse::new(
                "Invalid Signature".to_string(),
                StatusCode::NOT_ACCEPTABLE,
            )
            .format_response()),
            JwtErrorKind::ExpiredSignature => Ok(ErrorResponse::new(
                "Expired Token".to_string(),
                StatusCode::NOT_ACCEPTABLE,
            )
            .format_response()),
            _ => Ok(ErrorResponse::new(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .format_response()),
        }
    } else if let Some(crate::Error::ArgonLibraryError(e)) = r.find() {
        event!(Level::ERROR, "{}", e);
        match e {
            ArgonError::PwdTooLong => Ok(ErrorResponse::new(
                "Password Too Long".to_string(),
                StatusCode::NOT_ACCEPTABLE,
            )
            .format_response()),
            _ => Ok(ErrorResponse::new(
                "Internal Server Error".to_string(),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .format_response()),
        }
    } else if let Some(error) = r.find::<CorsForbidden>() {
        Ok(ErrorResponse::new(error.to_string(), StatusCode::FORBIDDEN).format_response())
    } else if let Some(error) = r.find::<BodyDeserializeError>() {
        event!(Level::ERROR, "{}", error);
        Ok(
            ErrorResponse::new(error.to_string(), StatusCode::UNPROCESSABLE_ENTITY)
                .format_response(),
        )
    } else if let Some(crate::Error::WrongPassword) = r.find() {
        event!(Level::ERROR, "Wrong E-Mail/Password combination");
        // Ok(warp::reply::with_status(
        //     warp::reply::json(&ErrorResponse::new(
        //         "Wrong E-Mail/Password combination".to_string(),
        //         StatusCode::UNAUTHORIZED,
        //     )),
        //     StatusCode::UNAUTHORIZED,
        // ))

        let json = warp::reply::json(&ErrorResponse::new(
            "Wrong E-Mail/Password combination".to_string(),
            StatusCode::UNAUTHORIZED,
        ));

        let reply = reply::with_status(json, StatusCode::UNAUTHORIZED);
        let reply = reply::with_header(
            reply,
            "Access-Control-Allow-Origin",
            "http://localhost:8080",
        );
        let reply = reply::with_header(
            reply,
            "Access-Control-Allow-Headers",
            "content-type, authorization",
        );

        Ok(reply)
    } else if let Some(crate::Error::UserAlreadyExists) = r.find() {
        event!(Level::ERROR, "User already exists");
        Ok(
            ErrorResponse::new("User already exists".to_string(), StatusCode::BAD_REQUEST)
                .format_response(),
        )
    } else if let Some(crate::Error::MissingUserId) = r.find() {
        event!(Level::ERROR, "Missing User Id");
        Ok(
            ErrorResponse::new("Missing User Id".to_string(), StatusCode::BAD_REQUEST)
                .format_response(),
        )
    } else if let Some(crate::Error::NotLoggedIn) = r.find() {
        event!(Level::ERROR, "You are not logged in");
        Ok(ErrorResponse::new(
            "You are not logged in".to_string(),
            StatusCode::UNAUTHORIZED,
        )
        .format_response())
    } else if let Some(crate::Error::CannotBindPort(e)) = r.find() {
        event!(Level::ERROR, "Cannot Bind To Port");
        Ok(ErrorResponse::new(
            "Cannot Bind To Port".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .format_response())
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
        Ok(ErrorResponse::new(
            "Cannot Bind To Port".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .format_response())
    } else {
        Ok(
            ErrorResponse::new("Route not found".to_string(), StatusCode::NOT_FOUND)
                .format_response(),
        )
    }
}
