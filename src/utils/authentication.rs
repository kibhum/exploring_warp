use crate::store::Store;
use crate::types::user::{User,UserExtracts};
use crate::utils::date_fns::convert_bson_datetime_to_usize;
use argon2::{self, Config};
use cookie::{Cookie, time::Duration};
use handle_errors::Error as CustomError;
use jsonwebtoken::errors::{Error as JwtError, ErrorKind as JwtErrorKind};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header as JwtHeader, TokenData, Validation, decode, encode,
};
use mongodb::Collection;
use mongodb::bson::{doc, oid::ObjectId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use warp::Filter;
use warp::http::StatusCode;
use warp::http::header;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: String,
    pub iat: usize,
    pub exp: usize,
    pub purpose: Option<String>,
}

impl Claims {
    pub fn new(user_id: String, iat: usize, exp: usize, purpose: Option<String>) -> Self {
        Self {
            user_id,
            iat,
            exp,
            purpose,
        }
    }

    pub fn send_created_token(user_claims: Claims) -> Result<impl warp::Reply, warp::Rejection> {
        if let Some(_purpose) = &user_claims.purpose {
            let token = encode(
                &JwtHeader::default(),
                &user_claims,
                &EncodingKey::from_secret("secret".as_ref()),
            )
            .map_err(|jwt_error| warp::reject::custom(CustomError::JwtError(jwt_error)))?;

            Ok(warp::reply::with_status(
                warp::reply::json(
                    &serde_json::json!({ "success": true, "password_reset_token": token }),
                ),
                StatusCode::OK,
            ))
        } else {
            let token = encode(
                &JwtHeader::default(),
                &user_claims,
                &EncodingKey::from_secret("secret".as_ref()),
            )
            .map_err(|jwt_error| warp::reject::custom(CustomError::JwtError(jwt_error)))?;

            // Create the cookie string (e.g., jwt=the_token; HttpOnly; SameSite=Lax)
            // let cookie: String = Cookie::build(("jwt", token.clone()))
            //     .path("/")
            //     // .secure(true)
            //     .http_only(true)
            //     .max_age(Duration::days(1))
            //     .build()
            //     .to_string();

            // Build JSON response with Set-Cookie header
            // let reply = warp::reply::with_header(
            //     warp::reply::json(&serde_json::json!({ "success": true, "token": token })),
            //     header::SET_COOKIE,
            //     cookie,
            // );
            // // Adding Authorization header
            // let reply_with_authorization_header =
            //     warp::reply::with_header(reply, header::AUTHORIZATION, format!("Bearer {}", token));

            // Ok(warp::reply::with_status(
            //     reply_with_authorization_header,
            //     StatusCode::CREATED,
            // ))

            Ok(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({ "success": true, "token": token })),
                StatusCode::CREATED,
            ))
        }
    }

    pub fn verify_token(token: String) -> Result<TokenData<Claims>, warp::reject::Rejection> {
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::default(),
        )
        .map_err(|jwt_error| warp::reject::custom(CustomError::JwtError(jwt_error)))?;
        if let Some(purpose) = &token_data.claims.purpose {
            if *purpose == "Password_Reset".to_string() {
                Ok(token_data)
            } else {
                Err(warp::reject::custom(CustomError::JwtError(JwtError::from(
                    JwtErrorKind::InvalidToken,
                ))))
            }
        } else {
            Ok(token_data)
        }
    }
}

pub fn hash_password(password: String) -> String {
    let mut salt = [0u8; 8];
    rand::rng().fill_bytes(&mut salt);
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap()
}

pub fn verify_password(hash: &str, password: String) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(hash, password.as_bytes())
}

pub fn protect(
    store: Store,
) -> impl Filter<Extract = (UserExtracts,), Error = warp::Rejection> + Clone {
    warp::header::optional::<String>("Authorization").and_then(move |token: Option<String>| {
        let db = store.db.clone();
        let user_collection: mongodb::Collection<User> =
            store.db.clone().collection::<User>("user");
        async move {
            if let Some(token) = token {
                if token.starts_with("Bearer ") {
                    if let Some(tkn) = token.split_whitespace().last() {
                        match Claims::verify_token(tkn.to_string()) {
                            Ok(token_data) => {
                                if token_data.claims.purpose.is_none() {
                                    let user_id = token_data.claims.user_id;
                                    match ObjectId::parse_str(&user_id) {
                                        Ok(obj_id) => {
                                            let db_user = db
                                                .collection::<User>("user")
                                                .find_one(doc! { "_id": obj_id })
                                                .await
                                                .map_err(|e| {
                                                    warp::reject::custom(CustomError::MissingUserId)
                                                })?;
                                            if let Some(usr) = db_user {
                                                match usr.password_changed_at {
                                                    Some(password_changed_at) => {
                                                        if convert_bson_datetime_to_usize(
                                                            password_changed_at,
                                                        ) > token_data.claims.iat
                                                        {
                                                            Err(warp::reject::custom(
                                                                CustomError::NotLoggedIn,
                                                            ))
                                                        } else {
                                                            Ok(UserExtracts::new(usr,user_collection))
                                                        }
                                                    }
                                                    None => Ok(UserExtracts::new(usr,user_collection))
                                                }
                                            } else {
                                                Err(warp::reject::custom(CustomError::NotLoggedIn))
                                            }
                                        }
                                        Err(e) => {
                                            Err(warp::reject::custom(CustomError::ObjectIdError(e)))
                                        }
                                    }
                                } else if  token_data.claims.purpose.is_some() {
                                    let user_id = token_data.claims.user_id;
                                    match ObjectId::parse_str(&user_id) {
                                        Ok(obj_id) => {
                                            let db_user = db
                                                .collection::<User>("user")
                                                .find_one(doc! { "_id": obj_id })
                                                .await
                                                .map_err(|e| {
                                                    warp::reject::custom(CustomError::MissingUserId)
                                                })?;
                                            if let Some(usr) = db_user {
                                                match usr.password_changed_at {
                                                    Some(password_changed_at) => {
                                                        if convert_bson_datetime_to_usize(
                                                            password_changed_at,
                                                        ) > token_data.claims.iat
                                                        {
                                                            Err(warp::reject::custom(
                                                                CustomError::JwtError(JwtError::from(
                                                                    JwtErrorKind::ExpiredSignature,
                                                                )),
                                                            ))
                                                        } else {
                                                            Ok(UserExtracts::new(usr,user_collection))
                                                        }
                                                    }
                                                    None => Ok(UserExtracts::new(usr,user_collection))
                                                }
                                            } else {
                                                Err(warp::reject::custom(CustomError::NotLoggedIn))
                                            }
                                        }
                                        Err(e) => {
                                            Err(warp::reject::custom(CustomError::ObjectIdError(e)))
                                        }
                                    }
                                } 
                                
                                else {
                                    Err(warp::reject::custom(CustomError::NotLoggedIn))
                                }
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        Err(warp::reject::custom(CustomError::NotLoggedIn))
                    }
                } else {
                    Err(warp::reject::custom(CustomError::NotLoggedIn))
                }
            } else {
                Err(warp::reject::custom(CustomError::NotLoggedIn))
            }
        }
    })
}
