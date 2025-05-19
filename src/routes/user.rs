use crate::Store;
use crate::types::user::{User, UserResponse};
use crate::utils::authentication::{Claims, hash_password, verify_password};
use handle_errors::Error as CustomError;
use mongodb::bson::doc;
use std::time::{Duration, SystemTime};
use warp::{Rejection, reject::Reject};

pub async fn register(store: Store, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    let db = store.db;
    // Checking whether the username or email is already in use
    let db_user = db
        .collection::<User>("user")
        .find_one(doc! {
            "$or": [
                { "username": &user.username },
                { "email": &user.email }
            ]
        })
        .await;
    match db_user {
        Ok(user_option) => {
            if user_option.is_some() {
                return Err(warp::reject::custom(CustomError::UserAlreadyExists));
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            return Err(warp::reject::custom(CustomError::DbError(e)));
        }
    }

    // Hash the user's password
    let hashed_password = hash_password(user.password);

    let updated_user = User {
        email: user.email,
        password: hashed_password,
        username: user.username,
        _id: None,
    };

    let new_user = db.collection("user").insert_one(updated_user).await;
    match new_user {
        Ok(result) => {
            let user_id = result.inserted_id.as_object_id().unwrap().to_string();
            let expires_in = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as usize
                + Duration::from_millis(24 * 60 * 60 * 1000).as_millis() as usize;
            let user_claims = Claims::new(user_id, expires_in);
            let token = Claims::create_token(&user_claims).map_err(|e| CustomError::JwtError(e))?;
            let user_response = UserResponse::new(token);

            Ok(warp::reply::json(&user_response))
        }

        Err(e) => {
            eprintln!("{}", e);
            Err(warp::reject::custom(CustomError::DbError(e)))
        }
    }
}

pub async fn login(store: Store, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    let db = store.db;
    // Checking whether the username or email exists
    match db
        .collection::<User>("user")
        .find_one(doc! {
            "$or": [
                { "username": &user.username },
                { "email": &user.email }
            ]
        })
        .show_record_id(true)
        .await
    {
        Ok(user_option) => {
            // Check if the user exists
            if let Some(current_user) = user_option {
                match verify_password(&current_user.password, user.password) {
                    Ok(success) => {
                        if success {
                            let expires_in = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as usize
                                + Duration::from_millis(24 * 60 * 60 * 1000).as_millis() as usize;
                            if let Some(user_id) = current_user._id {
                                let user_claims = Claims::new(user_id.to_string(), expires_in);
                                let token = Claims::create_token(&user_claims)
                                    .map_err(|e| CustomError::JwtError(e))?;
                                let user_response = UserResponse::new(token);

                                Ok(warp::reply::json(&user_response))
                            } else {
                                return Err(warp::reject::custom(CustomError::MissingUserId));
                            }
                        } else {
                            return Err(warp::reject::custom(CustomError::WrongPassword));
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        return Err(warp::reject::custom(CustomError::ArgonLibraryError(e)));
                    }
                }
            } else {
                return Err(warp::reject::custom(CustomError::WrongPassword));
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            Err(warp::reject::custom(CustomError::DbError(e)))
        }
    }
}
