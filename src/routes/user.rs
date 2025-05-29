use crate::Store;
use crate::types::user::{
    ForgotPasswordUser, NewUser, Passwords, User, UserExtracts, UserResponse,
};
use crate::utils::authentication::{Claims, hash_password, verify_password};
use handle_errors::Error as CustomError;
use mongodb::Collection;
use mongodb::bson::{DateTime, doc};
use std::time::{Duration, SystemTime};
use warp::http::StatusCode;

pub async fn register(store: Store, user: NewUser) -> Result<impl warp::Reply, warp::Rejection> {
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

    let updated_user = NewUser {
        email: user.email,
        password: hashed_password,
        username: user.username,
        created_at: Some(DateTime::now()),
        is_active: true,
        last_login: Some(DateTime::now()),
        updated_at: Some(DateTime::now()),
    };

    let new_user: mongodb::results::InsertOneResult = db
        .collection("user")
        .insert_one(updated_user)
        .await
        .map_err(CustomError::DbError)?;

    let user_id = new_user.inserted_id.as_object_id().unwrap().to_string();

    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let expires_in = current_time + Duration::from_secs(24 * 60 * 60 * 1000).as_secs() as usize;

    let user_claims = Claims::new(user_id, expires_in, expires_in, None);

    Claims::send_created_token(user_claims)
}

pub async fn login(store: Store, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    let user_collection = store.db.collection::<User>("user");
    // Checking whether the username or email exists
    match user_collection
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
                            let current_time = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as usize;

                            let expires_in = current_time
                                + Duration::from_secs(24 * 60 * 60 * 1000).as_secs() as usize;
                            if let Some(user_id) = current_user.id {
                                let filter = doc! { "_id": &user_id };
                                let update = doc! { "$set": { "last_login": DateTime::now() } };
                                match user_collection.update_one(filter, update).await {
                                    Ok(update_result) => {
                                        if update_result.matched_count == 1 {
                                            let user_claims = Claims::new(
                                                user_id.to_string(),
                                                current_time,
                                                expires_in,
                                                None,
                                            );
                                            Claims::send_created_token(user_claims)
                                        } else {
                                            Err(warp::reject::custom(CustomError::MissingUserId))
                                        }
                                    }
                                    Err(_) => Err(warp::reject::custom(CustomError::MissingUserId)),
                                }
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

pub async fn logged_in_user(
    user_extracts: UserExtracts,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::with_status(
        warp::reply::json(
            &serde_json::json!({ "success": true, "user": UserResponse::new(user_extracts.user_extracts.0) }),
        ),
        StatusCode::OK,
    ))
}

pub async fn forgot_password(
    store: Store,
    user: ForgotPasswordUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    let user_collection = store.db.collection::<User>("user");
    // Checking whether the email exists
    match user_collection
        .find_one(doc! {
            "$or": [
                { "email": &user.email }
            ]
        })
        .show_record_id(true)
        .await
    {
        Ok(user_option) => {
            if let Some(current_user) = user_option {
                let current_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as usize;

                let expires_in = current_time + Duration::from_secs(30 * 60).as_secs() as usize;
                if let Some(user_id) = current_user.id {
                    let user_claims = Claims::new(
                        user_id.to_string(),
                        current_time,
                        expires_in,
                        Some("Password_Reset".to_string()),
                    );
                    Claims::send_created_token(user_claims)
                } else {
                    return Err(warp::reject::custom(CustomError::MissingUserId));
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

pub async fn reset_password(
    user_extracts: UserExtracts,
    new_password: Passwords,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&serde_json::json!({
        "success": true,
        "user": user_extracts.user_extracts.0.username,
    })))
}
