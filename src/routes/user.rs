use crate::Store;
use crate::types::user::{NewUser, User};
use crate::utils::authentication::{Claims, hash_password, verify_password};
use handle_errors::Error as CustomError;
use mongodb::bson::{Document, doc, oid::ObjectId};
use std::time::{Duration, SystemTime};
use warp::http::{StatusCode, header};

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
    };

    let new_user: mongodb::results::InsertOneResult = db
        .collection("user")
        .insert_one(updated_user)
        .await
        .map_err(CustomError::DbError)?;

    let user_id = new_user.inserted_id.as_object_id().unwrap().to_string();

    let expires_in = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as usize
        + Duration::from_millis(24 * 60 * 60 * 1000).as_millis() as usize;

    let user_claims = Claims::new(user_id, expires_in);

    Claims::send_created_token(user_claims)
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
    session: Claims,
    store: Store,
) -> Result<impl warp::Reply, warp::Rejection> {
    // let filter: Document = Document::new();
    let db = store.db;
    // Checking whether the username or email exists
    if let Ok(user_id) = ObjectId::parse_str(session.user_id) {
        let user = db
            .collection::<User>("user")
            .find_one(doc! { "_id": user_id })
            .await
            .map_err(|e| warp::reject::custom(CustomError::DbError(e)));
        if let Ok(curent_user) = user {
            match curent_user {
                Some(usr) => Ok(warp::reply::with_status(
                    warp::reply::json(&serde_json::json!({ "success": true, "user": usr })),
                    StatusCode::OK,
                )),
                None => Err(warp::reject::custom(CustomError::MissingUserId)),
            }
        } else {
            Err(warp::reject::custom(CustomError::MissingUserId))
        }
    } else {
        Err(warp::reject::custom(CustomError::MissingUserId))
    }
}
