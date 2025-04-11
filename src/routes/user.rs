use crate::Store;
use crate::types::user::{User, UserResponse};
use crate::utils::authentication::{Claims, hash_password};
use jsonwebtoken::get_current_timestamp;
use mongodb::bson::Bson;
use mongodb::error::Error;
use std::time::{Duration, SystemTime};
use warp::{Rejection, reject::Reject};

pub async fn register(store: Store, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    let db = store.db;
    // Hash the user's password
    let hashed_password = hash_password(user.password);

    let updated_user = User {
        email: user.email,
        password: hashed_password,
        username: user.username,
        id: None,
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
            let token = Claims::create_token(&user_claims).expect("Could not generate token");
            let user_response = UserResponse::new(token);

            Ok(warp::reply::json(&user_response))
        }

        Err(e) => {
            eprintln!("{}", e);
            Err(warp::reject())
        }
    }
}
