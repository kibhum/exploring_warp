use crate::Store;
use crate::types::user::{User, UserResponse};
use crate::utils::authentication::Claims;
use jsonwebtoken::get_current_timestamp;
use mongodb::bson::Bson;
use mongodb::error::Error;
use std::time::{Duration, SystemTime};
use warp::{Rejection, reject::Reject};

pub async fn add_user(store: Store, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    let db = store.db;
    let new_user = db.collection("user").insert_one(user).await;
    match new_user {
        Ok(result) => {
            // let user_id = result.inserted_id.as_str();
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
            eprintln!("e");
            Err(warp::reject())
        }
    }
}
