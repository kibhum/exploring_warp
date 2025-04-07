use crate::Store;
use crate::types::user::User;
use mongodb::error::Error;
use warp::{Rejection, reject::Reject};

pub async fn add_user(store: Store, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    let db = store.db;
    let new_user = db.collection("user").insert_one(user).await;
    match new_user {
        Ok(result) => Ok(warp::reply::json(&result)),
        Err(e) => {
            eprintln!("e");
            Err(warp::reject())
        }
    }
}
