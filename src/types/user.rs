use crate::store::Store;
use mongodb::{Client, bson::oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    id: Option<ObjectId>,
    username: String,
    email: String,
    password: String,
}
