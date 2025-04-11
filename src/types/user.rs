use crate::store::Store;
use mongodb::{Client, bson::oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<ObjectId>,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub token: String,
}
impl UserResponse {
    pub fn new(token: String) -> Self {
        Self { token }
    }
}
