use crate::utils::date_fns::format_bson_datetime;
use mongodb::Collection;
use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub username: String,
    pub email: String,
    pub password: String,

    #[serde(default)]
    pub is_active: bool,

    #[serde(default)]
    pub created_at: Option<DateTime>,

    #[serde(default)]
    pub updated_at: Option<DateTime>,

    #[serde(default)]
    pub last_login: Option<DateTime>,

    #[serde(default)]
    pub password_changed_at: Option<DateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub is_active: bool,

    #[serde(default)]
    pub created_at: Option<DateTime>,

    #[serde(default)]
    pub updated_at: Option<DateTime>,

    #[serde(default)]
    pub last_login: Option<DateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub last_login: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

impl UserResponse {
    pub fn new(user: User) -> Self {
        Self {
            id: user.id.map_or(String::new(), |id| id.to_string()),
            username: user.username,
            email: user.email,
            is_active: user.is_active,
            last_login: format_bson_datetime(user.last_login),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgotPasswordUser {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passwords {
    pub password: String,
    pub password_confirmation: String,
}

pub type UserExtracts = (User, Collection<User>);
