use argon2::{self, Config, hash_encoded};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::{Error, ErrorKind},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    user_id: String,
    exp: usize,
}

impl Claims {
    pub fn new(user_id: String, timestamp: usize) -> Self {
        Self {
            user_id,
            exp: timestamp,
        }
    }
    pub fn create_token(user_claims: &Claims) -> Result<String, Error> {
        encode(
            &Header::default(),
            user_claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
    }

    pub fn verify_token(&self, token: String) -> Result<TokenData<Claims>, Error> {
        decode::<Claims>(
            &token,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::default(),
        )
    }
}

pub fn hash_password(password: String) -> String {
    let mut salt = [0u8; 8];
    rand::rng().fill_bytes(&mut salt);
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap()
}

fn verify_password(hash: &str, password: String) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(hash, password.as_bytes())
}
