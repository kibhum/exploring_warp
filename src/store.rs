use handle_errors::Error as CustomError;
use mongodb::{Client, Database};

#[derive(Debug, Clone)]
pub struct Store {
    pub db: Database,
}

impl Store {
    pub async fn new(uri: String) -> Result<Self, CustomError> {
        let client = Client::with_uri_str(uri)
            .await
            .map_err(|e| CustomError::DbError(e))?;
        
        Ok(Self {
            db: client.database("RUST"),
        })
    }
}
