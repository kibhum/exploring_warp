use mongodb::{Client, Database};
#[derive(Debug, Clone)]
pub struct Store {
    pub db: Database,
}

impl Store {
    pub async fn new(uri: String) -> Self {
        let client = Client::with_uri_str(uri)
            .await
            .expect("Failed to connect to the database");
        Self {
            db: client.database("RUST"),
        }
    }
}
