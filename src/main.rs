use config::Config;
use dotenv;
use serde::{Deserialize, Serialize};
use std::env;
use warp::{Filter, http::Method};
mod store;
use store::Store;
use tracing_subscriber::fmt::format::FmtSpan;
mod controllers;
mod routes;
mod types;
mod utils;
use handle_errors::{Error as CustomError, return_error};
use routes::user::user;
use std::sync::Arc;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct Args {
    log_level: String,
    mongodb_uri: String,
    database_port: u16,
    database_name: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), CustomError> {
    // Loading the env values
    dotenv::from_filename("config.env").ok();
    // Making sure the env values are set
    // TODO: CREATE A MACRO

    if let Err(_) = env::var("MONGODB_URL") {
        eprintln!("Database host not set: Default values will be used");
    }
    if let Err(_) = env::var("DATABASE_NAME") {
        panic!("Database name not set, Default values will be used");
    }
    if let Err(_) = env::var("DATABASE_PORT") {
        panic!("Database port not set, Default values will be used");
    }
    utils::email::send_mail().await;
    let port = env::var("PORT")
        .ok()
        .map(|val| val.parse::<u16>())
        .unwrap_or(Ok(8080))
        .map_err(|e| CustomError::CannotBindPort(e))?;
    // Fetching default configurations
    let config = Config::builder()
        .add_source(config::File::with_name("setup"))
        .build()
        .unwrap();
    // Attempt to deserialize it
    let config = config.try_deserialize::<Args>().unwrap();
    // Setting log level
    let log_filter = env::var("RUST_LOG").unwrap_or_else(|_| {
        format!(
            "Handle errors: {}, Web server: {}, Warp: {}",
            config.log_level, config.log_level, config.log_level
        )
    });
    // Initializing the store with database connection
    let store = Arc::new(Store::new(format!("{}", config.mongodb_uri)).await?);
    // Initializing collections
    store.initialize_collections();
    // let cloned_store = store.clone();
    // let store_filter = warp::any().map(move || store.clone());

    // Setting the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();
    // Implemenenting cors
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(["Authorization", "content-type"])
        .allow_methods(&[Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    // Combining all the routes
    let routes = user::user_routes(store)
        .with(cors)
        .with(warp::trace::request())
        .recover(return_error);
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
    Ok(())
}
