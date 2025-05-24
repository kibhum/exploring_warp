use config::Config;
use dotenv;
use serde::{Deserialize, Serialize};
use std::{
    env,
    fmt::format,
    io::{Error, ErrorKind},
};
use warp::{Filter, http::Method, reply::html};
mod store;
use store::Store;
use tracing_subscriber::fmt::format::FmtSpan;
mod routes;
mod types;
mod utils;
use handle_errors::return_error;
use types::user::User;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct Args {
    log_level: String,
    mongodb_uri: String,
    database_port: u16,
    database_name: String,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Loading the env values
    dotenv::dotenv().ok();
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

    let port = env::var("port")
        .ok()
        .map(|val| val.parse::<u16>())
        .unwrap_or(Ok(8080))
        .map_err(|_e| Error::new(ErrorKind::Other, "Port not parseble"))?;
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
    let store = Store::new(format!("{}", config.mongodb_uri)).await;
    // Initializing collections
    store.clone().db.collection::<User>("user");
    let store_filter = warp::any().map(move || store.clone());

    // Setting the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();
    // Implemenenting cors
    let cors = warp::cors()
        .allow_any_origin()
        .allow_header("content-type")
        .allow_methods(&[Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    // Routes
    // 1. Users path
    let register = warp::post()
        .and(warp::path("auth"))
        .and(warp::path("register"))
        .and(warp::path::end())
        // .and(routes::authentication::auth())
        .and(store_filter.clone())
        .and(warp::body::json())
        .and_then(routes::user::register);

    let login = warp::post()
        .and(warp::path("auth"))
        .and(warp::path("login"))
        .and(warp::path::end())
        // .and(utils::authentication::protect())
        .and(store_filter.clone())
        .and(warp::body::json())
        .and_then(routes::user::login);

    let current_user = warp::get()
        .and(warp::path("auth"))
        .and(warp::path("me"))
        .and(warp::path::end())
        .and(utils::authentication::protect())
        .and(store_filter.clone())
        .and_then(routes::user::logged_in_user);

    // Combining all the routes
    let routes = register
        .or(login)
        .or(current_user)
        .with(cors)
        .with(warp::trace::request())
        .recover(return_error);
    warp::serve(routes).run(([127, 0, 0, 1], port)).await;
    Ok(())
}
