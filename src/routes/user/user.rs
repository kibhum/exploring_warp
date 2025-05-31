use crate::{
    Store,
    controllers::user::{forgot_password, logged_in_user, login, register, reset_password},
    utils,
};
use std::sync::Arc;
use warp::{Filter, Rejection};

pub fn user_routes(
    store: Arc<Store>,
) -> impl Filter<Extract = impl warp::Reply, Error = Rejection> + Clone {
    let store_filter = warp::any().map({
        let store = store.clone();
        move || store.clone()
    });

    let register = warp::post()
        .and(warp::path("auth"))
        .and(warp::path("register"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and(warp::body::json())
        .and_then(register);

    let login = warp::post()
        .and(warp::path("auth"))
        .and(warp::path("login"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and(warp::body::json())
        .and_then(login);

    let forgot_password = warp::post()
        .and(warp::path("auth"))
        .and(warp::path("forgot_password"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and(warp::body::json())
        .and_then(forgot_password);

    let current_user = warp::get()
        .and(warp::path("auth"))
        .and(warp::path("me"))
        .and(warp::path::end())
        .and(utils::authentication::protect(store.clone()))
        .and_then(logged_in_user);

    let reset_password = warp::post()
        .and(warp::path("auth"))
        .and(warp::path("reset_password"))
        .and(warp::path::end())
        .and(utils::authentication::validate_password_reset_token(
            store.clone(),
        ))
        .and(warp::body::json())
        .and_then(reset_password);

    // Combine all routes
    register
        .or(login)
        .or(current_user)
        .or(forgot_password)
        .or(reset_password)
}
