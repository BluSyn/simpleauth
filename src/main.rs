/**
 * Simpleauth
 *
 * Simple HTTP authentication handler
 * Designed as a drop-in replacement for HTTP Basic Auth, but with GUI frontend
 * Compatible with nginx auth_request
 */

#[macro_use]
extern crate rocket;

use rocket::config::Config as RocketConfig;
use rocket_dyn_templates::Template;
use std::net::IpAddr;

mod app;
use app::config::CFG;

#[launch]
async fn rocket() -> _ {
    let conf = RocketConfig::figment()
        .merge((
            "address",
            CFG.host
                .parse::<IpAddr>()
                .expect("Invalid bind IP configured"),
        ))
        .merge(("port", CFG.port));

    rocket::custom(conf)
        .attach(Template::fairing())
        .mount(
            "/",
            routes![app::validate, app::login, app::validate_login, app::logout],
        )
        .register("/", catchers![app::unauthorized])
}
