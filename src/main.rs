#![feature(decl_macro)]

/**
 * Simpleauth
 *
 * Simple HTTP authentication handler
 * Designed as a drop-in replacement for HTTP Basic Auth, but with GUI frontend
 * Compatible with nginx auth_request
 */


#[macro_use]
extern crate rocket;
extern crate rocket_contrib;
extern crate base64;
extern crate toml;

#[macro_use]
extern crate lazy_static;

use rocket::config::Config as RocketConfig;
use rocket_contrib::templates::Template;

mod app;
use app::config::CFG;

fn main() -> Result<(), std::io::Error> {
    let mut rocket_conf = RocketConfig::active().unwrap();
    rocket_conf.set_address(CFG.host.as_str()).expect("Unable to bind to host provided");
    rocket_conf.set_port(CFG.port);

    rocket::custom(rocket_conf)
        .attach(Template::fairing())
        .mount("/",
            routes![app::index, app::validate,
            app::login, app::validate_login, app::logout]
        )
        .register(catchers![app::unauthorized]).launch();

    Ok(())
}
