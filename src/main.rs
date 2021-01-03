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

#[macro_use]
extern crate lazy_static;

use std::io::Error as ioError;
use std::collections::HashMap;
use rocket::config::Config as RocketConfig;
use rocket_contrib::templates::Template;

mod app;
use app::config::CFG;

fn main() -> Result<(), ioError> {
    let mut rocket_conf = RocketConfig::active().unwrap();
    rocket_conf.set_address(CFG.host.as_str()).expect("Unable to bind to host provided");
    rocket_conf.set_port(CFG.port);

    let mut extras = HashMap::new();
    extras.insert("template_dir".to_string(), "templates/".into());
    rocket_conf.set_extras(extras);

    rocket::custom(rocket_conf)
        .attach(Template::fairing())
        .mount("/",
            routes![app::index, app::validate,
            app::login, app::validate_login, app::logout]
        ).launch();

    Ok(())
}
