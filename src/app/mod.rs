/**
 * Main app routes
 */

use std::str::FromStr;
use std::collections::HashMap;

use rocket::Outcome;
use rocket::response::Redirect;
use rocket::request::{self, Request, FromRequest, FromForm, LenientForm};

use rocket::http::Status;
use rocket::http::hyper::header::Basic;

use rocket_contrib::templates::Template;

pub mod config;

pub struct Auth(String);

#[derive(Debug)]
pub enum AuthError {
    Invalid,
    Missing,
}

// Implement custom guard for validate request
// Note: This function will get called the most frequently
impl<'a, 'r> FromRequest<'a, 'r> for Auth {
    type Error = AuthError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let head = request.headers();
        let host = head.get_one("host");
        let auth = head.get_one("authorization");

        if host.is_none() || auth.is_none() {
            Outcome::Failure((Status::Unauthorized, AuthError::Missing))
        } else if auth_validate(String::from(host.unwrap()), String::from(auth.unwrap())) {
            Outcome::Success(Auth(String::from("")))
        } else {
            Outcome::Failure((Status::Unauthorized, AuthError::Invalid))
        }
    }
}

// TODO: Validate "host" header and use in cominbation with user/pass
fn auth_validate(_host: String, input: String) -> bool {
    // Validate "Basic" auth type is used (Bearer not supported)
    let auth_header: Vec<&str> = input.split(' ').collect();
    if auth_header.get(0) != Some(&"Basic") || auth_header.get(1).is_none() {
        return false;
    }

    // Validate base64 encoded value matches accepted logins
    if let Ok(basic) = Basic::from_str(auth_header[1]) {
        return user_validate(&String::from(""), &basic.username, &basic.password.unwrap());
    }

    false
}

#[derive(FromForm)]
pub struct AuthUser {
    user: String,
    pass: String,
    host: String,
    redirect: String,
}

fn user_validate(user: &String, pass: &String, host: &String) -> bool {
    if user.as_str() == "admin"
        && pass.as_str() == "pass123"
        && host.as_str() == "example.club" {
        return true;
    }

    false
}

#[get("/validate")]
pub fn validate(_auth: Auth) -> &'static str {
    "Authorized"
}

#[get("/")]
pub fn index() -> Template {
    let mut data = HashMap::new();
    data.insert("foo", "bar");
    Template::render("index", data)
}

#[get("/login?<url>&<error>")]
pub fn login(url: String, error: Option<String>) -> Template {
    let mut data = HashMap::new();

    // TODO: Based on request headers
    data.insert("host", "example.club");
    data.insert("redirect", url.as_str());

    if let Some(msg) = &error {
        data.insert("error", msg);
    }

    // Values to render: url, urlHost
    Template::render("login", &data)
}

#[post("/login", data = "<input>")]
pub fn validate_login(input: LenientForm<AuthUser>) -> Redirect {
    println!("Validating Login: {}, {}", &input.user, &input.host);

    if user_validate(&input.user, &input.pass, &input.host) {
        Redirect::to(format!("{}", &input.redirect))
    } else {
        Redirect::to(uri!(login: url = &input.redirect, error = "Invalid Login"))
    }
}

#[get("/logout")]
pub fn logout() -> Template {
    let mut data = HashMap::new();
    data.insert("foo", "bar");
    Template::render("logout", data)
}
