/**
 * Main app routes
 */

use std::str::FromStr;
use std::collections::HashMap;

use rocket::Outcome;
use rocket::response::Redirect;
use rocket::request::{self, Request, FromRequest, Form};

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
fn auth_validate(host: String, input: String) -> bool {
    // Validate "Basic" auth type is used (Bearer not supported)
    let authHeader: Vec<&str> = input.split(' ').collect();
    if authHeader.get(0) != Some(&"Basic") || authHeader.get(1).is_none() {
        return false;
    }

    // Validate base64 encoded value matches accepted logins
    if let Ok(basic) = Basic::from_str(authHeader[1]) {
        return user_validate(&String::from(""), &basic.username, &basic.password.unwrap());
    }

    false
}

const LIMIT: u64 = 256;

#[derive(FromForm)]
pub struct AuthUser {
    user: String,
    pass: String,
    host: String,
    redirect: String,
}

fn user_validate(user: &String, pass: &String, host: &String) -> bool {
    if user == &String::from("admin") && pass == &String::from("pass123") {
        return true;
    }

    false
}

#[get("/validate")]
pub fn validate(auth: Auth) -> &'static str {
    "Authorized"
}

#[get("/")]
pub fn index() -> Template {
    let mut data = HashMap::new();
    data.insert("foo", "bar");
    Template::render("index", data)
}

#[get("/login?<url>")]
pub fn login(url: String) -> Template {
    let mut data = HashMap::new();

    // TODO: Based on request headers
    data.insert("host", "example.club");
    data.insert("redirect", "success.example.club");

    // Values to render: url, urlHost
    Template::render("login", &data)
}

#[post("/login", data = "<input>")]
pub fn validate_login(input: Form<AuthUser>) -> Redirect {
    if user_validate(&input.user, &input.pass, &input.host) {
        // Redirect::to(input.redirect.as_str())
        Redirect::to("/login?success=1")
    } else {
        Redirect::to("/login?failure=1")
    }
}

#[get("/logout")]
pub fn logout() -> Template {
    let mut data = HashMap::new();
    data.insert("foo", "bar");
    Template::render("logout", data)
}
