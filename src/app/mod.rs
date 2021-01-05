/**
 * Main app routes
 */

use std::str::FromStr;
use std::collections::HashMap;

use base64::{encode_config as b64_encode, URL_SAFE};

use rocket::Outcome;
use rocket::response::{self, Redirect, Response, Responder};
use rocket::request::{self, Request, FromRequest, FromForm, LenientForm};
use rocket::http::{Status, Cookie, Cookies};
use rocket::http::hyper::header::Basic;
use rocket_contrib::templates::Template;

pub mod config;
use config::AUTHS;

static COOKIE_NAME: &str = "simple-auth";

pub struct Auth(&'static str);
#[derive(Debug)]
pub enum AuthError {
    Invalid,
    Missing,
}

#[derive(FromForm)]
pub struct AuthUser {
    user: String,
    pass: String,
    host: String,
    redirect: String,
}

// Get auth string can come from Authorization HTTP header
// or from previously set http cookie (COOKIE_NAME)
fn auth_from_request(request: &Request) -> Option<String> {
    let auth = request.headers().get_one("authorization");
    let mut cookies = request.cookies();
    let auth_cookie = cookies.get_private(COOKIE_NAME);

    if auth.is_some() {
        Some(String::from(auth.unwrap()))
    } else if auth_cookie.is_some() {
        Some(String::from(auth_cookie.unwrap().value()))
    } else {
        None
    }
}

// Encode user/pass login as HTTP Authorization string
// (Eg, "Basic base64<user:pass>")
fn auth_encode_string(user: &str, pass: &str) -> String {
    let b64 = b64_encode(format!("{}:{}", &user, &pass), URL_SAFE);
    format!("Basic {}", &b64)
}

// TODO: Validate "host" header and use in cominbation with user/pass
fn auth_validate(host: String, input: String) -> bool {
    // Validate "Basic" auth type is used (Bearer not supported)
    let auth_header: Vec<&str> = input.split(' ').collect();
    if auth_header.get(0) != Some(&"Basic") || auth_header.get(1).is_none() {
        return false;
    }

    // Validate base64 encoded value matches accepted logins
    if let Ok(basic) = Basic::from_str(auth_header[1]) {
        return user_validate(&basic.username, &basic.password.unwrap(), &host);
    }

    false
}

// Implement custom guard for validate request
// Note: This function will get called the most frequently
impl<'a, 'r> FromRequest<'a, 'r> for Auth {
    type Error = AuthError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let head = request.headers();
        let host = head.get_one("host");
        let auth = auth_from_request(&request);

        if host.is_none() || auth.is_none() {
            Outcome::Failure((Status::Unauthorized, AuthError::Missing))
        } else if auth_validate(String::from(host.unwrap()), auth.unwrap()) {
            Outcome::Success(Auth("Authorized"))
        } else {
            Outcome::Failure((Status::Unauthorized, AuthError::Invalid))
        }
    }
}

// Custom responder for validation endpoint
// returns custom headers + sets cookies
// Note: This custom responder is only used on request validation if Outcome::Success
// This header is used by nginx to pass onto proxied virual hosts
impl<'a> Responder<'a> for Auth {
    fn respond_to(self, request: &Request) -> response::Result<'a> {
        let mut resp = Response::build();

        if let Some(auth_string) = auth_from_request(&request) {
            resp.raw_header("X-Simple-Auth", auth_string);
        }

        resp.ok()
    }
}

fn user_validate(user: &String, pass: &String, host: &String) -> bool {
    // Check for host domain in auth settings
    if let Some(creds) = AUTHS.get(host.as_str()) {
        if creds == &(user.as_str(), pass.as_str()) {
            println!("Valid Auth: {} ({} / {})", &user, &host, &host);
            return true;
        }
    }

    println!("Invalid Auth: {} ({} / {})", &user, &host, &host);
    false
}

// Note: validate sends custom response headers
// does not need to send any content, as it is ignored by nginx anyway
#[get("/validate")]
pub fn validate(auth: Auth) -> Auth {
    auth
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
pub fn validate_login(mut cookies: Cookies, input: LenientForm<AuthUser>) -> Redirect {
    println!("Validating Login: {}, {}", &input.user, &input.host);

    if user_validate(&input.user, &input.pass, &input.host) {
        // Set cookie on login
        let auth_encode = auth_encode_string(&input.user.as_str(), &input.pass.as_str());
        let cookie = Cookie::build(COOKIE_NAME, auth_encode)
            .domain(input.host.clone())
            .path("/")
            .secure(true)
            .same_site(rocket::http::SameSite::Strict)
            .http_only(true)
            .finish();

        cookies.add_private(cookie);

        Redirect::to(String::from(&input.redirect))
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

#[catch(401)]
pub fn unauthorized(req: &Request) -> String {
    println!("Auth request failed {:?}", req.headers());
    String::from("Unauthorized User")
}
