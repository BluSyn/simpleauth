/**
 * Main app routes
 */

use std::str::FromStr;
use std::collections::HashMap;

use base64::{encode_config as b64_encode, URL_SAFE};

use rocket::Outcome;
use rocket::response::{self, status, Redirect, Response, Responder};
use rocket::request::{self, Request, FromRequest, FromForm, LenientForm};
use rocket::http::{Status, Cookie, Cookies};
use rocket::http::uri::Uri;
use rocket::http::hyper::header::Basic;
use rocket_contrib::templates::Template;

pub mod config;
use config::AUTHS;

static COOKIE_NAME: &str = "simpauth";

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
    url: String,
}

// Get auth string can come from Authorization HTTP header
// or from previously set http cookie (COOKIE_NAME)
fn auth_from_request(request: &Request) -> Option<String> {
    let head = request.headers();

    // Host is required, or cant process request
    let host = match head.get_one("host") {
        Some(h) => h,
        None => return None
    };

    let auth = head.get_one("authorization");
    let name = format!("{}_{}", COOKIE_NAME, &host);
    let mut cookies = request.cookies();
    let auth_cookie = cookies.get_private(&name.as_str());

    if let Some(a) = auth {
        Some(String::from(a))
    } else if let Some(acookie) = auth_cookie {
        Some(String::from(acookie.value()))
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
        if let Some(password) = &basic.password {
            return user_validate(&basic.username, &password, &host);
        }
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
            return true;
        }
    }

    println!("Invalid Auth: {} ({})", &user, &host);
    false
}

// Validates and parses url into raw hostname
fn parse_url_host(url: &String) -> Option<String> {
    match Uri::parse(&url) {
        Ok(p) => match p.absolute() {
            Some(a) => match a.authority() {
                Some(h) => Some(String::from(h.host())),
                None => None
            },
            None => None
        },
        Err(_) => None
    }
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

#[get("/login?<url>")]
pub fn login(url: String) -> Result<Template, status::BadRequest<&'static str>> {
    let mut data: HashMap<&str, &str> = HashMap::new();

    // Validate redirect URL
    if parse_url_host(&url).is_none() {
        return Err(status::BadRequest(Some("Invalid Hostname")));
    }

    data.insert("url", url.as_str());

    // Values to render: url, urlHost
    Ok(Template::render("login", &data))
}

#[post("/login", data = "<input>")]
pub fn validate_login(mut cookies: Cookies, input: LenientForm<AuthUser>) -> Result<Redirect, Template> {
    // Valdate input URL
    let host = match parse_url_host(&input.url) {
        Some(h) => h,
        None => {
            println!("Invalid login hostname: {}", &input.url);

            let mut data: HashMap<&str, &str> = HashMap::new();
            data.insert("url", &input.url);
            data.insert("error", "Invalid Login URL");

            return Err(Template::render("login", &data));
        }
    };

    println!("Validating Login: {} ({})", &input.user, &host);

    if user_validate(&input.user, &input.pass, &host) {
        // Parse host domain
        // magic.simple.foo.example.domain -> example.domain
        // TODO: This is fairly dumb manipulation, should make this more robust
        let host_url: Vec<&str> = host.rsplitn(3, ".").collect();
        let mut domain_part = String::from("");
        if host_url.get(1).is_some() {
            domain_part.push_str(host_url[1]);
            domain_part.push_str(".");
        }
        domain_part.push_str(host_url[0]);

        // Set cookie on login
        let auth_encode = auth_encode_string(&input.user.as_str(), &input.pass.as_str());
        let name = format!("{}_{}", COOKIE_NAME, &host);
        let cookie = Cookie::build(name, auth_encode)
            .domain(domain_part)
            .path("/")
            .secure(true)
            .same_site(rocket::http::SameSite::Strict)
            .http_only(true)
            .finish();

        cookies.add_private(cookie);

        return Ok(Redirect::to(String::from(&input.url)));
    }

    let mut data: HashMap<&str, &str> = HashMap::new();
    data.insert("url", &input.url);
    data.insert("error", "Invalid Login");

    Err(Template::render("login", &data))
}

#[get("/logout")]
pub fn logout() -> Template {
    let mut data = HashMap::new();
    data.insert("foo", "bar");
    Template::render("logout", data)
}

#[catch(401)]
pub fn unauthorized(req: &Request) -> String {
    let head = req.headers();
    println!("Auth request failed ({:?})", head.get_one("host"));
    String::from("Unauthorized User")
}
