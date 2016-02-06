//! This crate provides an iron middleware that handles user login sessions
//! using an encrypted authentication cookie.
//!
//! # Example
//! ```no_run
//! # extern crate iron;
//! # extern crate iron_login;
//! #
//! use iron::prelude::*;
//! use iron_login::User;
//!
//! #[derive(Debug)]
//! /// Representation of an authenticated user
//! struct MyUser(String);
//! impl MyUser {
//!     fn new(name: &str) -> MyUser {
//!         MyUser( name.to_owned() )
//!     }
//! }
//! impl User for MyUser {
//!     fn from_username(_: &mut Request, name: &str) -> Option<MyUser> {
//!         Some( MyUser(name.to_owned()) )
//!     }
//!     fn get_username(&self) -> &str {
//!         &self.0
//!     }
//! }
//!
//! /// A basic iron request handler
//! fn request_handler(req: &mut Request) -> IronResult<Response> {
//!     let login = MyUser::get_login(req);
//!     // If a query (`?username`) is passed, set the username to that string
//!     if let Some(ref uname) = req.url.query
//!     {
//!         let uname: &str = &req.url.path[0];
//!         Ok(Response::new()
//!             .set( ::iron::status::Ok )
//!             .set( "User set" )
//!             .set( login.log_in( MyUser::new(uname) ) )
//!             )
//!     }
//!     // Otherwise respond with the current user
//!     else
//!     {
//!         let user = login.get_user();
//!         Ok(Response::new()
//!             .set( ::iron::status::Ok )
//!             .set( format!("user = {:?}", user) )
//!             )
//!     }
//! }
//! 
//! fn main() {
//!     let cookie_signing_key = b"My Secret Key"[..].to_owned();
//! 
//!     let mut chain = Chain::new(request_handler);
//!     chain.link_around( ::iron_login::LoginManager::new(cookie_signing_key) );
//!     Iron::new(chain).http("localhost:3000").unwrap();
//! }
//! ```
extern crate iron;
extern crate oven;
extern crate cookie;
extern crate persistent;

use iron::prelude::*;
use iron::typemap::Key;
use iron::middleware;
use oven::prelude::*;

/// Re-export of the Cookie class.
pub use cookie::Cookie;


/// Iron middleware providing user loging management
/// 
/// Stores the configuration in persistent data and adds an oven with the specified key.
pub struct LoginManager {
    signing_key: Vec<u8>,
    pub config: Config
}

impl LoginManager {
    /// Construct a new login middleware
    pub fn new(signing_key: Vec<u8>) -> LoginManager {
        LoginManager {
            signing_key: signing_key,
            config: Config::defaults()
        }
    }
}

impl middleware::AroundMiddleware for LoginManager {
    fn around(self, handler: Box<middleware::Handler>) -> Box<middleware::Handler> {
        let mut ch = Chain::new(handler);
        let key = self.signing_key;

        ch.link(oven::new(key));
        ch.link(persistent::Read::<Config>::both(self.config));

        Box::new(ch)
    }
}

/// Configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// This cookie contains the default values that will be used for session cookies.
    ///
    /// You may e.g. override `httponly` or `secure` however you wish.
    pub cookie_base: Cookie
}

impl Config {
    /// Construct a configuration instance with default values
    pub fn defaults() -> Self {
        Config {
            cookie_base: {
                let mut c = Cookie::new("logged_in_user".to_owned(), "".to_owned());
                c.httponly = true;
                c.path = Some("/".to_owned());
                c
            }
        }
    }
}

impl Key for Config { type Value = Config; }

/// Trait repesenting an authenticated user
pub trait User: Send + Sync + Sized {
    fn from_username(request: &mut Request, username: &str) -> Option<Self>;
    fn get_username(&self) -> &str;
    /// Create a `Login<Self>` instance (no need to override)
    fn get_login(request: &mut Request) -> Login<Self> {
        Login::from_request(request)
    }
}

/// Login state
/// 
/// To construct this within a request, use `User::get_login()`
pub struct Login<U: User> {
    user: Option<U>,
    config: Config
}

impl<U: User> Login<U> {
    fn from_request(request: &mut Request) -> Login<U> {
        let config = (*request.get::<persistent::Read<Config>>().unwrap()).clone();
        let username = match request.get_cookie(&config.cookie_base.name) {
            Some(x) if x.value.len() > 0 => Some(x.value.clone()),
            _ => None
        };

        Login {
            user: username.and_then(|username| U::from_username(request, &username)),
            config: config
        }
    }

    /// Unwrap into the `User` instance
    pub fn get_user(self) -> Option<U> {
        self.user
    }

    /// Log in as the passed `User` instance
    pub fn log_in(mut self, user: U) -> LoginModifier<U> {
        self.user = Some(user);
        LoginModifier { login: self }
    }

    /// Log out (clearing the cookie)
    pub fn log_out(mut self) -> LoginModifier<U> {
        self.user = None;
        LoginModifier { login: self }
    }
}


/// Iron modifier that updates the cookie
pub struct LoginModifier<U: User> { login: Login<U> }
impl<U: User> iron::modifier::Modifier<Response> for LoginModifier<U> {
    fn modify(self, response: &mut Response) {
        response.set_cookie({
            let mut x = self.login.config.cookie_base.clone();
            x.value = self.login.user.as_ref().map(|u| u.get_username()).unwrap_or("").to_owned();
            x
        });
    }
}
