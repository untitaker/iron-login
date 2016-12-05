// DOCS

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
#[deprecated(since="0.5.1", note="Please use iron-sessionstorage. This entire crate is deprecated.")]
pub struct LoginManager {
    signing_key: Vec<u8>,
    /// Configuration for this manager
    pub config: Config,
}

impl LoginManager {
    /// Construct a new login middleware using the provided signing key
    pub fn new(signing_key: Vec<u8>) -> LoginManager {
        LoginManager {
            signing_key: signing_key,
            config: Config::defaults(),
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
    pub cookie_base: Cookie,
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
            },
        }
    }
}

impl Key for Config { type Value = Config; }

/// Trait repesenting an authenticated user
pub trait User: Send + Sync + Sized {
    /// Create a `User` instance from a user id
    fn from_user_id(request: &mut Request, user_id: &str) -> Option<Self>;
    /// Get the user_id associated with this `User`
    fn get_user_id(&self) -> String;
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
    config: Config,
}

impl<U: User> Login<U> {
    fn from_request(request: &mut Request) -> Login<U> {
        let config = request.get::<persistent::Read<Config>>()
                            .expect("config is not found in request");
        let config = (*config).clone();
        let user_id = match request.get_cookie(&config.cookie_base.name) {
            Some(c) if !c.value.is_empty() => Some(c.value.clone()),
            _ => None,
        };

        Login {
            user: user_id.and_then(|user_id| U::from_user_id(request, &user_id)),
            config: config,
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
pub struct LoginModifier<U: User> {
    login: Login<U>,
}
impl<U: User> iron::modifier::Modifier<Response> for LoginModifier<U> {
    fn modify(self, response: &mut Response) {
        response.set_cookie({
            let mut x = self.login.config.cookie_base.clone();
            x.value = self.login.user
                .map_or_else(|| "".to_owned(), |u| u.get_user_id());
            x
        });
    }
}
