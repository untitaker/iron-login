extern crate iron;
extern crate oven;
extern crate cookie;
extern crate persistent;

use iron::prelude::*;
use iron::typemap::Key;
use iron::middleware;
use oven::prelude::*;

pub struct LoginManager {
    signing_key: Vec<u8>,
    pub config: Config
}

impl LoginManager {
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

#[derive(Debug, Clone)]
pub struct Config {
    pub httponly: bool,
    pub path: Option<String>,
    pub cookie_name: String
}

impl Config {
    pub fn defaults() -> Self {
        Config {
            httponly: true,
            path: Some("/".to_owned()),
            cookie_name: "logged_in_user".to_owned()
        }
    }
}

impl Key for Config { type Value = Config; }

pub trait User: Send + Sync + Sized {
    fn from_username(request: &mut Request, username: &str) -> Option<Self>;
    fn get_username(&self) -> &str;
    fn get_login(request: &mut Request) -> Login<Self> {
        Login::from_request(request)
    }
}


pub struct Login<U: User> {
    user: Option<U>,
    config: Config
}

impl<U: User> Login<U> {
    fn from_request(request: &mut Request) -> Login<U> {
        let config = (*request.get::<persistent::Read<Config>>().unwrap()).clone();
        let username = match request.get_cookie(&config.cookie_name) {
            Some(x) if x.value.len() > 0 => Some(x.value.clone()),
            _ => None
        };

        Login {
            user: username.and_then(|username| U::from_username(request, &username)),
            config: config
        }
    }

    pub fn get_user(self) -> Option<U> {
        self.user
    }

    pub fn log_in(mut self, user: U) -> LoginModifier<U> {
        self.user = Some(user);
        LoginModifier { login: self }
    }

    pub fn log_out(mut self) -> LoginModifier<U> {
        self.user = None;
        LoginModifier { login: self }
    }
}

pub struct LoginModifier<U: User> { login: Login<U> }
impl<U: User> iron::modifier::Modifier<Response> for LoginModifier<U> {
    fn modify(self, response: &mut Response) {
        response.set_cookie({
            let mut x = cookie::Cookie::new(
                self.login.config.cookie_name.clone(),
                self.login.user.as_ref().map(|u| u.get_username()).unwrap_or("").to_owned()
            );
            x.path = self.login.config.path.clone();
            x.httponly = self.login.config.httponly;
            x
        });
    }
}
