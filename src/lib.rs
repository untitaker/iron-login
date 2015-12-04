extern crate iron;
extern crate oven;
extern crate cookie;

use iron::prelude::*;
use iron::middleware;
use oven::prelude::*;

pub struct LoginManager {
    signing_key: Vec<u8>
}

impl LoginManager {
    pub fn new(signing_key: Vec<u8>) -> LoginManager {
        LoginManager { signing_key: signing_key }
    }
}

impl middleware::AroundMiddleware for LoginManager {
    fn around(self, handler: Box<middleware::Handler>) -> Box<middleware::Handler> {
        let mut ch = Chain::new(handler);
        let key = self.signing_key;

        ch.link(oven::new(key.clone()));

        Box::new(ch)
    }
}

pub trait User: Send + Sync + Sized {
    fn from_username(request: &mut Request, username: &str) -> Option<Self>;
    fn get_username(&self) -> &str;

    fn from_request(request: &mut Request) -> Option<Self> {
        let value = match request.get_cookie("logged_in_user") {
            Some(x) if x.value.len() > 0 => x.value.clone(),
            _ => return None
        };
        Self::from_username(request, &value[..])
    }

    fn log_in(self) -> LoginModifier<Self> { LoginModifier { user: self } }
}


pub struct LoginModifier<U: User> { user: U }
impl<U: User> iron::modifier::Modifier<Response> for LoginModifier<U> {
    fn modify(self, response: &mut Response) { log_in_on(response, self.user.get_username()) }
}

pub fn log_in_on(response: &mut Response, username: &str) {
    response.set_cookie({
        let mut x = cookie::Cookie::new("logged_in_user".to_owned(), username.to_owned());
        x.path = Some("/".to_owned());
        x
    });
}


pub struct LogoutModifier;
impl iron::modifier::Modifier<Response> for LogoutModifier {
    fn modify(self, response: &mut Response) { log_out_of(response) }
}

pub fn log_out_of(response: &mut Response) {
    log_in_on(response, "");
}

pub fn log_out() -> LogoutModifier { LogoutModifier }
