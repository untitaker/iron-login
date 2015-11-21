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
            Some(x) => x.value.clone(),
            None => return None
        };
        Self::from_username(request, &value[..])
    }

    fn log_in_on(&self, response: &mut Response) {
        response.set_cookie(cookie::Cookie::new("logged_in_user".to_owned(), self.get_username().to_owned()));
    }

    fn log_in(self) -> LoginModifier<Self> { LoginModifier { user: self } }
}

pub struct LoginModifier<U: User> { user: U }
impl<U: User> iron::modifier::Modifier<Response> for LoginModifier<U> {
    fn modify(self, response: &mut Response) { self.user.log_in_on(response) }
}


pub fn log_out_of(response: &mut Response) {
    response.get_mut::<oven::ResponseCookies>().unwrap().remove("logged_in_user");
}

pub fn log_out() -> LogoutModifier { LogoutModifier }

pub struct LogoutModifier;
impl iron::modifier::Modifier<Response> for LogoutModifier {
    fn modify(self, response: &mut Response) { log_out_of(response) }
}
