extern crate iron;
extern crate iron_login;

use iron::prelude::*;
use iron_login::User;

#[derive(Debug)]
/// Representation of an authenticated user
struct MyUser(String);
impl MyUser {
    fn new(user_id: &str) -> MyUser {
        MyUser(user_id.to_owned())
    }
}
impl User for MyUser {
    fn from_user_id(_: &mut Request, user_id: &str) -> Option<MyUser> {
        Some(MyUser(user_id.to_owned()))
    }
    fn get_user_id(&self) -> String {
        self.0.to_owned()
    }
}

/// A basic iron request handler
fn request_handler(req: &mut Request) -> IronResult<Response> {
    let login = MyUser::get_login(req);
    // If a query (`?username`) is passed, set the username to that string
    if let Some(ref uid) = req.url.query() {
        // If no username is passed, log out
        if uid.is_empty() {
            Ok(Response::new()
                   .set(::iron::status::Ok)
                   .set(format!("Logged out"))
                   .set(login.log_out()))
        } else {
            Ok(Response::new()
                   .set(::iron::status::Ok)
                   .set(format!("User set to '{}'", uid))
                   .set(login.log_in(MyUser::new(uid))))
        }
    } else {
        let user = login.get_user();
        Ok(Response::new()
               .set(::iron::status::Ok)
               .set(format!("user = {:?}", user)))
    }
}

fn main() {
    let cookie_signing_key = b"My Secret Key"[..].to_owned();

    let mut chain = Chain::new(request_handler);
    chain.around(::iron_login::LoginManager::new(cookie_signing_key));
    Iron::new(chain).http("localhost:3000").unwrap();
}
