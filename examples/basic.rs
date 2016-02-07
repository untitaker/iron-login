extern crate iron;
extern crate iron_login;

use iron::prelude::*;
use iron_login::User;

#[derive(Debug)]
/// Representation of an authenticated user
struct MyUser(String);
impl MyUser {
    fn new(name: &str) -> MyUser {
        MyUser( name.to_owned() )
    }
}
impl User for MyUser {
    fn from_username(_: &mut Request, name: &str) -> Option<MyUser> {
        Some( MyUser(name.to_owned()) )
    }
    fn get_username(&self) -> &str {
        &self.0
    }
}

/// A basic iron request handler
fn request_handler(req: &mut Request) -> IronResult<Response> {
    let login = MyUser::get_login(req);
    // If a query (`?username`) is passed, set the username to that string
    if let Some(ref uname) = req.url.query
    {
		// If no username is passed, log out
		if uname == ""
		{
			Ok(Response::new()
				.set( ::iron::status::Ok )
				.set( format!("Logged out") )
				.set( login.log_out() )
				)
		}
		else
		{
			Ok(Response::new()
				.set( ::iron::status::Ok )
				.set( format!("User set to '{}'", uname) )
				.set( login.log_in( MyUser::new(uname) ) )
				)
		}
    }
    // Otherwise respond with the current user
    else
    {
        let user = login.get_user();
        Ok(Response::new()
            .set( ::iron::status::Ok )
            .set( format!("user = {:?}", user) )
            )
    }
}

fn main() {
    let cookie_signing_key = b"My Secret Key"[..].to_owned();

    let mut chain = Chain::new(request_handler);
    chain.link_around( ::iron_login::LoginManager::new(cookie_signing_key) );
    Iron::new(chain).http("localhost:3000").unwrap();
}
