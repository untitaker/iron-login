# iron-login

[![Build Status](https://travis-ci.org/untitaker/iron-login.svg?branch=master)](https://travis-ci.org/untitaker/iron-login)

This crate provides an iron middleware that handles user login sessions
using a cryptographically signed authentication cookie.

## Usage

- Add an instance of the `LoginMagager` to your Iron handler chain
- Call `<MyUserType as iron_login::User>::get_login(req)` in your handler to get a `Login` instance

See `/examples/` for usage.

## License

Licensed under the MIT, see `LICENSE`.
