Functions for creating and parsing signed & encrypted cookies.

The [cookie](https://crates.io/crates/cookie) crate is the de facto secure cookie library in Rust.
It is Way Too Complicated (TM) for what I need. (And, in my opinion, for what most people need.)
This is the 80% solution for 20% of the effort.

This library has only two goals:
- A simple, easily auditable implementation of signing, encrypting, decrypting & verifying cookies.
- Clear comments pointing out security issues and describing how to avoid them.

The goals of this library are *not*:
- Automatically detecting when a new Set-Cookie header is required.
- Tracking changes to cookies.
- Validating cookie name compliance with [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265). (Just don't use any weird cookie names.)
- Any kind of cookie "jar" functionality.
- Literally anything else.

## Examples

Basic use:

```rust,ignore
use simple_cookie::{generate_signing_key, encode_cookie, decode_cookie};

let signing_key = generate_signing_key();
let encoded = encode_cookie(&signing_key, "account_id", &[56]);
let decoded = decode_cookie(&signing_key, "account_id", encoded);

assert_eq!(decoded, Some(vec![56]));
```

You probably want an actual Set-Cookie header. You can build one pretty easily:

```rust,ignore
use simple_cookie::{generate_signing_key, encode_cookie};

let signing_key = generate_signing_key();
let encoded = encode_cookie(&signing_key, "account_id", &[56]);
let header = format!("Set-Cookie: session={}; Max-Age=604800; Secure; HttpOnly; SameSite=Strict", encoded);
```

Then, to decrypt a header:

```rust,ignore
use simple_cookie::{parse_cookie_header_value, decode_cookie};

// You can create your own key or load it from somewhere.
// Don't use all zeros like this though. See the documentation for SigningKey for more info.
let signing_key = [0; 32];

// This is a standard HTTP Cookie header, pretty much exactly what the browser sends to your server.
let header = b"Cookie: session=gNm1wQ6lTTgAxLxfD2ntNS2nIBVcnjSmI+7FdFk; another-cookie=another-value";

// parse_cookie_header_value doesn't expect the header name.
// You don't normally need this step since HTTP libraries typically automatically parse
// the header name & value into separate parts of a tuple or struct or something.
let header = &header[8..];

// parse_cookie_header_value returns an iterator, so you can use it in a for loop or something.
// I'll just find the cookie we're interested in here.
let (name, encoded_value) = parse_cookie_header_value(header).find(|(name, _value)| *name == "session").unwrap();
let value = decode_cookie(&signing_key, name, encoded_value);

assert!(value.is_some())
```