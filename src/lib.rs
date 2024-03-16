#![doc = include_str!("../README.md")]



/// A bit of cryptographically secure random data is attached to every encoded cookie so that
/// identical values don't have identical encoded representations. This prevents attackers
/// from determining the value of an encoded cookie by comparing it to the encoded value of
/// a known cookie.
const NONCE_LENGTH: usize = 12;



/// Key used to sign, encrypt, decrypt & verify your cookies
///
/// The signing key should be cryptographically secure random data.
/// You can use [generate_signing_key] to safely make a signing key,
/// or you can generate it yourself as long as you make sure the randomness is cryptographically secure.
/// This signing key may be stored in a secure location and loaded at startup if you like. You might want to store & load if:
/// - Cookie based sessions should out-last server restarts
/// - The same cookie needs to be read by separate instances of the server in horizontal scaling situations
/// - The cookie needs to be read by an entirely separate unrelated server (say, a caching server or something)
pub type SigningKey = [u8; 32];



/// Generate a new signing key for use with the [encode_cookie] and [decode_cookie] functions.
///
/// This uses the thread-local random number generator, which is guaranteed by the rand crate
/// to produce cryptographically secure random data.
pub fn generate_signing_key() -> SigningKey {
    use rand::RngCore;
    let mut data = [0; 32];
    rand::thread_rng().fill_bytes(&mut data);
    data
}



/// Build an iterator from the value part of a Cookie: header that will yield a name/value tuple for each cookie.
///
/// Certain characters are not permitted in cookie names, and different characters are not permitted
/// in cookie values. See [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265) for details. This function makes no attempt to validate the name
/// or value of the cookie headers.
///
/// Cookie values may or may not be quoted. (Like this: session="38h29onuf20138t")
/// This iterator will never include the quotes in the emitted value.
/// In the above example, the pair will be: ("session", "38h29onuf20138t") instead of ("session", "\"38h29onuf20138t\"")
/// Note that according to [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265), using quotes is optional and never necessary
/// because the characters permitted inside a quoted value are the exact same characters
/// permitted outside the quoted value.
///
/// Cookie values may not necessarily be valid UTF-8.
/// As such, this function emits values of type &[u8]
pub fn parse_cookie_header_value(header: &[u8]) -> impl Iterator<Item = (&str, &[u8])> {
    header
        .split(|c| *c == b';')
        .map(|x| trim_ascii_whitespace(x))
        .filter_map(|x| {
            let mut key_value_iterator = x.split(|c| *c == b'=').into_iter();

            let key: &[u8] = key_value_iterator.next()?;
            let key: &[u8] = trim_ascii_whitespace(key);
            let key: &str = std::str::from_utf8(key).ok()?;

            let value: &[u8] = trim_ascii_whitespace(key_value_iterator.next()?);
            let value: &[u8] = value.strip_prefix(&[b'"']).unwrap_or(value);
            let value: &[u8] = value.strip_suffix(&[b'"']).unwrap_or(value);

            Some((key, value))
        })
}



// Trims ascii whitespace from either end of a slice.
// Calls should be replaced with &[u8]::trim_ascii() when it stabilizes
fn trim_ascii_whitespace(slice: &[u8]) -> &[u8] {
    let mut start_index = 0;
    for (index, character) in slice.iter().enumerate() {
        start_index = index;
        if *character != b' ' && *character != b'\t' {
            break;
        }
    }

    let mut end_index = slice.len();
    for (index, character) in slice.iter().enumerate().rev() {
        end_index = index;
        if *character != b' ' && *character != b'\t' {
            break;
        }
    }

    &slice[start_index..=end_index]
}



/// Encrypt & sign a cookie value.
///
/// ## Cookie Name
/// The name of the cookie is required to prevent attackers
/// from swapping the encrypted value of one cookie with the encrypted value of another cookie.
///
/// For example, say you have two cookies:
///
/// ```txt
/// session-account-id=2381
/// last-cache-reload=3193
/// ```
///
/// When encrypted, the cookies might look like:
///
/// ```txt
/// session-account=LfwFJ8N0YR5f4U8dWFc5vARKQL7GvRJI
/// last-cache-reload=NyOwR3npVm0gn8xlm89qcPMzQHjLZLs99
/// ```
///
/// If the name of the cookie wasn't included in the encrypted value it would be possible for
/// an attacker to swap the values of the two cookies and make your server think that the
/// session-account-id cookie value was 3193, effectively impersonating another user.
///
/// The name will be included in the encrypted value and verified against the name you provide
/// when calling [decode_cookie] later.
///
/// ## Other Notes
/// [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265) restricts the characters valid in cookie names. This function does *not* validate the name you provide.
///
/// Inspired by the [cookie](https://crates.io/crates/cookie) crate.
pub fn encode_cookie<Name: AsRef<str>, Value: AsRef<[u8]>>(key: &SigningKey, name: Name, value: Value) -> String {
    let value: &[u8] = value.as_ref();
    let name: &str = name.as_ref();

    // Final message will be [nonce, encrypted_value, signature]
    let mut data = vec![0; NONCE_LENGTH + value.len() + 16];

    // Split the data vec apart into mutable slices for each component
    let (nonce_slot, message_and_tag) = data.split_at_mut(NONCE_LENGTH);
    let (encrypted_slot, signature_slot) = message_and_tag.split_at_mut(value.len());

    // Generate some random data for the nonce
    use rand::RngCore;
    rand::thread_rng().fill_bytes(nonce_slot);

    // Copy the unencrypted message into the slot for the encrypted message
    // (It will be encrypted in-place.)
    encrypted_slot.copy_from_slice(value);

    // Encrypt the message
    // This encryption method has a convenient associated data option that will be part
    // of the signature, so we'll drop the cookie name into that rather than doing something
    // more complex like concatenating the message and name ourselves.
    use aes_gcm::{AeadInPlace, KeyInit};
    let key_array = aes_gcm::aead::generic_array::GenericArray::from_slice(key);
    let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce_slot);
    let encryptor = aes_gcm::Aes256Gcm::new(key_array);
    let signature = encryptor
        .encrypt_in_place_detached(&nonce_array, name.as_bytes(), encrypted_slot)
        .expect("failed to encrypt");

    // Copy the signature into the final message
    signature_slot.copy_from_slice(&signature);

    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(&data)
}



/// Decrypt & verify the signature of a cookie value.
///
/// The name of the cookie is included in the signed content generated by
/// encode_cookie, and is cross-referenced with the value you provide here to
/// guarantee that the cookie's encrypted content was not swapped with the
/// encrypted content of another cookie. For security purposes (e.g. to
/// prevent side-channel attacks) no details about a decoding failure are
/// returned.
///
/// Inspired by the [cookie](https://crates.io/crates/cookie) crate.
pub fn decode_cookie<Name: AsRef<str>, Value: AsRef<[u8]>>(key: &SigningKey, name: Name, value: Value) -> Option<Vec<u8>> {
    use aes_gcm::KeyInit;
    use aes_gcm::aead::Aead;
    use base64::Engine;

    // The binary cipher is base64 encoded
    let message = base64::engine::general_purpose::STANDARD_NO_PAD.decode(value.as_ref()).ok()?;

    // The binary cipher is constructed as [ nonce, encrypted_value_with_signature ]
    // so we need to split it into it's individual parts
    let (nonce, cipher) = message.split_at(NONCE_LENGTH);

    /*
    The API we should have is
       aes256gcm::decrypt(key: &[u8], nonce: &[u8], expected_associated_data: &[u8], cipher: &[u8]) -> Option<Vec<u8>>

    Instead we have to wrap the first two arguments in GenericArray structs,
    construct a decryptor object with the wrapped signing key, build a struct containing
    the cipher text and expected associated data, then call decrypt on the decryptor
    object passing in the struct and wrapped nonce. I really hope there's a good reason
    for this API, because if not it's really stupid.
    */

    // Wrap the slices up in GenericArrays because that's what aes_gcm expects
    let key_array = aes_gcm::aead::generic_array::GenericArray::from_slice(key);
    let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);

    // Wrap the cipher and expected associated data in a struct because that's what aes_gcm expects
    let payload = aes_gcm::aead::Payload {
        msg: cipher,
        aad: name.as_ref().as_bytes(),
    };

    // Build the decryptor object which we'll use to decrypt the cipher text
    let cipher = aes_gcm::Aes256Gcm::new(key_array);

    // Actually decrypt the value!
    // For security reasons aes_gcm returns no details about the error, just an empty struct.
    // This prevents side-channel leakage.
    cipher.decrypt(nonce_array, payload).ok()
}




#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_decode_succeeds() {
        let key = &generate_signing_key();
        let name = "session";
        let data = r#"{"id":5}"#;
        let encoded = encode_cookie(key, name, data);
        let decoded = decode_cookie(key, name, encoded);
        assert_eq!(decoded.unwrap(), data.as_bytes());
    }

    #[test]
    fn different_keys_fails() {
        let key_a = generate_signing_key();
        let name = "session";
        let data = r#"{"id":5}"#;
        let encoded = encode_cookie(&key_a, name, data);

        let key_b = generate_signing_key();
        let decoded = decode_cookie(&key_b, name, encoded);

        assert_eq!(decoded, None);
    }

    #[test]
    fn different_names_fails() {
        let key = &generate_signing_key();
        let name_a = "session";
        let data = r#"{"id":5}"#;
        let encoded = encode_cookie(key, name_a, data);

        let name_b = "laskdjf";
        let decoded = decode_cookie(key, name_b, encoded);

        assert_eq!(decoded, None);
    }

    #[test]
    fn identical_values_have_different_ciphers() {
        let key = &generate_signing_key();
        let name = "session";
        let data = "which wolf do you feed?";
        let encoded_1 = encode_cookie(key, name, data);
        let encoded_2 = encode_cookie(key, name, data);
        assert_ne!(encoded_1, encoded_2);
    }

    #[test]
    fn parses_spaceless_header() {
        let header = b"session=213lkj1;another=3829";
        let mut iterator = parse_cookie_header_value(header);

        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "session");
        assert_eq!(value, b"213lkj1");

        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "another");
        assert_eq!(value, b"3829");
    }

    #[test]
    fn parses_spaced_header() {
        let header = b"session = 123kj; sakjdf = klsjdf23";
        let mut iterator = parse_cookie_header_value(header);

        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "session");
        assert_eq!(value, b"123kj");

        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "sakjdf");
        assert_eq!(value, b"klsjdf23");
    }

    #[test]
    fn strips_value_quotes() {
        let header = b"session=\"alkjs\"";
        let mut iterator = parse_cookie_header_value(header);
        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "session");
        assert_eq!(value, b"alkjs");
    }

    #[test]
    fn ignores_name_quotes() {
        let header = b"\"session\"=asdf";
        let mut iterator = parse_cookie_header_value(header);
        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "\"session\"");
        assert_eq!(value, b"asdf");
    }
}