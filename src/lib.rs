#![doc = include_str!("../README.md")]
#![cfg_attr(all(not(std), not(debug_assertions)), no_std)]




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

/// A bit of random data attached to every cookie before encrypting to avoid the same cookie
/// value being encrypted into the same bits.
///
/// Use [generate_nonce] to create one, or make your own from **cryptographically secure** random data.
pub type Nonce = [u8; 12];

const NONCE_LENGTH: usize = core::mem::size_of::<Nonce>();
const SIGNATURE_LENGTH: usize = 16;



/// Generate a new signing key for use with the [encode_cookie] and [decode_cookie] functions.
///
/// This uses the thread-local random number generator, which is guaranteed by the rand crate
/// to produce cryptographically secure random data.
#[cfg(any(test, feature="rand"))]
pub fn generate_signing_key() -> SigningKey {
    let mut data = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    data
}



/// Generate a new nonce for encrypting a cookie with the [encode_cookie] function
///
/// This uses the thread-local random number generator, which is guaranteed by the rand crate
/// to produce cryptographically secure random data.
#[cfg(any(test, feature="rand"))]
pub fn generate_nonce() -> Nonce {
    let mut data = [0; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
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
            let key: &str = core::str::from_utf8(key).ok()?;

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
/// You can use the [output_len] function to get the required size of the buffer.
///
/// ## Other Notes
/// [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265) restricts the characters valid in cookie names. This function does *not* validate the name you provide.
///
/// Inspired by the [cookie](https://crates.io/crates/cookie) crate.
pub fn encode_cookie(key: SigningKey, nonce: Nonce, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>, output: &mut [u8]) -> Result<(), EncodeError> {
    let value: &[u8] = value.as_ref();

    let expected_size = decode_buffer_size(value.len());
    if output.len() != expected_size {
        return Err(EncodeError::IncorrectBufferSize { expected_size });
    }

    // Final message will be [nonce, encrypted_value, signature]
    // Split the output buffer apart into mutable slices for each component
    let (nonce_slot, rest_of_output) = output.split_at_mut(NONCE_LENGTH);
    let (encrypted_slot, rest_of_output) = rest_of_output.split_at_mut(value.len());
    let (signature_slot, _rest_of_output) = rest_of_output.split_at_mut(SIGNATURE_LENGTH);

    // Generate some random output for the nonce
    nonce_slot.copy_from_slice(&nonce);

    // Copy the unencrypted message into the slot for the encrypted message
    // (It will be encrypted in-place.)
    encrypted_slot.copy_from_slice(value);

    // Encrypt the message
    // This encryption method has a convenient associated output option that will be part
    // of the signature, so we'll drop the cookie name into that rather than doing something
    // more complex like concatenating the message and name ourselves.
    use aes_gcm::{AeadInPlace, KeyInit};
    let key_array = aes_gcm::aead::generic_array::GenericArray::from_slice(&key);
    let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce_slot);
    let encryptor = aes_gcm::Aes256Gcm::new(key_array);
    let signature = encryptor
        .encrypt_in_place_detached(&nonce_array, name.as_ref(), encrypted_slot)
        .expect("failed to encrypt");

    // The signature is returned from aes_gcm rather than being written into the output buffer,
    // so we need to write it in ourselves.
    signature_slot.copy_from_slice(&signature);

    // Cookie values must be in the ASCII printable range
    base64_encode_in_place(NONCE_LENGTH + value.len() + SIGNATURE_LENGTH, output);

    Ok(())
}

#[derive(Debug)]
pub enum EncodeError {
    IncorrectBufferSize {
        /// Expected size of the output buffer, or None if the expected size would overflow a usize.
        expected_size: usize
    },
}


/// Get the required size of the output buffer passed to encode_cookie for the given value length
pub const fn decode_buffer_size(value_length: usize) -> usize {
    base64_encode_buffer_size(NONCE_LENGTH + value_length + SIGNATURE_LENGTH)
}




// I couldn't find an in-place version of this function on crates.io, so here we are
fn base64_encode_in_place(length: usize, data: &mut [u8]) {
    let data_len = data.len();

    let (mut input_index, mut output_index) =
        if 2 == length % 3 {
            encode_segment(data[length - 2], data[length - 1], 0, &mut data[data_len - 4..]);
            data[data_len - 1] = b'=';
            (length.saturating_sub(2), data.len().saturating_sub(4))
        }
        else if 1 == length % 3 {
            encode_segment(data[length - 1], 0, 0, &mut data[data_len - 4..]);
            data[data_len - 1] = b'=';
            data[data_len - 2] = b'=';
            (length.saturating_sub(1), data.len().saturating_sub(4))
        }
        else {
            (length, data.len())
        };

    while input_index > 0 {
        output_index -= 4;
        input_index -= 3;
        encode_segment(data[input_index + 0], data[input_index + 1], data[input_index + 2], &mut data[output_index..][..4]);
    }
}

/// Encode the given 3 bytes into the first 4 bytes of the
/// output slice according to the base64 alphabet.
///
/// Helper function for [base64_encode_in_place]
fn encode_segment(a: u8, b: u8, c: u8, output: &mut [u8]) {
    let (a, b, c) = (a as u32, b as u32, c as u32);

    let temp = a << 16 | b << 8 | c;

    let a = (temp >> 18) & 0b111111;
    let b = (temp >> 12) & 0b111111;
    let c = (temp >>  6) & 0b111111;
    let d = (temp >>  0) & 0b111111;

    output[0] = ALPHABET[a as usize];
    output[1] = ALPHABET[b as usize];
    output[2] = ALPHABET[c as usize];
    output[3] = ALPHABET[d as usize];
}

/// Calculate the length of the encoded representation of a buffer with the given length
const fn base64_encode_buffer_size(data_length: usize) -> usize {
    4 * ((data_length + 2) / 3)
}

const fn base64_decoded_size(encoded_size: usize) -> usize {
    ((encoded_size * 3) / 4)
}

/// Standard base64 alphabet
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";




// The only reason this code exists is because I couldn't find a library for base64_encode_in_place
// and it seemed silly to bring an entire library in (especially one as complex as the defacto `base64` crate)
// for a single function
// fn base64_decode_in_place(data: &mut [u8])


#[test]
fn test_base64_encode() {
    // Poor man's fuzz testing
    let seed = rand::Rng::gen_range(&mut rand::thread_rng(), 100_000_000..999_999_999);
    let mut random = oorandom::Rand64::new(seed);
    println!("Seed: {}", seed);

    for _ in 0..100 {
        let length = random.rand_range(0..50);
        let mut data = vec![0; length as usize];
        for entry in data.iter_mut() {
            *entry = random.rand_u64() as u8;
        }

        // What kind of base64 encoding library needs traits and a prelude?
        // I maintain that this is insane.
        use base64::prelude::*;
        let known_good_encoding = BASE64_STANDARD.encode(&data);

        let mut in_place_buffer = vec![0u8; base64_encode_buffer_size(data.len())];
        in_place_buffer[0..data.len()].copy_from_slice(&data);
        base64_encode_in_place(data.len(), &mut in_place_buffer);

        assert_eq!(in_place_buffer, known_good_encoding.as_bytes());
    }
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
pub fn decode_cookie(key: &SigningKey, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>, output: &mut [u8]) -> Result<(), DecodeError> {
    use aes_gcm::KeyInit;
    use aes_gcm::aead::Aead;
    use base64::Engine;
    use aes_gcm::AeadInPlace;

    // The binary cipher is base64 encoded
    let message = base64::engine::general_purpose::STANDARD_NO_PAD.decode(value.as_ref()).or(Err(DecodeError))?;

    // The binary cipher is constructed as [ nonce, encrypted_value_with_signature ]
    // so we need to split it into it's individual parts
    let (nonce, rest_of_message) = message.split_at(NONCE_LENGTH);
    let (encrypted_message, signature) = rest_of_message.split_at(rest_of_message.len() - SIGNATURE_LENGTH);
    output.copy_from_slice(encrypted_message);

    // Wrap the slices up in GenericArrays because that's what aes_gcm requires
    let key_array = aes_gcm::aead::generic_array::GenericArray::from_slice(key);
    let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(nonce);
    let signature = aes_gcm::aead::generic_array::GenericArray::from_slice(signature);

    // Actually decrypt the value!
    aes_gcm::Aes256Gcm::new(key_array)
        .decrypt_in_place_detached(
            nonce_array,
            name.as_ref(),
            output,
            signature,
        )
        .or(Err(DecodeError))
}

/// The given cookie is not valid.
///
/// To avoid side-channel leakage no further information can be returned about the error.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DecodeError;

pub const fn message_length(encrypted_length: usize) -> usize {
    todo!()
}




#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_decode_succeeds() {
        for i in 0..13 {
            println!("{}: {}", i, base64_decoded_size(i));
        }
        panic!();

        let key = generate_signing_key();
        let nonce = generate_nonce();
        let name = "session";
        let data = r#"{"id":5}"#;

        let mut encoded = [0u8; decode_buffer_size(8)];
        encode_cookie(key, nonce, name, data, &mut encoded).unwrap();

        let mut decoded = [0u8; 8];
        decode_cookie(&key, name, encoded, &mut decoded).unwrap();
        assert_eq!(decoded, data.as_bytes());
    }

    #[test]
    fn different_keys_fails() {
        let key_a = generate_signing_key();
        let nonce = generate_nonce();
        let name = "session";
        let data = r#"{"id":5}"#;

        let mut encoded = [0u8; decode_buffer_size(8)];
        encode_cookie(key_a, nonce, name, data, &mut encoded).unwrap();

        let key_b = generate_signing_key();
        let mut decoded = [0u8; 8];
        let decode_result = decode_cookie(&key_b, name, encoded, &mut decoded);

        assert_eq!(decode_result, Err(DecodeError));
    }

    #[test]
    fn different_names_fails() {
        let key = generate_signing_key();
        let nonce = generate_nonce();
        let name_a = "session";
        let data = r#"{"id":5}"#;

        let mut encoded = [0u8; decode_buffer_size(8)];
        encode_cookie(key, nonce, name_a, data, &mut encoded).unwrap();

        let name_b = "laskdjf";
        let mut decoded = [0u8; 8];
        let decode_result = decode_cookie(&key, name_b, encoded, &mut decoded);

        assert_eq!(decode_result, Err(DecodeError));
    }

    #[test]
    fn identical_values_have_different_ciphers() {
        let key = generate_signing_key();
        let name = "session";
        let data = "which wolf do you feed?";

        let mut encoded_1 = [0u8; decode_buffer_size(23)];
        encode_cookie(key, generate_nonce(), name, data, &mut encoded_1).unwrap();

        let mut encoded_2 = [0u8; decode_buffer_size(23)];
        encode_cookie(key, generate_nonce(), name, data, &mut encoded_2).unwrap();

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