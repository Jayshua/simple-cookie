#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

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
#[cfg(any(test, feature = "rand"))]
pub fn generate_signing_key() -> SigningKey {
    let mut data = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    data
}

/// Generate a new nonce for encrypting a cookie with the [encode_cookie] function
///
/// This uses the thread-local random number generator, which is guaranteed by the rand crate
/// to produce cryptographically secure random data.
#[cfg(any(test, feature = "rand"))]
pub fn generate_nonce() -> Nonce {
    let mut data = [0; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
    data
}

/**
Build an iterator from the value part of a Cookie: header that will yield a name/value tuple for each cookie.

Certain characters are not permitted in cookie names, and different characters are not permitted
in cookie values. See [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265) for details. This function makes no attempt to validate the name
or value of the cookie headers.

Cookie values may or may not be quoted. (Like this: session="38h29onuf20138t")
This iterator will never include the quotes in the emitted value.
In the above example, the pair will be: ("session", "38h29onuf20138t") instead of ("session", "\"38h29onuf20138t\"")
Note that according to [RFC6265](https://datatracker.ietf.org/doc/html/rfc6265), using quotes is optional and never necessary
because the characters permitted inside a quoted value are the exact same characters
permitted outside the quoted value.

Cookie values may not necessarily be valid UTF-8.
As such, this function emits values of type [&\[u8\]](slice).
*/
pub fn parse_cookie_header_value(header: &[u8]) -> impl Iterator<Item = (&str, &[u8])> {
    header
        .split(|c| *c == b';')
        .map(|x| x.trim_ascii())
        .filter_map(|x| {
            let mut key_value_iterator = x.split(|c| *c == b'=').into_iter();

            let key: &[u8] = key_value_iterator.next()?;
            let key: &[u8] = key.trim_ascii();
            let key: &str = core::str::from_utf8(key).ok()?;

            let value: &[u8] = key_value_iterator.next()?.trim_ascii();
            let value: &[u8] = value.strip_prefix(&[b'"']).unwrap_or(value);
            let value: &[u8] = value.strip_suffix(&[b'"']).unwrap_or(value);

            Some((key, value))
        })
}

/**
Encrypt & sign a cookie value.

You may be interested in [encode_cookie_advanced] for no_std support.

## Cookie Name
The name of the cookie is required to prevent attackers
from swapping the encrypted value of one cookie with the encrypted value of another cookie.

For example, say you have two cookies:

```txt
session-account-id=2381
last-cache-reload=3193
```

When encrypted, the cookies might look like:

```txt
session-account=LfwFJ8N0YR5f4U8dWFc5vARKQL7GvRJI
last-cache-reload=NyOwR3npVm0gn8xlm89qcPMzQHjLZLs99
```

If the name of the cookie wasn't included in the encrypted value it would be possible for
an attacker to swap the values of the two cookies and make your server think that the
session-account-id cookie value was 3193, effectively impersonating another user.

The name will be included in the encrypted value and verified against the name you provide
when calling [decode_cookie] later.

## Other Notes
[RFC6265](https://datatracker.ietf.org/doc/html/rfc6265) restricts the characters valid in cookie names. This function does *not* validate the name you provide.

Inspired by the [cookie](https://crates.io/crates/cookie) crate.
*/
#[cfg(all(feature = "std", feature = "rand"))]
pub fn encode_cookie(key: SigningKey, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> String {
    let nonce = generate_nonce();
    let mut output = vec![0; encoded_buffer_size(value.as_ref().len()).expect("unreachable, len comes from a slice and no slice can be large enough to make this operation overflow")];
    encode_cookie_advanced(key, nonce, name, value, &mut output)
        .expect("unreachable, the buffer should always be correctly sized");
    String::from_utf8(output)
        .expect("unreachable, encode_cookie_advanced should always produce ascii data")
}

/**
Just like [encode_cookie], but advanced.

This function supports running in a no_std environment without the rand crate. To securely produce
cookies you must guarantee that the provided [Nonce] is filled with cryptographically secure random
data and the signing key you provide abides by the requirements documented on the [SigningKey] type.

You can use the [encoded_buffer_size] function to get the required size of the output buffer.
*/
pub fn encode_cookie_advanced<'a>(
    key: SigningKey,
    nonce: Nonce,
    name: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
    output: &'a mut [u8],
) -> Result<(), OutputBufferWrongSize> {
    let value: &[u8] = value.as_ref();

    let expected_size = match encoded_buffer_size(value.len()) {
        None => {
            return Err(OutputBufferWrongSize {
                expected_size: None,
                was: value.len(),
            })
        }
        Some(x) if output.len() < x => {
            return Err(OutputBufferWrongSize {
                expected_size: Some(x),
                was: value.len(),
            })
        }
        Some(x) if x < output.len() => {
            return Err(OutputBufferWrongSize {
                expected_size: Some(x),
                was: value.len(),
            })
        }
        Some(x) => x,
    };

    // Final message will be [nonce, encrypted_value, signature]
    // Split the output buffer apart into mutable slices for each component
    let (nonce_slot, rest_of_output) = output.split_at_mut(NONCE_LENGTH);
    let (encrypted_slot, rest_of_output) = rest_of_output.split_at_mut(value.len());
    let (signature_slot, _rest_of_output) = rest_of_output.split_at_mut(SIGNATURE_LENGTH);

    // Copy unencrypted data into the encrypted buffer.
    // The message will will be encrypted in-place.
    nonce_slot.copy_from_slice(&nonce);
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

    let total_length = NONCE_LENGTH + value.len() + SIGNATURE_LENGTH;

    // Cookie values must be in the ASCII printable range
    // unwrap: encoded data guaranteed to fit, output size checked at start of function
    encode_bytes_as_ascii(&mut output[..expected_size], total_length).unwrap();

    Ok(())
}

/// Unable to encode the cookie. Returned from [encode_cookie_advanced].
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct OutputBufferWrongSize {
    /// Expected size of the output buffer, or None if the required size would overflow a usize.
    pub expected_size: Option<usize>,
    pub was: usize,
}

/**
Get the required size of the output buffer passed to encode_cookie for the given input buffer length

This will always be larger than the size of the decoded buffer.

Returns None if the calculation would overflow a usize. This happens somewhere around
usize::MAX/2, so shouldn't happen on 64 bit platforms unless you have more RAM than the CIA.
*/
pub const fn encoded_buffer_size(value_length: usize) -> Option<usize> {
    if (usize::MAX / 2) - NONCE_LENGTH - SIGNATURE_LENGTH < value_length {
        None
    } else {
        Some((NONCE_LENGTH + value_length + SIGNATURE_LENGTH) * 2)
    }
}

/**
Get the length of the data inside an encrypted buffer of the given length.

This is the length of the output buffer passed to [decode_cookie_advanced].

This will always be smaller than the length of the encoded data.

Note that the encrypted value includes a constant amount of non-message data and will therefore
have a minimum length. If the length passed to this function is too small to contain the required
constant data, this function will return None.
*/
pub const fn decode_buffer_size(value_length: usize) -> Option<usize> {
    if value_length < (NONCE_LENGTH + SIGNATURE_LENGTH) * 2 {
        None
    } else {
        Some((value_length / 2) - NONCE_LENGTH - SIGNATURE_LENGTH)
    }
}

/**
Decrypt & verify the signature of a cookie value.

See [decode_cookie_advanced] for no_std support.

The name of the cookie is included in the signed content generated by
[encode_cookie], and is cross-referenced with the value you provide here to
guarantee that the cookie's encrypted content was not swapped with the
encrypted content of another cookie. For security purposes (e.g. to
prevent side-channel attacks) no details about a decoding failure are
returned.

Returns `Err(DecodeCookieError)` if the value argument is empty.

Inspired by the [cookie](https://crates.io/crates/cookie) crate.
*/
#[cfg(feature = "std")]
pub fn decode_cookie(
    key: SigningKey,
    name: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
) -> Result<Vec<u8>, DecodeError> {
    let Some(output_buffer_length) = decode_buffer_size(value.as_ref().len()) else {
        return Err(DecodeError);
    };

    let mut output = vec![0; output_buffer_length];

    match decode_cookie_advanced(key, name, value, &mut output) {
        Ok(_) => Ok(output),
        Err(reason) => Err(reason),
    }
}

/**
Just like [decode_cookie], but advanced.

This function supports running in a no_std environment by taking an output buffer to write into
rather than allocating a Vec. It otherwise behaves identically to [decode_cookie].

Use [decode_buffer_size] to determine the required length of the output buffer.

Returns `Err(DecodeCookieError)` if the output buffer is too small.
*/
pub fn decode_cookie_advanced(
    key: SigningKey,
    name: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
    output: &mut [u8],
) -> Result<(), DecodeError> {
    let value = value.as_ref();

    if value.len() == 0 {
        return Err(DecodeError);
    }

    if output.len() != decode_buffer_size(value.len()).ok_or(DecodeError)? {
        return Err(DecodeError);
    }

    let merged_values_length = value.len() / 2;

    // The binary cipher is base64 encoded as [ nonce, encrypted_value, signature ]
    let mut nonce = [0u8; NONCE_LENGTH];
    decode_ascii_as_bytes(value, &mut nonce, 0, NONCE_LENGTH);

    let mut signature = [0u8; SIGNATURE_LENGTH];
    decode_ascii_as_bytes(
        value,
        &mut signature,
        merged_values_length - SIGNATURE_LENGTH,
        merged_values_length,
    );

    decode_ascii_as_bytes(
        value,
        output,
        NONCE_LENGTH,
        merged_values_length - SIGNATURE_LENGTH,
    );

    // Wrap the slices up in GenericArrays because that's what aes_gcm requires
    let key_array = aes_gcm::aead::generic_array::GenericArray::from_slice(&key);
    let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce);
    let signature = aes_gcm::aead::generic_array::GenericArray::from_slice(&signature);

    // Actually decrypt the value!
    use aes_gcm::AeadInPlace;
    use aes_gcm::KeyInit;
    aes_gcm::Aes256Gcm::new(key_array)
        .decrypt_in_place_detached(nonce_array, name.as_ref(), output, signature)
        .or(Err(DecodeError))
}

/// The given cookie is not valid.
///
/// To avoid side-channel leakage no further information can be returned about the error.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DecodeError;

/**
Encode arbitrary bytes into just letters in the ASCII range.

Returns None if the input buffer is not large enough to encode the given length of data.

## Rationale

Only letters, numbers, and some symbols are permitted in cookie values.
To store the arbitrary bytes output by the encryption algorithm, we need
to encode it into just the permitted characters.

Base64 is a common solution to this. I used this custom encoding instead for two reasons:

1. To support no_alloc I needed to be able to encode into the same buffer that the data
    being encoded is in. This is possible in base64 (I've written the code to do it before
    actually) but I wasn't able to find a base64 library on crates.io that could do it,
    meaning I'd need to write the code myself anyway.

2. To support no_alloc I needed to be able to decode starting from an arbitrary position in the
    input data. This is also possible in base64 (I've written that function too) but I've never
    seen that feature in *any* base64 library regardless of language, much less on crates.io.

I could have implemented the appropriate base64 functions, but this encoding is much,
much simpler to write and an explicit goal of this library is simplicity.

Downside is that the encoding is not as efficient as base64, resulting in larger encoded text.

base64 length = (4n + 2) / 3
This method = 2n

So this is somewhere around 1.5x larger
That's not too much larger, so it's worth the trade-off in my opinion.
*/
fn encode_bytes_as_ascii<'a>(input: &'a mut [u8], length: usize) -> Option<&'a mut str> {
    if input.len() < length * 2 {
        return None;
    }

    let mut read_index = length;
    let mut write_index = length * 2;

    while 0 < read_index {
        read_index -= 1;
        write_index -= 2;
        let byte = input[read_index];
        let high = byte >> 4;
        let low = byte & 0b1111;
        input[write_index + 0] = high + b'a';
        input[write_index + 1] = low + b'a';
    }

    let string = core::str::from_utf8_mut(&mut input[..length * 2])
        .expect("unreachable: code can only generate valid ascii");

    Some(string)
}

/**
Decode bytes encoded with [encode_bytes_as_ascii].

See the docs on that function for rationale.

- Does not error on invalid bytes - output will contain whatever data the algorithm happens to decode the invalid bytes to.
- Returns an empty slice if to < from.
- If the length indicated by from..to is larger than output, will decode as much as possible and return.
*/
fn decode_ascii_as_bytes<'a>(
    input: &[u8],
    output: &'a mut [u8],
    from: usize,
    to: usize,
) -> &'a mut [u8] {
    if to < from {
        return &mut output[..0];
    }

    let length = (to - from).min(output.len());

    for (index, chunk) in input.chunks_exact(2).skip(from).take(length).enumerate() {
        let [high, low] = chunk else { unreachable!() };

        output[index] =
            ((high.saturating_sub(b'a')) & 0b1111) << 4 | ((low.saturating_sub(b'a')) & 0b1111);
    }

    &mut output[..length]
}

#[cfg(test)]
mod test {
    use super::*;

    pub fn init_random() -> oorandom::Rand64 {
        // let seed = rand::Rng::gen_range(&mut rand::thread_rng(), 100_000_000..999_999_999);
        let seed = 473483852;
        println!("Seed: {}", seed);
        oorandom::Rand64::new(seed)
    }

    pub fn random_bytes(random: &mut oorandom::Rand64) -> Vec<u8> {
        let length = random.rand_range(0..50);
        let mut data = vec![0; length as usize];
        for entry in data.iter_mut() {
            *entry = random.rand_u64() as u8;
        }

        data
    }

    pub const fn const_unwrap(input: Option<usize>) -> usize {
        match input {
            None => panic!("Tried to unwrap a None value"),
            Some(t) => t,
        }
    }

    #[test]
    fn test_ascii_encode() {
        let mut random = test::init_random();

        for _ in 0..100 {
            let raw_data = test::random_bytes(&mut random);

            if raw_data.len() == 0 {
                continue;
            }

            let mut encoded_buffer = vec![0u8; raw_data.len() * 2];
            encoded_buffer[..raw_data.len()].copy_from_slice(&raw_data);
            encode_bytes_as_ascii(&mut encoded_buffer, raw_data.len()).unwrap();

            for _ in 0..10 {
                let from = random.rand_range(0..raw_data.len() as u64) as usize;
                let to = random.rand_range(from as u64..raw_data.len() as u64) as usize;
                let mut decoded_buffer = vec![0u8; to - from];
                decode_ascii_as_bytes(&encoded_buffer, &mut decoded_buffer, from, to);

                assert_eq!(&raw_data[from..to], &decoded_buffer);
            }
        }
    }

    #[test]
    fn encode_decode_succeeds() {
        let key = generate_signing_key();
        let nonce = generate_nonce();
        let name = "session";
        let data = r#"{"id":5}"#;

        let mut encoded = [0u8; const_unwrap(encoded_buffer_size(8))];
        encode_cookie_advanced(key, nonce, name, data, &mut encoded).unwrap();

        let mut decoded = [0u8; 8];
        decode_cookie_advanced(key, name, encoded, &mut decoded).unwrap();

        assert_eq!(decoded, data.as_bytes());
    }

    #[test]
    fn returns_error_for_invalid_buffer_lengths() {
        let key = generate_signing_key();

        assert_eq!(
            Err(DecodeError),
            decode_cookie_advanced(key, "", "", &mut [])
        );
        assert_eq!(
            Err(DecodeError),
            decode_cookie_advanced(key, "", "a", &mut [])
        );
        assert_eq!(
            Err(DecodeError),
            decode_cookie_advanced(key, "", "asdklfjaskdf", &mut [])
        );
        assert_eq!(
            Err(DecodeError),
            decode_cookie_advanced(key, "", "asdklfjaskdf", &mut [0u8])
        );
        assert_eq!(
            Err(DecodeError),
            decode_cookie_advanced(key, "", "asdklfjaskdf", &mut [0u8; 5])
        );
    }

    #[test]
    fn different_keys_fails() {
        let key_a = generate_signing_key();
        let nonce = generate_nonce();
        let name = "session";
        let data = r#"{"id":5}"#;

        let mut encoded = [0u8; const_unwrap(encoded_buffer_size(8))];
        encode_cookie_advanced(key_a, nonce, name, data, &mut encoded).unwrap();

        let key_b = generate_signing_key();
        let mut decoded = [0u8; 8];
        let decode_result = decode_cookie_advanced(key_b, name, encoded, &mut decoded);

        assert_eq!(decode_result, Err(DecodeError));
    }

    #[test]
    fn different_names_fails() {
        let key = generate_signing_key();
        let nonce = generate_nonce();
        let name_a = "session";
        let data = r#"{"id":5}"#;

        let mut encoded = [0u8; const_unwrap(encoded_buffer_size(8))];
        encode_cookie_advanced(key, nonce, name_a, data, &mut encoded).unwrap();

        let name_b = "laskdjf";
        let mut decoded = [0u8; 8];
        let decode_result = decode_cookie_advanced(key, name_b, encoded, &mut decoded);

        assert_eq!(decode_result, Err(DecodeError));
    }

    #[test]
    fn identical_values_have_different_ciphers() {
        let key = generate_signing_key();
        let name = "session";
        let data = "which wolf do you feed?";

        let mut encoded_1 = [0u8; const_unwrap(encoded_buffer_size(23))];
        encode_cookie_advanced(key, generate_nonce(), name, data, &mut encoded_1).unwrap();

        let mut encoded_2 = [0u8; const_unwrap(encoded_buffer_size(23))];
        encode_cookie_advanced(key, generate_nonce(), name, data, &mut encoded_2).unwrap();

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
    fn includes_name_quotes() {
        let header = b"\"session\"=asdf";
        let mut iterator = parse_cookie_header_value(header);
        let (name, value) = iterator.next().unwrap();
        assert_eq!(name, "\"session\"");
        assert_eq!(value, b"asdf");
    }
}
