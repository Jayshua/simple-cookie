#![doc = include_str!("../README.md")]
#![cfg_attr(all(not(test), not(debug_assertions)), no_std)]



mod base64;



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

You can use the [encoded_buffer_size] function to get the required size of the buffer.

## Other Notes
[RFC6265](https://datatracker.ietf.org/doc/html/rfc6265) restricts the characters valid in cookie names. This function does *not* validate the name you provide.

Inspired by the [cookie](https://crates.io/crates/cookie) crate.
*/
#[cfg(all(feature="std", feature="rand"))]
pub fn encode_cookie(key: SigningKey, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> String {
	let nonce = generate_nonce();
	let mut output = vec![0; encoded_buffer_size(value.as_ref().len()).expect("unreachable, len comes from a slice and no slice can be large enough to make this operation overflow")];
	encode_cookie_advanced(key, nonce, name, value, &mut output).expect("unreachable, the buffer should always be correctly sized");
	String::from_utf8(output).expect("unreachable, encode_cookie_advanced should always produce ascii data")
}

/**
Just like [encode_cookie], but advanced.

This function supports running in a no_std environment without the rand crate. To securely produce
cookies you must guarantee that the provided [Nonce] is filled with cryptographically secure random
data and the signing key you provide abides by the requirements documented on the [SigningKey] type.
*/
pub fn encode_cookie_advanced<'a>(
	key: SigningKey,
	nonce: Nonce,
	name: impl AsRef<[u8]>,
	value: impl AsRef<[u8]>,
	output: &'a mut [u8],
) -> Result<&'a str, OutputBufferTooSmall> {
	let value: &[u8] = value.as_ref();

	let expected_size =
		match encoded_buffer_size(value.len()) {
			None => return Err(OutputBufferTooSmall { expected_size: None }),
			Some(x) if output.len() < x => return Err(OutputBufferTooSmall { expected_size: Some(x) }),
			Some(x) => x,
		};

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

	let total_length = NONCE_LENGTH + value.len() + SIGNATURE_LENGTH;

	// Cookie values must be in the ASCII printable range
	base64::encode_in_place(total_length, &mut output[..expected_size]);
	println!("{:?}", output);

	// unwrap: Base64-encoded, guaranteed to be valid utf8
	Ok(core::str::from_utf8(&output[..total_length]).unwrap())
}

/// Unable to encode the cookie. Returned from [encode_cookie_advanced].
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct OutputBufferTooSmall {
	/// Expected size of the output buffer, or None if the required size would overflow a usize.
	pub expected_size: Option<usize>,
}


/**
Get the required size of the output buffer passed to encode_cookie for the given input buffer length

This will always be larger than the size of the decoded buffer.

Returns None if the calculation would overflow a usize. This happens somewhere around
usize::MAX/4, so shouldn't happen on 64 bit platforms unless you have more RAM than the CIA.
*/
pub const fn encoded_buffer_size(value_length: usize) -> Option<usize> {
	base64::encoded_buffer_size(NONCE_LENGTH + value_length + SIGNATURE_LENGTH)
}


/**
Get the required size of the output buffer passed to decode_cookie given the length of the encoded cookie value

This will always be smaller than the length of the encoded data.
*/
pub const fn decoded_buffer_size(value_length: usize) -> usize {
	base64::decoded_buffer_size(value_length).saturating_sub(NONCE_LENGTH).saturating_sub(SIGNATURE_LENGTH)
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
pub fn decode_cookie(key: SigningKey, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
	let mut output = vec![0; decoded_buffer_size(value.as_ref().len())];

	match decode_cookie_advanced(key, name, value, &mut output) {
		Ok(_) => Ok(output),
		Err(reason) => Err(reason),
	}
}


/**
Just like [decode_cookie], but advanced.

This function supports running in a no_std environment by taking an output buffer to write into
rather than allocating a Vec. It otherwise behaves identically to [decode_cookie].
*/
pub fn decode_cookie_advanced(key: SigningKey, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>, output: &mut [u8]) -> Result<(), DecodeError> {
	// todo: test values & outputs of incorrect lengths

	let value = value.as_ref();
	let decoded_length = base64::decoded_buffer_size(value.len());

	// The binary cipher is base64 encoded as [ nonce, encrypted_value, signature ]
	let mut nonce = [0u8; NONCE_LENGTH];
	base64::decode_range(value, &mut nonce, 0, NONCE_LENGTH).or(Err(DecodeError))?;

	let mut signature = [0u8; SIGNATURE_LENGTH];
	base64::decode_range(value, &mut signature, decoded_length - SIGNATURE_LENGTH, decoded_length).or(Err(DecodeError))?;

	base64::decode_range(value, output, NONCE_LENGTH, decoded_length - SIGNATURE_LENGTH).or(Err(DecodeError))?;

	// Wrap the slices up in GenericArrays because that's what aes_gcm requires
	let key_array = aes_gcm::aead::generic_array::GenericArray::from_slice(&key);
	let nonce_array = aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce);
	let signature = aes_gcm::aead::generic_array::GenericArray::from_slice(&signature);

	// Actually decrypt the value!
	use aes_gcm::KeyInit;
	use aes_gcm::AeadInPlace;
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





#[cfg(test)]
mod test {
	use super::*;

	pub fn init_random() -> oorandom::Rand64 {
		let seed = rand::Rng::gen_range(&mut rand::thread_rng(), 100_000_000..999_999_999);
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