/*
I had two requirements that I haven't been able to meet with any base64
libraries I could find on crates.io.

1. Encoding in place.
	The encode function must encode the data into the same buffer that the data is read from.
	I couldn't find any libraries that did this. Possibly because it's less obvious how it's done?
	You just need to encode backward from the end of the buffer rather than forward from the start.

2. Decoding ranges from the middle of a base64 value.
	The decode function must be able to decode a portion of the base64 buffer.
	Preferably without decoding from the beginning and discarding until it reaches the desired spot.

Both requirements come from the design decision to avoid allocating any memory:
- Encoding in place to avoid allocating a String or Vec<u8> for the output data.
- Decoding from the middle so that the cookie value's output buffer can be used during decrypting
  without having to allocate additional memory for the base64 decoding step.
*/


/// Standard base64 alphabet
pub const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/**
Calculate the length of the encoded representation of a buffer with the given length

This will always be larger than the size of the decoded buffer.

Returns None if the calculation would overflow a usize. This happens somewhere around
usize::MAX/4, so shouldn't happen on 64 bit platforms unless you have more RAM than the CIA.
*/
pub const fn encoded_buffer_size(decoded_buffer_size: usize) -> Option<usize> {
	let Some(x) = decoded_buffer_size.checked_mul(4) else { return None; };
	let Some(x) = x.checked_add(2) else { return None; };
	let Some(x) = x.checked_div(3) else { return None; };
	Some(x)
}


/**
Calculate the length of the decoded representation of a buffer containing base64 data

This will always be smaller than the encoded buffer size
*/
pub const fn decoded_buffer_size(encoded_buffer_size: usize) -> usize {
	// Do the div first to avoid overflow
	(3 * encoded_buffer_size) / 4
}


/// Encode the given data as base64, overwriting into the same buffer
///
/// Use [encoded_buffer_size] to determine the required size of the buffer.
pub fn encode_in_place(length: usize, data: &mut [u8]) {
	let data_len = data.len();

	let (mut input_index, mut output_index) =
		if 2 == length % 3 {
			let segment = encode_segment([data[length-2], data[length-1], 0]);
			data[data_len-3] = segment[0];
			data[data_len-2] = segment[1];
			data[data_len-1] = segment[2];
			(length.saturating_sub(2), data.len().saturating_sub(3))
		}
		else if 1 == length % 3 {
			let segment = encode_segment([data[length-1], 0, 0]);
			data[data_len-2] = segment[0];
			data[data_len-1] = segment[1];
			(length.saturating_sub(1), data.len().saturating_sub(2))
		}
		else {
			(length, data.len())
		};

	while input_index > 0 {
		output_index -= 4;
		input_index -= 3;
		let segment = data[input_index..][..3].try_into().expect("unreachable");
		let segment = encode_segment(segment);
		data[output_index..][..4].copy_from_slice(&segment);
	}
}


// Helper function for [base64_encode_in_place]
fn encode_segment(segment: [u8; 3]) -> [u8; 4] {
	let temp = (segment[0] as u32) << 16 | (segment[1] as u32) << 8 | segment[2] as u32;

	let a = (temp >> 18) & 0b111111;
	let b = (temp >> 12) & 0b111111;
	let c = (temp >>  6) & 0b111111;
	let d = (temp >>  0) & 0b111111;

	[
		ALPHABET[a as usize],
		ALPHABET[b as usize],
		ALPHABET[c as usize],
		ALPHABET[d as usize],
	]
}


/// Decode the given range of base64 encoded data.
///
/// From and to are indexes into the hypothetical *decoded* buffer, not the concrete encoded buffer or output buffer.
/// That is, if you have a base64 value AAAABBBB, it would fully decode to [0, 0, 0, 1, 1, 1].
/// If you called decode_range(data, &mut output, 2, 4) you would get [0, 1, 1]. `From` and `to` are indexes into the fully decoded 6-byte buffer,
/// although this function will never actually construct the fully decoded buffer.
pub fn decode_range<'a>(data: &[u8], output: &'a mut [u8], from: usize, to: usize) -> Result<&'a mut [u8], DecodeError> {
	if from > usize::MAX / 4 {
		return Err(DecodeError::FromTooLarge { was: from, max: usize::MAX / 4 });
	}

	if to > usize::MAX / 4 {
		return Err(DecodeError::ToTooLarge { was: to, max: usize::MAX / 4 });
	}

	let decoded_length = to.saturating_sub(from);
	let expected_encoded_length = encoded_buffer_size(decoded_length).expect("unreachable, from and to were already checked for being too large.");
	let quad_start = (from / 3) * 4;

	if data.len().saturating_sub(quad_start) < expected_encoded_length {
		let error =
			DecodeError::InputTooSmall {
				was: data.len(),
				needed: quad_start + expected_encoded_length,
			};

		return Err(error);
	}

	if output.len() < decoded_length {
		let error =
			DecodeError::OutputTooSmall {
				was: output.len(),
				needed: decoded_length,
			};

		return Err(error);
	}

	if expected_encoded_length == 0 {
		return Ok(&mut output[..0]);
	}

	// Decode the leading partial-quad
	let (mut input_index, mut output_index) =
		if from % 3 == 0 {
			(quad_start, 0)
		}
		else if from % 3 == 1 {
			if 2 <= decoded_length {
				let b = convert_digit(data, quad_start+1)?;
				let c = convert_digit(data, quad_start+2)?;
				let d = convert_digit(data, quad_start+3)?;
				output[0] = (b & 0b001111) << 4 | (c & 0b111100) >> 2;
				output[1] = (c & 0b000011) << 6 | (d & 0b111111);
				(quad_start + 4, 2)
			}
			else if 1 == decoded_length {
				let b = convert_digit(data, quad_start+1)?;
				let c = convert_digit(data, quad_start+2)?;
				output[0] = (b & 0b001111) << 4 | (c & 0b111100) >> 2;
				(quad_start + 4, 1)
			}
			else {
				(quad_start, 0)
			}
		}
		else if from % 3 == 2 {
			let c = convert_digit(data, quad_start+2)?;
			let d = convert_digit(data, quad_start+3)?;
			output[0] = (c & 0b000011) << 6 | (d & 0b111111);
			(quad_start + 4, 1)
		}
		else {
			unreachable!()
		};

	// Decode all the quads in the middle
	while output_index < decoded_length.saturating_sub(2) {
		let segment = decode_segment(data[input_index..][..4].try_into().expect("unreachable"))?;
		output[output_index..][..3].copy_from_slice(&segment);
		input_index += 4;
		output_index += 3;
	}

	// Decode the trailing partial quad
	match decoded_length - output_index {
		0 => {}

		1 => {
			let segment = decode_segment([data[input_index + 0], data[input_index + 1], b'A', b'A'])?;
			output[output_index] = segment[0];
			output_index += 1;
		}

		2 => {
			let segment = decode_segment([data[input_index + 0], data[input_index + 1], data[input_index + 2], b'A'])?;
			output[output_index + 0] = segment[0];
			output[output_index + 1] = segment[1];
			output_index += 2;
		}

		_ => unreachable!(),
	}

	Ok(&mut output[..output_index])
}


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
	OutputTooSmall { was: usize, needed: usize },
	InputTooSmall { was: usize, needed: usize },
	InvalidByte { index: usize, byte: u8 },
	ToTooLarge { was: usize, max: usize },
	FromTooLarge { was: usize, max: usize },
}


// Helper function for [decode_range]
// Base64 encodes 3 byte chunks into 4 byte chunks.
// This function decodes a single 4 byte chunk into the corresponding 3 bytes that generated it.
fn decode_segment(segment: [u8; 4]) -> Result<[u8; 3], DecodeError> {
	let temp =
		(convert_digit(&segment, 0)? as u32) << 18
		| (convert_digit(&segment, 1)? as u32) << 12
		| (convert_digit(&segment, 2)? as u32) << 6
		| (convert_digit(&segment, 3)? as u32);

	Ok([
		((temp >> 16) & 0xff) as u8,
		((temp >>  8) & 0xff) as u8,
		((temp >>  0) & 0xff) as u8,
	])
}


// Helper function for [decode_range]
// Converts an ASCII base64 value to the corresponding decoded value
fn convert_digit(data: &[u8], index: usize) -> Result<u8, DecodeError> {
	let digit = data[index];

	if b'A' <= digit && digit <= b'Z' {
		Ok(digit - b'A')
	}
	else if b'a' <= digit && digit <= b'z' {
		Ok(digit - b'a' + 26)
	}
	else if b'0' <= digit && digit <= b'9' {
		Ok(digit - b'0' + 52)
	}
	else if digit == b'+' {
		Ok(62)
	}
	else if digit == b'/' {
		Ok(63)
	}
	else {
		Err(DecodeError::InvalidByte { byte: digit, index: index })
	}
}





#[cfg(test)]
mod test {
	use super::*;



	#[test]
	fn test_base64_decode_range() {
		let mut random = crate::test::init_random();


		/*
		Edge-case tests
		*/
		assert_eq!(Ok([].as_mut_slice()), decode_range(&[], &mut [], 0, 0));
		assert_eq!(Ok([].as_mut_slice()), decode_range(&[1, 2, 3], &mut [], 0, 0));
		assert_eq!(Ok([].as_mut_slice()), decode_range(&[], &mut [0, 0, 0], 0, 0));
		assert_eq!(Ok([].as_mut_slice()), decode_range(&[0, 0, 0], &mut [0, 0, 0], 0, 0));
		assert_eq!(Ok([4].as_mut_slice()), decode_range(b"BA", &mut [0], 0, 1));
		assert_eq!(Ok([0b0010_0001].as_mut_slice()), decode_range(b"BCE", &mut [0], 1, 2));
		assert_eq!(Ok([0b1100_0100].as_mut_slice()), decode_range(b"BCDE", &mut [0], 2, 3));
		assert_eq!(Ok([0b0010_0000, 0b1100_0100].as_mut_slice()), decode_range(b"BCDE", &mut [0, 0], 1, 3));


		/*
		Unconstrained fuzzing
		Just checking that the function doesn't panic
		*/
		for _ in 0..1000 {
			let input = crate::test::random_bytes(&mut random);
			let mut output = crate::test::random_bytes(&mut random);

			let start = random.rand_u64() as usize;
			let end = random.rand_u64() as usize;

			let _ = decode_range(&input, &mut output, start, end);
		}


		/*
		Constrained fuzzing
		Generate realistic random values to ensure the function actually runs
		rather than stopping at input validation checks like the fully random runs typically do.
		*/
		for _ in 0..100 {
			let input = crate::test::random_bytes(&mut random);

			if input.len() == 0 { continue; }

			let encoded_input =
				base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &input);

			for _ in 0..10 {
				let start = random.rand_range(0..input.len() as u64) as usize;
				let end = random.rand_range(start as u64..input.len() as u64) as usize;
				let mut output = vec![0; input.len()];
				let decoded_slice = decode_range(encoded_input.as_bytes(), &mut output, start, end).unwrap();
				assert_eq!(decoded_slice, &input[start..end]);
			}
		}


		/*
		Invalid argument tests
		Ensure the function returns the proper error messages.
		*/

		let encoded = b"ABCDEFGH";
		let mut decode_buffer = [0];
		assert_eq!(
			Err(DecodeError::OutputTooSmall { was: 1, needed: 6 }),
			decode_range(encoded, &mut decode_buffer, 0, 6)
		);

		let mut decode_buffer = [0, 0];
		assert_eq!(
			Err(DecodeError::InputTooSmall { was: 8, needed: 15 }),
			decode_range(encoded, &mut decode_buffer, 10, 12),
		);

		let encoded = [1, 2, 3, 4];
		let mut decode_buffer = [0];
		assert_eq!(
			Err(DecodeError::InvalidByte { index: 0, byte: 1 }),
			decode_range(&encoded, &mut decode_buffer, 0, 1),
		);

		match decode_range(&[], &mut [], usize::MAX - 5, usize::MAX) {
			Err(DecodeError::FromTooLarge { was, .. }) if was == usize::MAX - 5 => {}
			error => panic!("Invalid error: {:?}", error),
		}

		match decode_range(&[], &mut [], 0, usize::MAX) {
			Err(DecodeError::ToTooLarge { was, .. }) if was == usize::MAX => {}
			error => panic!("Invalid error: {:?}", error),
		}
	}



	#[test]
	fn test_decoded_buffer_size() {
		// Test the most important lengths every time
		for i in 0..10000 {
			let round_trip = decoded_buffer_size(encoded_buffer_size(i).unwrap());
			assert_eq!(i, round_trip);
		}

		// Test other lengths by fuzzing
		let mut random = crate::test::init_random();
		for _ in 0..100 {
			let length = random.rand_range(0..u64::MAX/4) as usize;
			let round_trip = decoded_buffer_size(encoded_buffer_size(length).unwrap());
			assert_eq!(length, round_trip);
		}
	}



	#[test]
	fn test_encode_in_place() {
		// Ensure function works on empty and length 1 data
		encode_in_place(0, &mut []);
		encode_in_place(1, &mut [0, 0]);

		// Fuzz test other lengths
		let mut random = crate::test::init_random();
		for _ in 0..100 {
			let data = crate::test::random_bytes(&mut random);

			let known_good_encoding =
				base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, &data);

			let mut in_place_buffer = vec![0u8; crate::test::const_unwrap(encoded_buffer_size(data.len()))];
			in_place_buffer[0..data.len()].copy_from_slice(&data);
			encode_in_place(data.len(), &mut in_place_buffer);

			assert_eq!(in_place_buffer, known_good_encoding.as_bytes());
		}
	}
}
