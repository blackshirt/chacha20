module chacha20

import math.bits
import crypto.cipher
import crypto.internal.subtle
import encoding.binary

// quarter_round is the basic operation of the ChaCha algorithm. It operates
// on four 32-bit unsigned integers, by performing AXR (add, xor, rotate)
// operation on this quartet u32 numbers.
fn quarter_round(a u32, b u32, c u32, d u32) (u32, u32, u32, u32) {
	// The operation is as follows (in C-like notation):
	// where `<<<=` denotes bits rotate left operation
	// a += b; d ^= a; d <<<= 16;
	// c += d; b ^= c; b <<<= 12;
	// a += b; d ^= a; d <<<= 8;
	// c += d; b ^= c; b <<<= 7;

	mut ax := a
	mut bx := b
	mut cx := c
	mut dx := d

	ax += bx
	dx ^= ax
	dx = bits.rotate_left_32(dx, 16)

	cx += dx
	bx ^= cx
	bx = bits.rotate_left_32(bx, 12)

	ax += bx
	dx ^= ax
	dx = bits.rotate_left_32(dx, 8)

	cx += dx
	bx ^= cx
	bx = bits.rotate_left_32(bx, 7)

	return ax, bx, cx, dx
}

/*
// encrypt was a thin wrapper around two supported nonce size, ChaCha20 with 96 bits
// and XChaCha20 with 192 bits nonce.
fn encrypt_generic(key []u8, ctr u32, nonce []u8, plaintext []u8) ![]u8 {
	_ = key[..key_size]
	if nonce.len == x_nonce_size {
		ciphertext := xchacha20_encrypt(key, ctr, nonce, plaintext)!
		return ciphertext
	}
	if nonce.len == nonce_size {
		ciphertext := chacha20_encrypt(key, ctr, nonce, plaintext)!
		return ciphertext
	}
	return error('Wrong nonce size : ${nonce.len}')
}

// serialize serializes ChaCha20 state (array of 16 u32) to array of bytes
fn serialize(cs []u32) []u8 {
	_ = cs[15]
	mut res := []u8{len: 4 * cs.len}
	for idx, val in cs {
		binary.little_endian_put_u32(mut res[idx * 4..idx * 4 + 4], val)
	}
	return res
}

// initialize_state initializes ChaCha20 state, represented as array of [16]u32
fn initialize_state(key []u8, counter u32, nonce []u8) ![]u32 {
	if key.len != key_size {
		return error('ChaCha20: wrong key size provided=${key.len}')
	}
	if nonce.len != nonce_size {
		return error('ChaCha20: wrong nonce size provided=${nonce.len}')
	}
	mut state := []u32{len: 16}

	state[0] = cc0
	state[1] = cc1
	state[2] = cc2
	state[3] = cc3

	state[4] = binary.little_endian_u32(key[0..4])
	state[5] = binary.little_endian_u32(key[4..8])
	state[6] = binary.little_endian_u32(key[8..12])
	state[7] = binary.little_endian_u32(key[12..16])

	state[8] = binary.little_endian_u32(key[16..20])
	state[9] = binary.little_endian_u32(key[20..24])
	state[10] = binary.little_endian_u32(key[24..28])
	state[11] = binary.little_endian_u32(key[28..32])

	state[12] = counter
	state[13] = binary.little_endian_u32(nonce[0..4])
	state[14] = binary.little_endian_u32(nonce[4..8])
	state[15] = binary.little_endian_u32(nonce[8..12])

	return state
}

// block_generic generates block/key stream from 256 bits key and 96 bits nonce
// ChaCha block function transforms a ChaCha state by running multiple quarter rounds, aka 20 round.
// The output is 64 random-looking bytes.
fn block_generic(key []u8, counter u32, nonce []u8) ![]u8 {
	// setup chacha state, checking was done on initialization step
	mut cs := initialize_state(key, counter, nonce)!

	// copy of state
	initial_state := cs[..cs.len].clone()

	// perform quarter round on ChaCha20 state
	for i := 0; i < 10; i++ {
		// Diagonal round.
		cs[0], cs[4], cs[8], cs[12] = quarter_round(cs[0], cs[4], cs[8], cs[12])
		cs[1], cs[5], cs[9], cs[13] = quarter_round(cs[1], cs[5], cs[9], cs[13])
		cs[2], cs[6], cs[10], cs[14] = quarter_round(cs[2], cs[6], cs[10], cs[14])
		cs[3], cs[7], cs[11], cs[15] = quarter_round(cs[3], cs[7], cs[11], cs[15])

		// Column round.
		cs[0], cs[5], cs[10], cs[15] = quarter_round(cs[0], cs[5], cs[10], cs[15])
		cs[1], cs[6], cs[11], cs[12] = quarter_round(cs[1], cs[6], cs[11], cs[12])
		cs[2], cs[7], cs[8], cs[13] = quarter_round(cs[2], cs[7], cs[8], cs[13])
		cs[3], cs[4], cs[9], cs[14] = quarter_round(cs[3], cs[4], cs[9], cs[14])
	}

	// state += initial_state
	for i := 0; i < cs.len; i++ {
		cs[i] = cs[i] + initial_state[i]
	}

	// return state
	return serialize(cs)
}

// encrypt_generic generates encrypted message from plaintext
fn chacha20_encrypt(key []u8, counter u32, nonce []u8, plaintext []u8) ![]u8 {
	// bound early check
	_, _ = key[key_size - 1], nonce[nonce_size - 1]
	mut encrypted_message := []u8{}

	for i := 0; i < plaintext.len / block_size; i++ {
		key_stream := block_generic(key, counter + u32(i), nonce) or {
			return error('chacha20: encrypt_generic fail key_stream')
		}
		block := plaintext[i * block_size..(i + 1) * block_size]

		// encrypted_message += block ^ key_stream
		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		// encrypted_message = encrypted_message + dst
		encrypted_message << dst
	}
	if plaintext.len % block_size != 0 {
		j := plaintext.len / block_size
		key_stream := block_generic(key, counter + u32(j), nonce) or {
			return error('chacha20: encrypt_generic fail key_stream')
		}
		block := plaintext[j * block_size..]

		// encrypted_message += (block^key_stream)[0..len(plaintext)%block_size]
		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		dst = unsafe { dst[0..plaintext.len % block_size] }

		// encrypted_message = encrypted_message[0..plaintext.len % block_size]
		encrypted_message << dst
	}
	return encrypted_message
}

// chacha20_decrypt decrypts the ciphertext, opposites of encryption process
fn chacha20_decrypt(key []u8, counter u32, nonce []u8, ciphertext []u8) ![]u8 {
	// bound early check
	_, _ = key[key_size - 1], nonce[nonce_size - 1]
	mut decrypted_message := []u8{}

	for i := 0; i < ciphertext.len / block_size; i++ {
		key_stream := block_generic(key, counter + u32(i), nonce)!
		block := ciphertext[i * block_size..(i + 1) * block_size]

		mut dst := []u8{len: block.len}
		if subtle.inexact_overlap(block, key_stream) {
			panic('chacha: subtle inexact overlap')
		}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		decrypted_message << dst
	}
	if ciphertext.len % block_size != 0 {
		j := ciphertext.len / block_size
		key_stream := block_generic(key, counter + u32(j), nonce)!
		block := ciphertext[j * block_size..]

		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		// use unsafe or explicit .clone()
		dst = unsafe { dst[0..ciphertext.len % block_size] }

		decrypted_message << dst
	}
	return decrypted_message
}
*/