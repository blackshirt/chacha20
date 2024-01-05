module chacha20

import math.bits

// encrypt was a thin wrapper around two supported nonce size, ChaCha20 with 96 bits
// and XChaCha20 with 192 bits nonce. If you want more control with internal counter
// see `encrypt_with_counter`
pub fn encrypt(key []u8, nonce []u8, plaintext []u8) ![]u8 {
	return encrypt_with_counter(key, nonce, u32(0), plaintext)
}

// encrypt_with_counter encrypts plaintext with internal counter set to ctr
pub fn encrypt_with_counter(key []u8, nonce []u8, ctr u32, plaintext []u8) ![]u8 {
	if key.len != key_size {
		return error('bad key size')
	}
	if nonce.len == x_nonce_size {
		ciphertext := xchacha20_encrypt_with_counter(key, nonce, ctr, plaintext)!
		return ciphertext
	}
	if nonce.len == nonce_size {
		ciphertext := chacha20_encrypt_with_counter(key, nonce, ctr, plaintext)!
		return ciphertext
	}
	return error('Wrong nonce size')
}

fn chacha20_encrypt(key []u8, nonce []u8, plaintext []u8) ![]u8 {
	return chacha20_encrypt_with_counter(key, nonce, u32(0), plaintext)
}

fn chacha20_encrypt_with_counter(key []u8, nonce []u8, ctr u32, plaintext []u8) ![]u8 {
	mut c := new_cipher(key, nonce)!
	c.set_counter(ctr)
	mut out := []u8{len: plaintext.len}

	c.encrypt(mut out, plaintext)

	return out
}

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
