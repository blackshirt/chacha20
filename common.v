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

// otk_key_gen generates one time key using `chacha20` block function if provided
// nonce was 12 bytes and using `xchacha20`, when its nonce was 24 bytes.
// This function is intended to generate key for poly1305 mac.
fn otk_key_gen(key []u8, nonce []u8) ![]u8 {
	if key.len != chacha20.key_size {
		return error('chacha20: bad key size provided ')
	}
	// check for nonce's length is 12 or 24
	if nonce.len != chacha20.nonce_size && nonce.len != chacha20.x_nonce_size {
		return error('chacha20: bad nonce size provided')
	}

	if nonce.len == chacha20.x_nonce_size {
		mut cnonce := nonce[16..].clone()
		subkey := hchacha20(key, nonce[0..16])!
		cnonce.prepend([u8(0x00), 0x00, 0x00, 0x00])
		mut c := new_cipher(subkey, nonce)!
		c.chacha20_block()
		return c.block[0..32]
	}