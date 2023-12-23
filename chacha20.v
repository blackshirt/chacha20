// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Chacha20 symetric key stream cipher encryption based on RFC 8439
module chacha20

import math
import math.bits
import crypto.cipher
import crypto.internal.subtle
import encoding.binary


// key_size is key size of ChaCha20 key (256 bits size), in bytes
pub const key_size     = 32
// nonce_size is nonce_size for original ChaCha20 nonce (96 bits size), in bytes
pub const nonce_size   = 12
// extended nonce size of chacha20, called xchacha20, 192 bits nonce size
pub const x_nonce_size = 24
// internal block size ChaCha20 operates on, in bytes
const block_size   = 64


// first of four words ChaCha20 state constant
const cc0 = u32(0x61707865) // expa
const cc1 = u32(0x3320646e) // nd 3
const cc2 = u32(0x79622d32) // 2-by
const cc3 = u32(0x6b206574) // te k


// Cipher represents ChaCha20 stream cipher instances.
struct Cipher {
	block_size = chacha20.block_size
	// key
	key []u8
	// nonce
	nonce []u8
mut:
	counter u32
}

// ChachaState represents ChaCha20 state, represented in 4x4 u32 vector
type ChachaState = [16]u32

// initializes ChaCha20 state
fn ChachaState.init(key []u8, ctr u32, nonce []u8) ChachaState {
	if key.len != key_size || nonce.len != nonce_size {
		panic("chacha20: bad key or nonce length")
	}
	// The ChaCha20 state is initialized as follows:
	// cccccccc  cccccccc  cccccccc  cccccccc
	// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
	// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
	// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
	// where c=constant k=key b=blockcount n=nonce

	mut cs :=  [16]u32{}
	cs[0] = cc0
	cs[1] = cc1
	cs[2] = cc2
	cs[3] = cc3

	cs[4] = binary.little_endian_u32(key[0..4])
	cs[5] = binary.little_endian_u32(key[4..8])
	cs[6] = binary.little_endian_u32(key[8..12])
	cs[7] = binary.little_endian_u32(key[12..16])

	cs[8] = binary.little_endian_u32(key[16..20])
	cs[9] = binary.little_endian_u32(key[20..24])
	cs[10] = binary.little_endian_u32(key[24..28])
	cs[11] = binary.little_endian_u32(key[28..32])

	cs[12] = ctr
	cs[13] = binary.little_endian_u32(nonce[0..4])
	cs[14] = binary.little_endian_u32(nonce[4..8])
	cs[15] = binary.little_endian_u32(nonce[8..12])

	return ChachaState(cs)
}
	
//interface Block {
//	block_size int // block_size returns the cipher's block size.
//	encrypt(mut dst []u8, src []u8) // Encrypt encrypts the first block in src into dst.
//	// Dst and src must overlap entirely or not at all.
//	decrypt(mut dst []u8, src []u8) // Decrypt decrypts the first block in src into dst.
//	// Dst and src must overlap entirely or not at all.
//}

fn (mut c Cipher) encrypt_generic(mut dst_ []u8, src_ []u8) {
	unsafe {
		mut dst := *dst_
		mut src := src_
		
		if dst.len < src.len {
			panic('chacha20: output smaller than input')
		}
		if subtle.inexact_overlap(dst[..src.len], src_) {
			panic('chacha20: invalid buffer overlap')
		}
		out := encrypt_generic(c.key, c.counter, c.nonce, src) ! // []u8 {
		copy(mut dst, out) 
	}
}
	
// new_cipher creates a new ChaCha20 stream cipher with the given 32 bytes key
// and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided, the XChaCha20 construction
// will be used. It returns an error if key or nonce have any other length.
// This is the only exported function to create initialized Cipher instances.
//
// Note: see `encrypt` or `README` notes.
pub fn new_cipher(key []u8, nonce []u8) !Cipher {
	if key.len != chacha20.key_size {
		return error('error wrong key size provided ')
	}

	if nonce.len !in [chacha20.nonce_size, chacha20.x_nonce_size] {
		return error('error nonce size provided')
	}
	mut nonces := nonce.clone()
	mut keys := key.clone()

	if nonces.len == chacha20.x_nonce_size {
		// XChaCha20 uses the ChaCha20 core to mix 16 bytes of the nonce into a
		// derived key, allowing it to operate on a nonce of 24 bytes. See
		// draft-irtf-cfrg-xchacha-01, Section 2.3.
		keys = hchacha20(keys, nonces[0..16])
		mut cnonce := []u8{len: chacha20.nonce_size}
		copy(mut cnonce[4..12], nonces[16..24])
		nonces = cnonce.clone()
	} else if nonces.len != chacha20.nonce_size {
		return error('chacha20: wrong nonce size')
	}

	c := Cipher{
		key: keys
		nonce: nonces
	}
	return c
}

// encrypt encrypts plaintext with chacha20 stream cipher based on nonce size provided in cipher instance,
// it's sizes was 12 bytes on standard ietf, constructed using standar chachar20 generic function,
// otherwise the size was 24 bytes and constructed using extended xchacha20 mechanism using `hchacha20` function.
//
// This is provided as convenient mechanism to do some encryption on the some plaintext.
pub fn (c Cipher) encrypt(plaintext []u8) ![]u8 {
	return encrypt(c.key, c.counter, c.nonce, plaintext)
}

// decrypt decrypts ciphertext encrypted with ChaCha20 encryption function.
// This doing thing in reverse way of encrypt.
pub fn (c Cipher) decrypt(ciphertext []u8) ![]u8 {
	return encrypt(c.key, c.counter, c.nonce, ciphertext)
}

// set_counter sets the Cipher counter
pub fn (mut c Cipher) set_counter(ctr u32) {
	// WARNING: maybe racy
	c.counter = ctr
}

// encrypt was a thin wrapper around two supported nonce size, ChaCha20 with 96 bits
// and XChaCha20 with 192 bits nonce.
fn encrypt(key []u8, ctr u32, nonce []u8, plaintext []u8) ![]u8 {
	_ = key[..chacha20.key_size]
	if nonce.len == chacha20.x_nonce_size {
		ciphertext := encrypt_extended(key, ctr, nonce, plaintext)!
		return ciphertext
	}
	if nonce.len == chacha20.nonce_size {
		ciphertext := encrypt_generic(key, ctr, nonce, plaintext)!
		return ciphertext
	}
	return error('Wrong nonce size : ${nonce.len}')
}

// otk_key_gen generates one time key using `chacha20` block function if provided
// nonce was 12 bytes and using `xchacha20`, when its nonce was 24 bytes.
// This function is intended to generate key for poly1305 mac.
pub fn otk_key_gen(key []u8, nonce []u8) ![]u8 {
	_ = key[chacha20.key_size - 1]
	if nonce.len !in [chacha20.nonce_size, chacha20.x_nonce_size] {
		return error('Bad nonce size')
	}
	// ensure nonce size is valid
	counter := u32(0)
	if nonce.len == chacha20.x_nonce_size {
		mut cnonce := nonce[16..].clone()
		subkey := hchacha20(key, nonce[0..16])
		cnonce.prepend([u8(0x00), 0x00, 0x00, 0x00])
		block := block_generic(subkey, counter, cnonce)!
		return block[0..32]
	}
	if nonce.len == chacha20.nonce_size {
		block := block_generic(key, counter, nonce)!
		return block[0..32]
	}
	return error('wrong nonce size')
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

// initialize_state initializes ChaCha20 state, represented as array of [16]u32
fn initialize_state(key []u8, counter u32, nonce []u8) ![]u32 {
	if key.len != chacha20.key_size {
		return error('ChaCha20: wrong key size provided=${key.len}')
	}
	if nonce.len != chacha20.nonce_size {
		return error('ChaCha20: wrong nonce size provided=${nonce.len}')
	}
	mut state := []u32{len: 16}

	state[0] = chacha20.cc0
	state[1] = chacha20.cc1
	state[2] = chacha20.cc2
	state[3] = chacha20.cc3

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
fn encrypt_generic(key []u8, counter u32, nonce []u8, plaintext []u8) ![]u8 {
	// bound early check
	_, _ = key[chacha20.key_size - 1], nonce[chacha20.nonce_size - 1]
	mut encrypted_message := []u8{}

	for i := 0; i < plaintext.len / chacha20.block_size; i++ {
		key_stream := block_generic(key, counter + u32(i), nonce) or {
			return error('chacha20: encrypt_generic fail key_stream')
		}
		block := plaintext[i * chacha20.block_size..(i + 1) * chacha20.block_size]

		// encrypted_message += block ^ key_stream
		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		// encrypted_message = encrypted_message + dst
		encrypted_message << dst
	}
	if plaintext.len % chacha20.block_size != 0 {
		j := plaintext.len / chacha20.block_size
		key_stream := block_generic(key, counter + u32(j), nonce) or {
			return error('chacha20: encrypt_generic fail key_stream')
		}
		block := plaintext[j * chacha20.block_size..]

		// encrypted_message += (block^key_stream)[0..len(plaintext)%block_size]
		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		dst = unsafe { dst[0..plaintext.len % chacha20.block_size] }

		// encrypted_message = encrypted_message[0..plaintext.len % block_size]
		encrypted_message << dst
	}
	return encrypted_message
}

// decrypt_generic decrypts the ciphertext, opposites of encryption process
fn decrypt_generic(key []u8, counter u32, nonce []u8, ciphertext []u8) ![]u8 {
	// bound early check
	_, _ = key[chacha20.key_size - 1], nonce[chacha20.nonce_size - 1]
	mut decrypted_message := []u8{}

	for i := 0; i < ciphertext.len / chacha20.block_size; i++ {
		key_stream := block_generic(key, counter + u32(i), nonce)!
		block := ciphertext[i * chacha20.block_size..(i + 1) * chacha20.block_size]

		mut dst := []u8{len: block.len}
		if subtle.inexact_overlap(block, key_stream) {
			panic('chacha: subtle inexact overlap')
		}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		decrypted_message << dst
	}
	if ciphertext.len % chacha20.block_size != 0 {
		j := ciphertext.len / chacha20.block_size
		key_stream := block_generic(key, counter + u32(j), nonce)!
		block := ciphertext[j * chacha20.block_size..]

		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		// use unsafe or explicit .clone()
		dst = unsafe { dst[0..ciphertext.len % chacha20.block_size] }

		decrypted_message << dst
	}
	return decrypted_message
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
