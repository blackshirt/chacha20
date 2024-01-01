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
pub const key_size = 32
// nonce_size is nonce_size for original ChaCha20 nonce (96 bits size), in bytes
pub const nonce_size = 12
// extended nonce size of chacha20, called xchacha20, 192 bits nonce size
pub const x_nonce_size = 24
// internal block size ChaCha20 operates on, in bytes
const block_size = 64

// vfmt off
// magic constant of first of four words of ChaCha20 state 
const cc0 = u32(0x61707865) // expa
const cc1 = u32(0x3320646e) // nd 3
const cc2 = u32(0x79622d32) // 2-by
const cc3 = u32(0x6b206574) // te k
// vfmt on

// Cipher represents ChaCha20 stream cipher instances.
struct Cipher {
	block_size int = chacha20.block_size
	// internal of ChaCha20 states is 16 of u32 word, 4 constant,
	// 8 of key, 3 of nonce and 1 counter
	key   [8]u32 // key_size of bytes length
	nonce [3]u32 // (x)_nonce_size of bytes length
mut:
	counter  u32
	overflow bool
	// we follow the go version
	precomp bool
	//
	p1  u32
	p5  u32
	p9  u32
	p13 u32
	//
	p2  u32
	p6  u32
	p10 u32
	p14 u32
	//
	p3  u32
	p7  u32
	p11 u32
	p15 u32
}

// new_cipher creates a new ChaCha20 stream cipher with the given 32 bytes key
// and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided, the XChaCha20 construction
// will be used. It returns an error if key or nonce have any other length.
// This is the only exported function to create initialized Cipher instances.
//
// Note: see `encrypt` or `README` notes.
pub fn new_cipher(key []u8, nonce []u8) !&Cipher {
	if key.len != chacha20.key_size {
		return error('chacha20: bad key size provided ')
	}

	if nonce.len !in [chacha20.nonce_size, chacha20.x_nonce_size] {
		return error('chacha20: Bad nonce size provided')
	}
	mut nonces := nonce.clone()
	mut keys := key.clone()

	if nonces.len == chacha20.x_nonce_size {
		// XChaCha20 uses the ChaCha20 core to mix 16 bytes of the nonce into a
		// derived key, allowing it to operate on a nonce of 24 bytes.
		keys = hchacha20(keys, nonces[0..16])
		mut cnonce := []u8{len: chacha20.nonce_size}
		copy(mut cnonce[4..12], nonces[16..24])
		nonces = cnonce.clone()
	} else if nonces.len != chacha20.nonce_size {
		return error('chacha20: wrong nonce size')
	}

	// bounds check elimination hint
	_ = keys[chacha20.key_size - 1]
	_ = nonce[chacha20.nonce_size - 1]
	// keys = keys[..chacha20.key_size]
	// nonce = nonce[..chacha20.nonce_size]

	// setup key
	mut k := [8]u32{}
	k[0] = binary.little_endian_u32(keys[0..4])
	k[1] = binary.little_endian_u32(keys[4..8])
	k[2] = binary.little_endian_u32(keys[8..12])
	k[3] = binary.little_endian_u32(keys[12..16])
	k[4] = binary.little_endian_u32(keys[16..20])
	k[5] = binary.little_endian_u32(keys[20..24])
	k[6] = binary.little_endian_u32(keys[24..28])
	k[7] = binary.little_endian_u32(keys[28..32])
	// setup nonce
	mut n := [3]u32{}
	n[0] = binary.little_endian_u32(nonce[0..4])
	n[1] = binary.little_endian_u32(nonce[4..8])
	n[2] = binary.little_endian_u32(nonce[8..12])

	c := &Cipher{
		key: k
		nonce: n
	}
	return c
}

// make_block_generic_ref creates block stream from internal state
// and stores it to dst
fn (mut c Cipher) make_block_generic_ref() []u8 {
	mut dst := []u8{len: chacha20.block_size}
	// initializes ChaCha20 state
	//      0:cccccccc   1:cccccccc   2:cccccccc   3:cccccccc
	//      4:kkkkkkkk   5:kkkkkkkk   6:kkkkkkkk   7:kkkkkkkk
	//      8:kkkkkkkk   9:kkkkkkkk  10:kkkkkkkk  11:kkkkkkkk
	//     12:bbbbbbbb  13:nnnnnnnn  14:nnnnnnnn  15:nnnnnnnn
	//
	// where c=constant k=key b=blockcounter n=nonce
	c0, c1, c2, c3 := chacha20.cc0, chacha20.cc1, chacha20.cc2, chacha20.cc3
	c4 := c.key[0]
	c5 := c.key[1]
	c6 := c.key[2]
	c7 := c.key[3]
	c8 := c.key[4]
	c9 := c.key[5]
	c10 := c.key[6]
	c11 := c.key[7]

	_ := c.counter
	c13 := c.nonce[0]
	c14 := c.nonce[1]
	c15 := c.nonce[2]

	// precomputes three first column round thats not depend on counter
	if !c.precomp {
		c.p1, c.p5, c.p9, c.p13 = quarter_round(c1, c5, c9, c13)
		c.p2, c.p6, c.p10, c.p14 = quarter_round(c2, c6, c10, c14)
		c.p3, c.p7, c.p11, c.p15 = quarter_round(c3, c7, c11, c15)
		c.precomp = true
	}
	// remaining first column round
	fcr0, fcr4, fcr8, fcr12 := quarter_round(c0, c4, c8, c.counter)

	// The second diagonal round.
	mut x0, mut x5, mut x10, mut x15 := quarter_round(fcr0, c.p5, c.p10, c.p15)
	mut x1, mut x6, mut x11, mut x12 := quarter_round(c.p1, c.p6, c.p11, fcr12)
	mut x2, mut x7, mut x8, mut x13 := quarter_round(c.p2, c.p7, fcr8, c.p13)
	mut x3, mut x4, mut x9, mut x14 := quarter_round(c.p3, fcr4, c.p9, c.p14)

	// The remaining 18 rounds.
	for i := 0; i < 9; i++ {
		// Column round.
		x0, x4, x8, x12 = quarter_round(x0, x4, x8, x12)
		x1, x5, x9, x13 = quarter_round(x1, x5, x9, x13)
		x2, x6, x10, x14 = quarter_round(x2, x6, x10, x14)
		x3, x7, x11, x15 = quarter_round(x3, x7, x11, x15)

		// Diagonal round.
		x0, x5, x10, x15 = quarter_round(x0, x5, x10, x15)
		x1, x6, x11, x12 = quarter_round(x1, x6, x11, x12)
		x2, x7, x8, x13 = quarter_round(x2, x7, x8, x13)
		x3, x4, x9, x14 = quarter_round(x3, x4, x9, x14)
	}

	// add back to initial state and stores to dst
	x0 += c0
	binary.little_endian_put_u32(mut dst[0..4], x0)
	x1 += c1
	binary.little_endian_put_u32(mut dst[4..8], x1)
	x2 += c2
	binary.little_endian_put_u32(mut dst[8..12], x2)
	x3 += c3
	binary.little_endian_put_u32(mut dst[12..16], x3)
	x4 += c4
	binary.little_endian_put_u32(mut dst[16..20], x4)
	x5 += c5
	binary.little_endian_put_u32(mut dst[20..24], x5)
	x6 += c6
	binary.little_endian_put_u32(mut dst[24..28], x6)
	x7 += c7
	binary.little_endian_put_u32(mut dst[28..32], x7)
	x8 += c8
	binary.little_endian_put_u32(mut dst[32..36], x8)
	x9 += c9
	binary.little_endian_put_u32(mut dst[36..40], x9)
	x10 += c10
	binary.little_endian_put_u32(mut dst[40..44], x10)
	x11 += c11
	binary.little_endian_put_u32(mut dst[44..48], x11)
	// x12 is c.counter
	x12 += c.counter
	binary.little_endian_put_u32(mut dst[48..52], x12)
	x13 += c13
	binary.little_endian_put_u32(mut dst[52..56], x13)
	x14 += c14
	binary.little_endian_put_u32(mut dst[56..60], x14)
	x15 += c15
	binary.little_endian_put_u32(mut dst[60..64], x15)

	return dst
}

fn (mut c Cipher) add_counter(n int) {
	if c.overflow || u64(c.counter + n) > math.max_u32 {
		panic('chacha20: counter would overflow')
	} else if u64(c.counter + n) == math.max_u32 {
		c.overflow = true
	}

	if n >= 0 {
		c.counter += u32(n)
		return
	}
}

// encrypt fullfills cipher.Block.encrypt
fn (mut c Cipher) encrypt(mut dst []u8, src []u8) {
	if src.len == 0 {
		return
	}
	if dst.len < src.len {
		panic('chacha20.Encrypt: insufficient space; dst is shorter than src.')
	}
	if subtle.inexact_overlap(dst, src) {
		panic('chacha20: invalid buffer overlap')
	}
	dst = c.encrypt_generic_ref(src)
}

// key_stream fills stream with cryptographically secure pseudorandom bytes
// from c's keystream when a random key and nonce are used.
fn (mut c Cipher) key_stream(stream []u8) {
	mut out := []u8{len: stream.len}
	c.encrypt(mut out, stream)
}

fn (mut c Cipher) encrypt_generic_ref(src []u8) []u8 {
	// checks for counter overflow
	num_blocks := src.len + chacha20.block_size - 1 / chacha20.block_size
	if c.overflow || u64(c.counter + num_blocks) > 1 << 32 {
		panic('chacha20: counter would overflow')
	} else if u64(c.counter + num_blocks) == 1 << 32 {
		c.overflow = true
	}

	mut encrypted_message := []u8{}

	for i := 0; i < src.len / chacha20.block_size; i++ {
		// block_generic(key, counter + u32(i), nonce) or {
		c.add_counter(i)
		key_stream := c.make_block_generic_ref() or { return error('chacha20: fail on key_stream') }
		block := src[i * chacha20.block_size..(i + 1) * chacha20.block_size]

		// encrypted_message += block ^ key_stream
		mut dst := []u8{len: block.len}
		n := cipher.xor_bytes(mut dst, block, key_stream)
		assert n == key_stream.len

		// encrypted_message = encrypted_message + dst
		encrypted_message << dst
	}
	// partial block
	if src.len % chacha20.block_size != 0 {
		j := src.len / chacha20.block_size
		// block_generic(key, counter + u32(j), nonce) or {
		c.add_counter(j)
		key_stream := c.make_block_generic_ref() or {
			return error('chacha20: encrypt_generic fail key_stream')
		}
		block := src[j * chacha20.block_size..]

		// encrypted_message += (block^key_stream)[0..len(plaintext)%block_size]
		mut dst := []u8{len: block.len}
		n := cipher.xor_bytes(mut dst, block, key_stream)
		assert n == key_stream.len

		dst = unsafe { dst[0..src.len % chacha20.block_size] }

		// encrypted_message = encrypted_message[0..plaintext.len % block_size]
		encrypted_message << dst
	}
	return encrypted_message
}

// set_counter sets the Chacha20 Cipher counter
pub fn (mut c Cipher) set_counter(ctr u32) {
	// WARNING: maybe racy
	if ctr == math.max_u32 {
		c.overflow = true
	}
	if c.overflow || ctr > math.max_u32 {
		panic('counter overflow')
	}
	c.counter = ctr
}

/*
// encrypt_generic generates encrypted message from plaintext
fn encrypt_generic_ref(key []u8, counter u32, nonce []u8, plaintext []u8) ![]u8 {
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

// encrypt was a thin wrapper around two supported nonce size, ChaCha20 with 96 bits
// and XChaCha20 with 192 bits nonce.
fn encrypt(key []u8, ctr u32, nonce []u8, plaintext []u8) ![]u8 {
	_ = key[..chacha20.key_size]
	if nonce.len == chacha20.x_nonce_size {
		ciphertext := encrypt_extended(key, ctr, nonce, plaintext)!
		return ciphertext
	}
	if nonce.len == chacha20.nonce_size {
		ciphertext := encrypt_generic_ref(key, ctr, nonce, plaintext)!
		return ciphertext
	}
	return error('Wrong nonce size : ${nonce.len}')
}
*/

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
