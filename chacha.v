// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Chacha20 symetric key stream cipher encryption based on RFC 8439
module chacha20

import math
import crypto.rand
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

// Cipher represents ChaCha20 stream cipher instances.
struct Cipher {
pub:
	block_size int = chacha20.block_size
mut:
	// internal's of ChaCha20 state, ie, 16 of u32 words, 4 of ChaCha20 constants,
	// 8 word (32 bytes) of keys, 3 word (24 bytes) of nonces and 1 word of counter
	key      [8]u32 // key_size of bytes length
	nonce    [3]u32 // (x)_nonce_size of bytes length
	counter  u32
	overflow bool
	// internal block_size length buffer for storing block stream results
	block []u8 = []u8{len: chacha20.block_size}
	// we follow the go version
	precomp bool
	p1  u32 p5  u32 p9  u32 p13 u32
	p2  u32 p6  u32 p10 u32 p14 u32
	p3  u32 p7  u32 p11 u32 p15 u32
}
// vfmt on
	
// new_random_cipher creates new ChaCha20 cipher with random key and random nonce
// Its accepts `xnonce` flag thats driving the supported size of the nonce, 12 or 24.
pub fn new_random_cipher(xnonce bool) !&Cipher {
	key := rand.read(chacha20.key_size)!
	size := if xnonce { chacha20.x_nonce_size } else { chacha20.nonce_size }
	nonce := rand.read(size)!

	c := new_cipher(key, nonce)!
	return c
}

// new_cipher creates a new ChaCha20 stream cipher with the given 32 bytes key
// and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided, the XChaCha20 construction
// will be used. It returns an error if key or nonce have any other length.
// This is the only exported function to create initialized Cipher instances.
pub fn new_cipher(key []u8, nonce []u8) !&Cipher {
	mut c := &Cipher{}
	// we dont need reset on new cipher instance
	c.do_rekey(key, nonce)!

	return c 
}

// free the resources taken by the Cipher `c`. Dont use cipher after .free call
@[unsafe]
pub fn (mut c Cipher) free() {
	$if prealloc {
		return
	}
	unsafe {
		// c.key.free() // fixed arrays does not support free
		// c.nonce.free()
		c.block.free()
		free(c)
	}
}

// reset quickly sets the bytes of all elements of the array to 0
// and reset all fields to default value
@[unsafe]
pub fn (mut c Cipher) reset() {
	for i, _ in c.key {
		c.key[i] = u32(0)
	}
	for j, _ in c.nonce {
		c.nonce[j] = u32(0)
	}
	unsafe {
		c.block.reset()
	}

	c.counter = u32(0)
	c.overflow = false
	c.precomp = false
	//
	c.p1 = u32(0)
	c.p5 = u32(0)
	c.p9 = u32(0)
	c.p13 = u32(0)
	//
	c.p2 = u32(0)
	c.p6 = u32(0)
	c.p10 = u32(0)
	c.p14 = u32(0)
	//
	c.p3 = u32(0)
	c.p7 = u32(0)
	c.p11 = u32(0)
	c.p15 = u32(0)
}

// set_counter sets Cipher's counter
pub fn (mut c Cipher) set_counter(ctr u32) {
	if ctr == math.max_u32 {
		c.overflow = true
	}
	if c.overflow {
		panic('counter would overflow')
	}
	c.counter = ctr
}

// encrypt fullfills `cipher.Block.encrypt` interface.
pub fn (mut c Cipher) encrypt(mut dst []u8, src []u8) {
	c.xor_key_stream(mut dst, src)
}

// encrypt fullfills `cipher.Block.decrypt` interface.
pub fn (mut c Cipher) decrypt(mut dst []u8, src []u8) {
	c.xor_key_stream(mut dst, src)
}

// xor_key_stream xors each byte in the given slice with a byte from the
// cipher's key stream. It fullfills `cipher.Stream` interface. Its does encrypts plaintext message
// in src and stores ciphertext result in dst in single shot of run of encryption.
pub fn (mut c Cipher) xor_key_stream(mut dst []u8, src []u8) {
	if src.len == 0 {
		return
	}
	if dst.len < src.len {
		panic('chacha20/chacha: dst buffer is to small')
	}
	if subtle.inexact_overlap(dst, src) {
		panic('chacha20: invalid buffer overlap')
	}
	mut ciphertext := []u8{}

	// process for multiple blocks
	for i := 0; i < src.len / chacha20.block_size; i++ {
		// generates ciphers keystream and stored in c.block
		c.generic_key_stream()
		// get current's input block to be xor-ed
		block := unsafe { src[i * chacha20.block_size..(i + 1) * chacha20.block_size] }

		// xor-ing current block of plaintext with keystream in c.block and stores result in out
		mut out := []u8{len: block.len}
		n := cipher.xor_bytes(mut out, block, c.block)
		assert n == c.block.len

		// append current output to the ciphertext buffer
		ciphertext << out
	}
	// process for partial block
	if src.len % chacha20.block_size != 0 {
		j := src.len / chacha20.block_size
		c.generic_key_stream()
		// gets the remaining partial block
		block := unsafe { src[j * chacha20.block_size..] }
		// xor-ing block with keystream
		mut out := []u8{len: block.len}
		n := cipher.xor_bytes(mut out, block, c.block)
		assert n == block.len

		// we make sure, takes only required remaining bytes
		out = unsafe { out[0..src.len % chacha20.block_size] }

		// append last output to the ciphertext buffer
		ciphertext << out
	}
	// copy ciphertext message results to the dst buffer
	n := copy(mut dst, ciphertext)
	assert n == src.len
}

// chacha20_block was a ChaCha block function transforms a ChaCha20 state by running
// multiple quarter rounds.
// see https://datatracker.ietf.org/doc/html/rfc8439#section-2.3
fn (mut c Cipher) chacha20_block() {
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
	x1 += c1
	x2 += c2
	x3 += c3
	x4 += c4
	x5 += c5
	x6 += c6
	x7 += c7
	x8 += c8
	x9 += c9
	x10 += c10
	x11 += c11
	// x12 is c.counter
	x12 += c.counter
	x13 += c13
	x14 += c14
	x15 += c15

	binary.little_endian_put_u32(mut c.block[0..4], x0)
	binary.little_endian_put_u32(mut c.block[4..8], x1)
	binary.little_endian_put_u32(mut c.block[8..12], x2)
	binary.little_endian_put_u32(mut c.block[12..16], x3)
	binary.little_endian_put_u32(mut c.block[16..20], x4)
	binary.little_endian_put_u32(mut c.block[20..24], x5)
	binary.little_endian_put_u32(mut c.block[24..28], x6)
	binary.little_endian_put_u32(mut c.block[28..32], x7)
	binary.little_endian_put_u32(mut c.block[32..36], x8)
	binary.little_endian_put_u32(mut c.block[36..40], x9)
	binary.little_endian_put_u32(mut c.block[40..44], x10)
	binary.little_endian_put_u32(mut c.block[44..48], x11)
	binary.little_endian_put_u32(mut c.block[48..52], x12)
	binary.little_endian_put_u32(mut c.block[52..56], x13)
	binary.little_endian_put_u32(mut c.block[56..60], x14)
	binary.little_endian_put_u32(mut c.block[60..64], x15)
}

// generic_key_stream creates unoptimized generic ChaCha20 keystream block and stores the result in Cipher.block
fn (mut c Cipher) generic_key_stream() {
	// creates ChaCha20 block stream
	c.chacha20_block()
	// updates counter and checks for overflow
	ctr := u64(c.counter) + u64(1)
	if ctr == math.max_u32 {
		c.overflow = true
	}
	if c.overflow || ctr > math.max_u32 {
		panic('counter overflow')
	}
	c.counter += 1
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
	if nonce.len == chacha20.x_nonce_size {
		mut cnonce := nonce[16..].clone()
		subkey := hchacha20(key, nonce[0..16])
		cnonce.prepend([u8(0x00), 0x00, 0x00, 0x00])
		mut c := new_cipher(subkey, nonce)!
		c.chacha20_block()
		return c.block[0..32]
	}
	if nonce.len == chacha20.nonce_size {
		mut c := new_cipher(key, nonce)!
		c.chacha20_block()
		return c.block[0..32]
	}
	return error('wrong nonce size')
}

// rekey resets internal Cipher's state and reinitializes state with the provided key and nonce
pub fn (mut c Cipher) rekey(key []u8, nonce []u8) ! {
	c.reset()
	return c.do_rekey(key, nonce)!
}
		
// do_rekey reinitializes ChaCha20 instance with the provided key and nonce.
fn (mut c Cipher) do_rekey(key []u8, nonce []u8) ! {
	// check for correctness of key and nonce length
	if key.len != chacha20.key_size {
		return error('chacha20: bad key size provided ')
	}
	// check for nonce's length is 12 or 24
	if nonce.len != chacha20.nonce_size && nonce.len !=  chacha20.x_nonce_size {
		return error('chacha20: bad nonce size provided')
	}
	mut nonces := unsafe { nonce[..] }
	mut keys := unsafe { key[..] }
	if nonces.len == chacha20.x_nonce_size {
		keys = hchacha20(keys, nonces[0..16])
		mut cnonce := []u8{len: chacha20.nonce_size}
		_ := copy(mut cnonce[4..12], nonces[16..24])
		nonces = cnonce.clone()
	} else if nonces.len != chacha20.nonce_size {
		return error('chacha20: wrong nonce size')
	}

	// bounds check elimination hint
	_ = keys[chacha20.key_size - 1]
	_ = nonces[chacha20.nonce_size - 1]

	// setup ChaCha20 cipher key
	c.key[0] = binary.little_endian_u32(keys[0..4])
	c.key[1] = binary.little_endian_u32(keys[4..8])
	c.key[2] = binary.little_endian_u32(keys[8..12])
	c.key[3] = binary.little_endian_u32(keys[12..16])
	c.key[4] = binary.little_endian_u32(keys[16..20])
	c.key[5] = binary.little_endian_u32(keys[20..24])
	c.key[6] = binary.little_endian_u32(keys[24..28])
	c.key[7] = binary.little_endian_u32(keys[28..32])
	
	// setup ChaCha20 cipher nonce
	c.nonce[0] = binary.little_endian_u32(nonces[0..4])
	c.nonce[1] = binary.little_endian_u32(nonces[4..8])
	c.nonce[2] = binary.little_endian_u32(nonces[8..12])
}
