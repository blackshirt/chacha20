// Copyright (c) 2022 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Chacha20 symetric key stream cipher encryption based on RFC 8439
module chacha20

import math.bits
import encoding.binary

// size of ChaCha20 key, ie 256 bits size, in u8s
pub const key_size = 32
// size of ietf ChaCha20 nonce, ie 96 bits size, in u8s
pub const nonce_size = 12
// size of extended ChaCha20 nonce, called XChaCha20, 192 bits
pub const x_nonce_size = 24
// internal block size ChaCha20 operates on, in u8s
const block_size = 64

// vfmt off

// magic constant of first of four words of ChaCha20 state
const cc0 = u32(0x61707865) // expa
const cc1 = u32(0x3320646e) // nd 3
const cc2 = u32(0x79622d32) // 2-by
const cc3 = u32(0x6b206574) // te k

fn encrypt(key []u8, nonce []u8, msg []u8) ![]u8 {
	mut c := new_cipher(key, nonce, 0)!
	mut dst := []u8{len: msg.len}
	c.xor_key_stream(mut dst, msg)
	return dst
}

fn decrypt(key []u8, nonce []u8, ciphertext []u8) ![]u8 {
	mut c := new_cipher(key, nonce, 0)!
	mut dst := []u8{len: ciphertext.len}
	c.xor_key_stream(mut dst, ciphertext)
	return dst
}

@[noinit]
struct Cipher {
mut:
	key     [8]u32
	nonce   []u32
	counter u64
	block   [64]u8
	pos     int
}

@[direct_array_access]
fn new_cipher(key []u8, nonce []u8, counter u64) !&Cipher {
	if key.len != 32 {
		return error('key must be 32 u8s')
	}
	if nonce.len != 12 && nonce.len != 8 && nonce.len != 24 {
		return error('nonce must be 24, 12 or 8')
	}
	// if this an extended chacha20 construct, derives a new key and nonce
	new_key, new_nonce := if nonce.len == x_nonce_size {
		xkey, xnonce := derive_xchacha20_key_nonce(key, nonce)!
		xkey, xnonce
	} else {
		// otherwise, use provided key and nonce
		key, nonce
	}

	mut c := &Cipher{}
	c.key = [binary.little_endian_u32(new_key[0..4]), binary.little_endian_u32(new_key[4..8]),
		binary.little_endian_u32(new_key[8..12]), binary.little_endian_u32(new_key[12..16]),
		binary.little_endian_u32(new_key[16..20]), binary.little_endian_u32(new_key[20..24]),
		binary.little_endian_u32(new_key[24..28]), binary.little_endian_u32(new_key[28..32])]!

	c.counter = counter

	c.nonce = []u32{len: nonce.len / 4}
	c.nonce[0] = binary.little_endian_u32(new_nonce[0..4])
	c.nonce[1] = binary.little_endian_u32(new_nonce[4..8])

	if nonce.len == 12 {
		c.nonce[2] = binary.little_endian_u32(new_nonce[8..12])
	}

	c.set_chacha20_roundblock()

	return c
}

fn (mut c Cipher) set_counter(v u64) {
	if c.nonce.len == 3 {
		if v > max_u32 {
			panic('32-bit exceed')
		}
	}
	c.counter = v
}

@[direct_array_access]
fn (c &Cipher) to_state() [16]u32 {
	mut x := [16]u32{}
	x[0] = cc0
	x[1] = cc1
	x[2] = cc2
	x[3] = cc3

	x[4] = c.key[0]
	x[5] = c.key[1]
	x[6] = c.key[2]
	x[7] = c.key[3]
	x[8] = c.key[4]
	x[9] = c.key[5]
	x[10] = c.key[6]
	x[11] = c.key[7]

	if c.nonce.len == 3 {
		x[12] = u32(c.counter)
		x[13] = c.nonce[0]
		x[14] = c.nonce[1]
		x[15] = c.nonce[2]
	} else {
		x[12] = u32(c.counter)
		x[13] = u32(c.counter >> 32)
		x[14] = c.nonce[0]
		x[15] = c.nonce[1]
	}

	return x
}

@[direct_array_access]
fn (mut c Cipher) xor_key_stream(mut dst []u8, src []u8) {
	for i := 0; i < src.len; i++ {
		dst[i] = src[i] ^ c.block[c.pos]
		c.pos++
		if c.pos == block_size {
			c.counter++
			c.set_chacha20_roundblock()
		}
	}
}

@[inline]
fn (mut c Cipher) set_chacha20_roundblock() {
	c.block = c.chacha20_roundblock()
	c.pos = 0
}

@[direct_array_access]
fn (mut c Cipher) chacha20_roundblock() [64]u8 {
	mut x := c.to_state()
	for i := 0; i < 10; i++ {
		// column round
		x[0], x[4], x[8], x[12] = qround(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = qround(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = qround(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = qround(x[3], x[7], x[11], x[15])
		// diagonal round
		x[0], x[5], x[10], x[15] = qround(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = qround(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = qround(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = qround(x[3], x[4], x[9], x[14])
	}
	initial := c.to_state()
	for i, _ in x {
		x[i] += initial[i]
	}
	mut block := [64]u8{}
	for i, v in x {
		block[i * 4] = u8(v)
		block[i * 4 + 1] = u8(v >> 8)
		block[i * 4 + 2] = u8(v >> 16)
		block[i * 4 + 3] = u8(v >> 24)
	}
	
	return block
}

type State = [16]u32

fn qstate(mut s State, a int, b int, c int, d int) {
	// quarter round on state
	// a += b;  d ^= a;  d <<<= 16;
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = bits.rotate_left_32(s[d], 16)

	// c += d;  b ^= c;  b <<<= 12;
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = bits.rotate_left_32(s[b], 12)

	// a += b;  d ^= a;  d <<<=  8;
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = bits.rotate_left_32(s[d], 8)

	// c += d;  b ^= c;  b <<<=  7;
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = bits.rotate_left_32(s[b], 7)
}

fn qround(a_ u32, b_ u32, c_ u32, d_ u32) (u32, u32, u32, u32) {
	mut a := a_
	mut b := b_
	mut c := c_
	mut d := d_

	a += b
	d ^= a
	d = bits.rotate_left_32(d, 16)

	c += d
	b ^= c
	b = bits.rotate_left_32(b, 12)

	a += b
	d ^= a
	d = bits.rotate_left_32(d, 8)

	c += d
	b ^= c
	b = bits.rotate_left_32(b, 7)

	return a, b, c, d
}
