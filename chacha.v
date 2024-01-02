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
const buf_size = block_size
const empty_src = []u8{len: 0}

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
	offset   int
	buffer   []u8
	// keystream buffer and length
	ks_buf []u8
	ks_len int
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
	n[0] = binary.little_endian_u32(nonces[0..4])
	n[1] = binary.little_endian_u32(nonces[4..8])
	n[2] = binary.little_endian_u32(nonces[8..12])

	c := &Cipher{
		key: k
		nonce: n
	}
	return c
}

fn (mut c Cipher) ecrypt_msg(mut out []u8, msg []u8) !int {
	if msg.len == 0 {
		return 0
	}
	if out.len < msg.len {
		panic('chacha20.Encrypt: insufficient space; c is shorter than m.')
	}
	
	mut idx := 0
	for i := 0; i < msg.len / chacha20.block_size; i++ {
		c.incr_ctr_by(u32(i))
		mut key_stream := []u8{len:block_size}
		c.to_key_stream(mut key_stream) 
		block := msg[i * chacha20.block_size..(i + 1) * chacha20.block_size]

		// encrypted_message += block ^ key_stream
		mut part := []u8{len: block.len}
		_ := cipher.xor_bytes(mut part, block, key_stream)

		// encrypted_message = encrypted_message + part
		_ := copy(mut out[idx..], part)
		//encrypted_message << part
		idx += part.len 
	}
	if msg.len % chacha20.block_size != 0 {
		j := msg.len / chacha20.block_size
		c.incr_ctr_by(u32(j))
		mut key_stream := []u8{len:block_size}
		c.to_key_stream(mut key_stream) 
		//key_stream := block_generic(key, counter + u32(j), nonce) or {
		//	return error('chacha20: encrypt_generic fail key_stream')
		//}
		block := msg[j * chacha20.block_size..]

		// encrypted_message += (block^key_stream)[0..len(msg)%block_size]
		mut part := []u8{len: block.len}
		_ := cipher.xor_bytes(mut part, block, key_stream)
		//part = unsafe { part[0..msg.len % chacha20.block_size] }

		// encrypted_message = encrypted_message[0..msg.len % block_size]
		//  encrypted_message << dst
		n := copy(mut out[idx..], part)
		//encrypted_message << part
		idx += part.len 
	}
	return idx 
}

fn (mut c Cipher) xor_key_stream(mut dst []u8, mut src []u8) {
	if src.len == 0 {
		return
	}
	if dst.len < src.len {
		panic('chacha20: output smaller than input')
	}
	dst = unsafe { dst[..src.len] }
	if subtle.inexact_overlap(dst, src) {
		panic('chacha20: invalid buffer overlap')
	}

	// First, drain any remaining key stream from a previous xor_key_stream.
	if c.ks_len != 0 {
		mut keystream := c.ks_buf[chacha20.buf_size - c.ks_len..]
		if src.len < keystream.len {
			keystream = unsafe { keystream[..src.len] }
		}
		// bounds check
		_ = src[keystream.len - 1]
		// xor-ing bytes keystream with src
		n := cipher.xor_bytes(mut dst, src, keystream)
		assert n == keystream.len

		c.ks_len -= keystream.len
		dst = unsafe { dst[keystream.len..] }
		src = unsafe { src[keystream.len..] }
	}
	if src.len == 0 {
		return
	}

	// check if counter would overflow
	numblocks := (u64(src.len) + chacha20.block_size - 1) / chacha20.block_size
	if c.overflow || u64(c.counter) + u64(numblocks) > math.max_u32 {
		panic('chacha20: counter overflow')
	} else if u64(c.counter) + u64(numblocks) == math.max_u32 {
		c.overflow = true
	}

	// multiblock
	full := src.len - src.len % chacha20.buf_size
	if full > 0 {
		c.do_keystream_blocks(mut dst[..full], mut src[..full])
	}
	dst = unsafe { dst[full..] }
	src = unsafe { src[full..] }

	// If using a multi-block do_keystream_blocks would overflow, use the generic
	// one that does one block at a time.
	blocks_perbuf := chacha20.buf_size / chacha20.block_size
	if u64(c.counter) + u64(blocks_perbuf) > math.max_u32 {
		c.ks_buf = []u8{len: chacha20.buf_size}
		nr_blocks := (src.len + chacha20.block_size - 1) / chacha20.block_size
		mut buf := c.ks_buf[chacha20.buf_size - nr_blocks * chacha20.block_size..]
		_ := copy(mut buf, src)
		c.generic_do_keystream_blocks(mut buf, mut buf)
		c.ks_len = buf.len - copy(mut dst, buf)
		return
	}

	// If we have a partial (multi-)block, pad it for do_keystream_blocks, and
	// keep the leftover keystream for the next xor_key_stream invocation.
	if src.len > 0 {
		c.ks_buf = []u8{len: chacha20.buf_size}
		_ := copy(mut c.ks_buf[..], src)
		c.do_keystream_blocks(mut c.ks_buf[..], mut c.ks_buf[..])
		c.ks_len = chacha20.buf_size - copy(mut dst, c.ks_buf[..])
	}
}

fn (mut c Cipher) do_keystream_blocks(mut dst []u8, mut src []u8) {
	c.generic_do_keystream_blocks(mut dst, mut src)
}

fn (mut c Cipher) generic_do_keystream_blocks(mut dst []u8, mut src []u8) {
	if dst.len != src.len || dst.len % chacha20.block_size != 0 {
		panic('chacha20: internal error: wrong dst and/or src length')
	}
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
	for src.len >= 64 && dst.len >= 64 {
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
		// add back to initial state, xor-ing with u8 in the src and stores to dst
		x0 += c0
		binary.little_endian_put_u32(mut dst[0..4], binary.little_endian_u32(src[0..4]) ^ x0)
		x1 += c1
		binary.little_endian_put_u32(mut dst[4..8], binary.little_endian_u32(src[4..8]) ^ x1)
		x2 += c2
		binary.little_endian_put_u32(mut dst[8..12], binary.little_endian_u32(src[8..12]) ^ x2)
		x3 += c3
		binary.little_endian_put_u32(mut dst[12..16], binary.little_endian_u32(src[12..16]) ^ x3)
		x4 += c4
		binary.little_endian_put_u32(mut dst[16..20], binary.little_endian_u32(src[16..20]) ^ x4)
		x5 += c5
		binary.little_endian_put_u32(mut dst[20..24], binary.little_endian_u32(src[20..24]) ^ x5)
		x6 += c6
		binary.little_endian_put_u32(mut dst[24..28], binary.little_endian_u32(src[24..28]) ^ x6)
		x7 += c7
		binary.little_endian_put_u32(mut dst[28..32], binary.little_endian_u32(src[28..32]) ^ x7)
		x8 += c8
		binary.little_endian_put_u32(mut dst[32..36], binary.little_endian_u32(src[32..36]) ^ x8)
		x9 += c9
		binary.little_endian_put_u32(mut dst[36..40], binary.little_endian_u32(src[36..40]) ^ x9)
		x10 += c10
		binary.little_endian_put_u32(mut dst[40..44], binary.little_endian_u32(src[40..44]) ^ x10)
		x11 += c11
		binary.little_endian_put_u32(mut dst[44..48], binary.little_endian_u32(src[44..48]) ^ x11)
		// x12 is c.counter
		x12 += c.counter
		binary.little_endian_put_u32(mut dst[48..52], binary.little_endian_u32(src[48..52]) ^ x12)
		x13 += c13
		binary.little_endian_put_u32(mut dst[52..56], binary.little_endian_u32(src[52..56]) ^ x13)
		x14 += c14
		binary.little_endian_put_u32(mut dst[56..60], binary.little_endian_u32(src[56..60]) ^ x14)
		x15 += c15
		binary.little_endian_put_u32(mut dst[60..64], binary.little_endian_u32(src[60..64]) ^ x15)

		// updates state counter and new src and dst
		c.counter += 1
		src = unsafe { src[chacha20.block_size..] }
		dst = unsafe { dst[chacha20.block_size..] }
	}
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

// to_key_stream creates ChaCha20 keystream and serializes to dst
fn (mut c Cipher) to_key_stream(mut dst []u8) {
	_ = dst[chacha20.block_size - 1]
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

	binary.little_endian_put_u32(mut dst[0..4], x0)
	binary.little_endian_put_u32(mut dst[4..8], x1)
	binary.little_endian_put_u32(mut dst[8..12], x2)
	binary.little_endian_put_u32(mut dst[12..16], x3)
	binary.little_endian_put_u32(mut dst[16..20], x4)
	binary.little_endian_put_u32(mut dst[20..24], x5)
	binary.little_endian_put_u32(mut dst[24..28], x6)
	binary.little_endian_put_u32(mut dst[28..32], x7)
	binary.little_endian_put_u32(mut dst[32..36], x8)
	binary.little_endian_put_u32(mut dst[36..40], x9)
	binary.little_endian_put_u32(mut dst[40..44], x10)
	binary.little_endian_put_u32(mut dst[44..48], x11)
	binary.little_endian_put_u32(mut dst[48..52], x12)
	binary.little_endian_put_u32(mut dst[52..56], x13)
	binary.little_endian_put_u32(mut dst[56..60], x14)
	binary.little_endian_put_u32(mut dst[60..64], x15)
}

// set_counter sets the Chacha20 Cipher counter
pub fn (mut c Cipher) set_counter(ctr u32) {
	out_ctr := c.counter - u32(c.ks_len)/block_size
	if c.overflow ||  ctr < out_ctr {
		panic('chacha20: set_counter attempted to rollback counter')
	}

	// In the general case,
	if ctr < c.counter {
		c.ks_len = int(c.counter - ctr) * chacha20.block_size
	} else {
		c.counter = ctr
		c.ks_len = 0
	}
}

fn (mut c Cipher) incr_ctr_by(n u32) {
	if u64(c.counter) + u64(n) == math.max_u32 {
		c.overflow = true
	}

	if c.overflow || u64(c.counter) + u64(n) > math.max_u32 {
		panic("counter would overflow")
	}

	c.counter += n 
}	