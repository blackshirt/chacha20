module chacha20

import crypto.cipher
import encoding.binary
import crypto.internal.subtle

// xor_key_stream fullfills `cipher.Stream` interface
pub fn (mut c Cipher) xor_key_stream(mut dst []u8, src_ []u8) {
	mut src := unsafe { src_ }
	if src.len == 0 {
		return
	}
	if dst.len < src.len {
		panic('chacha20: dest smaller than src')
	}
	dst = unsafe { dst[..src.len] }
	if subtle.inexact_overlap(dst, src) {
		panic('chacha20: invalid buffer overlap')
	}

	// First, drain any remaining key stream from a previous xorkeystream.
	if c.kslen != 0 {
		mut key_stream := c.ksbuf[buf_size - c.kslen..]
		if src.len < key_stream.len {
			key_stream = unsafe { key_stream[..src.len] }
		}
		// bounds check elimination hint
		_ = src[key_stream.len - 1]
		n := cipher.xor_bytes(mut dst, src, key_stream)
		assert n == key_stream.len
		// for i, b in key_stream {
		// 	dst[i] = src[i] ^ b
		// }
		c.kslen -= key_stream.len
		dst = unsafe { dst[key_stream.len..] }
		src = unsafe { src[key_stream.len..] }
	}
	if src.len == 0 {
		return
	}

	// checks for counter overflow
	// num_blocks := (u64(src.len) + block_size - 1) / block_size
	mut num_blocks := src.len / block_size
	if src.len % block_size != 0 {
		num_blocks += 1
	}
	if c.eof || u64(c.counter + num_blocks) > 1 << 32 {
		panic('chacha20: counter is eof')
	} else if u64(c.counter + num_blocks) == 1 << 32 {
		c.eof = true
	}

	full := src.len - src.len % buf_size
	if full > 0 {
		c.xor_key_stream_blocks(mut dst[..full], src[..full])
	}
	dst = unsafe { dst[full..] }
	src = unsafe { src[full..] }

	// If using a multi-block xorKeyStreamBlocks would eof, use the generic
	// one that does one block at a time.
	blocks_perbuf := buf_size / block_size
	if u64(c.counter + blocks_perbuf) > 1 << 32 {
		c.ksbuf = []u8{len: buf_size}
		nr_blocks := (src.len + block_size - 1) / block_size
		mut buf := c.ksbuf[buf_size - nr_blocks * block_size..]
		_ := copy(mut buf, src)
		c.xor_key_stream_blocks(mut buf, buf)
		c.kslen = buf.len - copy(mut dst, buf)
		return
	}

	// partial block
	if src.len > 0 {
		c.ksbuf = []u8{len: buf_size}
		copy(mut c.ksbuf[..], src)
		c.xor_key_stream_blocks(mut c.ksbuf[..], c.ksbuf[..])
		c.kslen = buf_size - copy(mut dst, c.ksbuf[..])
	}
}

// adapted from go version
// reads a little endian u32 from src, XORs it with (a + b) and
// places the result in little endian byte order in dst.
fn axr(mut dst []u8, src []u8, a u32, b u32) {
	// bounds check elimination hint
	_ = src[3]
	_ = dst[3]

	mut v := u32(src[0])
	v |= u32(src[1]) << 8
	v |= u32(src[2]) << 16
	v |= u32(src[3]) << 24
	v ^= (a + b)

	dst[0] = u8(v)
	dst[1] = u8(v >> 8)
	dst[2] = u8(v >> 16)
	dst[3] = u8(v >> 24)
}

fn (mut c Cipher) xor_key_stream_blocks(mut dst []u8, src []u8) {
	c.chacha20_block_generic(mut dst, src)
}

// chacha20_block_generic is a generic ChaCha20 Block Function as described in RFC 8439.
// chacha20_block(key, counter, nonce):
//         state = constants | key | counter | nonce
//         initial_state = state
//         for i=1 upto 10
//            inner_block(state)
//         state += initial_state
//         return serialize(state)
// where :
// inner_block (state):
//      Qround(state, 0, 4, 8, 12)
//      Qround(state, 1, 5, 9, 13)
//      Qround(state, 2, 6, 10, 14)
//      Qround(state, 3, 7, 11, 15)
//      Qround(state, 0, 5, 10, 15)
//      Qround(state, 1, 6, 11, 12)
//      Qround(state, 2, 7, 8, 13)
//      Qround(state, 3, 4, 9, 14)
//
