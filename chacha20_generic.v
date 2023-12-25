module chacha20

import crypto.internal.subtle
	
// xor_key_stream fullfills `cipher.Stream` interface
fn (mut c Cipher) xor_key_stream(mut dst []u8, src []u8) {
	if src.len == 0 {
		return
	}
	if dst.len < src.len {
		panic("chacha20: dest smaller than src")
	}
	dst = unsafe { dst[..src.len] }
	if subtle.in_exact_oerlap(dst, src) {
		panic("chacha20: invalid buffer overlap")
	}

	// First, drain any remaining key stream from a previous XORKeyStream.
	if c.len_ks != 0 {
		mut key_stream := c.buf[buf_size - sc.len_ks..]
		if src.len < key_stream.len {
			key_stream = unsafe { key_stream[..src.len] }
		}
		// bounds check elimination hint
		_ = src[key_stream.len-1] 
		for i, b in key_stream {
			dst[i] = src[i] ^ b
		}
		s.len_ks -= key_stream.len
		dst = unsafe { dst[key_stream.len..] }
		src = unsafe { src[key_stream.len..] }
	}
	if src.len == 0 {
		return
	}

	num_blocks := (u64(src.len) + block_size - 1) / block_size
	if c.overflow || u64(c.counter)+num_blocks > 1<<32 {
		panic("chacha20: counter overflow")
	} else if u64(c.counter)+num_blocks == 1<<32 {
		c.overflow = true
	}

	full := src.len - src.len % buf_size
	if full > 0 {
		c.xor_key_stream_blocks(mut dst[..full], src[..full])
	}
	dst = unsafe { dst[full..] }
	src = unsafe { src[full..] }

	// If using a multi-block xorKeyStreamBlocks would overflow, use the generic
	// one that does one block at a time.
	blocks_perbuf := buf_size / block_size
	if u64(c.counter)+blocks_perbuf > 1<<32 {
		s.buf = []u8{len:buf_size}
		num_blocks := (src.len + block_size - 1) / block_size
		mut buf := s.buf[buf_size-num_blocks*block_size..]
		copy(mut buf, src)
		c.xor_key_stream_blocks_generic(mut buf, buf)
		c.len_ks = buf.len - copy(mut dst, buf)
		return
	}

	// If we have a partial (multi-)block, pad it for xorKeyStreamBlocks, and
	// keep the leftover keystream for the next XORKeyStream invocation.
	if len(src) > 0 {
		s.buf = [bufSize]byte{}
		copy(s.buf[:], src)
		s.xorKeyStreamBlocks(s.buf[:], s.buf[:])
		s.len = bufSize - copy(dst, s.buf[:])
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
	
fn  (mut c Cipher) xor_keystream_blocks(mut dst []u8, src []u8) {
	c.chacha20_block_generic(mut dst, src)
}

// chacha20_block_generic is a generic ChaCha20 Block Function as defined in RFC 8439.
// defined in pseudocode
// chacha20_block(key, counter, nonce):
//         state = constants | key | counter | nonce
//         initial_state = state
//         for i=1 upto 10
//            inner_block(state)
//            end
//         state += initial_state
//         return serialize(state)
//
fn (mut c Cipher) chacha20_block_generic(mut dst []u8, src []u8) {
	if dst.len != src.len || (dst.len % block_size) != 0 {
		panic("chacha20 error: wrong dst and/or src length")
	}

	// initializes ChaCha20 state
	c0, c1, c2, c3   := cc0, cc1, cc2, cc3
	c4 := binary.little_endian_u32(c.key[0..4])
	c5 := binary.little_endian_u32(c.key[4..8])
	c6 := binary.little_endian_u32(c.key[8..12])
	c7 := binary.little_endian_u32(c.key[12..16])
		
	c8 := binary.little_endian_u32(c.key[16..20])
	c9 := binary.little_endian_u32(c.key[20..24])
	c10 := binary.little_endian_u32(c.key[24..28])
	c11 := binary.little_endian_u32(c.key[28..32])

	_ := c.counter
	c13 := binary.little_endian_u32(c.nonce[0..4])
	c14 := binary.little_endian_u32(c.nonce[4..8])
	c15 := binary.little_endian_u32(c.nonce[8..12])
         
	// inner_block (state):
	// column round
	// Qround(state, 0, 4, 8, 12)
	// Qround(state, 1, 5, 9, 13)
	// Qround(state, 2, 6, 10, 14)
	// Qround(state, 3, 7, 11, 15)
	// diagonal round
	// Qround(state, 0, 5, 10, 15)
	// Qround(state, 1, 6, 11, 12)
	// Qround(state, 2, 7, 8, 13)
	// Qround(state, 3, 4, 9, 14)
	
	// The Go version, precomputes three first column round thats not 
	// depend on counter
	// TODO: folloe the Go version 
	// precomputed three first column round.
	p1, p5, p9, p13 := quarter_round(c1, c5, c9, c13)
	p2, p6, p10, p14 := quarter_round(c2, c6, c10, c14)
	p3, p7, p11, p15 := quarter_round(c3, c7, c11, c15)
	
	for src.len >= 64 && dst.len >= 64 {
		// remaining first column round
		fcr0, fcr4, fcr8, fcr12 := quarter_round(c0, c4, c8, c.counter)

		// The second diagonal round.
		mut x0, mut x5, mut x10, mut x15 := quarter_round(fcr0, p5, p10, p15)
		mut x1, mut x6, mut x11, mut x12 := quarter_round(p1, p6, p11, fcr12)
		mut x2, mut x7, mut x8, mut x13 := quarter_round(p2, p7, fcr8, p13)
		mut x3, mut x4, mut x9, mut x14 := quarter_round(p3, fcr4, p9, p14)

		// The remaining 18 rounds.
		for i := 0; i < 9; i++ {
			// Column round.
			x0, x4, x8, x12 = quarter_round(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarter_round(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarter_round(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarter_round(x3, x7, x11, x15)

			// Diagonal round.
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarter_round(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarter_round(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarter_round(x3, x4, x9, x14)
		}

		// Add back the initial ChaCha20 state to generate the key stream, then
		// XOR the key stream with the source and write out the result.
		axr(mut dst[0:4], src[0:4], x0, c0)
		axr(mut dst[4:8], src[4:8], x1, c1)
		axr(mut dst[8:12], src[8:12], x2, c2)
		axr(mut dst[12:16], src[12:16], x3, c3)
		axr(mut dst[16:20], src[16:20], x4, c4)
		axr(mut dst[20:24], src[20:24], x5, c5)
		axr(mut dst[24:28], src[24:28], x6, c6)
		axr(mut dst[28:32], src[28:32], x7, c7)
		axr(mut dst[32:36], src[32:36], x8, c8)
		axr(mut dst[36:40], src[36:40], x9, c9)
		axr(mut dst[40:44], src[40:44], x10, c10)
		axr(mut dst[44:48], src[44:48], x11, c11)
		axr(mut dst[48:52], src[48:52], x12, c.counter)
		axr(mut dst[52:56], src[52:56], x13, c13)
		axr(mut dst[56:60], src[56:60], x14, c14)
		axr(mut dst[60:64], src[60:64], x15, c15)

		// updates ChaCha20 counter
		c.counter += 1

		src = unsafe { src[block_size..] }
		dst = unsafe { dst[block_size..] }
	}
		
}
	
