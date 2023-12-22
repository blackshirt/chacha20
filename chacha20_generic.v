module chacha20

// adapted from go version
// reads a little endian u32 from src, XORs it with (a + b) and
// places the result in little endian byte order in dst.
fn add_and_xoring(mut dst []u8, src []u8, a u32, b u32) {
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
	c.xor_keystream_blocks_generic(mut dst, src)
}
	
fn (mut c Cipher) xor_keystream_blocks_generic(mut dst []u8, src []u8) {
	if dst.len != src.len || (dst.len % block_size) != 0 {
		panic("chacha20 error: wrong dst and/or src length")
	}

	// initial state
	c0, c1, c2, c3   := cc0, cc1, cc2, cc3
	c4, c5, c6, c7   := s.key[0], s.key[1], s.key[2], s.key[3]
	c8, c9, c10, c11 := s.key[4], s.key[5], s.key[6], s.key[7]
	_, c13, c14, c15 := s.counter, s.nonce[0], s.nonce[1], s.nonce[2]
	
        // caches part of first round
	if !s.precomp_done {
		s.p1, s.p5, s.p9, s.p13 = quarter_round(c1, c5, c9, c13)
		s.p2, s.p6, s.p10, s.p14 = quarter_round(c2, c6, c10, c14)
		s.p3, s.p7, s.p11, s.p15 = quarterRound(c3, c7, c11, c15)
		s.precomp_done = true
	}

	for src.len >= 64 && dst.len >= 64 {
		// The remainder of the first column round.
		fcr0, fcr4, fcr8, fcr12 := quarter_round(c0, c4, c8, s.counter)

		// The second diagonal round.
		x0, x5, x10, x15 := quarter_round(fcr0, s.p5, s.p10, s.p15)
		x1, x6, x11, x12 := quarter_round(s.p1, s.p6, s.p11, fcr12)
		x2, x7, x8, x13 := quarter_round(s.p2, s.p7, fcr8, s.p13)
		x3, x4, x9, x14 := quarter_round(s.p3, fcr4, s.p9, s.p14)

		// The remaining 18 rounds.
		for i := 0; i < 9; i++ {
			// Column round.
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarter_round(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarter_round(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarter_round(x3, x7, x11, x15)

			// Diagonal round.
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarter_round(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarter_round(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarter_round(x3, x4, x9, x14)
		}

		// Add back the initial state to generate the key stream, then
		// XOR the key stream with the source and write out the result.
		add_and_xoring(mut dst[0:4], src[0:4], x0, c0)
		add_and_xoring(mut dst[4:8], src[4:8], x1, c1)
		add_and_xoring(mut dst[8:12], src[8:12], x2, c2)
		add_and_xoring(mut dst[12:16], src[12:16], x3, c3)
		add_and_xoring(mut dst[16:20], src[16:20], x4, c4)
		add_and_xoring(mut dst[20:24], src[20:24], x5, c5)
		add_and_xoring(mut dst[24:28], src[24:28], x6, c6)
		add_and_xoring(mut dst[28:32], src[28:32], x7, c7)
		add_and_xoring(mut dst[32:36], src[32:36], x8, c8)
		add_and_xoring(mut dst[36:40], src[36:40], x9, c9)
		add_and_xoring(mut dst[40:44], src[40:44], x10, c10)
		add_and_xoring(mut dst[44:48], src[44:48], x11, c11)
		add_and_xoring(mutvdst[48:52], src[48:52], x12, s.counter)
		add_and_xoring(mut dst[52:56], src[52:56], x13, c13)
		add_and_xoring(mut dst[56:60], src[56:60], x14, c14)
		add_and_xoring(mut dst[60:64], src[60:64], x15, c15)

		s.counter += 1

		src = unsafe { src[block_size..] }
		dst = unsafe { dst[block_size..] }
	}
		
}
	
