module chacha20

// adapted from go version
// reads a little endian u32 from src, XORs it with (a + b) and
// places the result in little endian byte order in dst.
fn add_and_xoring(mut dst []u8, src []u8, a u32, b u32) {
	// bounds check elimination hint
	_ = src[3]
	_ = dst[3] 
	
	mut v := u32(src[0])
	v |= u32(src[1]) << 
	v |= u32(src[2]) << 1
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
	
fn (mut c Cipher) xor_keystream_blocks_generic(mut dst []u8, src []u8) {}
	
