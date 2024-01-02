module chacha20

// key_stream fills stream with cryptographically secure pseudorandom bytes
// from c's keystream when a random key and nonce are used.
fn (mut c Cipher) key_stream(stream []u8) {
	mut out := []u8{len: stream.len}
	c.encrypt(mut out, stream)
}

fn (mut c Cipher) encrypt_generic_ref(src []u8) []u8 {
	// checks for counter overflow
	num_blocks := src.len + block_size - 1 / block_size
	if c.overflow || u64(c.counter + num_blocks) > 1 << 32 {
		panic('chacha20: counter would overflow')
	} else if u64(c.counter + num_blocks) == 1 << 32 {
		c.overflow = true
	}

	mut encrypted_message := []u8{}

	for i := 0; i < src.len / block_size; i++ {
		// block_generic(key, counter + u32(i), nonce) or {
		c.add_counter(i)
		key_stream := c.make_block_generic_ref() or { return error('chacha20: fail on key_stream') }
		block := src[i * block_size..(i + 1) * block_size]

		// encrypted_message += block ^ key_stream
		mut dst := []u8{len: block.len}
		n := cipher.xor_bytes(mut dst, block, key_stream)
		assert n == key_stream.len

		// encrypted_message = encrypted_message + dst
		encrypted_message << dst
	}
	// partial block
	if src.len % block_size != 0 {
		j := src.len / block_size
		// block_generic(key, counter + u32(j), nonce) or {
		c.add_counter(j)
		key_stream := c.make_block_generic_ref() or {
			return error('chacha20: encrypt_generic fail key_stream')
		}
		block := src[j * block_size..]

		// encrypted_message += (block^key_stream)[0..len(plaintext)%block_size]
		mut dst := []u8{len: block.len}
		n := cipher.xor_bytes(mut dst, block, key_stream)
		assert n == key_stream.len

		dst = unsafe { dst[0..src.len % block_size] }

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
	_ = key[key_size - 1]
	if nonce.len !in [nonce_size, x_nonce_size] {
		return error('Bad nonce size')
	}
	// ensure nonce size is valid
	counter := u32(0)
	if nonce.len == x_nonce_size {
		mut cnonce := nonce[16..].clone()
		subkey := hchacha20(key, nonce[0..16])
		cnonce.prepend([u8(0x00), 0x00, 0x00, 0x00])
		block := block_generic(subkey, counter, cnonce)!
		return block[0..32]
	}
	if nonce.len == nonce_size {
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
	if key.len != key_size {
		return error('ChaCha20: wrong key size provided=${key.len}')
	}
	if nonce.len != nonce_size {
		return error('ChaCha20: wrong nonce size provided=${nonce.len}')
	}
	mut state := []u32{len: 16}

	state[0] = cc0
	state[1] = cc1
	state[2] = cc2
	state[3] = cc3

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
	_, _ = key[key_size - 1], nonce[nonce_size - 1]
	mut decrypted_message := []u8{}

	for i := 0; i < ciphertext.len / block_size; i++ {
		key_stream := block_generic(key, counter + u32(i), nonce)!
		block := ciphertext[i * block_size..(i + 1) * block_size]

		mut dst := []u8{len: block.len}
		if subtle.inexact_overlap(block, key_stream) {
			panic('chacha: subtle inexact overlap')
		}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		decrypted_message << dst
	}
	if ciphertext.len % block_size != 0 {
		j := ciphertext.len / block_size
		key_stream := block_generic(key, counter + u32(j), nonce)!
		block := ciphertext[j * block_size..]

		mut dst := []u8{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		// use unsafe or explicit .clone()
		dst = unsafe { dst[0..ciphertext.len % block_size] }

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
