# module chacha




## Contents
- [Constants](#Constants)
- [new_cipher](#new_cipher)
- [otk_key_gen](#otk_key_gen)
- [Cipher](#Cipher)
  - [encrypt](#encrypt)
  - [decrypt](#decrypt)
  - [set_counter](#set_counter)

## Constants
```v
const (
	// key_size is key size of ChaCha20 key (256 bits size), in bytes
	key_size     = 32
	// nonce_size is nonce_size for original ChaCha20 nonce (96 bits size), in bytes
	nonce_size   = 12
	// extended nonce size of chacha20, called xchacha20, 192 bits nonce size
	x_nonce_size = 24
	// ChaCha20 block size, in bytes
	block_size   = 64
)
```


[[Return to contents]](#Contents)

## new_cipher
```v
fn new_cipher(key []u8, nonce []u8) !Cipher
```

new_cipher creates a new ChaCha20 stream cipher with the given 32 bytes key and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided, the XChaCha20 construction
will be used. It returns an error if key or nonce have any other length.  
This is the only exported function to create initialized Cipher instances.  

Note: see `encrypt` or `README` notes.  

[[Return to contents]](#Contents)

## otk_key_gen
```v
fn otk_key_gen(key []u8, nonce []u8) ![]u8
```

otk_key_gen generates one time key using `chacha20` block function if provided
nonce was 12 bytes and using `xchacha20`, when its nonce was 24 bytes.  
This function is intended to generate key for poly1305 mac.  

[[Return to contents]](#Contents)

## Cipher
## encrypt
```v
fn (c Cipher) encrypt(plaintext []u8) ![]u8
```

encrypt encrypts plaintext with chacha20 stream cipher based on nonce size provided in cipher instance, it's sizes was 12 bytes on standard ietf, constructed using standar chachar20 generic function,
otherwise the size was 24 bytes and constructed using extended xchacha20 mechanism using `hchacha20` function.  

This is provided as convenient mechanism to do some encryption on the some plaintext.  

[[Return to contents]](#Contents)

## decrypt
```v
fn (c Cipher) decrypt(ciphertext []u8) ![]u8
```

decrypt decrypts ciphertext encrypted with ChaCha20 encryption function.  
This doing thing in reverse way of encrypt.  

[[Return to contents]](#Contents)

## set_counter
```v
fn (mut c Cipher) set_counter(ctr u32)
```

set_counter sets the Cipher counter

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 28 Jul 2023 20:04:10
