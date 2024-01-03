chacha20
-------

Chacha20 (and XChacha20) stream cipher encryption algorithm in V language based on [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

Note that ChaCha20, like all stream ciphers, is not authenticated and allows attackers to silently tamper with the plaintext. For this reason, it is more appropriate as a building block than as a standalone encryption mechanism. Instead, consider using secure modules, like `chacha20poly1305`.

# module chacha

## Contents
- [Constants](#Constants)
- [new_cipher](#new_cipher)
- [otk_key_gen](#otk_key_gen)
- [Cipher](#Cipher)
  - [set_counter](#set_counter)
  - [encrypt](#encrypt)
  - [decrypt](#decrypt)
  - [xor_key_stream](#xor_key_stream)

## Constants
```v
const key_size = 32
```
key_size is key size of ChaCha20 key (256 bits size), in bytes

[[Return to contents]](#Contents)

```v
const nonce_size = 12
```
nonce_size is nonce_size for original ChaCha20 nonce (96 bits size), in bytes

[[Return to contents]](#Contents)

```v
const x_nonce_size = 24
```
extended nonce size of chacha20, called xchacha20, 192 bits nonce size

[[Return to contents]](#Contents)

## new_cipher
```v
fn new_cipher(key []u8, nonce []u8) !&Cipher
```
new_cipher creates a new ChaCha20 stream cipher with the given 32 bytes key and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided, the XChaCha20 construction will be used. It returns an error if key or nonce have any other length. This is the only exported function to create initialized Cipher instances.

[[Return to contents]](#Contents)

## otk_key_gen
```v
fn otk_key_gen(key []u8, nonce []u8) ![]u8
```
otk_key_gen generates one time key using `chacha20` block function if provided nonce was 12 bytes and using `xchacha20`, when its nonce was 24 bytes. This function is intended to generate key for poly1305 mac.

[[Return to contents]](#Contents)

## Cipher
## set_counter
```v
fn (mut c Cipher) set_counter(ctr u32)
```
set_counter sets Cipher's counter

[[Return to contents]](#Contents)

## encrypt
```v
fn (mut c Cipher) encrypt(mut dst []u8, src []u8)
```
encrypt fullfills `cipher.Block.encrypt` interface.

[[Return to contents]](#Contents)

## decrypt
```v
fn (mut c Cipher) decrypt(mut dst []u8, src []u8)
```
encrypt fullfills `cipher.Block.decrypt` interface.

[[Return to contents]](#Contents)

## xor_key_stream
```v
fn (mut c Cipher) xor_key_stream(mut dst []u8, src []u8)
```
xor_key_stream fullfills `cipher.Stream` interface. Internally, its encrypts plaintext message in src and stores ciphertext result in dst. Its not fully compliant with the interface in the manner its run in single run of encryption.

[[Return to contents]](#Contents)


