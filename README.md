# module chacha20

Note:
-----
This repo has been archived, Its has been merged to experimental module inside `vlib/x/crypto/chacha,20`. Development will be carried out there.

chacha20
-------

Chacha20 (and XChacha20) stream cipher encryption algorithm in V language based on [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

Note that ChaCha20, like all stream ciphers, is not authenticated and allows attackers to silently tamper with the plaintext. For this reason, it is more appropriate as a building block than as a standalone encryption mechanism. Instead, consider using secure modules, like `chacha20poly1305`.

## Contents
- [Constants](#Constants)
- [encrypt](#encrypt)
- [encrypt_with_counter](#encrypt_with_counter)
- [new_cipher](#new_cipher)
- [Cipher](#Cipher)
  - [free](#free)
  - [reset](#reset)
  - [set_counter](#set_counter)
  - [encrypt](#encrypt)
  - [decrypt](#decrypt)
  - [xor_key_stream](#xor_key_stream)
  - [rekey](#rekey)

## Constants
```v
const key_size = 32
```
size of ChaCha20 key, ie 256 bits size, in bytes

[[Return to contents]](#Contents)

```v
const nonce_size = 12
```
size of ietf ChaCha20 nonce, ie 96 bits size, in bytes

[[Return to contents]](#Contents)

```v
const x_nonce_size = 24
```
size of extended ChaCha20 nonce, called XChaCha20, 192 bits

[[Return to contents]](#Contents)

## encrypt
```v
fn encrypt(key []u8, nonce []u8, plaintext []u8) ![]u8
```
encrypt was a thin wrapper around two supported nonce size, ChaCha20 with 96 bits and XChaCha20 with 192 bits nonce. If you want more control with internal counter see `encrypt_with_counter`

[[Return to contents]](#Contents)

## encrypt_with_counter
```v
fn encrypt_with_counter(key []u8, nonce []u8, ctr u32, plaintext []u8) ![]u8
```
encrypt_with_counter encrypts plaintext with internal counter set to ctr

[[Return to contents]](#Contents)

## new_cipher
```v
fn new_cipher(key []u8, nonce []u8) !&Cipher
```
new_cipher creates a new ChaCha20 stream cipher with the given 32 bytes key and a 12 or 24 bytes nonce. If a nonce of 24 bytes is provided, the XChaCha20 construction will be used. It returns an error if key or nonce have any other length.

[[Return to contents]](#Contents)

## Cipher
## free
```v
fn (mut c Cipher) free()
```
free the resources taken by the Cipher `c`. Dont use cipher after .free call

[[Return to contents]](#Contents)

## reset
```v
fn (mut c Cipher) reset()
```
reset quickly sets all Cipher's fields to default value

[[Return to contents]](#Contents)

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
encrypt encrypts plaintext in src bytes and stores ciphertext result in dst. Its fullfills `cipher.Block.encrypt` interface.

[[Return to contents]](#Contents)

## decrypt
```v
fn (mut c Cipher) decrypt(mut dst []u8, src []u8)
```
decrypt does reverse of .encrypt() operation, decrypts ciphertext in src, and stores the result in dst. decrypt fullfills `cipher.Block.decrypt` interface.

[[Return to contents]](#Contents)

## xor_key_stream
```v
fn (mut c Cipher) xor_key_stream(mut dst []u8, src []u8)
```
xor_key_stream xors each byte in the given slice in the src with a byte from the cipher's key stream. It fullfills `cipher.Stream` interface. Its does encrypts plaintext message in src and stores ciphertext result in dst in single shot of run of encryption.

[[Return to contents]](#Contents)

## rekey
```v
fn (mut c Cipher) rekey(key []u8, nonce []u8) !
```
rekey resets internal Cipher's state and reinitializes state with the provided key and nonce

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 5 Jan 2024 11:23:39
