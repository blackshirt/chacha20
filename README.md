chacha20
-------

Chacha20 (and XChacha20) stream cipher encryption algorithm in V language based on [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

Note that ChaCha20, like all stream ciphers, is not authenticated and allows attackers to silently tamper with the plaintext. For this reason, it is more appropriate as a building block than as a standalone encryption mechanism. Instead, consider using secure modules, like `chacha20poly1305`.