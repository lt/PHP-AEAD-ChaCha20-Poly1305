RFC 7539 ChaCha20/Poly1305 AEAD construction
============================================

This library contains a pure PHP implementation of the RFC 7539 ChaCha20/Poly1305 [AEAD construction](https://en.wikipedia.org/wiki/Authenticated_encryption).

### Usage:

Remember that *a nonce must not be used more than once for a particular key*

The library contains both one-shot functions for small amounts of data, and methods for processing streams of information without consuming large amounts of memory.

*One-shot functions*

```
// Encrypt and produce a ciphertext and tag.
list($ciphertext, $tag) = \ChaCha20Poly1305\encrypt($key, $nonce, $aad, $plaintext);

// Decrypt and produce a plaintext, throw an exception if the tag is invalid.
$plaintext = \ChaCha20Poly1305\decrypt($key, $nonce, $aad, $plaintext, $tag);

// Verify without decryption, return true/false depending the tag being valid.
$valid = \ChaCha20Poly1305\verify($key, $nonce, $aad, $plaintext, $tag);
```

The `Context` object maintains the current state of all of the moving parts so they can be used for streaming. A separate context is needed for each stream.

*Stream methods*

```
$cipher = new \ChaCha20Poly1305\Cipher;
$encCtx = $cipher->init($key, $nonce);

$cipher->aad($encCtx, $additionalData);
$cipher->aad($encCtx, $moreData);

$ciphertext = $cipher->encrypt($encCtx, $plaintext);
$ciphertext .= $cipher->encrypt($encCtx, $morePlaintext);

$tag = $cipher->finish($encCtx);

// Or

$cipher = new \ChaCha20Poly1305\Cipher;
$decCtx = $cipher->init($key, $nonce);

$cipher->aad($decCtx, $additionalData);
$cipher->aad($decCtx, $moreData);

// Could also $cipher->verify() to skip decryption overhead.
$plaintext = $cipher->decrypt($decCtx, $ciphertext);
$plaintext .= $cipher->decrypt($decCtx, $moreCiphertext);

try {
    $cipher->finish($decCtx, $tag);
}
catch (\ChaCha20Poly1305\AuthenticationException $e) {
    // Tag was not valid
}
```