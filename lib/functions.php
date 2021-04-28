<?php declare(strict_types = 1);

namespace ChaCha20Poly1305;

function encrypt(string $key, string $nonce, string $aad, string $plaintext): array
{
    $cipher = new Cipher();
    $context = $cipher->init($key, $nonce);
    $cipher->aad($context, $aad);
    $ciphertext = $cipher->encrypt($context, $plaintext);
    $tag = $cipher->finish($context);
    return [$ciphertext, $tag];
}

function decrypt(string $key, string $nonce, string $aad, string $ciphertext, string $tag): string
{
    $cipher = new Cipher();
    $context = $cipher->init($key, $nonce);
    $cipher->aad($context, $aad);
    $plaintext = $cipher->decrypt($context, $ciphertext);
    $cipher->finish($context, $tag);
    return $plaintext;
}

function verify(string $key, string $nonce, string $aad, string $ciphertext, string $tag): bool
{
    $cipher = new Cipher();
    $context = $cipher->init($key, $nonce);
    $cipher->aad($context, $aad);
    $cipher->verify($context, $ciphertext);
    try {
        $cipher->finish($context, $tag);
        return true;
    }
    catch (AuthenticationException $e) {
        return false;
    }
}
