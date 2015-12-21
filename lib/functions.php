<?php

namespace ChaCha20Poly1305;

function encrypt($key, $nonce, $aad, $plaintext)
{
    $cipher = new Cipher();
    $context = $cipher->init($key, $nonce);
    $cipher->aad($context, $aad);
    $ciphertext = $cipher->encrypt($context, $plaintext);
    $tag = $cipher->finish($context);
    return [$ciphertext, $tag];
}

function decrypt($key, $nonce, $aad, $ciphertext, $tag)
{
    $cipher = new Cipher();
    $context = $cipher->init($key, $nonce);
    $cipher->aad($context, $aad);
    $plaintext = $cipher->decrypt($context, $ciphertext);
    $cipher->finish($context, $tag);
    return $plaintext;
}

function verify($key, $nonce, $aad, $ciphertext, $tag)
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