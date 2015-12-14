<?php declare(strict_types = 1);

namespace AEAD;

use ChaCha20\Cipher;
use Poly1305\Authenticator;

class ChaCha20Poly1305
{
    function keygen($key, $nonce)
    {
        $cipher = new Cipher();
        $ctx = $cipher->init($key, $nonce);
        return $cipher->encrypt($ctx, str_repeat("\0", 32));
    }

    function pad16($data)
    {
        return str_repeat("\0", 16 - (strlen($data) % 16));
    }

    function encrypt($aad, $key, $nonce, $plaintext)
    {
        $otk = $this->keygen($key, $nonce);

        $cipher = new Cipher();
        $ctx = $cipher->init($key, $nonce);
        $cipher->setCounter($ctx, 1);

        $ciphertext = $cipher->encrypt($ctx, $plaintext);

        $aadLen = packLength(strlen($aad));
        $cipherLen = packLength(strlen($ciphertext));

        $tag = \Poly1305\authenticate($otk, $aad . $this->pad16($aad) . $ciphertext . $this->pad16($ciphertext) . $aadLen . $cipherLen);

        return [
            $ciphertext,
            $tag
        ];
    }

    function decrypt($aad, $key, $nonce, $ciphertext, $tag)
    {
        $otk = $this->keygen($key, $nonce);

        $aadLen = packLength(strlen($aad));
        $cipherLen = packLength(strlen($ciphertext));

        if (\Poly1305\verify($tag, $otk, $aad . $this->pad16($aad) . $ciphertext . $this->pad16($ciphertext) . $aadLen . $cipherLen)) {
            throw new \Exception('Incorrect tag');
        }

        $cipher = new Cipher();
        $ctx = $cipher->init($key, $nonce);
        $cipher->setCounter($ctx, 1);

        return $cipher->decrypt($ctx, $ciphertext);
    }
}

if (version_compare(PHP_VERSION, '5.6.3') >= 0) {
    function packLength($len)
    {
        return pack('P', $len);
    }
}
else {
    function packLength($len)
    {
        return pack('VV', $len, $len >> 32);
    }
}
