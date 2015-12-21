<?php declare(strict_types = 1);

namespace ChaCha20Poly1305;

class Cipher
{
    private $chacha20;
    private $poly1305;

    function __construct()
    {
        $this->chacha20 = new \ChaCha20\Cipher();
        $this->poly1305 = new \Poly1305\Authenticator();
    }

    function init($key, $nonce)
    {
        $ctx = new Context();
        $ctx->cipherCtx = $this->chacha20->init($key, $nonce);

        $otk = $this->chacha20->encrypt($ctx->cipherCtx, str_repeat("\0", 32));
        $ctx->authCtx = $this->poly1305->init($otk);

        $this->chacha20->setCounter($ctx->cipherCtx, 1);

        return $ctx;
    }

    function aad(Context $ctx, $aad)
    {
        if ($ctx->cipherLen) {
            throw new \LogicException('Authenticated data not allowed after encrypt/decrypt operations.');
        }

        $this->poly1305->update($ctx->authCtx, $aad);
        $ctx->aadLen += strlen($aad);
    }

    private function pad16($len)
    {
        return str_repeat("\0", 16 - ($len % 16));
    }

    function encrypt(Context $ctx, $plaintext)
    {
        if (!$ctx->cipherLen) {
            $this->poly1305->update($ctx->authCtx, $this->pad16($ctx->aadLen));
        }

        $ciphertext = $this->chacha20->encrypt($ctx->cipherCtx, $plaintext);
        $this->poly1305->update($ctx->authCtx, $ciphertext);

        $ctx->cipherLen += strlen($ciphertext);

        return $ciphertext;
    }

    function decrypt(Context $ctx, $ciphertext)
    {
        if (!$ctx->cipherLen) {
            $this->poly1305->update($ctx->authCtx, $this->pad16($ctx->aadLen));
        }

        $this->poly1305->update($ctx->authCtx, $ciphertext);
        $plaintext = $this->chacha20->encrypt($ctx->cipherCtx, $ciphertext);

        $ctx->cipherLen += strlen($ciphertext);

        return $plaintext;
    }

    function verify(Context $ctx, $ciphertext)
    {
        if (!$ctx->cipherLen) {
            $this->poly1305->update($ctx->authCtx, $this->pad16($ctx->aadLen));
        }

        $this->poly1305->update($ctx->authCtx, $ciphertext);

        $ctx->cipherLen += strlen($ciphertext);
    }

    function finish(Context $ctx, $tag = '')
    {
        $cipherLen = $ctx->cipherLen;
        $this->poly1305->update($ctx->authCtx, $this->pad16($cipherLen));

        // Pack code P only available in 5.6.3 or greater.
        $packedAadLen = pack('VV', $ctx->aadLen, $ctx->aadLen >> 32);
        $packedCipherLen = pack('VV', $cipherLen, $cipherLen >> 32);

        $this->poly1305->update($ctx->authCtx, $this->pad16($cipherLen) . $packedAadLen . $packedCipherLen);
        $mac = $this->poly1305->finish($ctx->authCtx);

        if ($tag) {
            if (!hash_equals($mac, $tag)) {
                throw new \Exception('Calculated tag does not match supplied tag');
            }
        }

        return $mac;
    }
}
