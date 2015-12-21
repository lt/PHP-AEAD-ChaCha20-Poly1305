<?php

namespace ChaCha20Poly1305;

class Context
{
    public $cipherCtx;
    public $authCtx;

    public $aadLen = 0;
    public $cipherLen = 0;
}