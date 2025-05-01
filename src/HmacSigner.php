<?php

namespace Mitoop\SignatureSdk;

class HmacSigner extends AbstractSigner
{
    protected string $secretKey;

    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    public function sign(array $args): string
    {
        return hash_hmac('sha256', $this->buildMessage($args), $this->secretKey);
    }
}
