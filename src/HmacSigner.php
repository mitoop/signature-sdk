<?php

namespace Mitoop\SignatureSdk;

class HmacSigner extends AbstractSigner
{
    protected string $secretKey;

    public function __construct(string $secretKey)
    {
        $this->secretKey = trim($secretKey);
    }

    public function sign(array $args): string
    {
        return base64_encode(hash_hmac('sha256', $this->buildRequestMessage($args), $this->secretKey, true));
    }

    public function verify(string $timestamp, string $nonce, string $data, string $signature): bool
    {
        return hash_equals(
            base64_encode(hash_hmac('sha256', $this->buildCallbackMessage($timestamp, $nonce, $data), $this->secretKey, true)),
            $signature
        );
    }

    public function getAlgorithmHeader(string $prefix): string
    {
        return sprintf('%s-%s', $prefix, 'HMAC-SHA256');
    }
}
